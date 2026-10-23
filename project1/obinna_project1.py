#!/usr/bin/env python3
"""Secure Log and IOC Analyzer (Cyber Operations Project 1).

This command-line tool authenticates an analyst, parses Linux SSH
authentication logs and Apache/Nginx web access logs, extracts indicators
of compromise (IOCs), applies simple detection rules, checks the results
against an optional watchlist, and writes a defanged report.

Security design highlights:
    * The analyst passphrase is never stored or hardcoded.  Only a salted
      scrypt hash is loaded from the environment (or a local ``.env`` file
      that is excluded from version control).
    * Passphrases are compared in constant time and login attempts are
      limited with an increasing delay to slow brute-force guessing.
    * Every user-supplied value (paths, thresholds, formats) is validated
      against an allowlist before use.
    * Log output is sanitized to prevent log injection, and report files are
      protected against CSV formula injection and accidental overwrite.

Author: Obinna Obiora
Course: M.Sc. Cyber Operations, University of Maryland Global Campus
"""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import stat
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

# Configuration constants --------------------

APP_NAME = "ioc-analyzer"
APP_VERSION = "1.2.0"

#: Environment variable that holds the scrypt hash of the analyst passphrase.
HASH_ENV_VAR = "IOC_ANALYZER_PASSWORD_HASH"
#: Optional local file the hash can be loaded from (never committed to Git).
ENV_FILE_NAME = ".env"

MAX_LOGIN_ATTEMPTS = 3
MIN_PASSPHRASE_LENGTH = 12
MAX_PASSPHRASE_LENGTH = 128

# scrypt work factors: OWASP Password Storage Cheat Sheet minimum (N=2^17, r=8, p=1).
SCRYPT_N = 2**17  # 128 MiB of memory per hash
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_MAXMEM = 256 * 1024 * 1024

MAX_LOG_BYTES = 50 * 1024 * 1024  # Refuse files larger than 50 MB.
MAX_LINE_LENGTH = 8192  # Truncate pathological lines.
ALLOWED_LOG_SUFFIXES = frozenset({".log", ".txt", ""})
ALLOWED_WATCHLIST_SUFFIXES = frozenset({".txt", ".csv"})
ALLOWED_REPORT_FORMATS = ("console", "json", "csv")
THRESHOLD_RANGE = (1, 1000)

LOG_DIR = Path("logs")
APP_LOG_FILE = LOG_DIR / "ioc_analyzer.log"

# Common passphrases rejected regardless of length (NIST SP 800-63B).
WEAK_PASSPHRASES = frozenset({
    "password1234", "passwordpassword", "123456789012", "qwertyuiopas",
    "letmeinletmein", "administrator", "changemenow123",
})

# Regular expressions used for parsing and IOC extraction --------------------

SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F.:]+) port \d+"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F.:]+) port \d+"
)
WEB_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+)'
    r'[^"]*" (?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agent>[^"]*)")?'
)

IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|gov|edu|mil)\b",
        re.IGNORECASE,
    ),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}

WEB_ATTACK_SIGNATURES: dict[str, re.Pattern[str]] = {
    "SQL injection": re.compile(
        r"(?:'|%27)\s*(?:or|and)\s|union(?:\s|%20|\+)+select|sleep\(",
        re.IGNORECASE,
    ),
    "Cross-site scripting": re.compile(r"<script|%3Cscript|onerror=", re.I),
    "Path traversal": re.compile(r"\.\./|%2e%2e%2f|/etc/passwd", re.IGNORECASE),
    "Command injection": re.compile(r";\s*(?:wget|curl|nc|bash)\b|\|\s*sh\b", re.I),
}

SCANNER_AGENTS = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan", re.IGNORECASE
)
URL_SCHEME_RE = re.compile(r"http(s?)://", re.IGNORECASE)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

LOGGER = logging.getLogger(APP_NAME)


# Custom exceptions --------------------


class AnalyzerError(Exception):
    """Base class for all expected, user-facing application errors."""


class ValidationError(AnalyzerError):
    """Raised when user input fails validation."""


class AuthenticationError(AnalyzerError):
    """Raised when the analyst cannot be authenticated."""


class SecretConfigError(AnalyzerError):
    """Raised when the passphrase hash is missing or malformed."""


# Data model --------------------


@dataclass
class Finding:
    """A single detection produced by the analyzer."""

    severity: str
    category: str
    indicator: str
    detail: str
    line_number: int = 0


@dataclass
class AnalysisResult:
    """Aggregated output of one analysis run."""

    source_file: str
    lines_processed: int = 0
    lines_skipped: int = 0
    iocs: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    findings: list[Finding] = field(default_factory=list)
    failed_logins: Counter = field(default_factory=Counter)

    def severity_counts(self) -> dict[str, int]:
        """Return the number of findings for each severity level."""
        counts = Counter(finding.severity for finding in self.findings)
        return {level: counts.get(level, 0) for level in ("HIGH", "MEDIUM", "LOW")}


# Logging helpers --------------------


def sanitize_log_record(record: logging.LogRecord) -> bool:
    """Neutralize CR/LF and control characters to prevent log injection.

    Attackers can embed newline characters in usernames or URLs so that a
    single log line appears as several forged entries (CWE-117).  This filter
    renders the final message, replaces control characters, and clears the
    arguments so the sanitized text is what reaches every handler.

    Args:
        record: The log record about to be emitted.

    Returns:
        Always True, so the (now sanitized) record is still logged.
    """
    record.msg = CONTROL_CHARS_RE.sub("?", record.getMessage())
    record.args = None
    return True


def configure_logging(verbose: bool = False) -> None:
    """Configure console and rotating file logging for the application.

    Args:
        verbose: When True, DEBUG messages are also printed to the console.
    """
    LOG_DIR.mkdir(mode=0o700, exist_ok=True)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(funcName)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = RotatingFileHandler(
        APP_LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    LOGGER.handlers.clear()
    LOGGER.filters.clear()
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.addFilter(sanitize_log_record)
    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(console_handler)
    LOGGER.propagate = False


# Secrets management and authentication --------------------


def validate_passphrase_policy(passphrase: str) -> None:
    """Enforce a length-based passphrase policy aligned with NIST SP 800-63B.

    Args:
        passphrase: Candidate passphrase entered by the analyst.

    Raises:
        ValidationError: If the passphrase is too short, too long, or common.
    """
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValidationError(
            f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )
    if len(passphrase) > MAX_PASSPHRASE_LENGTH:
        raise ValidationError(
            f"Passphrase must be at most {MAX_PASSPHRASE_LENGTH} characters."
        )
    if passphrase.lower() in WEAK_PASSPHRASES or len(set(passphrase)) < 4:
        raise ValidationError("Passphrase is too common or too repetitive.")


def hash_passphrase(passphrase: str, salt: bytes | None = None) -> str:
    """Derive a self-describing scrypt hash string for a passphrase.

    Args:
        passphrase: The plaintext passphrase (held only in memory).
        salt: Optional salt, used by unit tests; a random 16-byte salt is
            generated with the ``secrets`` module when omitted.

    Returns:
        A string in the form ``scrypt$n$r$p$salt_b64$hash_b64``.
    """
    salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(digest).decode("ascii")
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt_b64}${hash_b64}"


def verify_passphrase(passphrase: str, stored_hash: str) -> bool:
    """Check a passphrase against a stored scrypt hash in constant time.

    Args:
        passphrase: The passphrase entered at the prompt.
        stored_hash: Hash string produced by :func:`hash_passphrase`.

    Returns:
        True when the passphrase matches, otherwise False.

    Raises:
        SecretConfigError: If the stored hash is malformed.
    """
    try:
        scheme, n_str, r_str, p_str, salt_b64, hash_b64 = stored_hash.split("$")
        if scheme != "scrypt":
            raise ValueError("unsupported hash scheme")
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
        candidate = hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=int(n_str),
            r=int(r_str),
            p=int(p_str),
            dklen=len(expected),
            maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError) as exc:
        raise SecretConfigError(
            f"The value in {HASH_ENV_VAR} is not a valid scrypt hash."
        ) from exc
    return hmac.compare_digest(candidate, expected)


def read_env_file(env_path: Path) -> dict[str, str]:
    """Parse a minimal ``KEY=VALUE`` .env file without executing it.

    A warning is logged if the file is readable by other users, because the
    hash, while not reversible, should still be treated as sensitive.

    Args:
        env_path: Location of the .env file.

    Returns:
        A dictionary of variables; empty when the file does not exist.
    """
    if not env_path.is_file():
        return {}
    if os.name == "posix" and env_path.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH):
        LOGGER.warning("%s is readable by other users; run chmod 600.", env_path)
    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def load_password_hash(env_path: Path = Path(ENV_FILE_NAME)) -> str:
    """Load the passphrase hash from the environment or a local .env file.

    The process environment takes precedence so that CI pipelines and secret
    managers (for example GitHub Actions secrets) can inject the value.

    Args:
        env_path: Optional .env file consulted when the variable is unset.

    Returns:
        The stored scrypt hash string.

    Raises:
        SecretConfigError: If no hash has been configured.
    """
    stored = os.environ.get(HASH_ENV_VAR) or read_env_file(env_path).get(
        HASH_ENV_VAR
    )
    if not stored:
        raise SecretConfigError(
            f"{HASH_ENV_VAR} is not set. Run 'set-password' first."
        )
    return stored


def authenticate(
    stored_hash: str,
    prompt_func=None,
    max_attempts: int = MAX_LOGIN_ATTEMPTS,
    base_delay: float = 1.0,
) -> None:
    """Prompt for the analyst passphrase and verify it.

    Args:
        stored_hash: The scrypt hash loaded from the secret store.
        prompt_func: Reads the passphrase without echo; defaults to
            ``getpass.getpass`` and is injectable for unit tests.
        max_attempts: Number of attempts before the session is refused.
        base_delay: Seconds to wait after a failure; doubles each time.

    Raises:
        AuthenticationError: When every attempt fails.
    """
    prompt_func = prompt_func or getpass.getpass
    for attempt in range(1, max_attempts + 1):
        passphrase = prompt_func("Analyst passphrase: ")
        if verify_passphrase(passphrase, stored_hash):
            LOGGER.info("Authentication succeeded on attempt %d.", attempt)
            return
        LOGGER.warning("Authentication failed (attempt %d of %d).", attempt, max_attempts)
        print(f"Invalid passphrase ({attempt}/{max_attempts}).", file=sys.stderr)
        time.sleep(base_delay * (2 ** (attempt - 1)))
    LOGGER.error("Maximum authentication attempts exceeded; session refused.")
    raise AuthenticationError("Too many failed attempts. Access denied.")


def create_password_hash(prompt_func=None) -> str:
    """Interactively create and confirm a new analyst passphrase hash.

    Args:
        prompt_func: Function used to read input without echo.

    Returns:
        The new scrypt hash string.

    Raises:
        ValidationError: If the passphrases differ or violate the policy.
    """
    prompt_func = prompt_func or getpass.getpass
    first = prompt_func("New analyst passphrase: ")
    validate_passphrase_policy(first)
    if not hmac.compare_digest(first, prompt_func("Confirm passphrase: ")):
        raise ValidationError("Passphrases do not match.")
    return hash_passphrase(first)


def write_env_file(stored_hash: str, env_path: Path = Path(ENV_FILE_NAME)) -> None:
    """Write the hash to a .env file (mode 600) that .gitignore excludes."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(env_path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(f"{HASH_ENV_VAR}={stored_hash}\n")
    LOGGER.info("Passphrase hash written to %s with mode 600.", env_path)


# Input validation --------------------


def validate_input_file(raw_path: str, allowed_suffixes: frozenset[str]) -> Path:
    """Validate that a user-supplied path is a safe, readable regular file.

    Args:
        raw_path: Path text entered by the user.
        allowed_suffixes: Permitted file extensions (lowercase).

    Returns:
        The resolved absolute path.

    Raises:
        ValidationError: If the path is empty, missing, a symlink, a
            directory, an unsupported type, or too large.
    """
    if not raw_path or not raw_path.strip():
        raise ValidationError("A file path is required.")
    if "\x00" in raw_path:
        raise ValidationError("File path contains an invalid character.")
    candidate = Path(raw_path.strip()).expanduser()
    if candidate.is_symlink():
        raise ValidationError("Symbolic links are not accepted.")
    path = candidate.resolve()
    if not path.exists():
        raise ValidationError(f"File not found: {path}")
    if not path.is_file():
        raise ValidationError(f"Not a regular file: {path}")
    if path.suffix.lower() not in allowed_suffixes:
        allowed = ", ".join(sorted(s or "(none)" for s in allowed_suffixes))
        raise ValidationError(f"Unsupported file type. Allowed: {allowed}")
    if path.stat().st_size > MAX_LOG_BYTES:
        raise ValidationError("File exceeds the 50 MB size limit.")
    return path


def validate_threshold(raw_value: str | int) -> int:
    """Return the brute-force threshold as an int within THRESHOLD_RANGE.

    Raises:
        ValidationError: If the value is not a whole number within range.
    """
    try:
        value = int(str(raw_value).strip())
    except ValueError as exc:
        raise ValidationError("Threshold must be a whole number.") from exc
    low, high = THRESHOLD_RANGE
    if not low <= value <= high:
        raise ValidationError(f"Threshold must be between {low} and {high}.")
    return value


def validate_report_format(raw_value: str) -> str:
    """Return the normalized report format or raise ValidationError."""
    value = (raw_value or "").strip().lower()
    if value not in ALLOWED_REPORT_FORMATS:
        raise ValidationError(
            f"Format must be one of: {', '.join(ALLOWED_REPORT_FORMATS)}."
        )
    return value


def validate_output_path(raw_path: str, report_format: str, force: bool) -> Path:
    """Validate a report destination and protect existing files.

    Args:
        raw_path: Destination path entered by the user.
        report_format: ``json`` or ``csv``; used to check the extension.
        force: Allow an existing file to be overwritten.

    Returns:
        The resolved destination path.

    Raises:
        ValidationError: If the directory is missing, the extension does not
            match the format, or the file exists and ``force`` is False.
    """
    if not raw_path or "\x00" in raw_path:
        raise ValidationError("A valid output path is required.")
    path = Path(raw_path.strip()).expanduser().resolve()
    if path.suffix.lower() != f".{report_format}":
        raise ValidationError(f"Output file must end in .{report_format}.")
    if not path.parent.is_dir():
        raise ValidationError(f"Output directory does not exist: {path.parent}")
    if path.exists() and not force:
        raise ValidationError(f"{path} already exists; use --force to overwrite.")
    return path


# Parsing and detection --------------------


def read_log_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, text)`` pairs, replacing undecodable bytes and
    truncating oversized lines so a crafted file cannot exhaust memory."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            yield number, line.rstrip("\n")[:MAX_LINE_LENGTH]


def is_public_ip(value: str) -> bool:
    """Return True if ``value`` is a valid, globally routable IP address."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def extract_iocs(line: str) -> dict[str, set[str]]:
    """Extract and normalize indicators of compromise from a log line.

    IPv4 candidates are validated with :mod:`ipaddress` so that version
    strings such as ``1.2.3.999`` are not reported. Shorter hash types are
    not reported when they are substrings of a longer hash.

    Args:
        line: One line of log text.

    Returns:
        A mapping of IOC type to the set of values found.
    """
    found: dict[str, set[str]] = defaultdict(set)
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.findall(line):
            value = match.rstrip(".,;)")
            if ioc_type == "ipv4":
                try:
                    ipaddress.IPv4Address(value)
                except ValueError:
                    continue
            if ioc_type in {"domain", "email", "cve"}:
                value = value.lower() if ioc_type != "cve" else value.upper()
            found[ioc_type].add(value)
    longer = found.get("sha256", set()) | found.get("sha1", set())
    for short_type in ("sha1", "md5"):
        found[short_type] = {
            value
            for value in found.get(short_type, set())
            if not any(value in long_hash and value != long_hash for long_hash in longer)
        }
    return {key: values for key, values in found.items() if values}


def decode_request_path(path: str, max_rounds: int = 3) -> str:
    """URL-decode a request path repeatedly to defeat (double) encoding.

    Attackers encode payloads (``%27%20OR``) to slip past naive signatures,
    so the path is decoded until it stops changing or ``max_rounds`` is hit.
    """
    decoded = path
    for _ in range(max_rounds):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def detect_web_attacks(line_number: int, line: str) -> list[Finding]:
    """Apply web attack and scanner signatures to an access log line.

    Args:
        line_number: Line position, recorded for the analyst.
        line: The raw access log line.

    Returns:
        A list of findings (empty if the line is benign or not a web log).
    """
    match = WEB_ACCESS_RE.match(line)
    if not match:
        return []
    findings: list[Finding] = []
    source_ip = match.group("ip")
    request_path = match.group("path")
    decoded_path = decode_request_path(request_path)
    for attack_name, signature in WEB_ATTACK_SIGNATURES.items():
        if signature.search(decoded_path):
            findings.append(
                Finding("HIGH", attack_name, source_ip,
                        f"Suspicious request: {request_path[:120]}", line_number)
            )
    agent = match.group("agent") or ""
    if SCANNER_AGENTS.search(agent):
        findings.append(
            Finding("MEDIUM", "Scanner user agent", source_ip,
                    f"Tool signature in user agent: {agent[:80]}", line_number)
        )
    return findings


def analyze_line(result: AnalysisResult, line_number: int, line: str) -> None:
    """Update ``result`` in place with the IOCs and findings of one line."""
    if not line.strip():
        result.lines_skipped += 1
        return
    result.lines_processed += 1
    for ioc_type, values in extract_iocs(line).items():
        result.iocs[ioc_type].update(values)

    failed = SSH_FAILED_RE.search(line)
    if failed:
        result.failed_logins[failed.group("ip")] += 1
    accepted = SSH_ACCEPTED_RE.search(line)
    if accepted and result.failed_logins.get(accepted.group("ip"), 0) >= 3:
        result.findings.append(
            Finding("HIGH", "Login after repeated failures", accepted.group("ip"),
                    f"Successful login as '{accepted.group('user')}' "
                    "following multiple failures", line_number)
        )
    result.findings.extend(detect_web_attacks(line_number, line))


def apply_brute_force_rule(result: AnalysisResult, threshold: int) -> None:
    """Flag source IPs whose failed SSH logins meet ``threshold``.

    Twice the threshold or more is HIGH severity; otherwise MEDIUM.
    """
    for source_ip, count in result.failed_logins.most_common():
        if count < threshold:
            break
        severity = "HIGH" if count >= threshold * 2 else "MEDIUM"
        scope = "public" if is_public_ip(source_ip) else "private/reserved"
        result.findings.append(
            Finding(severity, "SSH brute force", source_ip,
                    f"{count} failed logins from {scope} address")
        )


def apply_watchlist(result: AnalysisResult, watchlist: set[str]) -> None:
    """Raise a HIGH finding for every extracted IOC on the watchlist."""
    for ioc_type, values in result.iocs.items():
        for value in sorted(values):
            if value.lower() in watchlist:
                result.findings.append(
                    Finding("HIGH", "Watchlist match", value,
                            f"Known-bad {ioc_type} from threat intelligence list")
                )


def load_watchlist(path: Path) -> set[str]:
    """Load a newline- or comma-separated list of known-bad IOCs.

    Lines starting with ``#`` are comments; defanged values are refanged
    and everything is lower-cased so matching is case-insensitive.
    """
    entries: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.lstrip().startswith("#"):
                continue
            for item in line.split(","):
                cleaned = refang(item.strip()).lower()
                if cleaned:
                    entries.add(cleaned)
    LOGGER.info("Loaded %d watchlist entries from %s.", len(entries), path.name)
    return entries


def analyze_file(
    path: Path, threshold: int, watchlist: set[str] | None = None
) -> AnalysisResult:
    """Run the full analysis pipeline on one log file.

    Args:
        path: Validated log file.
        threshold: Brute-force alert threshold.
        watchlist: Optional known-bad indicators.

    Returns:
        The completed :class:`AnalysisResult`.
    """
    result = AnalysisResult(source_file=path.name)
    for line_number, line in read_log_lines(path):
        analyze_line(result, line_number, line)
    apply_brute_force_rule(result, threshold)
    if watchlist:
        apply_watchlist(result, watchlist)
    LOGGER.info(
        "Analyzed %s: %d lines, %d findings.",
        path.name, result.lines_processed, len(result.findings),
    )
    return result


# Reporting --------------------


def defang(value: str) -> str:
    """Make an indicator non-clickable so reports cannot trigger visits."""
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


def refang(value: str) -> str:
    """Reverse :func:`defang` so watchlists may contain defanged values."""
    return (
        value.replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
        .replace("[.]", ".")
        .replace("[@]", "@")
    )


def neutralize_csv_cell(value: object) -> str:
    """Prevent CSV/formula injection when a report is opened in Excel.

    Values beginning with ``=``, ``+``, ``-``, ``@``, tab or carriage return
    are prefixed with a single quote, as recommended by OWASP.
    """
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def build_report(result: AnalysisResult) -> dict:
    """Convert an analysis result into a JSON-serializable, defanged report."""
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = sorted(
        result.findings, key=lambda item: (severity_order[item.severity], item.line_number)
    )
    return {
        "tool": f"{APP_NAME} {APP_VERSION}",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_file": result.source_file,
        "lines_processed": result.lines_processed,
        "severity_counts": result.severity_counts(),
        "iocs": {
            ioc_type: sorted(defang(value) for value in values)
            for ioc_type, values in sorted(result.iocs.items())
        },
        "findings": [
            {
                **asdict(item),
                "indicator": defang(item.indicator),
                "detail": URL_SCHEME_RE.sub(r"hxxp\1://", item.detail),
            }
            for item in findings
        ],
    }


def write_private_file(path: Path, text: str) -> None:
    """Write text to a file created with owner-only permissions."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def export_json(report: dict, path: Path) -> None:
    """Save the report as formatted JSON."""
    write_private_file(path, json.dumps(report, indent=2) + "\n")
    LOGGER.info("JSON report written to %s.", path)


def export_csv(report: dict, path: Path) -> None:
    """Save the findings as CSV with formula-injection protection."""
    columns = ["severity", "category", "indicator", "detail", "line_number"]
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for item in report["findings"]:
        writer.writerow(neutralize_csv_cell(item[col]) for col in columns)
    write_private_file(path, buffer.getvalue())
    LOGGER.info("CSV report written to %s.", path)


def print_report(report: dict) -> None:
    """Print a human-readable summary of the report to standard output."""
    counts = report["severity_counts"]
    print(f"\n=== IOC Analysis: {report['source_file']} ===")
    print(f"Lines processed: {report['lines_processed']}")
    print(
        f"Findings: HIGH={counts['HIGH']}  MEDIUM={counts['MEDIUM']}  "
        f"LOW={counts['LOW']}"
    )
    print("\nIndicators (defanged):")
    for ioc_type, values in report["iocs"].items():
        preview = ", ".join(values[:5]) + (" ..." if len(values) > 5 else "")
        print(f"  {ioc_type:<7} ({len(values)}): {preview}")
    print("\nFindings:")
    if not report["findings"]:
        print("  None.")
    for item in report["findings"]:
        location = f" [line {item['line_number']}]" if item["line_number"] else ""
        print(
            f"  [{item['severity']:<6}] {item['category']}: "
            f"{item['indicator']} - {item['detail']}{location}"
        )


# Command-line interface --------------------


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser with ``analyze`` and ``set-password``."""
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Authenticate, analyze logs for IOCs, and export reports.",
    )
    parser.add_argument("--version", action="version", version=APP_VERSION)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show debug messages on the console")
    commands = parser.add_subparsers(dest="command")

    analyze = commands.add_parser("analyze", help="analyze a log file")
    analyze.add_argument("logfile", help="path to a .log or .txt file")
    analyze.add_argument("-t", "--threshold", default="5",
                         help="failed logins that trigger an alert (1-1000)")
    analyze.add_argument("-w", "--watchlist", help="known-bad IOC list (.txt/.csv)")
    analyze.add_argument("-f", "--format", default="console",
                         help="console, json, or csv")
    analyze.add_argument("-o", "--output", help="report file for json/csv")
    analyze.add_argument("--force", action="store_true",
                         help="overwrite an existing report file")

    setpw = commands.add_parser("set-password", help="create the passphrase hash")
    setpw.add_argument("--write-env", action="store_true",
                       help="save the hash to .env (mode 600)")
    commands.add_parser("menu", help="start the interactive menu")
    return parser


def run_analysis(options: argparse.Namespace) -> None:
    """Validate analysis options, run the analyzer, and deliver the report.

    Args:
        options: Parsed arguments (or equivalent values from the menu).

    Raises:
        ValidationError: If any option is invalid.
    """
    log_path = validate_input_file(options.logfile, ALLOWED_LOG_SUFFIXES)
    threshold = validate_threshold(options.threshold)
    report_format = validate_report_format(options.format)
    watchlist = None
    if options.watchlist:
        watchlist = load_watchlist(
            validate_input_file(options.watchlist, ALLOWED_WATCHLIST_SUFFIXES)
        )

    output_path = None
    if report_format != "console":
        if not options.output:
            raise ValidationError("--output is required for json or csv reports.")
        output_path = validate_output_path(options.output, report_format, options.force)

    report = build_report(analyze_file(log_path, threshold, watchlist))
    print_report(report)
    if report_format == "json":
        export_json(report, output_path)
    elif report_format == "csv":
        export_csv(report, output_path)
    if output_path:
        print(f"\nReport saved to {output_path}")


def run_set_password(write_env: bool) -> None:
    """Create a passphrase hash and either print it or store it in .env."""
    stored_hash = create_password_hash()
    if write_env:
        write_env_file(stored_hash)
        print(f"Hash saved to {ENV_FILE_NAME}. Keep this file out of Git.")
    else:
        print("Add this line to your environment or secret manager:")
        print(f"{HASH_ENV_VAR}={stored_hash}")


def interactive_menu(input_func=input) -> None:
    """Offer a simple text menu for analysts who prefer prompts to flags.

    Args:
        input_func: Function used to read menu input (injectable for tests).
    """
    while True:
        print("\n1) Analyze a log file\n2) Exit")
        choice = input_func("Select an option: ").strip()
        if choice == "2":
            print("Goodbye.")
            return
        if choice != "1":
            print("Please enter 1 or 2.")
            continue
        options = argparse.Namespace(
            logfile=input_func("Log file path: "),
            threshold=input_func("Brute-force threshold [5]: ") or "5",
            watchlist=input_func("Watchlist path (blank for none): ") or None,
            format=input_func("Format console/json/csv [console]: ") or "console",
            output=None,
            force=False,
        )
        if options.format.strip().lower() in ("json", "csv"):
            options.output = input_func("Output file path: ")
        try:
            run_analysis(options)
        except ValidationError as exc:
            LOGGER.warning("Menu input rejected: %s", exc)
            print(f"Input error: {exc}")


def dispatch(options: argparse.Namespace) -> None:
    """Run the selected sub-command, authenticating first where required."""
    if options.command == "set-password":
        run_set_password(options.write_env)
        return
    authenticate(load_password_hash())
    if options.command == "menu":
        interactive_menu()
    else:
        run_analysis(options)


def main(argv: Iterable[str] | None = None) -> int:
    """Program entry point that maps outcomes to process exit codes.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        0 success, 1 error, 2 authentication failure, 130 user abort.
    """
    parser = build_parser()
    options = parser.parse_args(list(argv) if argv is not None else None)
    configure_logging(options.verbose)
    if options.command is None:
        parser.print_help()
        return 1
    exit_code = 0
    try:
        dispatch(options)
    except AuthenticationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        exit_code = 2
    except AnalyzerError as exc:
        LOGGER.error("%s", exc)
        exit_code = 1
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled by user.", file=sys.stderr)
        LOGGER.info("Session cancelled by user.")
        exit_code = 130
    except OSError as exc:
        LOGGER.error("File system error: %s", exc.strerror or exc)
        exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
