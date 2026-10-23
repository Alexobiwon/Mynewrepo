"""Unit and security tests for the Secure Log and IOC Analyzer.

Run with:  python -m unittest discover -s tests -v
"""

import csv
import io
import json
import logging
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import obinna_project1 as app  # noqa: E402  pylint: disable=wrong-import-position

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
TEST_PASSPHRASE = "Unit-Test-Only-Phrase-7"  # Test fixture, not a real credential.


def answers(*values):
    """Return a prompt function that replays the given answers in order."""
    iterator = iter(values)
    return lambda _prompt="": next(iterator)


class PassphraseTests(unittest.TestCase):
    """Hashing, verification, and policy enforcement."""

    @classmethod
    def setUpClass(cls):
        cls.stored = app.hash_passphrase(TEST_PASSPHRASE)

    def test_hash_format_and_random_salt(self):
        """Hashes are self-describing and salted, so equal inputs differ."""
        self.assertTrue(self.stored.startswith("scrypt$131072$8$1$"))
        self.assertNotEqual(self.stored, app.hash_passphrase(TEST_PASSPHRASE))

    def test_plaintext_never_in_hash(self):
        """The stored value must not contain the passphrase."""
        self.assertNotIn(TEST_PASSPHRASE, self.stored)

    def test_verify_correct_and_incorrect(self):
        """Only the exact passphrase verifies."""
        self.assertTrue(app.verify_passphrase(TEST_PASSPHRASE, self.stored))
        self.assertFalse(app.verify_passphrase("wrong-passphrase!!", self.stored))

    def test_malformed_hash_rejected(self):
        """Tampered or truncated hashes raise a configuration error."""
        for bad in ("", "md5$abc", "scrypt$1$2$3$!!$??", self.stored[:-10] + "$x"):
            with self.subTest(bad=bad):
                with self.assertRaises(app.SecretConfigError):
                    app.verify_passphrase(TEST_PASSPHRASE, bad)

    def test_policy(self):
        """Short, overly long, common, and repetitive passphrases fail."""
        for weak in ("short", "x" * 200, "password1234", "aaaaaaaaaaaaaaa"):
            with self.subTest(weak=weak[:20]):
                with self.assertRaises(app.ValidationError):
                    app.validate_passphrase_policy(weak)
        app.validate_passphrase_policy(TEST_PASSPHRASE)

    def test_create_hash_requires_matching_confirmation(self):
        """A mismatched confirmation is rejected."""
        with self.assertRaises(app.ValidationError):
            app.create_password_hash(answers(TEST_PASSPHRASE, "different-phrase-1"))
        created = app.create_password_hash(answers(TEST_PASSPHRASE, TEST_PASSPHRASE))
        self.assertTrue(app.verify_passphrase(TEST_PASSPHRASE, created))


class AuthenticationTests(unittest.TestCase):
    """Login attempt limiting and secret loading."""

    @classmethod
    def setUpClass(cls):
        cls.stored = app.hash_passphrase(TEST_PASSPHRASE)

    def test_success_on_second_attempt(self):
        """A later correct attempt is accepted."""
        with redirect_stderr(io.StringIO()):
            app.authenticate(self.stored, answers("bad-guess-0001", TEST_PASSPHRASE),
                             base_delay=0)

    def test_lockout_after_max_attempts(self):
        """Three wrong answers raise AuthenticationError."""
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(app.AuthenticationError):
                app.authenticate(self.stored, answers("a" * 12, "b" * 12, "c" * 12),
                                 base_delay=0)

    def test_hash_loaded_from_environment(self):
        """The environment variable takes precedence over .env."""
        with mock.patch.dict(os.environ, {app.HASH_ENV_VAR: self.stored}):
            self.assertEqual(app.load_password_hash(Path("missing.env")), self.stored)

    def test_hash_loaded_from_env_file_and_missing(self):
        """A .env file is used when the variable is unset; absence errors."""
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {}, clear=True):
            env_path = Path(tmp) / ".env"
            with self.assertRaises(app.SecretConfigError):
                app.load_password_hash(env_path)
            app.write_env_file(self.stored, env_path)
            self.assertEqual(app.load_password_hash(env_path), self.stored)
            if os.name == "posix":
                self.assertEqual(env_path.stat().st_mode & 0o777, 0o600)


class ValidationTests(unittest.TestCase):
    """Allowlist validation of every user-controlled input."""

    def test_threshold(self):
        """Thresholds must be whole numbers in range."""
        self.assertEqual(app.validate_threshold(" 7 "), 7)
        for bad in ("0", "1001", "five", "3.5", "-1", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(app.ValidationError):
                    app.validate_threshold(bad)

    def test_report_format(self):
        """Only console, json, and csv are accepted."""
        self.assertEqual(app.validate_report_format(" JSON "), "json")
        with self.assertRaises(app.ValidationError):
            app.validate_report_format("html")

    def test_input_file_rules(self):
        """Missing, empty, directory, wrong-type, and NUL paths are refused."""
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "payload.exe"
            exe.write_text("x", encoding="utf-8")
            for bad in ("", "   ", tmp, str(exe), "nope.log", "bad\x00.log"):
                with self.subTest(bad=bad):
                    with self.assertRaises(app.ValidationError):
                        app.validate_input_file(bad, app.ALLOWED_LOG_SUFFIXES)
        good = app.validate_input_file(str(SAMPLES / "auth.log"),
                                       app.ALLOWED_LOG_SUFFIXES)
        self.assertTrue(good.is_absolute())

    @unittest.skipIf(os.name != "posix", "symlinks need privileges on Windows")
    def test_symlink_refused(self):
        """Symbolic links are rejected to avoid reading unintended files."""
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link.log"
            link.symlink_to(SAMPLES / "auth.log")
            with self.assertRaises(app.ValidationError):
                app.validate_input_file(str(link), app.ALLOWED_LOG_SUFFIXES)

    def test_oversized_file_refused(self):
        """Files above the size limit are rejected before reading."""
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big.log"
            big.write_text("x", encoding="utf-8")
            with mock.patch.object(app, "MAX_LOG_BYTES", 0):
                with self.assertRaises(app.ValidationError):
                    app.validate_input_file(str(big), app.ALLOWED_LOG_SUFFIXES)

    def test_output_path(self):
        """Wrong extension, missing folder, and silent overwrite are refused."""
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "r.json"
            existing.write_text("{}", encoding="utf-8")
            with self.assertRaises(app.ValidationError):
                app.validate_output_path(str(existing), "json", force=False)
            self.assertEqual(app.validate_output_path(str(existing), "json", True),
                             existing.resolve())
            with self.assertRaises(app.ValidationError):
                app.validate_output_path(str(Path(tmp) / "r.txt"), "json", False)
            with self.assertRaises(app.ValidationError):
                app.validate_output_path(str(Path(tmp) / "no" / "r.csv"), "csv", False)


class DetectionTests(unittest.TestCase):
    """IOC extraction and detection rules."""

    def test_extract_iocs(self):
        """Valid IOCs are found; invalid IPs and embedded hashes are not."""
        line = ("visit http://bad.example.com/x from 10.1.2.3 and 1.2.3.999 "
                "mail ADMIN@Evil.org CVE-2021-44228 md5 "
                "d41d8cd98f00b204e9800998ecf8427e sha256 " + "a" * 64)
        iocs = app.extract_iocs(line)
        self.assertEqual(iocs["ipv4"], {"10.1.2.3"})
        self.assertIn("admin@evil.org", iocs["email"])
        self.assertEqual(iocs["cve"], {"CVE-2021-44228"})
        self.assertEqual(iocs["md5"], {"d41d8cd98f00b204e9800998ecf8427e"})
        self.assertNotIn("md5", app.extract_iocs("hash " + "b" * 64))

    def test_encoded_web_attacks(self):
        """URL-encoded and double-encoded payloads are decoded and detected."""
        template = '1.2.3.4 - - [19/Oct/2026:10:00:00 -0400] "GET {} HTTP/1.1" 200 1'
        cases = {
            "/p?id=1%27%20OR%201=1--": "SQL injection",
            "/p?id=1%2527%2520OR%25201=1": "SQL injection",
            "/a/..%2f..%2fetc/passwd": "Path traversal",
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                found = {f.category for f in app.detect_web_attacks(1, template.format(path))}
                self.assertIn(expected, found)
        self.assertEqual(app.detect_web_attacks(1, template.format("/index.html")), [])
        self.assertEqual(app.detect_web_attacks(1, "not a web log line"), [])

    def test_brute_force_and_login_after_failures(self):
        """Sample auth.log yields brute force and compromise indicators."""
        result = app.analyze_file(SAMPLES / "auth.log", threshold=5)
        categories = [f.category for f in result.findings]
        self.assertIn("SSH brute force", categories)
        self.assertIn("Login after repeated failures", categories)
        self.assertEqual(result.failed_logins["203.0.113.45"], 8)

    def test_watchlist_accepts_defanged_entries(self):
        """Defanged watchlist entries still match extracted IOCs."""
        watchlist = app.load_watchlist(SAMPLES / "watchlist.txt")
        self.assertIn("185.220.101.7", watchlist)
        result = app.analyze_file(SAMPLES / "auth.log", 5, watchlist)
        hits = {f.indicator for f in result.findings if f.category == "Watchlist match"}
        self.assertIn("malware-c2.xyz", hits)

    def test_is_public_ip(self):
        """Private, documentation, and malformed addresses are not public."""
        self.assertTrue(app.is_public_ip("8.8.8.8"))
        for value in ("10.0.0.1", "192.0.2.1", "not-an-ip"):
            self.assertFalse(app.is_public_ip(value))


class ReportingTests(unittest.TestCase):
    """Defanging, CSV injection protection, and file permissions."""

    def test_defang_round_trip(self):
        """Refang reverses defang."""
        original = "https://evil.example.com/a"
        self.assertEqual(app.defang(original), "hxxps://evil[.]example[.]com/a")
        self.assertEqual(app.refang(app.defang(original)), original)

    def test_csv_formula_injection_neutralized(self):
        """Cells starting with formula characters are prefixed with a quote."""
        for risky in ("=cmd|' /C calc'!A0", "+1", "-1", "@SUM(A1)"):
            self.assertTrue(app.neutralize_csv_cell(risky).startswith("'"))
        self.assertEqual(app.neutralize_csv_cell("safe"), "safe")

    def test_exports_are_private_and_valid(self):
        """JSON and CSV reports parse correctly and are owner-only."""
        report = app.build_report(app.analyze_file(SAMPLES / "access.log", 5))
        with tempfile.TemporaryDirectory() as tmp:
            json_path, csv_path = Path(tmp) / "r.json", Path(tmp) / "r.csv"
            app.export_json(report, json_path)
            app.export_csv(report, csv_path)
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["severity_counts"], report["severity_counts"])
            with csv_path.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), len(report["findings"]))
            if os.name == "posix":
                self.assertEqual(json_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("http://", json.dumps(report))


class LoggingTests(unittest.TestCase):
    """Log injection protection."""

    def test_newlines_neutralized(self):
        """CR/LF in logged values cannot forge extra log entries."""
        record = logging.LogRecord("t", logging.INFO, __file__, 1,
                                   "user=%s", ("evil\nFAKE ENTRY\r",), None)
        app.sanitize_log_record(record)
        self.assertEqual(record.getMessage(), "user=evil?FAKE ENTRY?")


class CommandLineTests(unittest.TestCase):
    """End-to-end tests of main() in an isolated working directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self._old_cwd = os.getcwd()
        os.chdir(self._tmp.name)
        self.stored = app.hash_passphrase(TEST_PASSPHRASE)

    def tearDown(self):
        logging.getLogger(app.APP_NAME).handlers.clear()
        os.chdir(self._old_cwd)
        self._tmp.cleanup()

    def run_main(self, argv, prompts):
        """Run main() with patched secrets and prompts; return (code, stdout)."""
        out = io.StringIO()
        with mock.patch.dict(os.environ, {app.HASH_ENV_VAR: self.stored}), \
                mock.patch.object(app.getpass, "getpass", answers(*prompts)), \
                mock.patch.object(app.time, "sleep"), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = app.main(argv)
        return code, out.getvalue()

    def test_analyze_json_success(self):
        """A valid run returns 0 and writes the report."""
        code, output = self.run_main(
            ["analyze", str(SAMPLES / "access.log"), "-f", "json", "-o", "r.json"],
            [TEST_PASSPHRASE])
        self.assertEqual(code, 0)
        self.assertIn("SQL injection", output)
        self.assertTrue(Path("r.json").exists())
        self.assertTrue(Path("logs/ioc_analyzer.log").exists())

    def test_wrong_passphrase_exit_code(self):
        """Failed authentication returns exit code 2."""
        code, _ = self.run_main(["analyze", str(SAMPLES / "auth.log")],
                                ["x" * 12, "y" * 12, "z" * 12])
        self.assertEqual(code, 2)

    def test_invalid_input_exit_code(self):
        """Invalid arguments return 1 after successful login."""
        code, _ = self.run_main(["analyze", str(SAMPLES / "auth.log"), "-t", "0"],
                                [TEST_PASSPHRASE])
        self.assertEqual(code, 1)
        code, _ = self.run_main(["analyze", str(SAMPLES / "auth.log"), "-f", "json"],
                                [TEST_PASSPHRASE])
        self.assertEqual(code, 1)

    def test_no_command_and_cancel(self):
        """No sub-command prints help; Ctrl+C returns 130."""
        self.assertEqual(self.run_main([], [])[0], 1)
        with mock.patch.object(app, "authenticate", side_effect=KeyboardInterrupt):
            self.assertEqual(self.run_main(["analyze", "x.log"], [])[0], 130)

    def test_set_password_prints_hash_only(self):
        """set-password prints a hash and never the passphrase itself."""
        code, output = self.run_main(["set-password"], [TEST_PASSPHRASE, TEST_PASSPHRASE])
        self.assertEqual(code, 0)
        self.assertIn(f"{app.HASH_ENV_VAR}=scrypt$", output)
        self.assertNotIn(TEST_PASSPHRASE, output)
        log_text = Path("logs/ioc_analyzer.log").read_text(encoding="utf-8")
        self.assertNotIn(TEST_PASSPHRASE, log_text)

    def test_interactive_menu(self):
        """The menu rejects bad input, runs an analysis, and exits."""
        out = io.StringIO()
        script = answers("9", "1", "missing.log", "", "", "", "1",
                         str(SAMPLES / "auth.log"), "3", "", "console", "2")
        with redirect_stdout(out):
            app.interactive_menu(script)
        text = out.getvalue()
        self.assertIn("Please enter 1 or 2.", text)
        self.assertIn("Input error", text)
        self.assertIn("SSH brute force", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
