# Secure Log & IOC Analyzer

A command-line tool that authenticates an analyst, parses SSH authentication
logs and Apache/Nginx access logs, extracts indicators of compromise (IPs,
domains, URLs, e-mail addresses, file hashes, CVE IDs), detects brute force,
web attacks and scanner activity, checks results against a watchlist, and
exports a defanged console, JSON, or CSV report.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install

# 1. Create the analyst passphrase hash (stored in .env, mode 600, Git-ignored)
python obinna_project1.py set-password --write-env

# 2. Analyze the samples
python obinna_project1.py analyze samples/auth.log -w samples/watchlist.txt
python obinna_project1.py analyze samples/access.log -f json -o report.json
python obinna_project1.py menu      # interactive mode
```

## Secrets handling

The passphrase is never stored. `set-password` derives a salted scrypt hash
(N=2^17, r=8, p=1) and saves only that hash in `IOC_ANALYZER_PASSWORD_HASH`,
read from the process environment first (CI, secret managers) and then from a
local `.env` file. Comparison uses `hmac.compare_digest`; three failed attempts
end the session with an increasing delay.

## Quality gates

| Check | Command |
|---|---|
| Lint (10/10 required) | `pylint obinna_project1.py tests/` |
| Style | `flake8 --max-line-length 100 obinna_project1.py tests/` |
| Static security analysis | `bandit -c pyproject.toml -r .` |
| Unit tests + coverage | `coverage run -m unittest discover -s tests -v && coverage report` |
| Dependency audit (SCA) | `pip-audit -r requirements-dev.txt` |
| Secret scan | `gitleaks git -v` and `detect-secrets scan` |

The same checks run in `.github/workflows/security-ci.yml` on every push and
pull request, alongside CodeQL code scanning.

## Exit codes

`0` success · `1` input or file error · `2` authentication failure · `130` cancelled
