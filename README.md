# EWB Phishing URL Awareness Checker

## Overview

Phishing is when someone disguises a link so it looks like a brand you
already trust, hoping you will type a password or other private data.
This tool is a small Python program that reads a URL **as text** and
looks for six selected warning signs (and one extra encoded-`@` check).
It never opens the page. Finding no warning signs **does not** mean the
URL is safe.

## Features

- Detects an `@` symbol in the URL
- Flags unusually long URLs (over 100 characters)
- Flags IP-address hostnames
- Flags many hostname segments (5 or more)
- Flags punycode-style hostnames (`xn--`)
- Flags the HTTP scheme
- Detects a percent-encoded `@` (`%40`), which can hide the same userinfo trick
- Flags HTTP only when you typed `http://` (a missing scheme is not treated as HTTP)

## Requirements

Python 3.10 or later. No extra packages.

## How to Run

Windows:

```text
python phishing_checker.py
```

Mac/Linux:

```text
python3 phishing_checker.py
```

On Windows, if the terminal uses a legacy code page, the formatter
automatically uses an ASCII-only version of its banner and icons so
inspection still works when output is redirected or piped.

Automated tests:

```text
python -m unittest tests.test_phishing_checker -v
```

## Example Output

```text
EWB Phishing URL Awareness Checker
Text checks only - this program does not open URLs.
Enter a sample URL to inspect: http://example.com@sample.invalid

Result:
- Inspected hostname: sample.invalid
- Contains an @ symbol; inspect carefully.
- Uses HTTP. HTTPS alone does not prove trust.

Never enter passwords from unexpected links.
No warning signs found never means the URL is safe.
```

## Testing

Full evidence is in [tests/test_samples.md](tests/test_samples.md).

| # | Input | Expected | Actual | Result |
|---|-------|----------|--------|--------|
| 1 | https://www.example.com/login | No warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | http://example.com@sample.invalid | @ and HTTP warnings | Both warnings printed; host is sample.invalid | PASS |
| 3 | long https://www.example.com/ URL (over 100 characters) | Long URL warning | Unusually long URL (over 100 characters). | PASS |
| 4 | https://192.168.1.1/login | IP hostname warning | Uses an IP address instead of a familiar domain. | PASS |
| 5 | https://a.b.c.d.e.example.invalid | Many hostname segments | Contains many hostname segments/subdomains. | PASS |

## Screenshots

![Sample run](screenshots/sample_run.png)
![Test results](screenshots/test_results.png)

## Design documents

- [Requirements](docs/REQUIREMENTS.md)
- [System design](docs/SYSTEM_DESIGN.md)
- [High-level design (HLD)](docs/HLD.md)
- [Low-level design (LLD)](docs/LLD.md)

## Improvements

1. **Encoded `@` detection** — `%40` is decoded with `urllib.parse.unquote` so a hidden `@` still raises the same warning. Tested with `https://example.com%40sample.invalid` in unit tests.
2. **Honest HTTP check** — HTTP is flagged only when the typed string starts with `http://`. The parse helper still adds `http://` when no scheme is present, but that helper prefix is not treated as a warning. Tested by comparing `www.example.com/login` with `http://www.example.com/login`.

## Limitations

This is an educational tool. It only reads URL text. It does not visit
URLs, scan for malware or prove that a URL is safe. No warning signs
found does NOT mean a URL is safe.

## Ethical Use

Use sample strings only. Do not collect credentials. Do not use this
project to deceive anyone or to test websites without permission.

## Author

Akshay Pratap Singh — Cybersecurity Mini Project Workbook
(Phishing URL Awareness Checker).
