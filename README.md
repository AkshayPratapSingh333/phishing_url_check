# EWB Phishing URL Awareness Checker

## Purpose

Phishing is a social-engineering attack in which an attacker disguises a
link or message to make a person trust the wrong destination. The goal may
be to steal passwords, payment details, session cookies, or other sensitive
information.

This project is a defensive learning tool. It reads URL text locally and
highlights selected warning signs. It never opens a URL, sends a request,
contacts a reputation service, or proves that a website is safe.

## Features

- Detects an `@` symbol, including percent-encoded `%40`, which can hide the
  real hostname behind URL user information.
- Flags URLs longer than 100 characters.
- Flags IPv4-address hostnames instead of named domains.
- Flags hostnames with five or more dot-separated segments.
- Flags the `xn--` punycode marker used for internationalised domain names.
- Flags an explicitly typed `http://` scheme.
- Handles empty input and malformed URL syntax without crashing.
- Shows the inspected hostname, scheme, severity, explanation, and honest
  limitation for each finding.
- Supports repeated local checks with `--loop`.
- Uses an ASCII fallback on legacy Windows terminals and preserves Unicode
  icons on UTF-8 terminals.

## Why these checks matter

These are clues for human review, not a verdict. Modern phishing campaigns
often combine several techniques:

| Term | Meaning | What this checker can do |
|---|---|---|
| URL user information | Text before `@` can make a trusted-looking label appear before the real host. | Flags literal and encoded `@`. |
| Look-alike or homograph domain | Similar-looking characters or internationalised names imitate a real brand. | Flags the `xn--` punycode marker. |
| Subdomain deception | Extra labels place a familiar word deep inside an attacker-controlled hostname. | Flags five or more hostname labels. |
| IP-based phishing | The link uses a numeric address instead of a recognisable domain. | Flags IPv4 hostnames. |
| Link wrapping or tracking | A long redirect or tracking URL hides important details. | Flags URLs over 100 characters. |
| Unencrypted transport | HTTP does not provide transport encryption. | Flags explicitly typed `http://`. |
| Typosquatting | A domain uses a misspelling such as `paypa1.example`. | Not automatically detected; inspect the registered domain manually. |
| QR-code phishing (quishing) | A QR code sends a person to a malicious URL. | The URL can be pasted here as text, but the QR image is not scanned. |
| HTTPS abuse | A phishing site can still have a valid HTTPS certificate. | The checker deliberately does not treat HTTPS as proof of trust. |

Attackers can also use redirects, URL shorteners, compromised legitimate
websites, look-alike Unicode characters, and malicious pages with no obvious
URL warning sign. No automated text-only result replaces checking the domain
through a trusted channel and avoiding unexpected login requests.

## Requirements

Python 3.10 or later. The checker itself uses only the Python standard
library. Pytest and coverage tools are development dependencies.

## How to run

From the project directory:

```powershell
# Windows
python phishing_checker.py

# macOS/Linux
python3 phishing_checker.py
```

You can inspect one URL directly:

```text
python phishing_checker.py "http://example.com@sample.invalid/login"
```

To inspect several URLs without restarting:

```text
python phishing_checker.py --loop
```

Type `q`, `quit`, or `exit` to leave loop mode. The program performs text
checks only; it does not browse to the address.

Useful commands:

```text
python phishing_checker.py --help
python phishing_checker.py --list-rules
python phishing_checker.py --version
```

On a Windows terminal that uses a legacy code page, the banner and icons
use readable ASCII fallbacks. A UTF-8 terminal displays the shield and
other Unicode icons.

## Example

```text
python phishing_checker.py "http://example.com@sample.invalid/login"

Inspected hostname: sample.invalid
Scheme: http
2 warning signs detected:
[HIGH] @ Symbol Detected
[MEDIUM] HTTP (Unencrypted) Scheme
```

The complete formatter output includes an explanation and an honest
limitation for each finding.

## Testing

Run the automated suite from the project root:

```powershell
python -m pytest -q
```

If a globally installed pytest plugin is incompatible with the local Python
environment, use:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
python -m pytest -q
```

The legacy compatibility tests can also be run with:

```powershell
python -m unittest tests.test_phishing_checker -v
```

The five workbook samples are documented in
[tests/test_samples.md](tests/test_samples.md):

| # | Sample input | Expected result |
|---|---|---|
| 1 | `https://www.example.com/login` | No listed warning signs; this is not a safety guarantee. |
| 2 | `http://192.0.2.10/account` | IP-address hostname and HTTP warnings. |
| 3 | `http://example.com@sample.invalid/login` | `@` symbol and HTTP warnings. |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Many hostname segments warning. |
| 5 | `https://xn--example.invalid/` | Punycode-style hostname warning. |

Additional edge checks include blank input, a missing scheme, a deceptive
HTTPS name, percent-encoded `@`, and malformed input such as
`http://[bad`. Malformed input returns `Could not parse the URL.` rather
than terminating the program.

## Improvements

1. **Encoded `@` detection**: decodes URL text before checking for hidden
   user-information markers.
2. **Honest HTTP handling**: only flags HTTP when the user explicitly typed
   `http://`; the parser's internal prefix for scheme-less text is not
   reported as user input.
3. **Malformed-input handling**: catches parser `ValueError` exceptions and
   returns a clear error result.
4. **Review-friendly output**: findings have severity, explanation, matched
   value, and an honest limitation.
5. **Loop mode**: `--loop` checks multiple samples and exits safely on
   `q`, `quit`, or `exit`.

## Limitations and safe use

This is an educational awareness checker, not an antivirus, browser
security boundary, domain-reputation service, or URL validator. It does not
resolve DNS, follow redirects, inspect page content, verify certificates,
detect every typo, or determine who owns a domain. A clean result means only
that these listed checks did not match.

Use reserved documentation domains and sample strings for demonstrations.
Never enter passwords, payment details, tokens, or private URLs into a
shared terminal. Do not use this project to deceive people, collect
credentials, scan websites, or test systems without permission.

## Design documents

- [Requirements](docs/REQUIREMENTS.md)
- [System design](docs/SYSTEM_DESIGN.md)
- [High-level design](docs/HLD.md)
- [Low-level design](docs/LLD.md)

## Author

Akshay Pratap Singh — Cybersecurity Mini Project Workbook
(Phishing URL Awareness Checker).
