# Requirements — Phishing URL Awareness Checker v2.0

## 1. Purpose

Build a **defensive learning** program that inspects **URL text** for
selected warning signs. The goal is awareness, not detection of every
phishing site. The tool must **never** claim a URL is "safe" or "unsafe".

## 2. Functional Requirements

| ID | Requirement | Priority | Module |
|----|-------------|----------|--------|
| FR-01 | Accept a URL as text input (terminal or CLI argument). | Must | `src/cli.py` |
| FR-02 | Detect an `@` symbol (literal or percent-encoded `%40`). | Must | `src/rules/at_symbol.py` |
| FR-03 | Flag URLs longer than 100 characters. | Must | `src/rules/long_url.py` |
| FR-04 | Flag an IPv4-style hostname (dotted-quad pattern). | Must | `src/rules/ip_hostname.py` |
| FR-05 | Flag hostnames with 5 or more labels (segments). | Must | `src/rules/many_segments.py` |
| FR-06 | Flag a punycode marker (`xn--`) in the hostname. | Must | `src/rules/punycode.py` |
| FR-07 | Flag the HTTP scheme **only** when the user typed `http://`. | Must | `src/rules/http_scheme.py` |
| FR-08 | Return all matching warnings with severity levels. | Must | `src/inspector.py` |
| FR-09 | If no warning signs found, return a cautious INFO message. | Must | `src/inspector.py` |
| FR-10 | Use Python dataclasses, enums, ABC, functions, regex. | Must | `src/models.py`, `src/rules/` |
| FR-11 | Provide a README a stranger can follow in two minutes. | Must | `README.md` |
| FR-12 | Record test evidence in `tests/test_samples.md`. | Must | `tests/` |

## 3. Improvement Requirements

| ID | Requirement | Priority | Module |
|----|-------------|----------|--------|
| IMP-01 | Decode `%40` as `@` for the at-symbol check. | Should | `src/rules/at_symbol.py` |
| IMP-02 | Do not treat a missing scheme as HTTP. | Should | `src/rules/http_scheme.py` |
| IMP-03 | Show the parsed hostname in CLI output. | Should | `src/formatter.py` |
| IMP-04 | Pluggable rule engine with abstract base class. | Should | `src/rules/` |
| IMP-05 | Typed data models (dataclasses, Enum severity). | Should | `src/models.py` |
| IMP-06 | CLI supports `--list-rules`, `--no-color`, `--version`. | Should | `src/cli.py` |
| IMP-07 | Rich coloured terminal output with severity icons. | Could | `src/formatter.py` |
| IMP-08 | Backward-compatible `inspect_url_simple()` API. | Should | `src/inspector.py` |

## 4. Out of Scope (Non-Goals)

The program **must not**:

- Visit websites or follow redirects
- Download pages, files, or certificates
- Scan for malware
- Call reputation, blocklist, or Safe Browsing APIs
- Collect passwords or personal data
- Claim that a URL is safe, trusted, or malicious
- Teach or perform attacks against real sites

> **"No warning signs found" NEVER means "safe".**

## 5. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-01 | Python 3.10 or later; core uses standard library only. |
| NFR-02 | Runs from a terminal (`python phishing_checker.py`). |
| NFR-03 | Automated tests run with `pytest` (or `python -m pytest`). |
| NFR-04 | Sample strings only (e.g. `example.com`, `sample.invalid`). |
| NFR-05 | Clear, honest wording: every warning has a limit (false positives exist). |
| NFR-06 | Modular architecture: adding a rule requires only one new file + registry entry. |
| NFR-07 | Virtual environment (`venv/`) with pinned dependencies. |
| NFR-08 | `pyproject.toml` for modern Python packaging. |

## 6. Users and Environment

- **Primary user:** A student learning defensive URL reading.
- **Environment:** Local Windows, macOS, or Linux with Python 3.10+.
- **Input:** One line of text typed or pasted into the terminal, or CLI argument.

## 7. Success Criteria

The project is complete when:

1. All six workbook warning signs are implemented as independent `Rule` classes.
2. Empty input and unparseable hostnames are handled without crashing.
3. All 50+ automated test cases pass.
4. README states limitations and ethical use in plain language.
5. System design, HLD, and LLD documents describe the same architecture as the code.
6. Virtual environment is created and dependencies are sorted.

## 8. Traceability Matrix

| Workbook Item | Requirement | Rule Class | Test File |
|---------------|-------------|------------|-----------|
| Ask for URL text | FR-01 | `cli.py` | `test_inspector.py` |
| `@` symbol | FR-02 | `AtSymbolRule` | `test_rules.py::TestAtSymbolRule` |
| Length > 100 | FR-03 | `LongURLRule` | `test_rules.py::TestLongURLRule` |
| IP hostname | FR-04 | `IPHostnameRule` | `test_rules.py::TestIPHostnameRule` |
| ≥ 5 labels | FR-05 | `ManySegmentsRule` | `test_rules.py::TestManySegmentsRule` |
| `xn--` | FR-06 | `PunycodeRule` | `test_rules.py::TestPunycodeRule` |
| HTTP scheme | FR-07 | `HTTPSchemeRule` | `test_rules.py::TestHTTPSchemeRule` |
| Cautious message | FR-09 | `inspector.py` | `test_inspector.py::test_clean_https_url_no_warnings` |
