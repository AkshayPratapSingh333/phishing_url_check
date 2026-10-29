# Test Samples — EWB Phishing URL Awareness Checker

These checks use **sample strings only**. The program never visits the
addresses. "No listed warning signs" does **not** mean a URL is safe.

## How to Run Tests

### Automated (pytest)

```bash
# From the project root with venv activated:
.\venv\Scripts\activate
pytest -v --tb=short

# With coverage report:
pytest --cov=src --cov-report=term-missing
```

### Legacy (unittest)

```bash
python -m pytest tests/ -v
```

### Interactive

```bash
python phishing_checker.py
python phishing_checker.py "http://example.com@evil.invalid"
python phishing_checker.py --list-rules
```

## Test Evidence Table

| #  | Input | Rule(s) Expected | Expected Output | Actual | Result |
|----|-------|-------------------|-----------------|--------|--------|
| 1  | `https://www.example.com/login` | None (clean URL) | `No listed warning signs found. This does NOT prove safety.` | No warnings, INFO severity finding | PASS |
| 2  | `http://example.com@sample.invalid` | AT_SYMBOL, HTTP_SCHEME | @ symbol warning + HTTP warning; hostname = `sample.invalid` | Both findings returned; hostname confirmed | PASS |
| 3  | `https://www.example.com/` + 100 `a` chars | LONG_URL | `Unusually long URL` warning with character count | Finding with length reported | PASS |
| 4  | `https://192.168.1.1/login` | IP_HOSTNAME | `IP address` warning; hostname = `192.168.1.1` | Finding with IP value reported | PASS |
| 5  | `https://a.b.c.d.e.example.invalid` | MANY_SEGMENTS | `Many hostname segments` warning with label count | Finding with 7 segments reported | PASS |
| 6  | `https://xn--exmple-cua.com` | PUNYCODE | `Punycode-style hostname` warning | Finding with `xn--` marker | PASS |
| 7  | `http://www.example.com/login` | HTTP_SCHEME | `HTTP (unencrypted)` warning | Finding returned | PASS |
| 8  | `https://example.com%40sample.invalid` | AT_SYMBOL | Encoded `@` (`%40`) treated as @ warning | Finding returned after URL-decode | PASS |
| 9  | (blank / spaces only) | N/A | `No URL entered.` error | Error result, no findings | PASS |
| 10 | `www.example.com/login` (no scheme) | None | No HTTP warning (scheme was not typed) | Only INFO finding | PASS |
| 11 | `HTTP://WWW.EXAMPLE.COM` (uppercase) | HTTP_SCHEME | HTTP warning (case-insensitive) | Finding returned | PASS |
| 12 | `https://example.com/xn--page` | None | `xn--` in path, not hostname → no punycode warning | No PUNYCODE finding | PASS |
| 13 | Multi-warning URL | AT_SYMBOL, LONG_URL, HTTP_SCHEME, + | Multiple findings combined | All matching rules fire | PASS |

## Warning Sign Reference

| # | Warning Sign | Why People Look at It | Honest Limit |
|---|--------------|----------------------|--------------|
| 1 | `@` symbol | Text before `@` is ignored by the browser. `example.com@evil.invalid` visits `evil.invalid`. | Rare in normal links, but possible. |
| 2 | Very long URL (>100 chars) | Long links can hide the real destination far to the right. | Many honest links are long too. |
| 3 | IP address as hostname | Real brands use names, not number addresses. | Some internal tools use IPs. |
| 4 | Many hostname segments (≥5 parts) | Stacking names makes the link look official. | Big companies sometimes use many parts. |
| 5 | Punycode marker (`xn--`) | Can hide look-alike foreign letters (homograph attack). | Real international sites use it too. |
| 6 | HTTP instead of HTTPS | HTTP is not encrypted; data can be intercepted. | HTTPS alone does not prove trust. |

## Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| INFO | Contextual note | No warnings found (does not prove safety) |
| LOW | Mild indicator | Unusually long URL |
| MEDIUM | Worth investigating | HTTP scheme, punycode, many segments |
| HIGH | Strong indicator | @ symbol, IP hostname |
| CRITICAL | Almost never legitimate | (reserved for future rules) |
