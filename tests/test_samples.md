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
python phishing_checker.py --loop
```

## Test Evidence Table

| # | Sample input (type exactly) | Expected observation | What you should actually see |
|---|-----------------------------|----------------------|------------------------------|
| 1 | `https://www.example.com/login` | May show no listed warning signs; not a safety guarantee. | No listed warning signs found. This does NOT prove safety. |
| 2 | `http://192.0.2.10/account` | Flags IP-address hostname and HTTP. | Uses an IP address instead of a familiar domain.<br>Uses HTTP. HTTPS alone does not prove trust. |
| 3 | `http://example.com@sample.invalid/login` | Flags @ symbol and HTTP. | Contains an @ symbol; inspect carefully.<br>Uses HTTP. HTTPS alone does not prove trust. |
| 4 | `https://a.b.c.d.e.example.invalid/path` | Flags many hostname segments. | Contains many hostname segments/subdomains. |
| 5 | `https://xn--example.invalid/` | Flags punycode-style hostname. | Contains a punycode-style hostname. |

## Optional improvement checks

| Try typing | What happens | What it teaches |
|---|---|---|
| *(just press Enter)* | `No URL entered.` | The program handles empty input. |
| `www.example.com` | No HTTP warning is reported because no scheme was typed. | Missing scheme is added internally for parsing, not treated as proof that the URL uses HTTP. |
| `https://secure-login.example.invalid` | No listed warning signs may be found. | A convincing name can still be unsafe; no signs does not mean safe. |
| `http://[bad` | `Could not parse the URL.` | Malformed input is handled without crashing. |
| Type `q` in `--loop` mode | The program prints `Goodbye! Stay alert online.` and exits. | Several local samples can be checked without restarting. |

## Modern-attack reminder

This checker is intentionally text-only. It can highlight URL user
information, IP hosts, deep subdomains, punycode, long links, and HTTP, but
it does not detect every typosquat, redirect, shortened URL, compromised
legitimate site, malicious QR code, or HTTPS phishing page. Always verify an
unexpected request through a trusted channel.

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
