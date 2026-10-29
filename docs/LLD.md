# Low-Level Design (LLD) — Phishing URL Awareness Checker v2.0

## 1. Package & Module Layout

```
src/
├── __init__.py          # __version__ = "2.0.0"
├── models.py            # Severity, Finding, InspectionResult
├── parser.py            # ParsedURL, parse_url()
├── inspector.py         # inspect_url(), inspect_url_simple()
├── formatter.py         # Formatter class (ANSI output)
├── cli.py               # main(), argparse
└── rules/
    ├── __init__.py      # Rule (ABC)
    ├── registry.py      # get_registered_rules(), run_all_rules()
    ├── at_symbol.py     # AtSymbolRule
    ├── long_url.py      # LongURLRule
    ├── ip_hostname.py   # IPHostnameRule
    ├── many_segments.py # ManySegmentsRule
    ├── punycode.py      # PunycodeRule
    └── http_scheme.py   # HTTPSchemeRule
```

## 2. Class Diagram

```
┌─────────────────────────────────────────────────┐
│                  «enum» Severity                 │
├─────────────────────────────────────────────────┤
│  INFO = 1                                        │
│  LOW = 2                                         │
│  MEDIUM = 3                                      │
│  HIGH = 4                                        │
│  CRITICAL = 5                                    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│            «frozen dataclass» Finding            │
├─────────────────────────────────────────────────┤
│  rule_id: str                                    │
│  title: str                                      │
│  message: str                                    │
│  severity: Severity                              │
│  honest_limit: str = ""                          │
│  matched_value: Optional[str] = None             │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│          «dataclass» InspectionResult            │
├─────────────────────────────────────────────────┤
│  raw_url: str                                    │
│  hostname: Optional[str]                         │
│  scheme: Optional[str]                           │
│  findings: list[Finding]                         │
│  error: Optional[str]                            │
│  is_safe: bool = False  (always, not settable)   │
├─────────────────────────────────────────────────┤
│  @property has_warnings → bool                   │
│  @property max_severity → Severity               │
│  @property warning_count → int                   │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│         «frozen dataclass» ParsedURL             │
├─────────────────────────────────────────────────┤
│  original: str                                   │
│  normalised: str                                 │
│  hostname: Optional[str]                         │
│  hostname_labels: tuple[str, ...]                │
│  scheme: str                                     │
│  user_typed_scheme: bool                         │
│  decoded: str                                    │
│  full_length: int                                │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│            «abstract» Rule (ABC)                 │
├─────────────────────────────────────────────────┤
│  rule_id: str                                    │
│  name: str                                       │
│  severity: Severity                              │
│  honest_limit: str                               │
├─────────────────────────────────────────────────┤
│  @abstractmethod check(ParsedURL) → Finding|None │
│  _make_finding(message, ...) → Finding           │
└─────────┬───────────────────────────────────────┘
          │ inherits
          │
    ┌─────┼──────┬──────────┬────────────┬───────────┬───────────┐
    │     │      │          │            │           │           │
┌───▼──┐┌─▼───┐┌─▼───────┐┌─▼──────────┐┌▼─────────┐┌▼─────────┐
│AtSym ││Long ││IPHost   ││ManySeg     ││Punycode  ││HTTPSchem │
│Rule  ││URL  ││nameRule ││mentsRule   ││Rule      ││eRule     │
│      ││Rule ││         ││            ││          ││          │
│HIGH  ││LOW  ││HIGH     ││MEDIUM      ││MEDIUM    ││MEDIUM    │
└──────┘└─────┘└─────────┘└────────────┘└──────────┘└──────────┘
```

## 3. Function: `parse_url(raw_url: str) → ParsedURL | None`

**Input:** Any string from `input()`, CLI argument, or test.

**Output:** A `ParsedURL` dataclass or `None` for empty input.

### Parse Steps

```python
url = raw_url.strip()
if not url: return None

user_typed_scheme = "://" in url
normalised = url if user_typed_scheme else f"http://{url}"

parsed = urlparse(normalised)
hostname = (parsed.hostname or "").lower() or None
labels = tuple(part for part in hostname.split(".") if part)
decoded = unquote(normalised)
```

## 4. Function: `inspect_url(raw_url: str) → InspectionResult`

**Input:** Any string.

**Output:** Always a non-`None` `InspectionResult`.

### Decision Flow

```
                    ┌─────────────┐
                    │  parse_url  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  None?      │──── Yes ──► error = "No URL entered."
                    └──────┬──────┘
                           │ No
                    ┌──────▼──────┐
                    │ hostname    │──── None ──► error = "Could not identify..."
                    │  is None?   │
                    └──────┬──────┘
                           │ No
                    ┌──────▼──────┐
                    │ run_all_    │
                    │ rules()     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ findings    │──── empty ──► add NO_WARNINGS sentinel
                    │  empty?     │
                    └──────┬──────┘
                           │ has items
                    ┌──────▼──────┐
                    │ Return      │
                    │ Inspection  │
                    │ Result      │
                    └─────────────┘
```

## 5. Rule Implementations

### Rule 1: AtSymbolRule

| Attribute | Value |
|-----------|-------|
| `rule_id` | `AT_SYMBOL` |
| `severity` | `HIGH` |
| **Condition** | `"@" in normalised` or `"@" in decoded` |
| **Why decoded** | `%40` is `@` percent-encoded; `unquote()` reveals it |

### Rule 2: LongURLRule

| Attribute | Value |
|-----------|-------|
| `rule_id` | `LONG_URL` |
| `severity` | `LOW` |
| **Condition** | `full_length > threshold` (default 100) |
| **Note** | Threshold is configurable via constructor |

### Rule 3: IPHostnameRule

| Attribute | Value |
|-----------|-------|
| `rule_id` | `IP_HOSTNAME` |
| `severity` | `HIGH` |
| **Regex** | `(?:\d{1,3}\.){3}\d{1,3}` with `fullmatch` |
| **Note** | Does NOT enforce 0–255 (sufficient for awareness) |

### Rule 4: ManySegmentsRule

| Attribute | Value |
|-----------|-------|
| `rule_id` | `MANY_SEGMENTS` |
| `severity` | `MEDIUM` |
| **Condition** | `len(hostname_labels) >= threshold` (default 5) |
| **Note** | Threshold is configurable via constructor |

### Rule 5: PunycodeRule

| Attribute | Value |
|-----------|-------|
| `rule_id` | `PUNYCODE` |
| `severity` | `MEDIUM` |
| **Condition** | `"xn--" in hostname` |
| **Note** | Only checks hostname, not path |

### Rule 6: HTTPSchemeRule

| Attribute | Value |
|-----------|-------|
| `rule_id` | `HTTP_SCHEME` |
| `severity` | `MEDIUM` |
| **Condition** | `user_typed_scheme and scheme == "http"` |
| **Key Design** | Missing scheme → parser injects `http://` → NOT flagged |

## 6. Formatter

The `Formatter` class renders an `InspectionResult` to a `TextIO` stream.

### Colour Mapping

| Severity | ANSI Colour | Icon |
|----------|-------------|------|
| INFO | Green | ℹ️ |
| LOW | Cyan | 🔵 |
| MEDIUM | Yellow | 🟡 |
| HIGH | Red | 🔴 |
| CRITICAL | Magenta | 🚨 |

### Colour Detection

1. `NO_COLOR` env var → plain text
2. `FORCE_COLOR` env var → colours
3. `isatty()` → auto-detect

## 7. CLI Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `url` | positional, optional | URL to inspect; omit for interactive mode |
| `--no-color` | flag | Disable ANSI colours |
| `--list-rules` | flag | Print all registered rules and exit |
| `--version` | flag | Print version and exit |

## 8. Test Mapping

| Test File | Module Tested | Test Count |
|-----------|---------------|------------|
| `test_parser.py` | `src/parser.py` | 12 |
| `test_models.py` | `src/models.py` | 11 |
| `test_rules.py` | `src/rules/*.py` | 20 |
| `test_registry.py` | `src/rules/registry.py` | 7 |
| `test_inspector.py` | `src/inspector.py` | 15 |
| **Total** | | **65+** |

## 9. Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Empty input | `InspectionResult` with `error = "No URL entered."` |
| Unparseable hostname | `InspectionResult` with `error = "Could not identify..."` |
| `KeyboardInterrupt` | CLI catches and exits cleanly with code 0 |
| `EOFError` (piped input) | CLI catches and exits cleanly with code 0 |
| Unknown exceptions | Left to the interpreter (acceptable for educational CLI) |
