# High-Level Design (HLD) — Phishing URL Awareness Checker v2.0

## 1. System Context

This is a **single-user, offline, terminal program**. There is no server,
database, browser plugin, or network client.

```
┌────────────┐     typed URL text      ┌──────────────────────────────────┐
│   Student  │ ──────────────────────► │  phishing_checker.py / src/      │
│  (terminal)│ ◄────────────────────── │  Rule Engine + Formatter         │
└────────────┘     coloured findings   │  (stdlib: re, urlparse, abc)     │
                                       └──────────────────────────────────┘
                                                │
                                                │ NO HTTP requests
                                                ▼
                                       ┌──────────────────────────────────┐
                                       │      (nothing on the wire)       │
                                       └──────────────────────────────────┘
```

## 2. Architecture Style

**Layered modular package** with a pluggable rule engine.

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     ENTRY POINTS                             │
│  phishing_checker.py   ←  backward-compatible launcher      │
│  src/cli.py            ←  argparse CLI (interactive + args)  │
└──────────────────┬──────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                     INSPECTOR FAÇADE                         │
│  src/inspector.py                                            │
│  • inspect_url(raw_url) → InspectionResult                   │
│  • inspect_url_simple(raw_url) → list[str]  (compat)         │
└──────────────────┬──────────────────────────────────────────┘
                   │
         ┌─────────┴─────────┐
         │                   │
┌────────▼────────┐  ┌───────▼──────────────────────────────┐
│  URL PARSER     │  │  RULE ENGINE                          │
│  src/parser.py  │  │  src/rules/                           │
│                 │  │  ├─ __init__.py  (abstract Rule ABC)   │
│  ParsedURL      │  │  ├─ registry.py (discovery + runner)  │
│  dataclass      │  │  ├─ at_symbol.py                      │
│                 │  │  ├─ long_url.py                        │
│                 │  │  ├─ ip_hostname.py                     │
│                 │  │  ├─ many_segments.py                   │
│                 │  │  ├─ punycode.py                        │
│                 │  │  └─ http_scheme.py                     │
└─────────────────┘  └──────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                     DATA MODELS                              │
│  src/models.py                                               │
│  • Severity (Enum: INFO → CRITICAL)                          │
│  • Finding (frozen dataclass)                                │
│  • InspectionResult (dataclass with computed properties)      │
└─────────────────────────────────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────────────┐
│                     PRESENTATION                             │
│  src/formatter.py                                            │
│  • ANSI colour-coded output with severity icons              │
│  • Auto-detect colour support                                │
│  • Banner, findings, footer with safety reminders            │
└─────────────────────────────────────────────────────────────┘
```

## 3. Data Flow (Sequence)

```
Student          cli.py           inspector.py        registry.py        Rule[1..6]
   │                │                  │                   │                  │
   │── type URL ──► │                  │                   │                  │
   │                │── raw_url ─────► │                   │                  │
   │                │                  │── parse_url() ──► │                  │
   │                │                  │◄── ParsedURL ─────│                  │
   │                │                  │── run_all_rules() ──────────────────►│
   │                │                  │                   │   check(parsed)  │
   │                │                  │                   │◄── Finding|None ─│
   │                │                  │◄── [Finding] ─────│                  │
   │                │◄── InspectionResult ─│               │                  │
   │                │── format ──────► formatter.py        │                  │
   │◄── coloured ───│                  │                   │                  │
   │    output      │                  │                   │                  │
```

## 4. Design Decisions

| #   | Decision                                | Rationale                                                                     |
| --- | --------------------------------------- | ----------------------------------------------------------------------------- |
| 1   | Standard library only (core)            | Course requirement; easy to run without pip                                   |
| 2   | `urlparse` for host extraction          | Avoids brittle split-on-slash logic                                           |
| 3   | Abstract `Rule` base class              | Open/Closed Principle — add rules without modifying existing code             |
| 4   | Frozen dataclasses                      | Immutability prevents accidental mutation of findings                         |
| 5   | `Severity` enum (INFO → CRITICAL)       | Ordered levels enable sorting and prioritisation                              |
| 6   | Messages, not scores                    | A score would imply a safety rating — this tool must not give one             |
| 7   | `is_safe = False` always                | Hardcoded field prevents any consumer from treating empty findings as "safe"  |
| 8   | Separate formatter                      | Single Responsibility; enables future JSON/HTML output without touching logic |
| 9   | Sample `.invalid` / `example.com` hosts | RFC-reserved names; ethical lab use                                           |
| 10  | `inspect_url_simple()` wrapper          | Backward compatibility for existing scripts                                   |

## 5. Extension Guide

### Adding a New Rule

1. Create `src/rules/new_rule.py` inheriting from `Rule`.
2. Set `rule_id`, `name`, `severity`, `honest_limit`.
3. Implement `check(parsed: ParsedURL) → Optional[Finding]`.
4. Add the class to `_ALL_RULE_CLASSES` in `src/rules/registry.py`.
5. Add tests in `tests/test_rules.py`.

**No other files need to change.** The inspector, formatter, and CLI
automatically pick up the new rule.

## 6. Trust Boundary

Everything inside the process is untrusted **text**. The program never
crosses a network trust boundary. Output is advice about **how the
string looks**, not about the remote server.

## 7. Risks and Honest Limits

- Long legitimate URLs (maps, tracking, SSO) will be flagged.
- Real sites use punycode and many subdomains.
- HTTP on a lab device is not automatically phishing.
- Attackers can avoid all six signs. **Absence of signs is not safety.**

## 8. Deployment View

```
phishing-url-awareness/
├── phishing_checker.py     ← backward-compatible entry point
├── pyproject.toml          ← modern Python packaging config
├── requirements.txt        ← pip dependencies (pytest, pytest-cov)
├── README.md               ← project instruction manual
├── venv/                   ← virtual environment (not in VCS)
├── src/                    ← core package
│   ├── __init__.py
│   ├── models.py
│   ├── parser.py
│   ├── inspector.py
│   ├── formatter.py
│   ├── cli.py
│   └── rules/
│       ├── __init__.py     ← abstract Rule ABC
│       ├── registry.py
│       ├── at_symbol.py
│       ├── long_url.py
│       ├── ip_hostname.py
│       ├── many_segments.py
│       ├── punycode.py
│       └── http_scheme.py
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   ├── test_models.py
│   ├── test_rules.py
│   ├── test_registry.py
│   ├── test_inspector.py
│   └── test_samples.md
├── docs/
│   ├── REQUIREMENTS.md
│   ├── SYSTEM_DESIGN.md
│   ├── HLD.md
│   └── LLD.md
└── screenshots/
    ├── sample_run.png
    └── test_results.png
```
