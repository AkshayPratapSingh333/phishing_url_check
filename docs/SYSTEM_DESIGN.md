# System Design — Phishing URL Awareness Checker

## Problem Statement

People glance at a link and trust a familiar name. Phishing URLs abuse
URL syntax so the familiar name is not the real destination. Students
need a tool that **slows that glance down** by highlighting six visible
warning signs in the URL text.

## Solution Overview

A modular Python 3 application that:

1. Accepts one URL string from the keyboard or CLI argument.
2. Parses it with `urllib.parse.urlparse` (no network access).
3. Runs a pluggable set of text-based rules via an abstract rule engine.
4. Returns structured `InspectionResult` with typed `Finding` objects.
5. Renders results with rich, colour-coded terminal output.

## Logical Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER                                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ cli.py          — argparse, interactive/CLI mode            │ │
│  │ formatter.py    — ANSI colours, severity icons, banner      │ │
│  └─────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  BUSINESS LOGIC LAYER                                             │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ inspector.py    — High-level façade: parse → rules → result │ │
│  │ rules/          — Pluggable rule engine                     │ │
│  │   ├─ base.py    — Abstract Rule class (ABC)                 │ │
│  │   ├─ registry   — Auto-discovery & execution                │ │
│  │   ├─ at_symbol  — Rule 1: @ symbol                          │ │
│  │   ├─ long_url   — Rule 2: URL length                        │ │
│  │   ├─ ip_hostname— Rule 3: IP address                        │ │
│  │   ├─ many_seg.  — Rule 4: Hostname segments                 │ │
│  │   ├─ punycode   — Rule 5: xn-- marker                       │ │
│  │   └─ http_scheme— Rule 6: HTTP scheme                        │ │
│  └─────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  DATA LAYER                                                       │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ models.py       — Finding, InspectionResult, Severity enum  │ │
│  │ parser.py       — ParsedURL dataclass, URL normalisation    │ │
│  └─────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  VERIFICATION LAYER                                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ tests/          — pytest with parametrized tests            │ │
│  │   ├─ test_parser.py     — URL parsing unit tests            │ │
│  │   ├─ test_models.py     — Data model unit tests             │ │
│  │   ├─ test_rules.py      — Individual rule unit tests        │ │
│  │   ├─ test_registry.py   — Rule registry tests               │ │
│  │   ├─ test_inspector.py  — Integration tests                 │ │
│  │   └─ test_samples.md    — Evidence table                    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Context Diagram

```
┌────────────┐     typed URL text      ┌──────────────────────────┐
│   Student  │ ──────────────────────► │  phishing_checker.py     │
│  (terminal)│ ◄────────────────────── │  src/ package            │
└────────────┘     coloured findings   │  (stdlib: re, urlparse)  │
                                       └──────────────────────────┘
                                                │
                                                │ NO network requests
                                                ▼
                                       ┌──────────────────────────┐
                                       │  (nothing on the wire)   │
                                       └──────────────────────────┘
```

## Data Flow

```
User Input → cli.py → inspector.inspect_url()
                          │
                          ├─ parser.parse_url() → ParsedURL
                          │
                          ├─ registry.run_all_rules(parsed) → [Finding]
                          │     │
                          │     ├─ AtSymbolRule.check()
                          │     ├─ LongURLRule.check()
                          │     ├─ IPHostnameRule.check()
                          │     ├─ ManySegmentsRule.check()
                          │     ├─ PunycodeRule.check()
                          │     └─ HTTPSchemeRule.check()
                          │
                          └─ InspectionResult → formatter.print_result()
                                                      │
                                                      └─ Terminal Output
```

## Quality Attributes

| Attribute | How It Is Met |
|-----------|---------------|
| **Safety of Use** | Never opens any URL; no network calls |
| **Honesty** | README, output, and `is_safe=False` deny any "safe" verdict |
| **Teachability** | Self-describing rules with `honest_limit` text |
| **Testability** | Pure functions; rules isolated via ABC; 50+ automated tests |
| **Extensibility** | New rule = one file + one line in registry tuple |
| **Portability** | Core uses stdlib only; pytest for dev |

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Rule engine with ABC | Open/Closed principle: extend without modifying existing rules |
| Dataclasses + Enum | Type safety, immutability (`frozen=True`), self-documentation |
| Severity levels | Helps users prioritise; avoids binary safe/unsafe judgement |
| Formatter separate from logic | Single Responsibility; enables future JSON/HTML output |
| `is_safe = False` always | Prevents any consumer from misinterpreting empty findings |
| Backward-compatible `inspect_url_simple()` | Old scripts/tests continue working |

## Trust Boundary

Everything inside the process is untrusted **text**. The program never
crosses a network trust boundary. Output is advice about **how the
string looks**, not about the remote server.

## Risks and Honest Limits

- Long legitimate URLs (maps, tracking, SSO) will be flagged.
- Real sites use punycode and many subdomains.
- HTTP on a lab device is not automatically phishing.
- Attackers can avoid all six signs. **Absence of signs is not safety.**

## Deployment

1. Clone or copy the project folder.
2. Install Python 3.10+.
3. Create venv: `python -m venv venv`
4. Activate: `.\venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Unix)
5. Install deps: `pip install -r requirements.txt`
6. Run: `python phishing_checker.py`
7. Test: `pytest -v`

## Related Documents

- [REQUIREMENTS.md](REQUIREMENTS.md) — FR / NFR / non-goals / traceability
- [HLD.md](HLD.md) — Components, data flow, design decisions
- [LLD.md](LLD.md) — Functions, regex, message table, class diagrams
