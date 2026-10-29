"""
EWB Phishing URL Awareness Checker — Advanced Refactored Package.

This package provides a modular, rule-engine-based URL text inspector
for educational phishing awareness. It does NOT visit websites, scan
for malware, query reputation services, or prove that a URL is safe.

Architecture:
    src/
    ├── models.py      — Data models (Finding, Severity enum)
    ├── parser.py       — URL parsing & normalisation utilities
    ├── rules/          — Pluggable rule engine with individual checks
    │   ├── base.py     — Abstract Rule base class
    │   ├── registry.py — Auto-discovery & execution of all rules
    │   ├── at_symbol.py
    │   ├── long_url.py
    │   ├── ip_hostname.py
    │   ├── many_segments.py
    │   ├── punycode.py
    │   └── http_scheme.py
    ├── inspector.py    — High-level inspect_url() façade
    ├── formatter.py    — Rich CLI output formatter
    └── cli.py          — Entry-point for terminal interaction
"""

__version__ = "1.0.0"
__author__ = "Akshay Pratap Singh"
