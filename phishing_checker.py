"""
EWB Phishing URL Awareness Checker — Main Entry Point.

This is the top-level script for backward compatibility.
It delegates all work to the modular ``src`` package.

Usage::

    python phishing_checker.py
    python phishing_checker.py "http://example.com@evil.invalid"
    python phishing_checker.py --list-rules
    python phishing_checker.py --help

What this tool does NOT do:
    It does not visit websites, scan for malware, ask reputation
    services, or prove a URL is safe. "No warning signs found"
    NEVER means "safe".
"""

import sys
from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
