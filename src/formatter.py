"""
Rich CLI output formatter.

Produces coloured, structured terminal output using ANSI escape
sequences.  Falls back gracefully to plain text when the terminal
does not support colours (detected via ``os.isatty``).
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from src.models import Finding, InspectionResult, Severity


# ── ANSI colour codes ─────────────────────────────────────────

class _Colours:
    """ANSI escape sequences for terminal styling."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colours
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GREY = "\033[90m"

    # Background
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN = "\033[42m"


def _supports_colour(stream: TextIO) -> bool:
    """Best-effort check for ANSI colour support."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return hasattr(stream, "isatty") and stream.isatty()
    except Exception:
        return False


class Formatter:
    """
    Formats an :class:`InspectionResult` for terminal display.

    Parameters:
        stream:     Output stream (default: ``sys.stdout``).
        use_colour: ``None`` = auto-detect, ``True`` = force,
                    ``False`` = plain text.
    """

    # Mapping from severity to colour and icon
    _SEVERITY_STYLE = {
        Severity.INFO:     (_Colours.GREEN,   "ℹ️ "),
        Severity.LOW:      (_Colours.CYAN,    "🔵"),
        Severity.MEDIUM:   (_Colours.YELLOW,  "🟡"),
        Severity.HIGH:     (_Colours.RED,     "🔴"),
        Severity.CRITICAL: (_Colours.MAGENTA, "🚨"),
    }
    _ASCII_REPLACEMENTS = str.maketrans({
        "╔": "+",
        "╗": "+",
        "╚": "+",
        "╝": "+",
        "║": "|",
        "═": "=",
        "─": "-",
        "🔵": "[o]",
        "🟡": "[!]",
        "🔴": "[!]",
        "🚨": "[!]",
        "⚠": "[!]",
        "✓": "[OK]",
        "📌": "*",
        "⚡": "*",
        "•": "*",
        "↳": "->",
        "≠": "!=",
        "—": "-",
    })
    _ASCII_SEQUENCE_REPLACEMENTS = (
        ("🛡️", "[shield]"),
        ("ℹ️", "[i]"),
    )

    def __init__(
        self,
        stream: TextIO | None = None,
        use_colour: bool | None = None,
    ) -> None:
        self._stream = stream or sys.stdout
        if use_colour is None:
            self._colour = _supports_colour(self._stream)
        else:
            self._colour = use_colour

    # ── Helpers ───────────────────────────────────────────────

    def _c(self, code: str, text: str) -> str:
        """Wrap *text* in ANSI *code* if colour is enabled."""
        if self._colour:
            return f"{code}{text}{_Colours.RESET}"
        return text

    def _write(self, text: str = "") -> None:
        encoding = getattr(self._stream, "encoding", None)
        if encoding and not text.isascii():
            try:
                text.encode(encoding)
            except UnicodeEncodeError:
                for source, replacement in self._ASCII_SEQUENCE_REPLACEMENTS:
                    text = text.replace(source, replacement)
                text = text.translate(self._ASCII_REPLACEMENTS)
                if not text.isascii():
                    text = text.encode("ascii", errors="replace").decode("ascii")
        print(text, file=self._stream)

    # ── Public API ────────────────────────────────────────────

    def print_banner(self) -> None:
        """Print the application header."""
        self._write()
        self._write(self._c(_Colours.BOLD + _Colours.CYAN,
                             "╔══════════════════════════════════════════════════╗"))
        self._write(self._c(_Colours.BOLD + _Colours.CYAN,
                             "║   🛡️  EWB Phishing URL Awareness Checker  🛡️    ║"))
        self._write(self._c(_Colours.BOLD + _Colours.CYAN,
                             "╚══════════════════════════════════════════════════╝"))
        self._write(self._c(_Colours.DIM,
                             "  Text checks only — this program does NOT open URLs."))
        self._write()

    def print_result(self, result: InspectionResult) -> None:
        """Print the full inspection result."""
        # ── Separator ─────────────────────────────────────────
        self._write(self._c(_Colours.DIM, "─" * 52))

        # ── Error path ────────────────────────────────────────
        if result.error:
            self._write(self._c(_Colours.RED + _Colours.BOLD,
                                 f"  ⚠  {result.error}"))
            self._write(self._c(_Colours.DIM, "─" * 52))
            return

        # ── Hostname display ──────────────────────────────────
        self._write(self._c(_Colours.WHITE + _Colours.BOLD,
                             "  📌 Inspected hostname: ")
                    + self._c(_Colours.CYAN, result.hostname or "unknown"))
        if result.scheme:
            self._write(self._c(_Colours.DIM,
                                 f"     Scheme: {result.scheme}"))
        self._write()

        # ── Findings ──────────────────────────────────────────
        if result.has_warnings:
            count = result.warning_count
            label = "warning sign" if count == 1 else "warning signs"
            self._write(self._c(
                _Colours.YELLOW + _Colours.BOLD,
                f"  ⚠  {count} {label} detected:",
            ))
        else:
            self._write(self._c(
                _Colours.GREEN + _Colours.BOLD,
                "  ✓  No listed warning signs found.",
            ))

        self._write()

        for finding in result.findings:
            self._print_finding(finding)

        # ── Footer ────────────────────────────────────────────
        self._write(self._c(_Colours.DIM, "─" * 52))
        self._write(self._c(_Colours.DIM + _Colours.BOLD,
                             "  ⚡ Remember:"))
        self._write(self._c(_Colours.DIM,
                             "     • Never enter passwords from unexpected links."))
        self._write(self._c(_Colours.DIM,
                             "     • No warning signs found ≠ URL is safe."))
        self._write(self._c(_Colours.DIM,
                             "     • This tool reads text only; it proves nothing."))
        self._write(self._c(_Colours.DIM, "─" * 52))
        self._write()

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding with severity icon and colour."""
        colour, icon = self._SEVERITY_STYLE.get(
            finding.severity, (_Colours.WHITE, "•")
        )

        # Title line
        severity_tag = self._c(
            colour + _Colours.BOLD,
            f"[{finding.severity.name}]",
        )
        self._write(f"  {icon} {severity_tag} "
                     + self._c(_Colours.BOLD, finding.title))

        # Message (indented)
        self._write(self._c(colour, f"     {finding.message}"))

        # Honest limit (dimmed)
        if finding.honest_limit:
            self._write(self._c(_Colours.GREY,
                                 f"     ↳ Honest limit: {finding.honest_limit}"))
        self._write()
