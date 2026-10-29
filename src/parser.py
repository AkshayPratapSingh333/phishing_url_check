"""
URL parsing and normalisation utilities.

This module isolates all ``urllib.parse`` interaction so that rule
classes receive a clean, structured :class:`ParsedURL` object instead
of raw strings.

Design note:
    When the user omits a scheme (e.g. ``www.example.com/login``),
    a temporary ``http://`` prefix is added **only** for parsing.
    The ``user_typed_scheme`` flag tracks whether the scheme came
    from the user or was injected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, unquote


@dataclass(frozen=True, slots=True)
class ParsedURL:
    """
    Structured representation of a URL after normalisation.

    All fields are derived from the original text without any
    network access.

    Attributes:
        original:           The raw string the user typed (stripped).
        normalised:         The URL with a scheme guaranteed for parsing.
        hostname:           Hostname extracted by ``urlparse``.
        hostname_labels:    Labels (dot-separated parts) of the hostname.
        scheme:             Scheme from the normalised URL.
        user_typed_scheme:  ``True`` if the user typed a scheme explicitly.
        decoded:            Percent-decoded version of ``normalised``.
        full_length:        Character length of the original string.
    """

    original: str
    normalised: str
    hostname: Optional[str]
    hostname_labels: tuple[str, ...]
    scheme: str
    user_typed_scheme: bool
    decoded: str
    full_length: int


def parse_url(raw_url: str) -> Optional[ParsedURL]:
    """
    Parse and normalise a raw URL string.

    Returns ``None`` if the string is empty after stripping whitespace.
    Returns a :class:`ParsedURL` even when the hostname cannot be
    identified (``hostname`` will be ``None`` in that case).

    This function **never** opens a network connection.
    """
    url = raw_url.strip()
    if not url:
        return None

    user_typed_scheme = "://" in url
    normalised = url if user_typed_scheme else f"http://{url}"

    parsed = urlparse(normalised)
    hostname = (parsed.hostname or "").lower() or None
    labels: tuple[str, ...] = ()
    if hostname:
        labels = tuple(part for part in hostname.split(".") if part)

    scheme = parsed.scheme.lower() if parsed.scheme else ""
    decoded = unquote(normalised)

    return ParsedURL(
        original=url,
        normalised=normalised,
        hostname=hostname,
        hostname_labels=labels,
        scheme=scheme,
        user_typed_scheme=user_typed_scheme,
        decoded=decoded,
        full_length=len(url),
    )
