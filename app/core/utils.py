"""Shared input and domain helpers."""

import re

import tldextract

extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    extra_suffixes=["bank.in", "fin.in"],
)


def local_digits(value: str) -> str:
    """Return digits without India's country code or a leading trunk zero."""
    digits = re.sub(r"\D", "", value or "")
    if digits.startswith("91") and len(digits) >= 12:
        digits = digits[2:]
    return digits.lstrip("0")


def registered_domain(host_or_url: str) -> str:
    """Return the registered domain for a host or URL."""
    return extract(host_or_url).registered_domain.lower()
"""app/core/utils.py — Shared helpers."""

import re
import tldextract

# Offline: bundled public-suffix snapshot; .bank.in added for Indian banks.
extract = tldextract.TLDExtract(suffix_list_urls=(), extra_suffixes=["bank.in", "fin.in"])


def local_digits(value: str) -> str:
    """Digits only, without the +91 country code or a leading trunk 0."""
    d = re.sub(r"\D", "", value or "")
    if d.startswith("91") and (len(d) >= 12 or d[2:].startswith(("1800", "1860"))):
        d = d[2:]
    return d.lstrip("0")


def registered_domain(host_or_url: str) -> str:
    return extract(host_or_url).registered_domain.lower()