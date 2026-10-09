"""Shared input and domain helpers."""

import re

import tldextract

extract = tldextract.TLDExtract(suffix_list_urls=())


def local_digits(value: str) -> str:
    """Return digits without India's country code or a leading trunk zero."""
    digits = re.sub(r"\D", "", value or "")
    if digits.startswith("91") and len(digits) >= 12:
        digits = digits[2:]
    return digits.lstrip("0")


def registered_domain(host_or_url: str) -> str:
    """Return the registered domain for a host or URL."""
    return extract(host_or_url).registered_domain.lower()
