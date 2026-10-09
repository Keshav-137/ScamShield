"""app/core/utils.py — Shared helpers."""

import re
import tldextract

# Offline: bundled public-suffix snapshot; bank.in / fin.in added so they parse as suffixes.
extract = tldextract.TLDExtract(suffix_list_urls=(), extra_suffixes=["bank.in", "fin.in"])

PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{6,18}\d")


def reg_domain(ext) -> str:
    """Registered domain, compatible with old and new tldextract versions."""
    val = getattr(ext, "top_domain_under_public_suffix", None)
    if val is None:
        val = ext.registered_domain
    return (val or "").lower()


def local_digits(value: str) -> str:
    """Digits only, without the +91 country code or a leading trunk 0."""
    d = re.sub(r"\D", "", value or "")
    if d.startswith("91") and (len(d) >= 12 or d[2:].startswith(("1800", "1860"))):
        d = d[2:]
    return d.lstrip("0")


def registered_domain(host_or_url: str) -> str:
    return reg_domain(extract(host_or_url))


def extract_numbers(text: str) -> set:
    """Phone-like numbers (8-11 digits) found in free text, as local digits."""
    out = set()
    for m in PHONE_RE.findall(text or ""):
        d = local_digits(m)
        if 8 <= len(d) <= 11 and not re.fullmatch(r"(?:19|20)\d{2}(?:19|20)\d{2}", d):
            out.add(d)
    return out