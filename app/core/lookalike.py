"""app/core/lookalike.py — Typosquatting, subdomain tricks, TLD swaps, brand impersonation."""

import re
from typing import Optional, Tuple
from app.core.utils import extract, registered_domain
from app.services.brand_directory import BRAND_DIRECTORY


def calc_distance(s1: str, s2: str) -> int:
    """Pure-Python Levenshtein (no C-extension needed on Windows)."""
    if len(s1) < len(s2):
        return calc_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


SUSPICIOUS_TLDS = {".xyz", ".top", ".info", ".online", ".site", ".live", ".work", ".click", ".buzz", ".tk", ".ml"}
HIGH_RISK_KEYWORDS = ["care", "helpline", "support", "kyc", "update", "refund", "login", "secure", "portal", "agent"]
GENERIC_LABELS = {"bank", "pay", "www", "online", "app"}  # words, not brand names


def _tokens(text: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def evaluate_domain_similarity(target: str, claimed_brand_id: Optional[str] = None) -> Tuple[bool, int, str]:
    """target: host, domain or full URL. Returns (is_lookalike, risk_penalty, explanation)."""
    ext = extract(target)
    label = ext.domain.lower()
    reg = ext.registered_domain.lower()
    if not label:
        return False, 0, "Could not parse domain."
    tld = f".{ext.suffix.lower()}" if ext.suffix else ""

    # 1. Exact official domain -> safe
    for p in BRAND_DIRECTORY.values():
        for d in p.official_domains:
            if registered_domain(d) == reg:
                return False, 0, f"Verified match with official domain '{d}'."

    label_tokens = _tokens(label)
    sub_tokens = _tokens(ext.subdomain)
    has_kw = any(kw in label for kw in HIGH_RISK_KEYWORDS)

    for profile in BRAND_DIRECTORY.values():
        claimed = claimed_brand_id == profile.brand_id
        for d in profile.official_domains:
            off = extract(d).domain.lower()
            if not off or off in GENERIC_LABELS:
                continue

            # Same name, different ending (hdfcbank.net vs hdfcbank.com)
            if off == label:
                if claimed or tld in SUSPICIOUS_TLDS:
                    return True, 30, f"'{reg}' reuses the name of official '{d}' under a different domain ending."
                continue

            # Brand name embedded in the domain (sbi-care-help.com)
            if off in label and (off in label_tokens or claimed or has_kw):
                if len(off) >= 5 or off in label_tokens:
                    return True, (35 if has_kw else 25), \
                        f"'{reg}' embeds '{off}' ({profile.display_name}) but is not an official domain."

            # Brand in subdomain of an unrelated domain (sbi.secure-login.com)
            if off in sub_tokens:
                return True, 35, f"'{target}' puts '{off}' in a subdomain of unrelated domain '{reg}'."

            # Typosquat (amazn.in, hdfcbnk.com)
            if len(off) >= 5:
                dist = calc_distance(label, off)
                if 0 < dist <= (1 if len(off) <= 6 else 2):
                    return True, 30, f"'{label}' is a typo-lookalike of '{off}' (edit distance {dist})."

    if tld in SUSPICIOUS_TLDS and has_kw:
        return True, 20, f"Domain uses high-risk ending '{tld}' with a sensitive keyword."

    return False, 0, "No obvious lookalike pattern detected."