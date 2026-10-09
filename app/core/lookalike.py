"""
app/core/lookalike.py
Detects domain typosquatting, suspicious TLDs, and brand impersonation.
"""

from typing import Tuple, Optional
import Levenshtein
import tldextract
from app.services.brand_directory import BRAND_DIRECTORY, lookup_brand


SUSPICIOUS_TLDS = {".xyz", ".top", ".info", ".online", ".site", ".live", ".work", ".click", ".buzz", ".tk", ".ml"}
HIGH_RISK_KEYWORDS = ["care", "helpline", "support", "kyc", "update", "refund", "login", "secure", "portal", "agent"]


def evaluate_domain_similarity(target_domain: str, claimed_brand_id: Optional[str] = None) -> Tuple[bool, int, str]:
    """
    Returns:
        (is_lookalike: bool, risk_penalty: int, explanation: str)
    """
    ext = tldextract.extract(target_domain)
    target_clean = ext.domain.lower()
    tld = f".{ext.suffix.lower()}"

    # Determine which brand profiles to inspect
    profiles = [BRAND_DIRECTORY[claimed_brand_id]] if (claimed_brand_id and claimed_brand_id in BRAND_DIRECTORY) else list(BRAND_DIRECTORY.values())

    for profile in profiles:
        for official_domain in profile.official_domains:
            off_ext = tldextract.extract(official_domain)
            official_clean = off_ext.domain.lower()

            # Exact match to verified official domain
            if target_domain.lower() == official_domain.lower():
                return False, 0, f"Verified exact match with official domain '{official_domain}'."

            # Direct substring impersonation (e.g., sbi-support-care.com vs sbi.co.in)
            if official_clean in target_clean and official_clean != target_clean:
                has_scam_keyword = any(kw in target_clean for kw in HIGH_RISK_KEYWORDS)
                penalty = 35 if has_scam_keyword else 25
                return True, penalty, f"Domain '{target_domain}' combines '{official_clean}' with suspicious keywords."

            # Levenshtein distance check (1 or 2 character edits, e.g., 'amazn' instead of 'amazon')
            dist = Levenshtein.distance(target_clean, official_clean)
            if 0 < dist <= 2 and len(official_clean) > 3:
                return True, 30, f"Domain '{target_clean}' is a lookalike of '{official_clean}' (Levenshtein distance: {dist})."

    # Generic check: Suspicious TLD coupled with high-risk keywords
    if tld in SUSPICIOUS_TLDS and any(kw in target_clean for kw in HIGH_RISK_KEYWORDS):
        return True, 20, f"Domain utilizes high-risk TLD '{tld}' alongside sensitive keyword."

    return False, 0, "No obvious lookalike pattern detected."