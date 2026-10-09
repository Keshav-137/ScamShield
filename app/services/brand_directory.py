"""app/services/brand_directory.py — Curated registry for high-risk Indian brands.

verified_helplines = numbers confirmed on the brand's OWN website.
Everything else in official_helplines is curated but UNVERIFIED: run testing/verify_registry.py
(it writes data/registry_verified.json, loaded automatically below).
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.config import settings
from app.core.utils import local_digits


class OfficialBrandProfile(BaseModel):
    brand_id: str
    display_name: str
    aliases: List[str]
    official_domains: List[str]
    official_helplines: List[str]
    official_upi_handles: List[str]
    verified_helplines: List[str] = Field(default_factory=list)
    live_helplines: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    source: str = "curated"


_SBI_VERIFIED = ["18001234", "18002100", "1800112211", "18004253800", "08026599990", "1800111109", "9449112211"]

BRAND_DIRECTORY: Dict[str, OfficialBrandProfile] = {
    "sbi": OfficialBrandProfile(
        brand_id="sbi", display_name="State Bank of India",
        aliases=["sbi", "state bank of india", "state bank", "yono"],
        official_domains=["sbi.bank.in", "sbi.co.in", "onlinesbi.sbi", "bank.sbi"],
        official_helplines=_SBI_VERIFIED, verified_helplines=list(_SBI_VERIFIED),
        official_upi_handles=["sbi", "oksbi"],
        notes="Helplines verified on sbi.bank.in / sbi.co.in contact pages.",
    ),
    "hdfc": OfficialBrandProfile(
        brand_id="hdfc", display_name="HDFC Bank", aliases=["hdfc", "hdfc bank"],
        official_domains=["hdfcbank.com"],
        official_helplines=["18001600", "18002600", "18002026161"],
        official_upi_handles=["hdfcbank", "okhdfcbank"],
        notes="Helplines NOT yet verified on the bank's own site.",
    ),
    "icici": OfficialBrandProfile(
        brand_id="icici", display_name="ICICI Bank", aliases=["icici", "icici bank", "imobile"],
        official_domains=["icicibank.com"], official_helplines=["18001080"],
        official_upi_handles=["icici", "okicici"],
        notes="Helplines NOT yet verified on the bank's own site.",
    ),
    "axis": OfficialBrandProfile(
        brand_id="axis", display_name="Axis Bank", aliases=["axis", "axis bank"],
        official_domains=["axisbank.com", "axis.bank.in"],
        official_helplines=["18604195555", "18605005555"],
        official_upi_handles=["axisbank", "okaxis"],
        notes="Helplines NOT yet verified on the bank's own site.",
    ),
    "bob": OfficialBrandProfile(
        brand_id="bob", display_name="Bank of Baroda",
        aliases=["bank of baroda", "bankofbaroda", "baroda"],
        official_domains=["bankofbaroda.bank.in", "bankofbaroda.com"],
        official_helplines=["18005700", "18002584455", "18001024455", "18001027788"],
        official_upi_handles=[],
        notes="Helplines seen only on third-party sites; NOT yet verified on the bank's own site.",
    ),
    "paytm": OfficialBrandProfile(
        brand_id="paytm", display_name="Paytm Payments Bank", aliases=["paytm", "paytm payments bank", "one97"],
        official_domains=["paytm.com", "paytmbank.com"],
        official_helplines=["01204456456", "01203888388"], official_upi_handles=["paytm"],
        notes="Helplines NOT yet verified on the brand's own site.",
    ),
    "phonepe": OfficialBrandProfile(
        brand_id="phonepe", display_name="PhonePe", aliases=["phonepe", "phone pe"],
        official_domains=["phonepe.com"], official_helplines=["08068727374", "02268727374"],
        official_upi_handles=["ybl", "ibl", "axl"],
        notes="Helplines NOT yet verified on the brand's own site.",
    ),
    "gpay": OfficialBrandProfile(
        brand_id="gpay", display_name="Google Pay", aliases=["google pay", "gpay", "tez"],
        official_domains=["pay.google.com"], official_helplines=["18004190157"],
        official_upi_handles=["oksbi", "okhdfcbank", "okicici", "okaxis"],
        notes="Helplines NOT yet verified on the brand's own site.",
    ),
    "airtel": OfficialBrandProfile(
        brand_id="airtel", display_name="Bharti Airtel", aliases=["airtel", "airtel payments bank"],
        official_domains=["airtel.in", "airtelbank.com"], official_helplines=["121", "198", "8800688006"],
        official_upi_handles=["airtel"],
        notes="Helplines NOT yet verified on the brand's own site.",
    ),
    "amazon": OfficialBrandProfile(
        brand_id="amazon", display_name="Amazon India", aliases=["amazon", "amazon india", "amazon pay"],
        official_domains=["amazon.in"], official_helplines=["180030009009"],
        official_upi_handles=["apl", "rapl"],
        notes="Helplines NOT yet verified on the brand's own site.",
    ),
}


def _load_verified_file() -> None:
    """Merge numbers confirmed by testing/verify_registry.py into each profile."""
    path = Path(__file__).resolve().parents[2] / settings.DATA_DIR / "registry_verified.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return
    for brand_id, numbers in data.items():
        profile = BRAND_DIRECTORY.get(brand_id)
        if profile:
            merged = {local_digits(n) for n in profile.verified_helplines} | {local_digits(n) for n in numbers}
            profile.verified_helplines = sorted(merged)


_load_verified_file()

# Whole-word alias matching: "sbi" must not match inside "possibility".
_ALIAS_PATTERNS = [
    (profile, re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])"))
    for profile in BRAND_DIRECTORY.values() for alias in profile.aliases
]


def lookup_brand(query_text: Optional[str]) -> Optional[OfficialBrandProfile]:
    if not query_text:
        return None
    q = query_text.lower()
    for profile, pattern in _ALIAS_PATTERNS:
        if pattern.search(q):
            return profile
    return None


def register_profile(profile: OfficialBrandProfile) -> None:
    """Add a dynamically discovered brand so lookups and lookalike checks use it."""
    BRAND_DIRECTORY[profile.brand_id] = profile
    for alias in profile.aliases:
        _ALIAS_PATTERNS.append((profile, re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])")))