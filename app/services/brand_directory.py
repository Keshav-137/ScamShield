"""
app/services/brand_directory.py
Curated ground-truth registry for high-risk Indian brands.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class OfficialBrandProfile(BaseModel):
    brand_id: str
    display_name: str
    aliases: List[str]
    official_domains: List[str]
    official_helplines: List[str]
    official_upi_handles: List[str]
    notes: Optional[str] = None
    source: str = "curated"


BRAND_DIRECTORY: Dict[str, OfficialBrandProfile] = {
    "sbi": OfficialBrandProfile(
        brand_id="sbi",
        display_name="State Bank of India",
        aliases=["sbi", "state bank of india", "state bank", "yono"],
        official_domains=["sbi.co.in", "onlinesbi.sbi", "bank.sbi", "sbi.bank.in"],
        official_helplines=["18001234", "18002100", "1800112211", "18004253800", "08026599990"],
        official_upi_handles=["sbi", "oksbi"],
        notes="India's largest public sector bank. Prime target for search poisoning."
    ),
    "hdfc": OfficialBrandProfile(
        brand_id="hdfc",
        display_name="HDFC Bank",
        aliases=["hdfc", "hdfc bank"],
        official_domains=["hdfcbank.com"],
        official_helplines=["18001600", "18002600", "18002026161"],
        official_upi_handles=["hdfcbank", "okhdfcbank"],
        notes="Large private bank frequently impersonated with fake SMS netbanking links."
    ),
    "icici": OfficialBrandProfile(
        brand_id="icici",
        display_name="ICICI Bank",
        aliases=["icici", "icici bank", "imobile"],
        official_domains=["icicibank.com"],
        official_helplines=["18001080"],
        official_upi_handles=["icici", "okicici"],
        notes="High-frequency target for APK and customer-care helpline fraud."
    ),
    "axis": OfficialBrandProfile(
        brand_id="axis",
        display_name="Axis Bank",
        aliases=["axis", "axis bank"],
        official_domains=["axisbank.com", "axis.bank.in"],
        official_helplines=["18604195555", "18605005555"],
        official_upi_handles=["axisbank", "okaxis"],
    ),
    "bob": OfficialBrandProfile(
        brand_id="bob",
        display_name="Bank of Baroda",
        aliases=["bank of baroda", "bankofbaroda", "bob"],
        official_domains=["bankofbaroda.bank.in", "bankofbaroda.in"],
        official_helplines=["18005700", "18005000"],
        official_upi_handles=[],
        notes="Official site lists 1800 5700 and 1800 5000 as domestic toll-free numbers. No UPI handle is published there.",
    ),
    "paytm": OfficialBrandProfile(
        brand_id="paytm",
        display_name="Paytm Payments Bank",
        aliases=["paytm", "paytm payments bank", "one97"],
        official_domains=["paytm.com", "paytmbank.com"],
        official_helplines=["01204456456", "01203888388"],
        official_upi_handles=["paytm"],
    ),
    "phonepe": OfficialBrandProfile(
        brand_id="phonepe",
        display_name="PhonePe",
        aliases=["phonepe", "phone pe"],
        official_domains=["phonepe.com"],
        official_helplines=["08068727374", "02268727374"],
        official_upi_handles=["ybl", "ibl", "axl"],
    ),
    "gpay": OfficialBrandProfile(
        brand_id="gpay",
        display_name="Google Pay",
        aliases=["google pay", "gpay", "tez"],
        official_domains=["pay.google.com", "support.google.com"],
        official_helplines=["18004190157"],
        official_upi_handles=["oksbi", "okhdfcbank", "okicici", "okaxis"],
    ),
    "airtel": OfficialBrandProfile(
        brand_id="airtel",
        display_name="Bharti Airtel",
        aliases=["airtel", "airtel payments bank"],
        official_domains=["airtel.in", "airtelbank.com"],
        official_helplines=["121", "198", "8800688006"],
        official_upi_handles=["airtel"],
    ),
    "amazon": OfficialBrandProfile(
        brand_id="amazon",
        display_name="Amazon India",
        aliases=["amazon", "amazon india", "amazon pay"],
        official_domains=["amazon.in"],
        official_helplines=["180030009009"],
        official_upi_handles=["apl", "rapl"],
    )
}

_ALIAS_PATTERNS = [
    (profile, re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])"))
    for profile in BRAND_DIRECTORY.values()
    for alias in profile.aliases
]


def register_profile(profile: OfficialBrandProfile) -> None:
    """Register a discovered profile and make its aliases available to lookups."""
    BRAND_DIRECTORY[profile.brand_id] = profile
    _ALIAS_PATTERNS[:] = [
        (existing, pattern)
        for existing, pattern in _ALIAS_PATTERNS
        if existing.brand_id != profile.brand_id
    ]
    _ALIAS_PATTERNS.extend(
        (
            profile,
            re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])"),
        )
        for alias in profile.aliases
    )


def lookup_brand(query_text: str) -> Optional[OfficialBrandProfile]:
    """Find a brand by a whole-word alias match."""
    if not query_text:
        return None
    query_lower = query_text.lower()
    for profile, pattern in _ALIAS_PATTERNS:
        if pattern.search(query_lower):
            return profile
    return None