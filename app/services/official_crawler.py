"""
app/services/official_crawler.py
Official source comparison logic.
"""

from typing import Tuple, Optional
from app.core.utils import local_digits
from app.models.schemas import InputType, NormalizedInput
from app.services.brand_directory import BRAND_DIRECTORY, OfficialBrandProfile


class OfficialCrawlerService:

    @staticmethod
    def verify_against_official_profile(
        value: str,
        profile: Optional[OfficialBrandProfile]
    ) -> Tuple[bool, str]:
        """
        Compares phone or domain value against ground truth brand profile.
        Returns: (is_verified_match, reason)
        """
        if not profile:
            return False, "No verified official brand profile available for comparison."

        # Compare phone number (digits only match)
        clean_digits = local_digits(value)
        for helpline in profile.official_helplines:
            clean_helpline = local_digits(helpline)
            has_indian_prefix = (
                clean_digits.startswith("91")
                and clean_digits[2:] == clean_helpline
            )
            if clean_digits and (clean_digits == clean_helpline or has_indian_prefix):
                return True, f"Contact matches official verified helpline for {profile.display_name} ({helpline})."

        # Compare domain
        clean_domain = value.lower().strip()
        for dom in profile.official_domains:
            if clean_domain == dom.lower() or clean_domain.endswith(f".{dom.lower()}"):
                return True, f"Domain matches verified official domain for {profile.display_name}."

        return False, f"Contact was NOT found on {profile.display_name}'s official directory."

    @classmethod
    def find_brand_by_contact(
        cls, normalized: NormalizedInput
    ) -> Optional[OfficialBrandProfile]:
        if normalized.input_type not in (InputType.PHONE, InputType.URL):
            return None
        for profile in BRAND_DIRECTORY.values():
            matches, _ = cls.verify_against_official_profile(
                normalized.normalized_value, profile
            )
            if matches:
                return profile
        return None


official_crawler_service = OfficialCrawlerService()