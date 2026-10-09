"""
app/services/official_crawler.py
Official source comparison logic.
"""

from typing import Tuple, Optional
from app.services.brand_directory import OfficialBrandProfile, lookup_brand


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
        clean_digits = "".join(filter(str.isdigit, value))
        for helpline in profile.official_helplines:
            clean_helpline = "".join(filter(str.isdigit, helpline))
            if clean_digits and (clean_digits.endswith(clean_helpline) or clean_helpline.endswith(clean_digits)):
                return True, f"Contact matches official verified helpline for {profile.display_name} ({helpline})."

        # Compare domain
        clean_domain = value.lower().strip()
        for dom in profile.official_domains:
            if clean_domain == dom.lower():
                return True, f"Domain matches verified official domain for {profile.display_name}."

        return False, f"Contact was NOT found on {profile.display_name}'s official directory."


official_crawler_service = OfficialCrawlerService()