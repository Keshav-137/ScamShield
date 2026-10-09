"""app/services/official_crawler.py — Compare a contact against the official brand registry."""

from typing import Optional, Tuple
from app.core.utils import extract, local_digits, registered_domain
from app.models.schemas import InputType, NormalizedInput
from app.services.brand_directory import BRAND_DIRECTORY, OfficialBrandProfile


class OfficialCrawlerService:

    @staticmethod
    def verify(ni: NormalizedInput, profile: OfficialBrandProfile) -> Tuple[Optional[bool], str]:
        """True = official match, False = contradicts registry, None = consistent but unverifiable."""
        name = profile.display_name

        if ni.input_type == InputType.PHONE:
            digits = local_digits(ni.normalized_value)
            for helpline in profile.official_helplines:
                if digits and digits == local_digits(helpline):
                    return True, f"Number matches official verified helpline for {name} ({helpline})."
            return False, f"Number is NOT in {name}'s verified helpline list."

        if ni.input_type == InputType.URL:
            reg = ni.extracted_domain or registered_domain(ni.normalized_value)
            for dom in profile.official_domains:
                if reg and reg == registered_domain(dom):
                    return True, f"Domain matches verified official domain of {name} ({dom})."
            ext = extract(ni.extracted_host or reg)
            if ext.suffix.lower() in {"bank.in", "fin.in"} and \
                    ext.domain.lower() in {a.replace(" ", "") for a in profile.aliases}:
                return True, f"'{reg}' is on the restricted .{ext.suffix} registry and matches {name}."
            return False, f"Domain '{reg}' is NOT an official domain of {name}."

        if ni.input_type == InputType.UPI:
            handle = ni.extracted_vpa_handle
            if handle and handle in profile.official_upi_handles:
                return None, f"UPI handle '@{handle}' is consistent with {name}, but an individual UPI ID cannot be verified."
            return False, f"UPI handle '@{handle}' is not used by {name}."

        return None, ""

    @classmethod
    def find_brand_by_contact(cls, ni: NormalizedInput) -> Optional[OfficialBrandProfile]:
        """Reverse lookup: does this phone/domain belong to any known brand?"""
        if ni.input_type not in (InputType.PHONE, InputType.URL):
            return None
        for profile in BRAND_DIRECTORY.values():
            ok, _ = cls.verify(ni, profile)
            if ok:
                return profile
        return None


official_crawler_service = OfficialCrawlerService()