"""app/core/normalizer.py — Canonicalize raw inputs."""

from typing import Optional
from urllib.parse import urlparse
import phonenumbers
from app.core.utils import extract, local_digits, reg_domain
from app.models.schemas import InputType, NormalizedInput
from app.services.brand_directory import lookup_brand


def normalize_input(raw_query: str, input_type: InputType, claimed_brand: Optional[str] = None) -> NormalizedInput:
    cleaned = raw_query.strip()
    profile = lookup_brand(claimed_brand) or lookup_brand(cleaned)
    detected_brand = profile.display_name if profile else claimed_brand

    domain = host = vpa = e164 = None
    value = cleaned

    if input_type == InputType.PHONE:
        digits = local_digits(cleaned)
        try:
            parsed = phonenumbers.parse(cleaned, "IN")
            if phonenumbers.is_valid_number(parsed):
                e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException:
            pass
        if not e164 and len(digits) == 10:
            e164 = f"+91{digits}"
        value = e164 or digits

    elif input_type == InputType.UPI:
        value = cleaned.lower()
        vpa = value.split("@", 1)[1]

    elif input_type == InputType.URL:
        target = cleaned if cleaned.lower().startswith(("http://", "https://")) else f"https://{cleaned}"
        ext = extract(target)
        host = urlparse(target).netloc.lower().split(":")[0]
        reg = reg_domain(ext)
        if reg:
            domain = reg
            value = domain
        else:
            value = host

    elif input_type == InputType.BRAND_SEARCH:
        value = cleaned.lower()

    return NormalizedInput(
        raw_query=raw_query, input_type=input_type, normalized_value=value,
        detected_brand=detected_brand, extracted_domain=domain, extracted_host=host,
        extracted_vpa_handle=vpa, extracted_phone_e164=e164,
    )
