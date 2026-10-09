"""
app/core/normalizer.py
Cleans and standardizes raw inputs into canonical formats.
"""

from typing import Optional
from urllib.parse import urlparse
import phonenumbers
import tldextract
from app.models.schemas import InputType, NormalizedInput
from app.services.brand_directory import lookup_brand


def normalize_input(raw_query: str, input_type: InputType, claimed_brand: Optional[str] = None) -> NormalizedInput:
    cleaned = raw_query.strip()
    detected_profile = lookup_brand(claimed_brand or cleaned)
    detected_brand_name = detected_profile.display_name if detected_profile else claimed_brand

    extracted_domain = None
    extracted_vpa_handle = None
    extracted_phone_e164 = None
    normalized_value = cleaned

    if input_type == InputType.PHONE:
        try:
            parsed = phonenumbers.parse(cleaned, "IN")
            if phonenumbers.is_valid_number(parsed):
                extracted_phone_e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                normalized_value = extracted_phone_e164
        except phonenumbers.NumberParseException:
            raw_digits = "".join(filter(str.isdigit, cleaned))
            if len(raw_digits) == 10:
                extracted_phone_e164 = f"+91{raw_digits}"
                normalized_value = extracted_phone_e164

    elif input_type == InputType.UPI:
        normalized_value = cleaned.lower()
        if "@" in normalized_value:
            extracted_vpa_handle = normalized_value.split("@")[1]

    elif input_type == InputType.URL:
        url_target = cleaned if cleaned.startswith(("http://", "https://")) else f"https://{cleaned}"
        extracted = tldextract.extract(url_target)
        if extracted.registered_domain:
            extracted_domain = extracted.registered_domain.lower()
            normalized_value = extracted_domain
        else:
            normalized_value = urlparse(url_target).netloc.lower()

    elif input_type == InputType.BRAND_SEARCH:
        normalized_value = cleaned.lower()

    return NormalizedInput(
        raw_query=raw_query,
        input_type=input_type,
        normalized_value=normalized_value,
        detected_brand=detected_brand_name,
        extracted_domain=extracted_domain,
        extracted_vpa_handle=extracted_vpa_handle,
        extracted_phone_e164=extracted_phone_e164
    )