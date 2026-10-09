"""app/services/phone_intel.py — Free offline phone intelligence via the phonenumbers library."""

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder

TYPE_NAMES = {
    PhoneNumberType.MOBILE: "MOBILE", PhoneNumberType.FIXED_LINE: "FIXED_LINE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "MOBILE_OR_LANDLINE", PhoneNumberType.TOLL_FREE: "TOLL_FREE",
    PhoneNumberType.VOIP: "VOIP", PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
    PhoneNumberType.SHARED_COST: "SHARED_COST", PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
}
RISKY = {PhoneNumberType.VOIP, PhoneNumberType.PREMIUM_RATE, PhoneNumberType.PERSONAL_NUMBER,
         PhoneNumberType.SHARED_COST}


def phone_intel(value: str) -> dict:
    try:
        p = phonenumbers.parse(value, "IN")
    except phonenumbers.NumberParseException:
        return {}
    t = phonenumbers.number_type(p)
    return {
        "type": TYPE_NAMES.get(t, "UNKNOWN"),
        "carrier": carrier.name_for_number(p, "en") or "",
        "region": geocoder.description_for_number(p, "en") or "",
        "risky": t in RISKY,
    }