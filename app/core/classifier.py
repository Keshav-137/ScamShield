"""
app/core/classifier.py
Heuristic and pattern classification for submitted queries.
"""

import re
from urllib.parse import urlparse
import phonenumbers
from app.models.schemas import InputType


UPI_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")
URL_PATTERN = re.compile(r"^(https?:\/\/)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$", re.IGNORECASE)


def classify_input(query: str) -> InputType:
    cleaned = query.strip()

    # 1. UPI ID check
    if UPI_PATTERN.match(cleaned):
        return InputType.UPI

    # 2. Phone number check (Prioritizes Indian locale "IN")
    try:
        parsed_phone = phonenumbers.parse(cleaned, "IN")
        if phonenumbers.is_possible_number(parsed_phone) and phonenumbers.is_valid_number(parsed_phone):
            return InputType.PHONE
    except phonenumbers.NumberParseException:
        pass

    # Fallback Indian phone regex (handles numbers with spaces/hyphens without country code)
    raw_digits = re.sub(r"[^\d]", "", cleaned)
    if (len(raw_digits) == 10 and raw_digits[0] in "6789") or (len(raw_digits) == 12 and raw_digits.startswith("91") and raw_digits[2] in "6789"):
        return InputType.PHONE

    # 3. URL check
    if cleaned.startswith("http://") or cleaned.startswith("https://") or (URL_PATTERN.match(cleaned) and " " not in cleaned):
        return InputType.URL

    # 4. Default: Brand / Customer Care search
    return InputType.BRAND_SEARCH