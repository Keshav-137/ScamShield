"""
app/core/scoring.py
Rule-based risk evaluation engine.
"""

import re
from typing import List, Tuple
from urllib.parse import urlsplit
from app.models.schemas import EvidenceItem, InputType, NormalizedInput, RiskLevel, SignalBreakdown
from app.core.lookalike import evaluate_domain_similarity
from app.core.utils import local_digits
from app.services.brand_directory import BRAND_DIRECTORY, lookup_brand
from app.services.official_crawler import official_crawler_service


SCAM_RE = re.compile(
    r"\b(?:fraud\w*|scam\w*|complaint\w*|cybercrime|fir|cheat\w*|"
    r"impersonat\w*|fake|stolen|unauthori[sz]ed|phishing)\b",
    re.IGNORECASE,
)


def _is_official_url(url: str) -> bool:
    try:
        parsed = urlsplit(url if "://" in url else f"//{url}")
    except ValueError:
        return False
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return False
    return any(
        host == domain.lower() or host.endswith(f".{domain.lower()}")
        for profile in BRAND_DIRECTORY.values()
        for domain in profile.official_domains
    )


def _scam_near_identifier(ni: NormalizedInput, item: EvidenceItem) -> bool:
    """Require a scam keyword near this identifier, without another number in between."""
    text = f"{item.title} {item.snippet}".lower()
    if ni.input_type == InputType.PHONE:
        digits = local_digits(ni.normalized_value)
        if len(digits) < 8:
            return False
        identifier_pattern = re.compile(r"\D{0,2}".join(digits))
    elif ni.input_type == InputType.URL:
        identifier_pattern = re.compile(
            re.escape(ni.extracted_domain or ni.normalized_value)
        )
    elif ni.input_type == InputType.UPI:
        identifier_pattern = re.compile(re.escape(ni.normalized_value))
    else:
        return False

    for identifier_match in identifier_pattern.finditer(text):
        for keyword_match in SCAM_RE.finditer(text):
            if keyword_match.start() >= identifier_match.end():
                gap = text[identifier_match.end():keyword_match.start()]
            elif keyword_match.end() <= identifier_match.start():
                gap = text[keyword_match.end():identifier_match.start()]
            else:
                gap = ""
            if len(gap) <= 60 and not re.search(r"\d{6,}", gap):
                return True
    return False


def calculate_risk_score(
    normalized_input: NormalizedInput,
    evidence_list: List[EvidenceItem]
) -> Tuple[int, RiskLevel, str, List[SignalBreakdown]]:
    score = 15  # Baseline neutral score
    signals: List[SignalBreakdown] = []

    # 1. Official Ground-Truth Verification
    brand_profile = lookup_brand(normalized_input.detected_brand or normalized_input.normalized_value)
    if not brand_profile and normalized_input.input_type == InputType.PHONE:
        for profile in BRAND_DIRECTORY.values():
            is_official, _ = official_crawler_service.verify_against_official_profile(
                normalized_input.normalized_value, profile
            )
            if is_official:
                brand_profile = profile
                break
    if brand_profile:
        is_official, reason = official_crawler_service.verify_against_official_profile(
            normalized_input.normalized_value, brand_profile
        )
        if is_official:
            score -= 30
            signals.append(SignalBreakdown(
                signal_name="OFFICIAL_SOURCE_MATCH",
                description=reason,
                score_impact=-30
            ))
        else:
            score += 25
            signals.append(SignalBreakdown(
                signal_name="OFFICIAL_SOURCE_MISMATCH",
                description=f"Item claims association with {brand_profile.display_name} but is missing from verified registry.",
                score_impact=25
            ))

    # 2. Lookalike Domain Analysis
    if normalized_input.extracted_domain:
        is_lookalike, penalty, explanation = evaluate_domain_similarity(
            normalized_input.extracted_domain,
            brand_profile.brand_id if brand_profile else None
        )
        if is_lookalike:
            score += penalty
            signals.append(SignalBreakdown(
                signal_name="LOOKALIKE_DOMAIN_DETECTED",
                description=explanation,
                score_impact=penalty
            ))

    # 3. Public News & Web Evidence Analysis (Scam keyword density)
    scam_evidence_urls = [
        item.url
        for item in evidence_list
        if item.url
        and not _is_official_url(item.url)
        and _scam_near_identifier(normalized_input, item)
    ]

    if scam_evidence_urls:
        impact = min(len(scam_evidence_urls) * 15, 45)
        score += impact
        signals.append(SignalBreakdown(
            signal_name="PUBLIC_SCAM_REPORT_FOUND",
            description=f"Contact found in {len(scam_evidence_urls)} public reports containing scam/fraud keywords.",
            score_impact=impact,
            matched_evidence_urls=scam_evidence_urls
        ))

    # Clamp final score between 0 and 100
    final_score = max(0, min(100, score))

    # Determine Risk Level
    if final_score >= 70:
        risk_level = RiskLevel.CRITICAL
    elif final_score >= 50:
        risk_level = RiskLevel.HIGH
    elif final_score >= 25:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    # Calculate Confidence based on evidence count
    confidence = "HIGH" if len(evidence_list) >= 3 else "MEDIUM" if len(evidence_list) >= 1 else "LOW"

    return final_score, risk_level, confidence, signals