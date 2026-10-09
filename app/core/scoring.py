"""Rule-based risk scoring with evidence tied to the submitted identifier."""

import re
from typing import List, Optional, Pattern, Tuple

from app.core.lookalike import evaluate_domain_similarity
from app.core.utils import local_digits, registered_domain
from app.models.schemas import (
    EvidenceItem,
    EvidenceSourceType,
    InputType,
    NormalizedInput,
    RiskLevel,
    SignalBreakdown,
)
from app.services.brand_directory import (
    BRAND_DIRECTORY,
    OfficialBrandProfile,
    lookup_brand,
)
from app.services.official_crawler import official_crawler_service

SCAM_RE = re.compile(
    r"\b(?:fraud\w*|scam\w*|complaint\w*|cybercrime|fir|cheat\w*|"
    r"impersonat\w*|fake|stolen|unauthori[sz]ed|phishing)\b",
    re.IGNORECASE,
)


def _is_official_url(url: Optional[str]) -> bool:
    if not url:
        return False
    domain = registered_domain(url)
    if not domain:
        return False
    official_domains = {
        registered_domain(official_domain)
        for profile in BRAND_DIRECTORY.values()
        for official_domain in profile.official_domains
    }
    return domain in official_domains


def _pattern(ni: NormalizedInput) -> Optional[Pattern[str]]:
    if ni.input_type == InputType.PHONE:
        digits = local_digits(ni.normalized_value)
        return re.compile(r"\D{0,2}".join(digits)) if len(digits) >= 8 else None
    if ni.input_type == InputType.URL:
        domain = ni.extracted_domain or ni.normalized_value
        return re.compile(re.escape(domain)) if domain else None
    if ni.input_type == InputType.UPI:
        return re.compile(re.escape(ni.normalized_value))
    return None


def _mentions(ni: NormalizedInput, item: EvidenceItem) -> bool:
    pattern = _pattern(ni)
    text = f"{item.title} {item.snippet} {item.url or ''}".lower()
    return bool(pattern and pattern.search(text))


def _scam_near_identifier(ni: NormalizedInput, item: EvidenceItem) -> bool:
    """Require a scam keyword near this identifier, without another long number between."""
    pattern = _pattern(ni)
    if not pattern:
        return False
    text = f"{item.title} {item.snippet}".lower()
    for identifier_match in pattern.finditer(text):
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
    ni: NormalizedInput,
    evidence: List[EvidenceItem],
    profile: Optional[OfficialBrandProfile] = None,
    domain_age_days: Optional[int] = None,
) -> Tuple[int, RiskLevel, str, List[SignalBreakdown], Optional[OfficialBrandProfile]]:
    score = 15
    signals: List[SignalBreakdown] = []
    official_match = False

    profile = profile or lookup_brand(ni.detected_brand or "") or lookup_brand(
        ni.normalized_value
    )
    claimed = profile is not None

    if ni.input_type != InputType.BRAND_SEARCH:
        if profile is None:
            profile = official_crawler_service.find_brand_by_contact(ni)
        if profile is not None:
            is_official, reason = official_crawler_service.verify_against_official_profile(
                ni.normalized_value, profile
            )
            if is_official:
                official_match = True
                score -= 30
                signals.append(
                    SignalBreakdown(
                        signal_name="OFFICIAL_SOURCE_MATCH",
                        description=reason,
                        score_impact=-30,
                    )
                )
            elif claimed:
                impact = 25 if profile.source == "curated" else 15
                if ni.input_type == InputType.PHONE and not profile.official_helplines:
                    impact = 0
                source_note = (
                    ""
                    if profile.source == "curated"
                    else " (discovered profile may be incomplete)"
                )
                score += impact
                signals.append(
                    SignalBreakdown(
                        signal_name="OFFICIAL_SOURCE_MISMATCH",
                        description=(
                            f"Claims association with {profile.display_name}. "
                            f"{reason}{source_note}"
                        ),
                        score_impact=impact,
                    )
                )

    if ni.input_type == InputType.URL:
        is_lookalike, penalty, explanation = evaluate_domain_similarity(
            ni.extracted_host or ni.extracted_domain or ni.normalized_value,
            profile.brand_id if profile else None,
        )
        if is_lookalike:
            score += penalty
            signals.append(
                SignalBreakdown(
                    signal_name="LOOKALIKE_DOMAIN_DETECTED",
                    description=explanation,
                    score_impact=penalty,
                )
            )
        if not official_match and domain_age_days is not None and domain_age_days < 180:
            impact = 30 if domain_age_days < 30 else 15
            score += impact
            signals.append(
                SignalBreakdown(
                    signal_name="NEWLY_REGISTERED_DOMAIN",
                    description=f"Domain was registered only {domain_age_days} day(s) ago.",
                    score_impact=impact,
                )
            )

    if ni.input_type == InputType.BRAND_SEARCH and profile:
        lookalike_urls = [
            item.url
            for item in evidence
            if item.source_type == EvidenceSourceType.GOOGLE_SEARCH
            and item.url
            and evaluate_domain_similarity(item.url, profile.brand_id)[0]
        ]
        if lookalike_urls:
            impact = min(25 * len(lookalike_urls), 50)
            score += impact
            signals.append(
                SignalBreakdown(
                    signal_name="POISONED_SEARCH_RESULTS",
                    description=(
                        f"{len(lookalike_urls)} Google result(s) for this search come "
                        f"from lookalike/non-official domains impersonating {profile.display_name}."
                    ),
                    score_impact=impact,
                    matched_evidence_urls=lookalike_urls,
                )
            )

    if ni.input_type == InputType.PHONE and profile and not official_match:
        third_party_listings = [
            item.url
            for item in evidence
            if item.source_type == EvidenceSourceType.GOOGLE_SEARCH
            and item.url
            and not _is_official_url(item.url)
            and _mentions(ni, item)
        ]
        if third_party_listings:
            score += 10
            signals.append(
                SignalBreakdown(
                    signal_name="THIRD_PARTY_LISTING",
                    description=(
                        f"Number appears on {len(third_party_listings)} non-official "
                        f"page(s) but not in {profile.display_name}'s official directory."
                    ),
                    score_impact=10,
                    matched_evidence_urls=third_party_listings,
                )
            )

    if ni.input_type != InputType.BRAND_SEARCH:
        reports = [
            item.url
            for item in evidence
            if item.url
            and not _is_official_url(item.url)
            and _scam_near_identifier(ni, item)
        ]
        if reports:
            impact = min(len(reports) * 15, 45)
            score += impact
            signals.append(
                SignalBreakdown(
                    signal_name="PUBLIC_SCAM_REPORT_FOUND",
                    description=(
                        f"{len(reports)} public page(s) mention this contact together "
                        "with scam/fraud keywords."
                    ),
                    score_impact=impact,
                    matched_evidence_urls=reports,
                )
            )

    positive_impact = sum(signal.score_impact for signal in signals if signal.score_impact > 0)
    if ni.input_type != InputType.BRAND_SEARCH and not official_match and positive_impact == 0:
        score += 10
        signals.append(
            SignalBreakdown(
                signal_name="UNVERIFIED_CONTACT",
                description=(
                    "No official source confirms this contact and no public reports were "
                    "found. Absence of reports is not proof of safety."
                ),
                score_impact=10,
            )
        )

    final_score = max(0, min(100, score))
    risk_level = (
        RiskLevel.CRITICAL
        if final_score >= 70
        else RiskLevel.HIGH
        if final_score >= 50
        else RiskLevel.MEDIUM
        if final_score >= 25
        else RiskLevel.LOW
    )
    confidence = (
        "HIGH"
        if official_match or len(evidence) >= 5
        else "MEDIUM"
        if len(evidence) >= 2
        else "LOW"
    )
    return final_score, risk_level, confidence, signals, profile
