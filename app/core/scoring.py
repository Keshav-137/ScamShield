"""app/core/scoring.py — Rule-based risk engine."""

import re
from typing import List, Optional, Tuple
from app.core.lookalike import evaluate_domain_similarity
from app.core.utils import local_digits, registered_domain
from app.models.schemas import (EvidenceItem, EvidenceSourceType, InputType, NormalizedInput,
                                RiskLevel, SignalBreakdown)
from app.services.brand_directory import BRAND_DIRECTORY, OfficialBrandProfile, lookup_brand
from app.services.official_crawler import official_crawler_service

SCAM_RE = re.compile(
    r"\b(?:fraud\w*|scam\w*|complaint\w*|cybercrime|fir|cheat\w*|impersonat\w*|fake|stolen|unauthori[sz]ed|phishing)\b",
    re.IGNORECASE)


def _is_official_url(url: Optional[str]) -> bool:
    if not url:
        return False
    official = {registered_domain(d) for p in BRAND_DIRECTORY.values() for d in p.official_domains}
    return registered_domain(url) in official


def _pattern(ni: NormalizedInput) -> Optional[re.Pattern]:
    if ni.input_type == InputType.PHONE:
        d = local_digits(ni.normalized_value)
        return re.compile(r"\D{0,2}".join(d)) if len(d) >= 8 else None
    if ni.input_type == InputType.URL:
        return re.compile(re.escape(ni.extracted_domain or ni.normalized_value))
    if ni.input_type == InputType.UPI:
        return re.compile(re.escape(ni.normalized_value))
    return None


def _mentions(ni: NormalizedInput, item: EvidenceItem) -> bool:
    pat = _pattern(ni)
    return bool(pat and pat.search(f"{item.title} {item.snippet} {item.url or ''}".lower()))


def _scam_near_identifier(ni: NormalizedInput, item: EvidenceItem) -> bool:
    """Scam keyword must sit right next to THIS identifier, with no other long number between."""
    pat = _pattern(ni)
    if not pat:
        return False
    text = f"{item.title} {item.snippet}".lower()
    for a in pat.finditer(text):
        for k in SCAM_RE.finditer(text):
            if k.start() >= a.end():
                gap = text[a.end():k.start()]
            elif k.end() <= a.start():
                gap = text[k.end():a.start()]
            else:
                gap = ""
            if len(gap) <= 60 and not re.search(r"\d{6,}", gap):
                return True
    return False


def calculate_risk_score(
    ni: NormalizedInput, evidence: List[EvidenceItem],
    profile: Optional[OfficialBrandProfile] = None, domain_age_days: Optional[int] = None,
    threat_hits: Optional[List[str]] = None,
) -> Tuple[int, RiskLevel, str, List[SignalBreakdown], Optional[OfficialBrandProfile]]:
    score = 15
    signals: List[SignalBreakdown] = []
    official_match = False

    profile = profile or lookup_brand(ni.detected_brand) or lookup_brand(ni.normalized_value)
    claimed = profile is not None

    # 1. Official ground-truth verification
    if ni.input_type != InputType.BRAND_SEARCH:
        if not profile:
            profile = official_crawler_service.find_brand_by_contact(ni)
        if profile:
            result, reason = official_crawler_service.verify(ni, profile)
            source = getattr(profile, "source", "curated")
            if result is True:
                official_match = True
                score -= 30
                signals.append(SignalBreakdown(signal_name="OFFICIAL_SOURCE_MATCH", description=reason, score_impact=-30))
            elif result is False and claimed:
                impact = 25 if source == "curated" else 15
                note = "" if source == "curated" else " (official list was discovered from search and may be incomplete)"
                if ni.input_type == InputType.PHONE and not profile.official_helplines:
                    impact = 0
                score += impact
                signals.append(SignalBreakdown(
                    signal_name="OFFICIAL_SOURCE_MISMATCH",
                    description=f"Claims association with {profile.display_name}. {reason}{note}", score_impact=impact))
            elif result is None:
                signals.append(SignalBreakdown(signal_name="OFFICIAL_HANDLE_CONSISTENT", description=reason, score_impact=0))

    # 2. Threat feeds (OpenPhish / Google Safe Browsing)
    if threat_hits:
        score += 50
        signals.append(SignalBreakdown(
            signal_name="THREAT_FEED_MATCH",
            description="Listed by: " + "; ".join(threat_hits), score_impact=50))

    # 3. Lookalike domain + domain age (URL input)
    if ni.input_type == InputType.URL:
        is_look, penalty, expl = evaluate_domain_similarity(
            ni.extracted_host or ni.extracted_domain or ni.normalized_value,
            profile.brand_id if profile else None)
        if is_look:
            score += penalty
            signals.append(SignalBreakdown(signal_name="LOOKALIKE_DOMAIN_DETECTED", description=expl, score_impact=penalty))
        if not official_match and domain_age_days is not None and domain_age_days < 180:
            impact = 30 if domain_age_days < 30 else 15
            score += impact
            signals.append(SignalBreakdown(
                signal_name="NEWLY_REGISTERED_DOMAIN",
                description=f"Domain was registered only {domain_age_days} day(s) ago.", score_impact=impact))

    # 4. Phone type: a plain mobile number posing as a brand's customer care
    if ni.input_type == InputType.PHONE and claimed and not official_match:
        d = local_digits(ni.normalized_value)
        if len(d) == 10 and d[0] in "6789":
            score += 15
            signals.append(SignalBreakdown(
                signal_name="MOBILE_NUMBER_AS_CUSTOMER_CARE",
                description=f"Ordinary mobile number claiming to be {profile.display_name}. Official helplines are usually toll-free or landline numbers.",
                score_impact=15))

    # 5. Search poisoning: lookalike domains ranking for a brand search
    if ni.input_type == InputType.BRAND_SEARCH and profile:
        bad = []
        for e in evidence:
            if e.source_type == EvidenceSourceType.GOOGLE_SEARCH and e.url:
                is_look, _, expl = evaluate_domain_similarity(e.url, profile.brand_id)
                if is_look and "subdomain" not in expl:  # review/aggregator sites use brand subdomains legitimately
                    bad.append(e.url)
        if bad:
            impact = min(25 * len(bad), 50)
            score += impact
            signals.append(SignalBreakdown(
                signal_name="POISONED_SEARCH_RESULTS",
                description=f"{len(bad)} Google result(s) for this search come from lookalike/non-official domains impersonating {profile.display_name}.",
                score_impact=impact, matched_evidence_urls=bad))

    # 6. Number listed on third-party pages only
    if ni.input_type == InputType.PHONE and profile and not official_match:
        listings = [e.url for e in evidence
                    if e.source_type == EvidenceSourceType.GOOGLE_SEARCH and e.url
                    and not _is_official_url(e.url) and _mentions(ni, e)]
        if listings:
            score += 10
            signals.append(SignalBreakdown(
                signal_name="THIRD_PARTY_LISTING",
                description=f"Number appears on {len(listings)} non-official page(s) but not in {profile.display_name}'s official directory.",
                score_impact=10, matched_evidence_urls=listings))

    # 7. Public scam reports that actually talk about this identifier
    if ni.input_type != InputType.BRAND_SEARCH:
        reports = [e.url for e in evidence
                   if e.url and not _is_official_url(e.url) and _scam_near_identifier(ni, e)]
        if reports:
            impact = min(len(reports) * 15, 45)
            score += impact
            signals.append(SignalBreakdown(
                signal_name="PUBLIC_SCAM_REPORT_FOUND",
                description=f"{len(reports)} public page(s) mention this contact together with scam/fraud keywords.",
                score_impact=impact, matched_evidence_urls=reports))

    # 8. Nothing verifies it: never call it "safe"
    if (ni.input_type != InputType.BRAND_SEARCH and not official_match
            and sum(s.score_impact for s in signals if s.score_impact > 0) == 0):
        score += 10
        signals.append(SignalBreakdown(
            signal_name="UNVERIFIED_CONTACT",
            description="No official source confirms this contact and no public reports were found. Absence of reports is not proof of safety.",
            score_impact=10))

    final = max(0, min(100, score))
    level = (RiskLevel.CRITICAL if final >= 70 else RiskLevel.HIGH if final >= 50
             else RiskLevel.MEDIUM if final >= 25 else RiskLevel.LOW)
    confidence = "HIGH" if (official_match or len(evidence) >= 5) else "MEDIUM" if len(evidence) >= 2 else "LOW"
    return final, level, confidence, signals, profile