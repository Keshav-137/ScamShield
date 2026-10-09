"""
app/core/scoring.py
Rule-based risk evaluation engine.
"""

from typing import List, Tuple
from app.models.schemas import RiskLevel, SignalBreakdown, EvidenceItem, NormalizedInput
from app.core.lookalike import evaluate_domain_similarity
from app.services.brand_directory import lookup_brand
from app.services.official_crawler import official_crawler_service


SCAM_KEYWORDS = ["fraud", "scam", "complaint", "cybercrime", "fir", "cheating", "impersonator", "fake", "stolen", "unauthorized"]


def calculate_risk_score(
    normalized_input: NormalizedInput,
    evidence_list: List[EvidenceItem]
) -> Tuple[int, RiskLevel, str, List[SignalBreakdown]]:
    score = 15  # Baseline neutral score
    signals: List[SignalBreakdown] = []

    # 1. Official Ground-Truth Verification
    brand_profile = lookup_brand(normalized_input.detected_brand or normalized_input.normalized_value)
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
    scam_evidence_urls = []
    for item in evidence_list:
        combined_text = f"{item.title} {item.snippet}".lower()
        if any(keyword in combined_text for keyword in SCAM_KEYWORDS):
            if item.url:
                scam_evidence_urls.append(item.url)

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