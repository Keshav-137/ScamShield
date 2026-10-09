"""FastAPI entrypoint for ScamShield India."""

import asyncio
import logging
from collections import Counter
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.config import settings
from app.core.classifier import classify_input
from app.core.normalizer import normalize_input
from app.core.scoring import calculate_risk_score
from app.core.utils import local_digits, registered_domain
from app.models.schemas import (
    EvidenceItem,
    InputType,
    InvestigateRequest,
    InvestigationReport,
    Language,
    MessageAnalysisRequest,
    MessageAnalysisResponse,
    OfficialContacts,
)
from app.services.brand_directory import lookup_brand
from app.services.brand_resolver import brand_resolver, extract_brand_name
from app.services.claude_service import claude_service
from app.services.domain_intel import domain_age_days
from app.services.serpapi_service import serpapi_service

logging.basicConfig(level=settings.LOG_LEVEL)
log = logging.getLogger("scamshield")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="ScamShield India API",
    description="Search-poisoning and cyber-fraud contact verification engine",
    version="1.2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def dedupe(evidence: List[EvidenceItem], per_domain: int = 2) -> List[EvidenceItem]:
    seen: Counter[str] = Counter()
    output = []
    for item in evidence:
        key = (registered_domain(item.url) if item.url else "") or item.title
        if seen[key] < per_domain:
            seen[key] += 1
            output.append(item)
    return output


async def run_investigation(
    query: str,
    claimed_brand: Optional[str],
    language: Language,
) -> InvestigationReport:
    input_type = classify_input(query)
    normalized = normalize_input(query, input_type, claimed_brand)

    profile = lookup_brand(normalized.detected_brand or "") or lookup_brand(
        normalized.normalized_value
    )
    if not profile:
        brand_name = claimed_brand or (
            extract_brand_name(query) if input_type == InputType.BRAND_SEARCH else None
        )
        profile = await brand_resolver.resolve(brand_name)
        if profile:
            normalized.detected_brand = profile.display_name

    if input_type == InputType.PHONE:
        digits = local_digits(normalized.normalized_value)
        web_query = news_query = f'"{digits}"'
        maps_query = digits
    elif input_type == InputType.BRAND_SEARCH:
        web_query = news_query = maps_query = normalized.normalized_value
    else:
        web_query = news_query = normalized.normalized_value
        maps_query = None

    tasks = [
        serpapi_service.search_google(web_query),
        serpapi_service.search_google_news(news_query),
    ]
    if maps_query:
        tasks.append(serpapi_service.search_google_maps(maps_query))
    if normalized.detected_brand and input_type != InputType.BRAND_SEARCH:
        tasks.append(
            serpapi_service.search_google(
                f"{normalized.detected_brand} official customer care number",
                num=3,
            )
        )

    age_task = (
        asyncio.create_task(domain_age_days(normalized.extracted_domain))
        if input_type == InputType.URL and normalized.extracted_domain
        else None
    )

    evidence: List[EvidenceItem] = []
    for result in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(result, Exception):
            log.warning("Evidence task failed: %r", result)
        else:
            evidence.extend(result)
    evidence = dedupe(evidence)
    age = await age_task if age_task else None

    score, level, confidence, signals, profile = calculate_risk_score(
        normalized, evidence, profile, age
    )
    explanation = await claude_service.generate_explanation(
        query=query,
        risk_level=level,
        risk_score=score,
        language=language,
        signals=signals,
        evidence=evidence,
    )

    warnings = []
    if not serpapi_service.enabled:
        warnings.append("SERPAPI_API_KEY is not set: no live search evidence was collected.")
    elif not evidence:
        warnings.append("SerpApi returned no results (check quota/key).")
    if profile and profile.source == "discovered":
        warnings.append(
            "Brand details were discovered from live search consensus and are not independently verified."
        )
    if explanation.pop("_fallback", False):
        warnings.append("Claude unavailable; built-in template explanation used (see server log).")

    official_contacts = (
        OfficialContacts(
            display_name=profile.display_name,
            domains=profile.official_domains,
            helplines=profile.official_helplines,
            upi_handles=profile.official_upi_handles,
            notes=profile.notes,
            source=profile.source,
        )
        if profile
        else None
    )
    return InvestigationReport(
        query=query,
        input_type=input_type,
        normalized_value=normalized.normalized_value,
        detected_brand=normalized.detected_brand or (profile.display_name if profile else None),
        risk_level=level,
        risk_score=score,
        confidence=confidence,
        signals=signals,
        evidence=evidence,
        official_contacts=official_contacts,
        warnings=warnings,
        summary=explanation.get("summary", ""),
        what_was_checked=explanation.get("what_was_checked", []),
        risk_factors=explanation.get("risk_factors", []),
        unverified_points=explanation.get("unverified_points", []),
        recommended_actions=explanation.get("recommended_actions", []),
        language=language,
    )


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "serpapi_configured": serpapi_service.enabled,
        "claude_configured": claude_service.client is not None,
    }


@app.post("/api/v1/investigate", response_model=InvestigationReport)
async def investigate(payload: InvestigateRequest):
    try:
        return await run_investigation(
            payload.query, payload.claimed_brand, payload.language
        )
    except Exception as exc:
        log.exception("Pipeline error")
        raise HTTPException(
            status_code=500,
            detail=f"Investigation pipeline error: {exc!r}",
        ) from exc


@app.post("/api/v1/analyze-message", response_model=MessageAnalysisResponse)
async def analyze_message(payload: MessageAnalysisRequest):
    """Extract contacts from a pasted message and investigate each one."""
    entities = await claude_service.extract_entities(payload.message)
    targets = (entities["phones"] + entities["urls"] + entities["upi_ids"])[:3]
    if not targets:
        raise HTTPException(
            status_code=422,
            detail="No phone number, link, or UPI ID found in the message.",
        )

    results = await asyncio.gather(
        *[
            run_investigation(target, entities["brand"], payload.language)
            for target in targets
        ],
        return_exceptions=True,
    )
    reports = []
    for result in results:
        if isinstance(result, Exception):
            log.warning("Message investigation failed: %r", result)
        else:
            reports.append(result)
    if not reports:
        raise HTTPException(
            status_code=500,
            detail="All investigations failed; check the server log.",
        )

    worst_report = max(reports, key=lambda report: report.risk_score)
    return MessageAnalysisResponse(
        brand=entities["brand"],
        scam_type=entities["scam_type"],
        tactics=entities["tactics"],
        overall_risk_level=worst_report.risk_level,
        overall_risk_score=worst_report.risk_score,
        reports=reports,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
