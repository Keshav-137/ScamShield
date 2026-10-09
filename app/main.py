"""app/main.py — FastAPI entrypoint for ScamShield India."""

import asyncio
import logging
from collections import Counter
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.config import settings
from app.core.classifier import classify_input
from app.core.normalizer import normalize_input
from app.core.scoring import calculate_risk_score
from app.core.utils import local_digits, registered_domain
from app.models.schemas import (EvidenceItem, InputType, InvestigateRequest, InvestigationReport, Language,
                                MessageAnalysisRequest, MessageAnalysisResponse, OfficialContacts, RiskLevel)
from app.services.brand_directory import lookup_brand
from app.services.brand_resolver import brand_resolver, extract_brand_name
from app.services.claude_service import claude_service
from app.services.domain_intel import inspect_domain
from app.services.serpapi_service import serpapi_service

logging.basicConfig(level=settings.LOG_LEVEL)
for _name in ("httpx", "httpx2", "httpcore"):  # their INFO lines contain request URLs (and API keys)
    logging.getLogger(_name).setLevel(logging.WARNING)
log = logging.getLogger("scamshield")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="ScamShield India API",
              description="Search-poisoning & cyber-fraud contact verification engine", version="1.3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])


def dedupe(evidence: List[EvidenceItem], per_domain: int = 2) -> List[EvidenceItem]:
    seen: Counter = Counter()
    out = []
    for e in evidence:
        key = (registered_domain(e.url) if e.url else "") or e.title
        if seen[key] < per_domain:
            seen[key] += 1
            out.append(e)
    return out


def level_for(score: int) -> RiskLevel:
    return (RiskLevel.CRITICAL if score >= 70 else RiskLevel.HIGH if score >= 50
            else RiskLevel.MEDIUM if score >= 25 else RiskLevel.LOW)


async def run_investigation(query: str, claimed_brand: Optional[str], language: Language) -> InvestigationReport:
    fails_before = serpapi_service.failures
    input_type = classify_input(query)
    ni = normalize_input(query, input_type, claimed_brand)

    # Brand: curated registry first, otherwise discover it live (Google + Bing + Maps consensus)
    profile = lookup_brand(ni.detected_brand) or lookup_brand(ni.normalized_value)
    if not profile:
        name = claimed_brand or (extract_brand_name(query) if input_type == InputType.BRAND_SEARCH else None)
        try:
            profile = await brand_resolver.resolve(name)
        except Exception as exc:
            log.warning("Brand resolution failed: %r", exc)
        if profile:
            ni.detected_brand = profile.display_name

    if input_type == InputType.PHONE:
        digits = local_digits(ni.normalized_value)
        web_q, news_q, maps_q = f'"{digits}"', f'"{digits}"', digits
    elif input_type == InputType.BRAND_SEARCH:
        web_q = news_q = maps_q = ni.normalized_value
    else:
        web_q = news_q = ni.normalized_value
        maps_q = None

    tasks = [serpapi_service.search_google(web_q), serpapi_service.search_google_news(news_q)]
    if maps_q:
        tasks.append(serpapi_service.search_google_maps(maps_q))
    if ni.detected_brand and input_type != InputType.BRAND_SEARCH:
        tasks.append(serpapi_service.search_google(f"{ni.detected_brand} official customer care number", num=3))
    intel_task = asyncio.create_task(inspect_domain(ni.extracted_host or ni.extracted_domain, ni.extracted_domain)) \
        if input_type == InputType.URL and ni.extracted_domain else None

    evidence: List[EvidenceItem] = []
    for res in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(res, Exception):
            log.warning("Evidence task failed: %r", res)
        else:
            evidence.extend(res)
    evidence = dedupe(evidence)
    age, threat_hits = (await intel_task) if intel_task else (None, [])

    score, level, confidence, signals, profile = calculate_risk_score(ni, evidence, profile, age, threat_hits)

    explanation = await claude_service.generate_explanation(
        query=query, risk_level=level, risk_score=score, language=language, signals=signals, evidence=evidence)

    warnings = []
    if not serpapi_service.enabled:
        warnings.append("SERPAPI_API_KEY is not set: no live search evidence was collected.")
    elif not evidence:
        warnings.append("SerpApi returned no results (check quota/key).")
    if serpapi_service.failures > fails_before:
        warnings.append("Some SerpApi requests timed out; evidence may be partial.")
    if explanation.pop("_fallback", False):
        warnings.append("Claude unavailable; built-in template explanation used (see server log).")

    contacts = OfficialContacts(
        display_name=profile.display_name, domains=profile.official_domains,
        helplines=profile.official_helplines, upi_handles=profile.official_upi_handles,
        notes=profile.notes, source=profile.source) if profile else None

    return InvestigationReport(
        query=query, input_type=input_type, normalized_value=ni.normalized_value,
        detected_brand=ni.detected_brand or (profile.display_name if profile else None),
        risk_level=level, risk_score=score, confidence=confidence, signals=signals, evidence=evidence,
        official_contacts=contacts, warnings=warnings,
        summary=explanation.get("summary", ""),
        what_was_checked=explanation.get("what_was_checked", []),
        risk_factors=explanation.get("risk_factors", []),
        unverified_points=explanation.get("unverified_points", []),
        recommended_actions=explanation.get("recommended_actions", []),
        language=language)


async def analyze_text(message: str, language: Language) -> MessageAnalysisResponse:
    ent = await claude_service.extract_entities(message)
    targets = (ent["phones"] + ent["urls"] + ent["upi_ids"])[:3]  # cap to protect SerpApi credits
    if not targets:
        raise HTTPException(status_code=422, detail="No phone number, link or UPI ID found in the message.")
    results = await asyncio.gather(
        *[run_investigation(t, ent["brand"], language) for t in targets], return_exceptions=True)
    reports = [r for r in results if isinstance(r, InvestigationReport)]
    for r in results:
        if isinstance(r, Exception):
            log.warning("Message investigation failed: %r", r)
    if not reports:
        raise HTTPException(status_code=500, detail="All investigations failed; check the server log.")
    worst = max(reports, key=lambda r: r.risk_score)
    overall = worst.risk_score
    # Pressure tactics (urgency, fear, OTP request...) raise risk only when some contact is unverified
    if worst.risk_score >= 25 and ent["scam_type"] != "NOT_SCAM_LIKE":
        overall = min(100, overall + min(10 * len(ent["tactics"]), 30))
    return MessageAnalysisResponse(
        brand=ent["brand"], scam_type=ent["scam_type"], tactics=ent["tactics"],
        overall_risk_level=level_for(overall), overall_risk_score=overall, reports=reports)


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health():
    return {"status": "healthy", "serpapi_configured": serpapi_service.enabled,
            "claude_configured": claude_service.client is not None,
            "safe_browsing_configured": bool(settings.SAFE_BROWSING_API_KEY)}


@app.post("/api/v1/investigate", response_model=InvestigationReport)
async def investigate(payload: InvestigateRequest):
    try:
        return await run_investigation(payload.query, payload.claimed_brand, payload.language)
    except Exception as exc:
        log.exception("Pipeline error")
        raise HTTPException(status_code=500, detail=f"Investigation pipeline error: {exc!r}")


@app.post("/api/v1/analyze-message", response_model=MessageAnalysisResponse)
async def analyze_message(payload: MessageAnalysisRequest):
    return await analyze_text(payload.message, payload.language)


@app.post("/api/v1/analyze-screenshot", response_model=MessageAnalysisResponse)
async def analyze_screenshot(file: UploadFile = File(...), language: str = Form("en")):
    """Upload a WhatsApp/SMS screenshot: Claude reads it, then the normal pipeline verifies every contact."""
    if file.content_type not in ("image/png", "image/jpeg", "image/webp"):
        raise HTTPException(status_code=422, detail="Upload a PNG, JPEG or WEBP image.")
    data = await file.read()
    if len(data) > 5_000_000:
        raise HTTPException(status_code=413, detail="Image larger than 5 MB.")
    try:
        lang = Language(language)
    except ValueError:
        lang = Language.EN
    try:
        text = await claude_service.read_image_text(data, file.content_type)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        log.warning("Image read failed: %r", exc)
        raise HTTPException(status_code=502, detail="Could not read the screenshot.")
    if len(text) < 5:
        raise HTTPException(status_code=422, detail="No readable text found in the image.")
    return await analyze_text(text[:3000], lang)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)