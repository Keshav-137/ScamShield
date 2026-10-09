"""app/main.py — FastAPI entrypoint for ScamShield India."""

import asyncio
import json
import logging
import re
import time
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Awaitable, Callable, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

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
from app.services.llm_service import llm
from app.services.official_crawler import official_crawler_service
from app.services.serpapi_service import serpapi_service
from app.services.stats_service import stats_service

logging.basicConfig(level=settings.LOG_LEVEL)
for _name in ("httpx", "httpx2", "httpcore"):  # their INFO lines contain request URLs (and API keys)
    logging.getLogger(_name).setLevel(logging.WARNING)
log = logging.getLogger("scamshield")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="ScamShield India API",
              description="Search-poisoning & cyber-fraud contact verification engine", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

# ---------------------------------------------------------------- rate limiting (per IP, in memory)
_hits = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path.startswith("/api/"):
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        dq = _hits[ip]
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= settings.RATE_LIMIT_PER_MIN:
            return JSONResponse({"detail": "Too many requests. Please wait a minute and try again."},
                                status_code=429, headers={"Retry-After": "60"})
        dq.append(now)
    return await call_next(request)


REPORT_ACTIONS = {
    "en": ["If money was lost or you shared details, call 1930 (National Cyber Crime Helpline) immediately and report at cybercrime.gov.in.",
           "Report suspicious calls/SMS on sancharsaathi.gov.in (Chakshu)."],
    "hi": ["पैसे कटे हों या जानकारी साझा की हो तो तुरंत 1930 (राष्ट्रीय साइबर क्राइम हेल्पलाइन) पर कॉल करें और cybercrime.gov.in पर शिकायत करें।",
           "संदिग्ध कॉल/SMS की शिकायत sancharsaathi.gov.in (चक्षु) पर करें।"],
    "mr": ["पैसे गेले असतील किंवा माहिती शेअर केली असेल तर लगेच 1930 (राष्ट्रीय सायबर क्राइम हेल्पलाइन) वर कॉल करा आणि cybercrime.gov.in वर तक्रार करा.",
           "संशयास्पद कॉल/SMS ची तक्रार sancharsaathi.gov.in (चक्षु) वर करा."],
}

Emit = Callable[[str, str], Awaitable[None]]


async def _noop(stage: str, message: str) -> None:
    return None


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


# ---------------------------------------------------------------- core pipeline
async def run_investigation(query: str, claimed_brand: Optional[str], language: Language,
                            emit: Emit = _noop) -> InvestigationReport:
    fails_before, blocked_before = serpapi_service.failures, serpapi_service.budget_blocked
    input_type = classify_input(query)
    ni = normalize_input(query, input_type, claimed_brand)
    await emit("classify", f"Detected input type: {input_type.value}")

    profile = lookup_brand(ni.detected_brand) or lookup_brand(ni.normalized_value)
    if not profile:
        name = claimed_brand or (extract_brand_name(query) if input_type == InputType.BRAND_SEARCH else None)
        if name:
            await emit("brand", f"Finding the official identity of '{name}' (Google + Bing + Maps)…")
        try:
            profile = await brand_resolver.resolve(name)
        except Exception as exc:
            log.warning("Brand resolution failed: %r", exc)
        if profile:
            ni.detected_brand = profile.display_name
            await emit("brand", f"Official domain found: {profile.official_domains[0]}")

    if profile and input_type in (InputType.PHONE, InputType.BRAND_SEARCH):
        already = input_type == InputType.PHONE and official_crawler_service.verify(ni, profile)[0] is True
        if not already:
            await emit("verify", f"Reading {profile.display_name}'s official website for live helplines…")
            await brand_resolver.live_verify(profile)

    if input_type == InputType.PHONE:
        digits = local_digits(ni.normalized_value)
        web_q, news_q, maps_q, forum_q = f'"{digits}"', f'"{digits}"', digits, f'"{digits}"'
    elif input_type == InputType.BRAND_SEARCH:
        web_q = news_q = maps_q = ni.normalized_value
        forum_q = None
    else:
        web_q = news_q = forum_q = ni.normalized_value
        maps_q = None

    await emit("search", "Searching Google, News, Maps and Forums in parallel…")
    tasks = [serpapi_service.search_google(web_q), serpapi_service.search_google_news(news_q)]
    if maps_q:
        tasks.append(serpapi_service.search_google_maps(maps_q))
    if forum_q:
        tasks.append(serpapi_service.search_forums(forum_q))
    if ni.detected_brand and input_type != InputType.BRAND_SEARCH:
        tasks.append(serpapi_service.search_google(f"{ni.detected_brand} official customer care number", num=3))
    intel_task = None
    if input_type == InputType.URL and ni.extracted_domain:
        await emit("intel", "Checking domain age and phishing feeds…")
        intel_task = asyncio.create_task(inspect_domain(ni.extracted_host or ni.extracted_domain, ni.extracted_domain))

    evidence: List[EvidenceItem] = []
    for res in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(res, Exception):
            log.warning("Evidence task failed: %r", res)
        else:
            evidence.extend(res)
    evidence = dedupe(evidence)
    await emit("search", f"Collected {len(evidence)} pieces of evidence")
    age, threat_hits = (await intel_task) if intel_task else (None, [])

    await emit("score", "Scoring signals…")
    score, level, confidence, signals, profile = calculate_risk_score(ni, evidence, profile, age, threat_hits)

    await emit("explain", f"Writing the explanation in {language.value.upper()}…")
    explanation = await claude_service.generate_explanation(
        query=query, risk_level=level, risk_score=score, language=language, signals=signals, evidence=evidence)

    warnings = []
    if not serpapi_service.enabled:
        warnings.append("SERPAPI_API_KEY is not set: no live search evidence was collected.")
    elif not evidence:
        warnings.append("SerpApi returned no results (check quota/key).")
    if serpapi_service.failures > fails_before:
        warnings.append("Some SerpApi requests timed out; evidence may be partial.")
    if serpapi_service.budget_blocked > blocked_before:
        warnings.append("Daily SerpApi budget reached; some searches were skipped.")
    if explanation.pop("_fallback", False):
        warnings.append("AI explanation unavailable; built-in template used (see server log).")

    actions = list(explanation.get("recommended_actions", []))
    if score >= 25:
        actions += REPORT_ACTIONS[language.value]

    contacts = OfficialContacts(
        display_name=profile.display_name, domains=profile.official_domains,
        helplines=profile.official_helplines, upi_handles=profile.official_upi_handles,
        notes=profile.notes, source=profile.source, live_helplines=profile.live_helplines,
        live_checked=profile.live_checked) if profile else None

    brand = ni.detected_brand or (profile.display_name if profile else None)
    stats_service.record(input_type.value, level.value, score, brand or "",
                         [s.signal_name for s in signals if s.score_impact != 0], ni.normalized_value)

    return InvestigationReport(
        query=query, input_type=input_type, normalized_value=ni.normalized_value, detected_brand=brand,
        risk_level=level, risk_score=score, confidence=confidence, signals=signals, evidence=evidence,
        official_contacts=contacts, warnings=warnings,
        summary=explanation.get("summary", ""),
        what_was_checked=explanation.get("what_was_checked", []),
        risk_factors=explanation.get("risk_factors", []),
        unverified_points=explanation.get("unverified_points", []),
        recommended_actions=actions, language=language)


async def analyze_text(message: str, language: Language, emit: Emit = _noop) -> MessageAnalysisResponse:
    await emit("extract", "Reading the message…")
    ent = await claude_service.extract_entities(message)
    targets = (ent["phones"] + ent["urls"] + ent["upi_ids"])[:3]  # cap to protect SerpApi credits
    if not targets:
        raise HTTPException(status_code=422, detail="No phone number, link or UPI ID found in the message.")
    await emit("extract", f"Scam type: {ent['scam_type']}; verifying {len(targets)} contact(s)")
    stats_service.bump("by_scam_type", ent["scam_type"])

    def tag(t: str) -> Emit:
        async def _e(stage: str, msg: str) -> None:
            await emit(stage, f"[{t[:28]}] {msg}")
        return _e

    results = await asyncio.gather(
        *[run_investigation(t, ent["brand"], language, tag(t)) for t in targets], return_exceptions=True)
    reports = [r for r in results if isinstance(r, InvestigationReport)]
    for r in results:
        if isinstance(r, Exception):
            log.warning("Message investigation failed: %r", r)
    if not reports:
        raise HTTPException(status_code=500, detail="All investigations failed; check the server log.")
    worst = max(reports, key=lambda r: r.risk_score)
    overall = worst.risk_score
    if worst.risk_score >= 25 and ent["scam_type"] != "NOT_SCAM_LIKE":
        overall = min(100, overall + min(10 * len(ent["tactics"]), 30))
    return MessageAnalysisResponse(
        brand=ent["brand"], scam_type=ent["scam_type"], tactics=ent["tactics"],
        overall_risk_level=level_for(overall), overall_risk_score=overall, reports=reports)


async def analyze_image(data: bytes, content_type: str, language: Language, emit: Emit = _noop):
    await emit("ocr", "Reading the screenshot…")
    try:
        image_analysis = await claude_service.analyze_image(data, content_type)
    except Exception as exc:
        if (getattr(exc, "status_code", None) == 429
                or re.search(r"\bHTTP\s+429\b", str(exc), re.IGNORECASE)):
            raise HTTPException(
                status_code=503,
                detail="The configured AI provider has no available image-analysis quota. "
                       "Check its quota and billing settings, or configure another provider.",
            )
        if isinstance(exc, RuntimeError):
            raise HTTPException(status_code=503, detail=str(exc))
        log.warning("Image analysis failed: %r", exc)
        raise HTTPException(status_code=502, detail="Could not analyze the screenshot.")

    text = image_analysis["transcription"]
    stats_service.bump("actions", "screenshot")
    try:
        result = await analyze_text(text[:3000], language, emit)
    except HTTPException as exc:
        if exc.status_code != 422:
            raise
        return MessageAnalysisResponse(
            scam_type="NOT_ASSESSED",
            overall_risk_level=RiskLevel.UNKNOWN,
            overall_risk_score=0,
            reports=[],
            image_description=image_analysis["image_description"],
            transcribed_text=text[:3000],
            risk_assessment_note=(
                "No phone number, website, or UPI ID could be extracted from the image. "
                "The image is described above, but scam risk was not assessed."
            ),
        )
    return result.model_copy(update={
        "image_description": image_analysis["image_description"],
        "transcribed_text": text[:3000],
    })


# ---------------------------------------------------------------- live progress (Server-Sent Events)
def sse(job: Callable[[Emit], Awaitable[BaseModel]]) -> StreamingResponse:
    async def gen():
        q: asyncio.Queue = asyncio.Queue()

        async def emit(stage: str, message: str) -> None:
            await q.put({"type": "progress", "stage": stage, "message": message})

        async def runner() -> None:
            try:
                res = await job(emit)
                await q.put({"type": "result", "data": res.model_dump(mode="json")})
            except HTTPException as exc:
                await q.put({"type": "error", "message": str(exc.detail)})
            except Exception as exc:
                log.exception("Stream job failed")
                await q.put({"type": "error", "message": f"{type(exc).__name__}: see server log"})
            await q.put(None)

        task = asyncio.create_task(runner())
        try:
            while True:
                item = await q.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
        finally:
            task.cancel()

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def _read_upload(file: UploadFile) -> bytes:
    if file.content_type not in ("image/png", "image/jpeg", "image/webp"):
        raise HTTPException(status_code=422, detail="Upload a PNG, JPEG or WEBP image.")
    data = await file.read()
    if len(data) > 5_000_000:
        raise HTTPException(status_code=413, detail="Image larger than 5 MB.")
    return data


def _lang(value: str) -> Language:
    try:
        return Language(value)
    except ValueError:
        return Language.EN


# ---------------------------------------------------------------- routes
@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health():
    return {"status": "healthy", "serpapi_configured": serpapi_service.enabled,
            "claude_configured": claude_service.client is not None, "llm_provider": llm.provider,
            "safe_browsing_configured": bool(settings.SAFE_BROWSING_API_KEY),
            "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY)}


@app.get("/api/v1/stats")
async def stats():
    return {"stats": stats_service.snapshot(),
            "serpapi": {**serpapi_service.usage(), "account": await serpapi_service.account()},
            "ai_provider": llm.provider}


@app.get("/api/v1/alerts")
async def alerts():
    return {"items": await serpapi_service.search_scam_news()}


@app.post("/api/v1/investigate", response_model=InvestigationReport)
async def investigate(payload: InvestigateRequest):
    try:
        return await run_investigation(payload.query, payload.claimed_brand, payload.language)
    except Exception as exc:
        log.exception("Pipeline error")
        raise HTTPException(status_code=500, detail=f"Investigation pipeline error: {exc!r}")


@app.post("/api/v1/investigate/stream")
async def investigate_stream(payload: InvestigateRequest):
    return sse(lambda emit: run_investigation(payload.query, payload.claimed_brand, payload.language, emit))


@app.post("/api/v1/analyze-message", response_model=MessageAnalysisResponse)
async def analyze_message(payload: MessageAnalysisRequest):
    return await analyze_text(payload.message, payload.language)


@app.post("/api/v1/analyze-message/stream")
async def analyze_message_stream(payload: MessageAnalysisRequest):
    return sse(lambda emit: analyze_text(payload.message, payload.language, emit))


@app.post("/api/v1/analyze-screenshot", response_model=MessageAnalysisResponse)
async def analyze_screenshot(file: UploadFile = File(...), language: str = Form("en")):
    return await analyze_image(await _read_upload(file), file.content_type, _lang(language))


@app.post("/api/v1/analyze-screenshot/stream")
async def analyze_screenshot_stream(file: UploadFile = File(...), language: str = Form("en")):
    data = await _read_upload(file)  # read before streaming: the upload closes after the handler returns
    ctype, lang = file.content_type, _lang(language)
    return sse(lambda emit: analyze_image(data, ctype, lang, emit))


class AppCheckRequest(BaseModel):
    app_name: str = Field(..., min_length=2, max_length=80)
    claimed_brand: Optional[str] = None


@app.post("/api/v1/check-app")
async def check_app(payload: AppCheckRequest):
    """Fake-app check: Google Play search, flag apps using the brand name under another developer."""
    apps = await serpapi_service.search_play_apps(payload.app_name)
    stats_service.bump("actions", "app_check")
    if not apps:
        return {"verdict": "NO_RESULTS", "apps": [], "note": "No Google Play results (or SerpApi unavailable)."}
    token = extract_brand_name(payload.claimed_brand or payload.app_name).replace(" ", "")
    first = apps[0]
    clones = [a for a in apps[1:]
              if token and token in re.sub(r"\W", "", a["title"].lower())
              and a["id"] != first["id"] and not (a["developer"] and a["developer"] == first["developer"])]
    return {
        "verdict": "POSSIBLE_CLONES_FOUND" if clones else "NO_CLONES_FOUND",
        "presumed_official": first, "possible_clones": clones,
        "developer_data_available": any(a["developer"] for a in apps),
        "note": "The top Google Play result is only a heuristic for the official app. "
                "Confirm the developer on the brand's official website before installing.",
    }


@app.get("/api/v1/debug/serpapi")
async def debug_serpapi(engine: str = Query(...), q: str = Query(..., min_length=2)):
    """Development only: shows the raw SerpApi response SHAPE so you can verify parsing (costs 1 search)."""
    if settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=404)
    params = {"engine": engine, "q": q}
    if engine == "google_play":
        params["store"] = "apps"
    data = await serpapi_service.raw(params)

    def trim(v, depth=0):
        if isinstance(v, dict):
            return {k: trim(x, depth + 1) for k, x in list(v.items())[:25]} if depth < 4 else "{…}"
        if isinstance(v, list):
            return [trim(x, depth + 1) for x in v[:2]] if depth < 4 else "[…]"
        return v[:120] if isinstance(v, str) else v

    return {"top_level_keys": list(data.keys()), "sample": trim(data)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)