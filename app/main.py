"""
app/main.py
FastAPI application entrypoint for ScamShield India.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.models.schemas import InvestigateRequest, InvestigationReport
from app.core.classifier import classify_input
from app.core.normalizer import normalize_input
from app.core.scoring import calculate_risk_score
from app.services.serpapi_service import serpapi_service
from app.services.claude_service import claude_service


app = FastAPI(
    title="ScamShield India API",
    description="Search-Poisoning & Cyber Fraud Contact Verification Engine",
    version="1.0.0"
)

# Enable CORS for local and web frontend clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ScamShield India"}


@app.post("/api/v1/investigate", response_model=InvestigationReport)
async def investigate_contact(payload: InvestigateRequest):
    try:
        # Step 1: Input Classification
        input_type = classify_input(payload.query)

        # Step 2: Normalization & Brand Detection
        normalized = normalize_input(
            raw_query=payload.query,
            input_type=input_type,
            claimed_brand=payload.claimed_brand
        )

        # Step 3: Evidence Harvesting via SerpApi
        evidence_items = []
        
        # Primary web search
        web_results = await serpapi_service.search_google(normalized.normalized_value)
        evidence_items.extend(web_results)

        # Context-dependent collection
        if normalized.detected_brand:
            brand_results = await serpapi_service.search_google(f"{normalized.detected_brand} official contact customer care")
            evidence_items.extend(brand_results[:2])

        news_results = await serpapi_service.search_google_news(normalized.normalized_value)
        evidence_items.extend(news_results)

        # Step 4: Rule-based Scoring Engine
        risk_score, risk_level, confidence, signals = calculate_risk_score(
            normalized_input=normalized,
            evidence_list=evidence_items
        )

        # Step 5: Claude Multilingual Synthesis
        warnings = []
        explanation = await claude_service.generate_explanation(
            query=payload.query,
            risk_level=risk_level,
            risk_score=risk_score,
            language=payload.language,
            signals=signals,
            evidence=evidence_items
        )
        if explanation.pop("_fallback", False):
            warnings.append("Claude unavailable; built-in template explanation used.")

        # Step 6: Assemble Unified Investigation Report
        return InvestigationReport(
            query=payload.query,
            input_type=input_type,
            normalized_value=normalized.normalized_value,
            detected_brand=normalized.detected_brand,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            signals=signals,
            evidence=evidence_items,
            warnings=warnings,
            summary=explanation.get("summary", ""),
            what_was_checked=explanation.get("what_was_checked", []),
            risk_factors=explanation.get("risk_factors", []),
            unverified_points=explanation.get("unverified_points", []),
            recommended_actions=explanation.get("recommended_actions", []),
            language=payload.language
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation pipeline error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)