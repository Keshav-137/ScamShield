"""app/models/schemas.py — Pydantic schemas and enums for ScamShield India."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class InputType(str, Enum):
    PHONE = "PHONE"
    UPI = "UPI"
    URL = "URL"
    BRAND_SEARCH = "BRAND_SEARCH"


class RiskLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Language(str, Enum):
    EN = "en"
    HI = "hi"
    MR = "mr"


class EvidenceSourceType(str, Enum):
    GOOGLE_SEARCH = "GOOGLE_SEARCH"
    GOOGLE_MAPS = "GOOGLE_MAPS"
    GOOGLE_NEWS = "GOOGLE_NEWS"
    GOOGLE_AUTOCOMPLETE = "GOOGLE_AUTOCOMPLETE"
    OFFICIAL_SITE = "OFFICIAL_SITE"
    THREAT_FEED = "THREAT_FEED"


class InvestigateRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=500,
                       examples=["+91 9876543210", "support@sbi", "https://sbi-helpline-support.xyz", "SBI customer care"])
    claimed_brand: Optional[str] = Field(default=None, examples=["State Bank of India", "Amazon India"])
    language: Language = Language.EN


class NormalizedInput(BaseModel):
    raw_query: str
    input_type: InputType
    normalized_value: str
    detected_brand: Optional[str] = None
    extracted_domain: Optional[str] = None
    extracted_host: Optional[str] = None
    extracted_vpa_handle: Optional[str] = None
    extracted_phone_e164: Optional[str] = None


class EvidenceItem(BaseModel):
    source_type: EvidenceSourceType
    title: str
    snippet: str
    url: Optional[str] = None
    relevance_notes: Optional[str] = None
    timestamp: Optional[str] = None


class SignalBreakdown(BaseModel):
    signal_name: str
    description: str
    score_impact: int
    matched_evidence_urls: List[str] = Field(default_factory=list)


class OfficialContacts(BaseModel):
    display_name: str
    domains: List[str]
    helplines: List[str]
    verified_helplines: List[str] = Field(default_factory=list)  # confirmed on the brand's own website
    live_helplines: List[str] = Field(default_factory=list)
    live_checked: bool = False
    upi_handles: List[str]
    notes: Optional[str] = None
    source: str = "curated"


class InvestigationReport(BaseModel):
    query: str
    input_type: InputType
    normalized_value: str
    detected_brand: Optional[str] = None

    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    confidence: str

    signals: List[SignalBreakdown] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    official_contacts: Optional[OfficialContacts] = None
    warnings: List[str] = Field(default_factory=list)

    summary: str
    what_was_checked: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    unverified_points: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

    language: Language


class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., min_length=5, max_length=3000)
    language: Language = Language.EN


class MessageAnalysisResponse(BaseModel):
    brand: Optional[str] = None
    scam_type: str
    tactics: List[str] = Field(default_factory=list)
    overall_risk_level: RiskLevel
    overall_risk_score: int
    reports: List[InvestigationReport]
    image_description: Optional[str] = None
    transcribed_text: Optional[str] = None
    risk_assessment_note: Optional[str] = None