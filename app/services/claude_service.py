"""
app/services/claude_service.py
Multilingual explanation generator powered by Claude.
"""

from typing import List, Dict, Any
import json
import logging
from anthropic import AsyncAnthropic
from app.config import settings
from app.models.schemas import Language, RiskLevel, SignalBreakdown, EvidenceItem

log = logging.getLogger("scamshield.claude")


class ClaudeExplanationService:
    def __init__(self):
        self.api_key = settings.ANTHROPIC_API_KEY
        self.client = AsyncAnthropic(api_key=self.api_key) if self.api_key else None

    async def generate_explanation(
        self,
        query: str,
        risk_level: RiskLevel,
        risk_score: int,
        language: Language,
        signals: List[SignalBreakdown],
        evidence: List[EvidenceItem]
    ) -> Dict[str, Any]:
        """
        Produces a structured JSON explanation.
        """
        if not self.client:
            explanation = self._fallback_explanation(risk_level, risk_score, language)
            explanation["_fallback"] = True
            return explanation

        system_prompt = (
            "You are ScamShield India's cybersecurity analyst. "
            "Explain the contact investigation report objectively. "
            "Do NOT invent facts, numbers, or URLs. Only refer to the evidence provided. "
            f"Respond STRICTLY in JSON format in the requested language ({language.value})."
        )

        user_content = {
            "query": query,
            "risk_score": risk_score,
            "risk_level": risk_level.value,
            "language": language.value,
            "signals": [s.model_dump() for s in signals],
            "evidence": [e.model_dump() for e in evidence[:5]],
            "format_required": {
                "summary": "1-2 sentence verdict",
                "what_was_checked": ["list of checked items"],
                "risk_factors": ["list of discovered risks"],
                "unverified_points": ["limitations or unknown details"],
                "recommended_actions": ["immediate action steps"]
            }
        }

        try:
            response = await self.client.messages.create(
                model=settings.CLAUDE_MODEL,
                max_tokens=1000,
                temperature=0.2,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": f"Analyze this investigation data and return JSON:\n{json.dumps(user_content)}"}
                ]
            )
            raw_text = response.content[0].text
            # Extract JSON block if wrapped in markdown
            if "```json" in raw_text:
                raw_text = raw_text.split("```json")[1].split("```")[0].strip()
            return json.loads(raw_text)
        except Exception as exc:
            log.warning("Claude call failed, using fallback: %s", exc)
            explanation = self._fallback_explanation(risk_level, risk_score, language)
            explanation["_fallback"] = True
            return explanation

    def _fallback_explanation(self, risk_level: RiskLevel, risk_score: int, language: Language) -> Dict[str, Any]:
        """Deterministic multilingual template if API is unreachable."""
        if language == Language.HI:
            return {
                "summary": f"जांच पूरी हुई। जोखिम स्तर: {risk_level.value} (स्कोर: {risk_score}/100)।",
                "what_was_checked": ["आधिकारिक ब्रांड रिकॉर्ड", "वेब और समाचार प्रमाण"],
                "risk_factors": ["आधिकारिक रिकॉर्ड के साथ असंगत विवरण"],
                "unverified_points": ["थर्ड-पार्टी सूची की पूर्ण प्रामाणिकता"],
                "recommended_actions": ["ओटीपी (OTP) या यूपीआई पिन कभी साझा न करें।"]
            }
        elif language == Language.MR:
            return {
                "summary": f"तपासणी पूर्ण झाली. जोखीम पातळी: {risk_level.value} (गुण: {risk_score}/100).",
                "what_was_checked": ["अधिकृत ब्रँड नोंदी", "वेब आणि बातम्यांचे पुरावे"],
                "risk_factors": ["अधिकृत नोंदींशी जुळत नसलेली माहिती"],
                "unverified_points": ["अनोळखी स्रोतांची सत्यता"],
                "recommended_actions": ["कधीही कोणाशीही OTP किंवा UPI PIN शेअर करू नका."]
            }
        else:
            return {
                "summary": f"Investigation concluded with a risk rating of {risk_level.value} (Score: {risk_score}/100).",
                "what_was_checked": ["Official brand registries", "Google Search index", "Recent news reports"],
                "risk_factors": ["Contact not verified against official brand directories"] if risk_score > 30 else [],
                "unverified_points": ["Independent ownership of third-party telecom handles"],
                "recommended_actions": [
                    "Never reveal your UPI PIN or banking OTP to callers.",
                    "Verify contact details on the official mobile banking application."
                ]
            }


claude_service = ClaudeExplanationService()