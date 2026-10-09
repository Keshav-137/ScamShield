"""app/services/llm_service.py — Provider-agnostic completion: Anthropic (paid) or Gemini (free tier)."""

import base64
import logging
from typing import Optional, Tuple

import httpx
from anthropic import AsyncAnthropic
from app.config import settings

log = logging.getLogger("scamshield.llm")


class LLM:
    def __init__(self):
        self.anthropic = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY) if settings.ANTHROPIC_API_KEY else None

    @property
    def provider(self) -> Optional[str]:
        if self.anthropic:
            return "anthropic"
        if settings.GEMINI_API_KEY:
            return "gemini"
        return None

    @property
    def enabled(self) -> bool:
        return self.provider is not None

    async def complete(self, system: str, user: str, max_tokens: int = 1000,
                       image: Optional[Tuple[bytes, str]] = None, json_mode: bool = True) -> str:
        if self.anthropic:
            content = [{"type": "text", "text": user}]
            if image:
                content.insert(0, {"type": "image", "source": {
                    "type": "base64", "media_type": image[1],
                    "data": base64.standard_b64encode(image[0]).decode()}})
            kwargs = {"system": system} if system else {}
            resp = await self.anthropic.messages.create(
                model=settings.CLAUDE_MODEL, max_tokens=max_tokens,
                messages=[{"role": "user", "content": content}], **kwargs)
            return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")

        if settings.GEMINI_API_KEY:
            parts = []
            if image:
                parts.append({"inline_data": {"mime_type": image[1],
                                              "data": base64.standard_b64encode(image[0]).decode()}})
            parts.append({"text": user})
            body = {"contents": [{"role": "user", "parts": parts}],
                    "generationConfig": {"maxOutputTokens": max_tokens * 4, "temperature": 0.2}}
            if system:
                body["systemInstruction"] = {"parts": [{"text": system}]}
            if json_mode:
                body["generationConfig"]["responseMimeType"] = "application/json"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.GEMINI_MODEL}:generateContent"
            # Key goes in a header, never in the URL, so errors and logs cannot leak it.
            async with httpx.AsyncClient(timeout=60.0) as client:
                r = await client.post(url, headers={"x-goog-api-key": settings.GEMINI_API_KEY}, json=body)
            if r.status_code != 200:
                raise RuntimeError(f"Gemini HTTP {r.status_code}: {r.text[:200]}")
            cand = (r.json().get("candidates") or [{}])[0]
            return "".join(p.get("text", "") for p in cand.get("content", {}).get("parts", []))

        raise RuntimeError("No LLM key configured")


llm = LLM()