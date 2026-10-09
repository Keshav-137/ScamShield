"""app/services/llm_service.py — Provider-agnostic completion: Anthropic (paid) or Gemini (free tier)."""

import base64
import logging
from typing import Optional, Tuple

import httpx
from anthropic import AsyncAnthropic
from app.config import settings

log = logging.getLogger("scamshield.llm")

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
_gemini = {"model": None}


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

    @staticmethod
    async def _gemini_call(client: httpx.AsyncClient, model: str, body: dict) -> httpx.Response:
        # Key goes in a header, never in the URL, so errors and logs cannot leak it.
        return await client.post(f"{GEMINI_BASE}/models/{model}:generateContent",
                                 headers={"x-goog-api-key": settings.GEMINI_API_KEY}, json=body)

    @staticmethod
    async def _discover_model(client: httpx.AsyncClient) -> Optional[str]:
        r = await client.get(f"{GEMINI_BASE}/models", params={"pageSize": 100},
                             headers={"x-goog-api-key": settings.GEMINI_API_KEY})
        if r.status_code != 200:
            return None
        names = [m["name"].split("/", 1)[1] for m in r.json().get("models", [])
                 if "generateContent" in m.get("supportedGenerationMethods", [])]
        skip = ("lite", "image", "tts", "live", "audio", "embedding", "thinking")
        flash = sorted(n for n in names if "flash" in n and not any(s in n for s in skip))
        return flash[-1] if flash else None

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

            async with httpx.AsyncClient(timeout=60.0) as client:
                model = _gemini["model"] or settings.GEMINI_MODEL
                r = await self._gemini_call(client, model, body)
                if r.status_code == 404:
                    new_model = await self._discover_model(client)
                    if new_model and new_model != model:
                        log.warning("Gemini model %r unavailable, switching to %r", model, new_model)
                        r = await self._gemini_call(client, new_model, body)
                        model = new_model
                if r.status_code != 200:
                    raise RuntimeError(f"Gemini HTTP {r.status_code}: {r.text[:200]}")
                _gemini["model"] = model
            cand = (r.json().get("candidates") or [{}])[0]
            return "".join(p.get("text", "") for p in cand.get("content", {}).get("parts", []))

        raise RuntimeError("No LLM key configured")


llm = LLM()
