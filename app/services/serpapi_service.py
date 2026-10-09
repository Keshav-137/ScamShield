"""app/services/serpapi_service.py — SerpApi: Google Search/Maps/News + raw access (Bing etc.)."""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List

import httpx
from app.config import settings
from app.models.schemas import EvidenceItem, EvidenceSourceType

log = logging.getLogger("scamshield.serpapi")


class SerpApiService:
    BASE_URL = "https://serpapi.com/search.json"

    def __init__(self):
        self.api_key = settings.SERPAPI_API_KEY
        self._cache: Dict[str, tuple] = {}
        self.failures = 0  # timeouts / HTTP errors since start

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def _execute_query(self, params: Dict[str, Any], localize: bool = True) -> Dict[str, Any]:
        if not self.enabled:
            return {}
        params = dict(params)
        if localize:
            params.update({"gl": "in", "hl": "en"})

        key = json.dumps(params, sort_keys=True)
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < settings.CACHE_TTL_SECONDS:
            return hit[1]

        engine = params.get("engine")
        timeout = httpx.Timeout(settings.SERPAPI_TIMEOUT, connect=10.0)
        for attempt in (1, 2):
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.get(self.BASE_URL, params={**params, "api_key": self.api_key})
                if resp.status_code != 200:
                    log.warning("SerpApi HTTP %s (engine=%s)", resp.status_code, engine)
                    break  # do not retry HTTP errors
                data = resp.json()
                if data.get("error"):
                    log.info("SerpApi note (engine=%s): %s", engine, data["error"])
                    data = {}
                self._cache[key] = (time.time(), data)
                return data
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                log.warning("SerpApi attempt %d failed (engine=%s): %r", attempt, engine, exc)
                if attempt == 1:
                    await asyncio.sleep(1)
            except Exception as exc:
                log.warning("SerpApi unexpected error (engine=%s): %r", engine, exc)
                break
        self.failures += 1
        return {}

    async def raw(self, params: Dict[str, Any], localize: bool = True) -> Dict[str, Any]:
        return await self._execute_query(params, localize)

    async def search_google(self, query: str, num: int = 6) -> List[EvidenceItem]:
        data = await self._execute_query({"engine": "google", "q": query, "num": num})
        return [
            EvidenceItem(
                source_type=EvidenceSourceType.GOOGLE_SEARCH,
                title=r.get("title", "No title"), snippet=r.get("snippet", ""), url=r.get("link"),
                relevance_notes=f"Search rank: {r.get('position')}",
            )
            for r in data.get("organic_results", [])
        ]

    async def search_google_maps(self, query: str) -> List[EvidenceItem]:
        data = await self._execute_query({"engine": "google_maps", "q": query, "type": "search"})
        places = list(data.get("local_results", []))[:3]
        if not places and isinstance(data.get("place_results"), dict):
            places = [data["place_results"]]
        return [
            EvidenceItem(
                source_type=EvidenceSourceType.GOOGLE_MAPS,
                title=p.get("title", "Unknown place"),
                snippet=f"Phone: {p.get('phone', 'N/A')} | Address: {p.get('address', 'N/A')}",
                url=p.get("website") or p.get("link"),
                relevance_notes=f"Reviews: {p.get('reviews', 0)} | Rating: {p.get('rating', 'N/A')}",
            )
            for p in places
        ]

    async def search_google_news(self, query: str) -> List[EvidenceItem]:
        data = await self._execute_query({"engine": "google_news", "q": f"{query} (scam OR fraud OR complaint OR fake)"})
        out: List[EvidenceItem] = []
        for item in data.get("news_results", []):
            if item.get("stories"):
                item = item["stories"][0]
            src = item.get("source")
            src_name = src.get("name", "") if isinstance(src, dict) else str(src or "")
            out.append(EvidenceItem(
                source_type=EvidenceSourceType.GOOGLE_NEWS,
                title=item.get("title", ""), snippet=item.get("snippet") or src_name,
                url=item.get("link"), timestamp=item.get("date"),
            ))
            if len(out) == 4:
                break
        return out


serpapi_service = SerpApiService()