"""
app/services/serpapi_service.py
SerpApi integrations across Google Search, Google Maps, and Google News.
"""

import httpx
from typing import List, Dict, Any
from app.config import settings
from app.models.schemas import EvidenceItem, EvidenceSourceType


class SerpApiService:
    BASE_URL = "https://serpapi.com/search.json"

    def __init__(self):
        self.api_key = settings.SERPAPI_API_KEY

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def _execute_query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_key:
            return {}
        request_params = {
            **params,
            "api_key": self.api_key,
            "gl": "in",
            "hl": "en",
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self.BASE_URL, params=request_params)
            resp.raise_for_status()
            return resp.json()

    async def raw(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Return raw SerpApi JSON for discovery and structured result parsing."""
        return await self._execute_query(params)

    async def search_google(self, query: str, num: int = 5) -> List[EvidenceItem]:
        params = {"engine": "google", "q": query, "num": num}
        data = await self._execute_query(params)
        evidence = []
        for result in data.get("organic_results", []):
            evidence.append(EvidenceItem(
                source_type=EvidenceSourceType.GOOGLE_SEARCH,
                title=result.get("title", "No Title"),
                snippet=result.get("snippet", ""),
                url=result.get("link"),
                relevance_notes=f"Search rank: {result.get('position')}"
            ))
        return evidence

    async def search_google_maps(self, query: str) -> List[EvidenceItem]:
        params = {"engine": "google_maps", "q": query, "type": "search"}
        data = await self._execute_query(params)
        evidence = []
        for place in data.get("local_results", [])[:3]:
            evidence.append(EvidenceItem(
                source_type=EvidenceSourceType.GOOGLE_MAPS,
                title=place.get("title", "Unknown Place"),
                snippet=f"Phone: {place.get('phone', 'N/A')} | Address: {place.get('address', 'N/A')}",
                url=place.get("link"),
                relevance_notes=f"Reviews: {place.get('reviews', 0)} | Rating: {place.get('rating', 'N/A')}"
            ))
        return evidence

    async def search_google_news(self, query: str) -> List[EvidenceItem]:
        # Formulate fraud-focused search
        scam_query = f"{query} scam OR fraud OR complaint OR fake"
        params = {"engine": "google_news", "q": scam_query}
        data = await self._execute_query(params)
        evidence = []
        for item in data.get("news_results", [])[:3]:
            evidence.append(EvidenceItem(
                source_type=EvidenceSourceType.GOOGLE_NEWS,
                title=item.get("title", ""),
                snippet=item.get("snippet", "") or item.get("source", {}).get("name", ""),
                url=item.get("link"),
                timestamp=item.get("date")
            ))
        return evidence


serpapi_service = SerpApiService()