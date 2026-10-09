"""app/services/serpapi_service.py — SerpApi: Google Search/Maps/News/Forums/Play, Bing, account usage."""

import asyncio
import json
import logging
import time
from datetime import date
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
        self.failures = 0
        self.network_calls = 0
        self.cache_hits = 0
        self.budget_blocked = 0
        self._day = date.today()
        self._day_calls = 0
        self._account = (0.0, {})

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _spend(self) -> bool:
        today = date.today()
        if today != self._day:
            self._day, self._day_calls = today, 0
        if self._day_calls >= settings.DAILY_SEARCH_BUDGET:
            return False
        self._day_calls += 1
        self.network_calls += 1
        return True

    def usage(self) -> Dict[str, Any]:
        return {"network_calls": self.network_calls, "cache_hits": self.cache_hits,
                "searches_today": self._day_calls, "daily_budget": settings.DAILY_SEARCH_BUDGET,
                "budget_blocked": self.budget_blocked, "failures": self.failures}

    async def account(self) -> Dict[str, Any]:
        """Real remaining credits from SerpApi's account endpoint (does not consume a search)."""
        if not self.enabled:
            return {}
        ts, data = self._account
        if data and time.time() - ts < 300:
            return data
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get("https://serpapi.com/account.json", params={"api_key": self.api_key})
            if r.status_code == 200:
                j = r.json()
                data = {k: j.get(k) for k in ("plan_name", "searches_per_month", "plan_searches_left",
                                              "total_searches_left", "this_month_usage", "this_hour_searches")}
                self._account = (time.time(), data)
                return data
        except Exception as exc:
            log.info("SerpApi account lookup failed (%s)", type(exc).__name__)
        return {}

    async def _execute_query(self, params: Dict[str, Any], localize: bool = True) -> Dict[str, Any]:
        if not self.enabled:
            return {}
        params = dict(params)
        if localize:
            params.update({"gl": "in", "hl": "en"})

        key = json.dumps(params, sort_keys=True)
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < settings.CACHE_TTL_SECONDS:
            self.cache_hits += 1
            return hit[1]

        engine = params.get("engine")
        timeout = httpx.Timeout(settings.SERPAPI_TIMEOUT, connect=10.0)
        for attempt in (1, 2):
            if not self._spend():
                self.budget_blocked += 1
                log.warning("Daily SerpApi budget (%s) reached; skipping engine=%s", settings.DAILY_SEARCH_BUDGET, engine)
                return {}
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.get(self.BASE_URL, params={**params, "api_key": self.api_key})
                if resp.status_code != 200:
                    log.warning("SerpApi HTTP %s (engine=%s)", resp.status_code, engine)
                    break
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
            EvidenceItem(source_type=EvidenceSourceType.GOOGLE_SEARCH,
                         title=r.get("title", "No title"), snippet=r.get("snippet", ""), url=r.get("link"),
                         relevance_notes=f"Search rank: {r.get('position')}")
            for r in data.get("organic_results", [])
        ]

    async def search_google_maps(self, query: str) -> List[EvidenceItem]:
        data = await self._execute_query({"engine": "google_maps", "q": query, "type": "search"})
        places = list(data.get("local_results", []))[:3]
        if not places and isinstance(data.get("place_results"), dict):
            places = [data["place_results"]]
        return [
            EvidenceItem(source_type=EvidenceSourceType.GOOGLE_MAPS,
                         title=p.get("title", "Unknown place"),
                         snippet=f"Phone: {p.get('phone', 'N/A')} | Address: {p.get('address', 'N/A')}",
                         url=p.get("website") or p.get("link"),
                         relevance_notes=f"Reviews: {p.get('reviews', 0)} | Rating: {p.get('rating', 'N/A')}")
            for p in places
        ]

    @staticmethod
    def _news_rows(data: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        rows = []
        for item in data.get("news_results", []):
            if item.get("stories"):
                item = item["stories"][0]
            src = item.get("source")
            rows.append({"title": item.get("title", ""), "snippet": item.get("snippet", ""),
                         "link": item.get("link"), "date": item.get("date"),
                         "source": src.get("name", "") if isinstance(src, dict) else str(src or "")})
            if len(rows) == limit:
                break
        return rows

    async def search_google_news(self, query: str) -> List[EvidenceItem]:
        data = await self._execute_query({"engine": "google_news", "q": f"{query} (scam OR fraud OR complaint OR fake)"})
        return [EvidenceItem(source_type=EvidenceSourceType.GOOGLE_NEWS, title=r["title"],
                             snippet=r["snippet"] or r["source"], url=r["link"], timestamp=r["date"])
                for r in self._news_rows(data, 4)]

    async def search_scam_news(self, limit: int = 8) -> List[Dict[str, Any]]:
        """Live scam alerts for the dashboard (cached for CACHE_TTL_SECONDS)."""
        data = await self._execute_query(
            {"engine": "google_news", "q": "UPI fraud OR cyber fraud OR fake customer care scam India"})
        return self._news_rows(data, limit)

    async def search_forums(self, query: str) -> List[EvidenceItem]:
        data = await self._execute_query({"engine": "google_forums", "q": query})
        rows = data.get("organic_results") or data.get("forum_results") or []
        return [EvidenceItem(source_type=EvidenceSourceType.GOOGLE_SEARCH, title=r.get("title", ""),
                             snippet=r.get("snippet", ""), url=r.get("link"), relevance_notes="Forum discussion")
                for r in rows[:4]]

    async def search_play_apps(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        data = await self._execute_query({"engine": "google_play", "q": query, "store": "apps"})
        items: List[Dict[str, Any]] = []
        for section in data.get("organic_results", []):
            rows = section.get("items") or ([section] if section.get("title") else [])
            for it in rows:
                items.append({"title": it.get("title", ""),
                              "developer": it.get("author") or it.get("developer") or it.get("publisher") or "",
                              "link": it.get("link"), "rating": it.get("rating"),
                              "id": it.get("product_id") or it.get("link") or it.get("title")})
        return items[:limit]


serpapi_service = SerpApiService()