"""Discover candidate brand profiles from SerpApi search and Maps results."""

import asyncio
import logging
import re
from collections import Counter
from typing import Dict, Optional, Set

from app.core.utils import local_digits, registered_domain
from app.services.brand_directory import (
    OfficialBrandProfile,
    lookup_brand,
    register_profile,
)
from app.services.serpapi_service import serpapi_service

log = logging.getLogger("scamshield.brand_resolver")

GENERIC = re.compile(
    r"\b(customer|care|helpline|help|line|number|numbers|toll|free|contact|"
    r"support|phone|email|mail|official|website|site|complaint|service|call|"
    r"centre|center|no|of|the|for|in|india)\b",
    re.IGNORECASE,
)
AGGREGATORS = {
    "justdial.com", "wikipedia.org", "facebook.com", "instagram.com",
    "youtube.com", "linkedin.com", "twitter.com", "x.com", "quora.com",
    "reddit.com", "indiacustomercare.com", "pissedconsumer.com",
    "truecaller.com", "mouthshut.com", "glassdoor.co.in",
    "ambitionbox.com", "play.google.com", "apps.apple.com",
    "sulekha.com", "indiamart.com",
}
AGGREGATOR_DOMAINS = {registered_domain(domain) for domain in AGGREGATORS}
PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{6,18}\d")


def extract_brand_name(text: str) -> str:
    cleaned = GENERIC.sub(" ", text.lower())
    cleaned = re.sub(r"[^a-z0-9 ]", " ", cleaned)
    return " ".join(cleaned.split())[:40]


def extract_numbers(text: str) -> Set[str]:
    numbers = set()
    for match in PHONE_RE.findall(text or ""):
        digits = local_digits(match)
        if 8 <= len(digits) <= 11 and not re.fullmatch(
            r"(?:19|20)\d{2}(?:19|20)\d{2}", digits
        ):
            numbers.add(digits)
    return numbers


class BrandResolver:
    def __init__(self) -> None:
        self._cache: Dict[str, Optional[OfficialBrandProfile]] = {}
        self._inflight: Dict[str, asyncio.Task[Optional[OfficialBrandProfile]]] = {}

    async def resolve(self, text: Optional[str]) -> Optional[OfficialBrandProfile]:
        name = extract_brand_name(text or "")
        if len(name) < 3:
            return None
        known = lookup_brand(name)
        if known:
            return known
        if name not in self._cache:
            task = self._inflight.get(name)
            if task is None:
                task = asyncio.create_task(self._discover(name))
                self._inflight[name] = task
            try:
                self._cache[name] = await task
            finally:
                self._inflight.pop(name, None)
        return self._cache[name]

    async def _discover(self, name: str) -> Optional[OfficialBrandProfile]:
        search_data, maps_data = await asyncio.gather(
            serpapi_service.raw(
                {"engine": "google", "q": f"{name} official website", "num": 5}
            ),
            serpapi_service.raw(
                {"engine": "google_maps", "q": f"{name} head office", "type": "search"}
            ),
        )
        knowledge_graph = search_data.get("knowledge_graph") or {}

        votes: Counter[str] = Counter()
        website = knowledge_graph.get("website")
        if website:
            domain = registered_domain(website)
            if domain:
                votes[domain] += 2
        for result in search_data.get("organic_results", [])[:3]:
            domain = registered_domain(result.get("link", ""))
            if domain:
                votes[domain] += 1
        for place in (maps_data.get("local_results") or [])[:2]:
            if place.get("website"):
                domain = registered_domain(place["website"])
                if domain:
                    votes[domain] += 1

        for domain in list(votes):
            if domain in AGGREGATOR_DOMAINS:
                del votes[domain]
        if not votes:
            return None
        domain, consensus_score = votes.most_common(1)[0]
        if consensus_score < 3:
            return None

        search_data = await serpapi_service.raw(
            {
                "engine": "google",
                "q": f"site:{domain} customer care toll free number",
                "num": 8,
            }
        )
        helplines: Set[str] = set()
        for result in search_data.get("organic_results", []):
            if registered_domain(result.get("link", "")) == domain:
                helplines.update(
                    extract_numbers(
                        f"{result.get('title', '')} {result.get('snippet', '')}"
                    )
                )
        for key, value in knowledge_graph.items():
            if isinstance(value, str) and ("phone" in key.lower() or "customer" in key.lower()):
                helplines.update(extract_numbers(value))

        title = knowledge_graph.get("title") or name.title()
        profile = OfficialBrandProfile(
            brand_id=re.sub(r"\W+", "-", name),
            display_name=title,
            aliases=sorted({name, title.lower()}),
            official_domains=[domain],
            official_helplines=sorted(helplines),
            official_upi_handles=[],
            notes=(
                "Candidate profile discovered from SerpApi search and Maps consensus; "
                "details require independent verification."
            ),
            source="discovered",
        )
        register_profile(profile)
        log.info("Discovered candidate brand profile for %s from domain %s", name, domain)
        return profile


brand_resolver = BrandResolver()
