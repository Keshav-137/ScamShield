"""app/services/brand_resolver.py — Discover any brand's official domain/helplines from live search consensus."""

import asyncio
import logging
import re
from collections import Counter, defaultdict
from typing import Dict, Optional, Set

from app.core.utils import extract, local_digits, registered_domain
from app.services.brand_directory import OfficialBrandProfile, lookup_brand, register_profile
from app.services.serpapi_service import serpapi_service

log = logging.getLogger("scamshield.resolver")

GENERIC = re.compile(
    r"\b(customer|care|helpline|help|line|number|numbers|toll|free|contact|support|phone|email|mail|"
    r"official|website|site|complaint|service|call|centre|center|no|of|the|for|in|india)\b")
AGGREGATORS = {"justdial.com", "wikipedia.org", "facebook.com", "instagram.com", "youtube.com", "linkedin.com",
               "twitter.com", "x.com", "quora.com", "reddit.com", "indiacustomercare.com", "pissedconsumer.com",
               "truecaller.com", "mouthshut.com", "glassdoor.co.in", "ambitionbox.com", "play.google.com",
               "apps.apple.com", "sulekha.com", "indiamart.com", "cambridge.org", "dictionary.com",
               "merriam-webster.com", "britannica.com", "crunchbase.com", "naukri.com", "indeed.com",
               "wikidata.org", "yelp.com", "tripadvisor.in", "medium.com"}
BLOCKED_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".edu", ".ac.in", ".edu.in")
PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{6,18}\d")


def extract_brand_name(text: str) -> str:
    t = re.sub(r"[^a-z0-9 ]", " ", GENERIC.sub(" ", (text or "").lower()))
    return " ".join(t.split())[:40]


def extract_numbers(text: str) -> Set[str]:
    out = set()
    for m in PHONE_RE.findall(text or ""):
        d = local_digits(m)
        if 8 <= len(d) <= 11 and not re.fullmatch(r"(?:19|20)\d{2}(?:19|20)\d{2}", d):
            out.add(d)
    return out


class BrandResolver:
    def __init__(self):
        self._cache: Dict[str, Optional[OfficialBrandProfile]] = {}

    async def resolve(self, text: Optional[str]) -> Optional[OfficialBrandProfile]:
        name = extract_brand_name(text or "")
        if len(name) < 3:
            return None
        known = lookup_brand(name)
        if known:
            return known
        if name in self._cache:
            return self._cache[name]
        before = serpapi_service.failures
        try:
            profile = await self._discover(name)
        except Exception as exc:
            log.warning("Brand discovery crashed for %r: %r", name, exc)
            return None
        if profile or serpapi_service.failures == before:  # never cache a result caused by timeouts
            self._cache[name] = profile
        return profile

    async def _discover(self, name: str) -> Optional[OfficialBrandProfile]:
        q = f"{name} official website"
        g, b, m = await asyncio.gather(
            serpapi_service.raw({"engine": "google", "q": q, "num": 8}),
            serpapi_service.raw({"engine": "bing", "q": q, "cc": "IN"}, localize=False),
            serpapi_service.raw({"engine": "google_maps", "q": f"{name} head office", "type": "search"}))
        kg = g.get("knowledge_graph") or {}

        votes: Counter = Counter()
        surfaces = defaultdict(set)

        def vote(url: Optional[str], surface: str, weight: int = 1) -> None:
            d = registered_domain(url or "")
            if d and d not in AGGREGATORS and not d.endswith(BLOCKED_SUFFIXES):
                votes[d] += weight
                surfaces[d].add(surface)

        if kg.get("website"):
            vote(kg["website"], "knowledge_graph", 2)
        for r in g.get("organic_results", [])[:3]:
            vote(r.get("link"), "google")
        for r in b.get("organic_results", [])[:3]:
            vote(r.get("link"), "bing")
        for p in (m.get("local_results") or [])[:3]:
            vote(p.get("website"), "maps")

        compact = name.replace(" ", "")

        def name_matches(domain: str) -> bool:
            label = extract(domain).domain.lower()
            return label == compact or (len(compact) >= 4 and (
                compact in label or (len(label) >= 4 and label in compact)))

        domain = None
        for d, _ in votes.most_common():
            n = len(surfaces[d])
            if (name_matches(d) and n >= 2) or n >= 3 or ("knowledge_graph" in surfaces[d] and name_matches(d)):
                domain = d
                break
        log.info("Brand discovery %r -> %s (votes=%s, surfaces=%s)", name, domain, dict(votes),
                 {k: sorted(v) for k, v in surfaces.items()})
        if not domain:
            return None

        s = await serpapi_service.raw({"engine": "google", "q": f"site:{domain} customer care toll free number", "num": 8})
        nums: Set[str] = set()
        for r in s.get("organic_results", []):
            if registered_domain(r.get("link", "")) == domain:
                nums |= extract_numbers(f"{r.get('title', '')} {r.get('snippet', '')}")
        for k, v in kg.items():
            if isinstance(v, str) and ("phone" in k or "customer" in k):
                nums |= extract_numbers(v)

        title = kg.get("title") or name.title()
        profile = OfficialBrandProfile(
            brand_id=re.sub(r"\W+", "-", name), display_name=title,
            aliases=sorted({name, title.lower(), compact}), official_domains=[domain],
            official_helplines=sorted(nums), official_upi_handles=[],
            notes=f"Discovered live via {len(surfaces[domain])} search surface(s): {', '.join(sorted(surfaces[domain]))}. Not manually curated.",
            source="discovered")
        register_profile(profile)
        return profile


brand_resolver = BrandResolver()