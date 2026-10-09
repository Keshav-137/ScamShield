"""app/services/domain_intel.py — Free threat intel: RDAP domain age, OpenPhish feed, Google Safe Browsing."""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from app.config import settings

log = logging.getLogger("scamshield.intel")

OPENPHISH_FEED = "https://openphish.com/feed.txt"
_feed = {"ts": 0.0, "hosts": set()}


async def domain_age_days(domain: str) -> Optional[int]:
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}")
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception as exc:
        log.info("RDAP lookup failed for %s: %r", domain, exc)
    return None


async def openphish_hit(host: str) -> bool:
    if not _feed["ts"] or time.time() - _feed["ts"] > 3600:
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                r = await client.get(OPENPHISH_FEED)
            if r.status_code == 200:
                _feed["hosts"] = {urlparse(u.strip()).netloc.lower().split(":")[0]
                                  for u in r.text.splitlines() if u.startswith("http")}
                _feed["ts"] = time.time()
        except Exception as exc:
            log.info("OpenPhish feed unavailable: %r", exc)
        if not _feed["ts"] or time.time() - _feed["ts"] > 3600:
            _feed["ts"] = time.time() - 3300  # retry in ~5 minutes
    return host.lower() in _feed["hosts"]


async def safe_browsing(urls: List[str]) -> List[str]:
    if not settings.SAFE_BROWSING_API_KEY or not urls:
        return []
    body = {
        "client": {"clientId": "scamshield-india", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]},
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                  params={"key": settings.SAFE_BROWSING_API_KEY}, json=body)
        if r.status_code == 200:
            return sorted({m.get("threatType", "UNKNOWN") for m in r.json().get("matches", [])})
        log.info("Safe Browsing HTTP %s", r.status_code)
    except Exception as exc:
        log.info("Safe Browsing failed: %r", exc)
    return []


async def inspect_domain(host: str, domain: str) -> Tuple[Optional[int], List[str]]:
    """Returns (domain_age_days, threat_hits)."""
    age, feed, sb = await asyncio.gather(
        domain_age_days(domain), openphish_hit(host),
        safe_browsing([f"http://{host}/", f"https://{host}/"]), return_exceptions=True)
    hits: List[str] = []
    if feed is True:
        hits.append("OpenPhish community feed")
    if isinstance(sb, list) and sb:
        hits.append(f"Google Safe Browsing: {', '.join(sb)}")
    return (age if isinstance(age, int) else None), hits