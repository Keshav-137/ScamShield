"""Domain registration-age lookup using the public RDAP endpoint."""

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

log = logging.getLogger("scamshield.rdap")


async def domain_age_days(domain: str) -> Optional[int]:
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            response = await client.get(f"https://rdap.org/domain/{domain}")
            response.raise_for_status()
            events = response.json().get("events", [])
    except (httpx.HTTPError, ValueError) as exc:
        log.info("RDAP lookup failed for %s: %s", domain, exc)
        return None

    for event in events:
        if event.get("eventAction") != "registration":
            continue
        try:
            registered_at = datetime.fromisoformat(
                event["eventDate"].replace("Z", "+00:00")
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.info("RDAP registration date invalid for %s: %s", domain, exc)
            continue
        if registered_at.tzinfo is None:
            registered_at = registered_at.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - registered_at).days)
    return None
