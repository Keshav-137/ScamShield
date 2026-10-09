"""Opt-in: checks your curated helplines/domains against each brand's OWN website via SerpApi.
Run from the repository root:  python testing/verify_registry.py   (about 1 SerpApi credit per brand)
NOT SEEN means the number was not in the search snippets. It does not prove it is wrong: confirm manually."""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.utils import local_digits, registered_domain
from app.services.brand_directory import BRAND_DIRECTORY
from app.services.brand_resolver import extract_numbers
from app.services.serpapi_service import serpapi_service

for n in ("httpx", "httpcore"):
    logging.getLogger(n).setLevel(logging.WARNING)


async def check(profile) -> None:
    own = {registered_domain(d) for d in profile.official_domains}
    sites = " OR ".join(f"site:{d}" for d in profile.official_domains)
    data = await serpapi_service.raw({"engine": "google", "q": f"({sites}) customer care toll free number", "num": 10})
    rows = [r for r in data.get("organic_results", []) if registered_domain(r.get("link", "")) in own]
    seen = set()
    for r in rows:
        seen |= extract_numbers(f"{r.get('title', '')} {r.get('snippet', '')}")
    print(f"\n{profile.display_name}: {len(rows)} result(s) from its own domains "
          f"({'domains look right' if rows else 'NO results from these domains: check domain list'})")
    for h in profile.official_helplines:
        status = "VERIFIED on official site" if local_digits(h) in seen else "NOT SEEN (confirm manually)"
        print(f"  {h:>14}  {status}")
    extra = sorted(seen - {local_digits(h) for h in profile.official_helplines})
    if extra:
        print(f"  also on official site, not in your list: {', '.join(extra)}")


async def main() -> None:
    if not serpapi_service.enabled:
        print("SERPAPI_API_KEY is not set.")
        return
    for p in BRAND_DIRECTORY.values():
        await check(p)
    print("\nRemove or fix every number you cannot confirm on the brand's own website or app.")


asyncio.run(main())