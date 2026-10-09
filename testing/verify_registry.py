"""Opt-in: checks your curated helplines/domains against each brand's OWN website via SerpApi.
Run from the repository root:  python testing/verify_registry.py   (about 1 SerpApi credit per brand)
NOT SEEN means the number was not in the search snippets. It does not prove it is wrong: confirm manually."""

import asyncio
import argparse
import html
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.utils import local_digits, registered_domain
from app.services.brand_directory import BRAND_DIRECTORY
from app.services.brand_resolver import extract_numbers
from app.services.serpapi_service import serpapi_service

for n in ("httpx", "httpcore"):
    logging.getLogger(n).setLevel(logging.WARNING)


def number_is_present(text: str, number: str) -> bool:
    normalized = local_digits(number)
    if not normalized:
        return False
    pattern = r"\D*".join(re.escape(digit) for digit in normalized)
    return re.search(rf"(?<!\d){pattern}(?!\d)", text) is not None


def page_text(response_text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", response_text)))


async def fetch_official_pages(rows: Iterable[Dict[str, Any]]) -> List[str]:
    contents = []
    urls = list(dict.fromkeys(row.get("link", "") for row in rows if row.get("link")))[:3]
    async with httpx.AsyncClient(
        timeout=12.0,
        follow_redirects=True,
        headers={"User-Agent": "ScamShield registry verification/1.0"},
    ) as client:
        for url in urls:
            try:
                response = await client.get(url)
                print(f"  HTTP {response.status_code}  {url}")
                contents.append(page_text(response.text))
            except httpx.HTTPError as exc:
                print(f"  HTTP ERROR ({type(exc).__name__})  {url}")
    return contents


async def check(profile, fetch_pages: bool = False, diagnose: bool = False) -> None:
    own = {registered_domain(d) for d in profile.official_domains}
    query = f'"{profile.display_name}" customer care toll free helpline contact number'
    data = await serpapi_service.raw({"engine": "google", "q": query, "num": 10})
    rows = [r for r in data.get("organic_results", []) if registered_domain(r.get("link", "")) in own]
    all_rows = data.get("organic_results", [])
    if diagnose:
        print(f"\nDiagnostic search for {profile.display_name}: query={query!r}")
        print("Raw search result URLs:")
        for row in all_rows:
            print(f"  {row.get('link', '(missing URL)')}")
        if not all_rows:
            print("  No search results returned.")
        print("Direct HTTP status for official-domain results:")

    texts = [f"{r.get('title', '')} {r.get('snippet', '')}" for r in rows]
    pages_fetched = fetch_pages or diagnose
    if pages_fetched:
        texts.extend(await fetch_official_pages(rows))
    combined_text = "\n".join(texts)
    seen = set()
    for text in texts:
        seen |= extract_numbers(text)
    print(f"\n{profile.display_name}: {len(rows)} result(s) from its own domains "
          f"({'domains look right' if rows else 'NO results from these domains: check domain list'})")
    source = "official-domain result/page" if pages_fetched else "official-domain search result"
    for h in profile.official_helplines:
        found = number_is_present(combined_text, h) or local_digits(h) in seen
        status = f"SEEN in {source} (confirm manually)" if found else "NOT SEEN (confirm manually)"
        print(f"  {h:>14}  {status}")
    extra = sorted(seen - {local_digits(h) for h in profile.official_helplines})
    if extra:
        print(f"  also on official site, not in your list: {', '.join(extra)}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Check curated helplines against official-site search results.")
    parser.add_argument("--diagnose", metavar="BRAND", help="print raw URLs and HTTP statuses for one brand")
    parser.add_argument("--fetch-pages", action="store_true", help="fetch up to three official result pages per brand")
    args = parser.parse_args()
    if not serpapi_service.enabled:
        print("SERPAPI_API_KEY is not set.")
        return
    if args.diagnose:
        profile = BRAND_DIRECTORY.get(args.diagnose.lower())
        if not profile:
            known = ", ".join(BRAND_DIRECTORY)
            parser.error(f"unknown brand {args.diagnose!r}; choose one of: {known}")
        await check(profile, fetch_pages=True, diagnose=True)
        return
    for p in BRAND_DIRECTORY.values():
        await check(p, fetch_pages=args.fetch_pages)
    print("\nRemove or fix every number you cannot confirm on the brand's own website or app.")


if __name__ == "__main__":
    asyncio.run(main())