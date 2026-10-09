"""Opt-in SerpApi checks (costs credits). Run from the repository root:  python testing/live_checks.py
Each request is sent once, no retries. Discovery checks are SOFT (live Google data varies)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from app.main import app
from app.services.serpapi_service import serpapi_service


def sig(r) -> set:
    return {s["signal_name"] for s in r["signals"]}


# (label, body, predicate on report, soft?)
INVESTIGATIONS = [
    ("SBI helpline", {"query": "1800 1234", "claimed_brand": "SBI"},
     lambda r: r["risk_level"] == "LOW" and "OFFICIAL_SOURCE_MATCH" in sig(r), False),
    ("SBI phone mismatch", {"query": "9876543210", "claimed_brand": "SBI"},
     lambda r: "OFFICIAL_SOURCE_MISMATCH" in sig(r) and r["risk_score"] >= 40, False),
    ("SBI lookalike", {"query": "sbi-helpline-support.xyz"},
     lambda r: "LOOKALIKE_DOMAIN_DETECTED" in sig(r) and r["risk_score"] >= 70, False),
    ("HDFC TLD swap", {"query": "hdfcbank.net", "claimed_brand": "HDFC Bank"},
     lambda r: "LOOKALIKE_DOMAIN_DETECTED" in sig(r) and r["risk_score"] >= 50, False),
    ("SBI official domain", {"query": "bank.sbi"},
     lambda r: r["risk_level"] == "LOW" and "OFFICIAL_SOURCE_MATCH" in sig(r), False),
    ("SBI UPI mismatch", {"query": "sbi.care@okaxis"},
     lambda r: "OFFICIAL_SOURCE_MISMATCH" in sig(r), False),
    ("Unverified UPI", {"query": "support@okaxis"},
     lambda r: "OFFICIAL_SOURCE_MISMATCH" not in sig(r) and "UNVERIFIED_CONTACT" in sig(r), False),
    ("SBI brand search", {"query": "SBI customer care helpline"},
     lambda r: "OFFICIAL_SOURCE_MISMATCH" not in sig(r) and r["official_contacts"] is not None, False),
    ("Discover Flipkart", {"query": "Flipkart customer care number"},
     lambda r: (r["official_contacts"] or {}).get("source") == "discovered", True),
    ("Discover Zomato", {"query": "Zomato customer care number"},
     lambda r: (r["official_contacts"] or {}).get("source") == "discovered", True),
]

MESSAGES = [
    ("SBI KYC alert",
     {"message": "Dear SBI user, your YONO account will be blocked today. "
                 "Update KYC now: http://sbi-kyc-update.xyz or call 9876543210", "language": "en"},
     lambda r: r["overall_risk_score"] >= 70 and len(r["reports"]) >= 2, False),
    ("Amazon delivery",
     {"message": "Hi, your Amazon order is out for delivery today. Track: "
                 "https://www.amazon.in/gp/your-account/order-history", "language": "en"},
     lambda r: r["overall_risk_level"] == "LOW", False),
]


def verdict(ok: bool, soft: bool) -> str:
    return "PASS" if ok else ("WARN" if soft else "FAIL")


def main() -> int:
    if not serpapi_service.api_key:
        print("SERPAPI_API_KEY is not configured; live checks were not run.")
        return 2
    for name in ("httpx", "httpcore"):  # request URLs contain the API key
        logging.getLogger(name).setLevel(logging.WARNING)

    fails = 0
    print("Live checks: SerpApi enabled, no retries.")
    with TestClient(app) as client:
        for label, body, check, soft in INVESTIGATIONS + MESSAGES:
            is_msg = "message" in body
            url = "/api/v1/analyze-message" if is_msg else "/api/v1/investigate"
            try:
                resp = client.post(url, json=body)
                if resp.status_code != 200:
                    print(f"[FAIL] {label}: HTTP {resp.status_code}: {resp.text[:200]}")
                    fails += 1
                    continue
                data = resp.json()
                v = verdict(check(data), soft)
                fails += v == "FAIL"
                if is_msg:
                    detail = (f"{data['overall_risk_level']} ({data['overall_risk_score']}), "
                              f"scam_type={data['scam_type']}, reports={len(data['reports'])}")
                else:
                    detail = f"{data['risk_level']} ({data['risk_score']}), signals={sorted(sig(data))}"
                    if data.get("warnings"):
                        detail += f", warnings={data['warnings']}"
                print(f"[{v}] {label}: {detail}")
            except Exception as exc:
                print(f"[FAIL] {label}: {type(exc).__name__}: {exc}")
                fails += 1
    print(f"\n{fails} hard failure(s).")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())