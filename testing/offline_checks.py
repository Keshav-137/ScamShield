"""Zero-credit checks. Run from the repository root:  python testing/offline_checks.py"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from app.core.classifier import classify_input
from app.core.lookalike import evaluate_domain_similarity
from app.core.normalizer import normalize_input
from app.core.scoring import calculate_risk_score
from app.models.schemas import EvidenceItem, EvidenceSourceType, InputType, RiskLevel
from app.services.brand_directory import lookup_brand
from app.services.claude_service import claude_service
from app.services.official_crawler import official_crawler_service
from app.services.serpapi_service import serpapi_service


def ni_for(query: str, brand: str | None = None):
    return normalize_input(query, classify_input(query), brand)


def signal_names(signals) -> set:
    return {s.signal_name for s in signals}


class OfflineChecks(unittest.TestCase):
    def test_classifier(self) -> None:
        expected = {
            "+91 98765 43210": InputType.PHONE, "1800 1234": InputType.PHONE,
            "support@sbi": InputType.UPI, "sbi.co.in": InputType.URL,
            "SBI customer care": InputType.BRAND_SEARCH, "a@gmail.com": InputType.BRAND_SEARCH,
        }
        for query, kind in expected.items():
            with self.subTest(query=query):
                self.assertEqual(classify_input(query), kind)

    def test_official_verification(self) -> None:
        # True = official match, False = mismatch, None = consistent but unverifiable
        cases = [
            ("18001234", "SBI", True), ("1800 1234", "State Bank of India", True),
            ("+91 1800 1234", "SBI", True), ("9876543210", "SBI", False),
            ("bank.sbi", "SBI", True), ("sbi.bank.in", "SBI", True),
            ("sbi-kyc.xyz", "SBI", False), ("support@sbi", "SBI", None),
            ("sbi.care@okaxis", "SBI", False),
        ]
        for query, brand, expected in cases:
            with self.subTest(query=query):
                result, _ = official_crawler_service.verify(ni_for(query, brand), lookup_brand(brand))
                self.assertIs(result, expected)

    def test_official_helpline_scores_low(self) -> None:
        score, level, _, signals, _ = calculate_risk_score(ni_for("1800 1234", "SBI"), [], lookup_brand("SBI"))
        self.assertEqual(level, RiskLevel.LOW)
        self.assertIn("OFFICIAL_SOURCE_MATCH", signal_names(signals))

    def test_consistent_upi_handle_is_not_mismatch(self) -> None:
        _, _, _, signals, _ = calculate_risk_score(ni_for("support@sbi", "SBI"), [], lookup_brand("SBI"))
        self.assertNotIn("OFFICIAL_SOURCE_MISMATCH", signal_names(signals))

    def test_other_bank_upi_handle_is_mismatch(self) -> None:
        score, _, _, signals, _ = calculate_risk_score(ni_for("sbi.care@okaxis", "SBI"), [], lookup_brand("SBI"))
        self.assertIn("OFFICIAL_SOURCE_MISMATCH", signal_names(signals))
        self.assertGreaterEqual(score, 25)

    def test_brand_search_never_mismatch(self) -> None:
        _, _, _, signals, profile = calculate_risk_score(
            ni_for("SBI customer care helpline"), [], lookup_brand("SBI customer care helpline"))
        self.assertNotIn("OFFICIAL_SOURCE_MISMATCH", signal_names(signals))
        self.assertIsNotNone(profile)

    def test_lookalike_cases(self) -> None:
        cases = [
            ("sbi-helpline-support.xyz", None, True, 35), ("sbi.secure-login.com", None, True, 35),
            ("paytm-kyc.top", None, True, 35), ("amazn.in", None, True, 30),
            ("hdfcbank.net", "hdfc", True, 30), ("hdfcbank.net", None, False, 0),
            ("bank.sbi", None, False, 0), ("sbi.bank.in", None, False, 0),
            ("amazon.in", None, False, 0), ("paytm.com", None, False, 0), ("wikipedia.org", None, False, 0),
        ]
        for domain, brand, flag, penalty in cases:
            with self.subTest(domain=domain, brand=brand):
                got_flag, got_penalty, _ = evaluate_domain_similarity(domain, brand)
                self.assertEqual((got_flag, got_penalty), (flag, penalty))

    def test_restricted_registry_is_trusted(self) -> None:
        self.assertEqual(evaluate_domain_similarity("hdfc.bank.in", "hdfc")[:2], (False, 0))

    def test_review_site_subdomain_is_not_poisoning(self) -> None:
        ev = [EvidenceItem(source_type=EvidenceSourceType.GOOGLE_SEARCH, title="SBI reviews", snippet="",
                           url="https://sbi-bank.pissedconsumer.com/customer-service.html")]
        _, _, _, signals, _ = calculate_risk_score(ni_for("SBI customer care"), ev, lookup_brand("SBI"))
        self.assertNotIn("POISONED_SEARCH_RESULTS", signal_names(signals))

    def test_mobile_number_posing_as_customer_care(self) -> None:
        _, _, _, signals, _ = calculate_risk_score(ni_for("9876543210", "SBI"), [], lookup_brand("SBI"))
        self.assertIn("MOBILE_NUMBER_AS_CUSTOMER_CARE", signal_names(signals))

    def test_threat_feed_hit_raises_score(self) -> None:
        score, _, _, signals, _ = calculate_risk_score(
            ni_for("random-site.xyz"), [], None, None, ["OpenPhish community feed"])
        self.assertGreaterEqual(score, 50)
        self.assertIn("THREAT_FEED_MATCH", signal_names(signals))

    def test_api_validation_and_offline_warning(self) -> None:
        from app.main import app

        original_key, original_client = serpapi_service.api_key, claude_service.client
        serpapi_service.api_key = ""
        claude_service.client = None
        try:
            with TestClient(app) as client:
                self.assertEqual(client.post("/api/v1/investigate", json={"query": "ab"}).status_code, 422)

                r = client.post("/api/v1/analyze-message", json={"message": "Congratulations, you won a prize!!"})
                self.assertEqual(r.status_code, 422)
                self.assertIn("No phone number", r.json()["detail"])

                r = client.post("/api/v1/investigate", json={"query": "Some unfamiliar company customer care"})
                self.assertEqual(r.status_code, 200)
                self.assertTrue(any("SERPAPI_API_KEY is not set" in w for w in r.json()["warnings"]))
        finally:
            serpapi_service.api_key, claude_service.client = original_key, original_client

    def test_live_found_number_counts_as_official(self) -> None:
        profile = lookup_brand("SBI").model_copy(deep=True)
        profile.live_helplines = ["1800999888"]
        result, _ = official_crawler_service.verify(ni_for("1800 999 888", "SBI"), profile)
        self.assertIs(result, True)

    def test_stats_masking(self) -> None:
        from app.services.stats_service import mask
        self.assertTrue(mask("PHONE", "+919876543210").endswith("10"))
        self.assertNotIn("9876", mask("PHONE", "+919876543210"))


if __name__ == "__main__":
    print(f"Offline checks (no network). Repository: {PROJECT_ROOT}")
    unittest.main(verbosity=2)