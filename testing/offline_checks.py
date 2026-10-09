"""Zero-credit checks. Run from the repository root:  python testing/offline_checks.py"""

from __future__ import annotations

import sys
import unittest
from unittest.mock import AsyncMock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from app.core.classifier import classify_input
from app.core.lookalike import evaluate_domain_similarity
from app.core.normalizer import normalize_input
from app.core.scoring import calculate_risk_score
from app.models.schemas import EvidenceItem, EvidenceSourceType, InputType, Language, RiskLevel
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

    def test_registry_matching_accepts_formatted_numbers_and_bounds_short_codes(self) -> None:
        from testing.verify_registry import number_is_present

        self.assertTrue(number_is_present("Contact us: 1800-425-3800", "18004253800"))
        self.assertTrue(number_is_present("Call us at 1800 1234", "18001234"))
        self.assertTrue(number_is_present("Airtel support: (121)", "121"))
        self.assertFalse(number_is_present("Reference 91210 is unrelated", "121"))

    def test_live_brand_verification_uses_only_official_domain_results(self) -> None:
        import asyncio
        from unittest.mock import patch

        from app.services.brand_resolver import brand_resolver

        profile = lookup_brand("SBI").model_copy(deep=True)
        original_key = serpapi_service.api_key
        serpapi_service.api_key = "test-key"
        response = {
            "organic_results": [
                {"link": "https://www.sbi.co.in/web/customer-care", "title": "SBI contact",
                 "snippet": "Call 1800 1234 for support."},
                {"link": "https://fake-example.com/sbi", "title": "SBI number",
                 "snippet": "Call 1800 2100."},
            ]
        }
        try:
            with patch.object(serpapi_service, "raw", new=AsyncMock(return_value=response)):
                asyncio.run(brand_resolver.live_verify(profile))
        finally:
            serpapi_service.api_key = original_key

        self.assertTrue(profile.live_checked)
        self.assertEqual(profile.live_helplines, ["18001234"])

    def test_known_brand_investigation_returns_contacts_without_attribute_error(self) -> None:
        import json
        from unittest.mock import patch

        from app.main import app
        from app.services.brand_resolver import brand_resolver
        from app.services.claude_service import claude_service
        from app.services.stats_service import stats_service

        async def empty_results(*args, **kwargs):
            return []

        original_key = serpapi_service.api_key
        serpapi_service.api_key = ""
        try:
            with patch.object(brand_resolver, "live_verify", new=AsyncMock()), \
                    patch.object(serpapi_service, "search_google", new=AsyncMock(side_effect=empty_results)), \
                    patch.object(serpapi_service, "search_google_news", new=AsyncMock(side_effect=empty_results)), \
                    patch.object(serpapi_service, "search_google_maps", new=AsyncMock(side_effect=empty_results)), \
                    patch.object(claude_service, "generate_explanation", new=AsyncMock(return_value={
                        "summary": "Offline test report.", "what_was_checked": [],
                        "risk_factors": [], "unverified_points": [], "recommended_actions": [],
                    })), \
                    patch.object(stats_service, "record"):
                with TestClient(app) as client:
                    response = client.post(
                        "/api/v1/investigate/stream",
                        json={"query": "SBI customer care", "language": "en"},
                    )
        finally:
            serpapi_service.api_key = original_key

        self.assertEqual(response.status_code, 200)
        events = [
            json.loads(frame.removeprefix("data: "))
            for frame in response.text.split("\n\n")
            if frame.startswith("data: ")
        ]
        result = next((event["data"] for event in events if event["type"] == "result"), None)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result["official_contacts"])
        self.assertFalse(result["official_contacts"]["live_checked"])

    def test_image_analysis_sends_image_and_returns_description_and_transcription(self) -> None:
        import asyncio
        from types import SimpleNamespace

        from app.services.claude_service import claude_service

        original_client = claude_service.client
        fake_client = SimpleNamespace(complete=AsyncMock(return_value=(
            '{"image_description":"A screenshot of a text message.","transcription":"Update KYC now."}'
        )))
        claude_service.client = fake_client
        try:
            result = asyncio.run(claude_service.analyze_image(b"image-bytes", "image/png"))
        finally:
            claude_service.client = original_client

        self.assertEqual(result["image_description"], "A screenshot of a text message.")
        self.assertEqual(result["transcription"], "Update KYC now.")
        self.assertEqual(fake_client.complete.call_args.kwargs["image"], (b"image-bytes", "image/png"))
        self.assertTrue(fake_client.complete.call_args.kwargs["json_mode"])

    def test_gemini_quota_error_is_explained_to_screenshot_user(self) -> None:
        import asyncio
        from fastapi import HTTPException
        from app.main import analyze_image
        from app.services.claude_service import claude_service

        original = claude_service.analyze_image
        claude_service.analyze_image = AsyncMock(side_effect=RuntimeError("Gemini HTTP 429: quota exceeded"))
        try:
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(analyze_image(b"image-bytes", "image/png", Language.EN))
        finally:
            claude_service.analyze_image = original

        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn("quota", raised.exception.detail.lower())

    def test_gemini_429_retries_once_with_flash_model(self) -> None:
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import patch

        from app.config import settings
        from app.services.llm_service import LLM, _gemini

        response = SimpleNamespace(
            status_code=200,
            json=lambda: {"candidates": [{"content": {"parts": [{"text": "image result"}]}}]},
        )
        llm = LLM()
        llm.anthropic = None
        call = AsyncMock(side_effect=[
            SimpleNamespace(status_code=429, text="quota exceeded"),
            response,
        ])
        with patch.object(settings, "GEMINI_API_KEY", "test-key"), \
                patch.object(settings, "GEMINI_MODEL", "gemini-heavy-model"), \
                patch.object(LLM, "_gemini_call", new=call), \
                patch.dict(_gemini, {"model": None}):
            result = asyncio.run(llm.complete("", "Describe this image.", image=(b"image", "image/png")))

        self.assertEqual(result, "image result")
        self.assertEqual([entry.args[1] for entry in call.call_args_list],
                         ["gemini-heavy-model", "gemini-2.5-flash"])

    def test_image_without_contact_text_still_returns_description(self) -> None:
        import asyncio
        from unittest.mock import patch

        from fastapi import HTTPException
        from app.main import analyze_image
        from app.services.claude_service import claude_service

        async def no_contacts(*args, **kwargs):
            raise HTTPException(status_code=422, detail="No contact found.")

        with patch.object(
            claude_service, "analyze_image",
            AsyncMock(return_value={
                "image_description": "A screenshot of a suspicious-looking message.",
                "transcription": "Urgent account update required.",
            }),
        ), patch("app.main.analyze_text", side_effect=no_contacts):
            result = asyncio.run(analyze_image(b"image-bytes", "image/png", Language.EN))

        self.assertEqual(result.overall_risk_level.value, "UNKNOWN")
        self.assertEqual(result.image_description, "A screenshot of a suspicious-looking message.")
        self.assertIn("risk was not assessed", result.risk_assessment_note)


if __name__ == "__main__":
    print(f"Offline checks (no network). Repository: {PROJECT_ROOT}")
    unittest.main(verbosity=2)