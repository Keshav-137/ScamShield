# ScamShield test results

These checks were run against the current checkout without editing production
files. Run the zero-credit checks with `python testing\offline_checks.py`;
run the external API checks with `python testing\live_checks.py`. The live
checks use SerpApi and can consume account credits.

## Offline checks

**Result:** 4 of 6 test methods passed; 4 assertions failed in 2 methods.

Passed:

- All six sample classifier inputs returned their expected input types.
- Official SBI phone/domain checks returned the expected match results.
- The SBI-vs-`okaxis` UPI mismatch was reported.
- API validation returned HTTP 422 for a too-short query and a message with no
  phone/link/UPI identifier.
- With the SerpApi key disabled in-process, the API returned its missing-key
  warning without making a network request.

Expected-behavior failures:

| Check | Expected | Actual |
|---|---|---|
| `support@sbi` | Consistent official handle / unverifiable (`None`) | `OFFICIAL_SOURCE_MISMATCH` |
| `sbi.secure-login.com` | Lookalike, penalty 35 | Not flagged |
| `hdfcbank.net` with brand `hdfc` | Lookalike, penalty 30 | Not flagged |
| `hdfcbank.net` without a brand | Not flagged, penalty 0 | Flagged, penalty 25 |

## Live checks

All 10 investigation requests and both message-analysis requests returned
HTTP 200. Live search results can change over time.

| Input | Result | Signal / observation |
|---|---|---|
| `1800 1234` (SBI) | LOW, 0 | `OFFICIAL_SOURCE_MATCH` |
| `9876543210` (SBI) | HIGH, 50 | `OFFICIAL_SOURCE_MISMATCH`, `THIRD_PARTY_LISTING` |
| `sbi-helpline-support.xyz` | CRITICAL, 75 | `LOOKALIKE_DOMAIN_DETECTED`, mismatch |
| `hdfcbank.net` (HDFC Bank) | HIGH, 55 | Mismatch and `PUBLIC_SCAM_REPORT_FOUND`; no lookalike signal |
| `bank.sbi` | LOW, 0 | `OFFICIAL_SOURCE_MATCH` |
| `sbi.care@okaxis` | MEDIUM, 40 | `OFFICIAL_SOURCE_MISMATCH` |
| `support@okaxis` | MEDIUM, 25 | `UNVERIFIED_CONTACT` |
| SBI customer-care search | LOW, 15 | No mismatch signal; curated contacts returned |
| Flipkart customer-care search | LOW, 15 | Contacts were not returned with source `discovered` |
| Zomato customer-care search | LOW, 15 | Contacts returned with source `discovered` |
| SBI KYC message | CRITICAL, 75 | Two reports extracted; phone MEDIUM 25 and URL CRITICAL 75 |
| Amazon delivery message | LOW, 0 | One report; Amazon URL verified LOW |

Anthropic is not configured in this environment. Consequently, the live message
test returned `scam_type=UNKNOWN` and no tactics, and responses warned that the
built-in template explanation was used. One evidence-search task timed out
during the Zomato request; the API still returned a report.

The supplied sample's stated cache behavior was not assumed by these checks;
each live request was sent once. Each investigation can trigger multiple
SerpApi searches; account credit usage was not queried. The live runner now
suppresses HTTP client logs because their request URLs contain the API key.
