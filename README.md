# ScamShield India

ScamShield India is a web application and JSON API for assessing suspicious Indian contact details and messages. It checks phone numbers, UPI IDs, URLs, pasted messages, screenshots, and app names against a local brand registry, deterministic risk rules, and optional live search and threat-intelligence services.

ScamShield is an investigative aid, not a fraud authority. Its scores are heuristic risk indicators, not probabilities or proof that a contact is safe or fraudulent. Search results and third-party reports may be incomplete or wrong; always verify contact details through the organization’s official app or website.

## Features

- **Contact investigation:** submit a phone number, UPI ID, URL/domain, or general brand/customer-care search.
- **Brand and contact checks:** compare inputs with curated domains, helplines, verified helplines, and UPI handles. Unknown brands can be discovered from search-result consensus when search credentials are configured.
- **Evidence search:** optional SerpApi searches for Google Search, Google News, Google Maps, forums, and Google Play results.
- **URL checks:** lookalike-domain rules plus registration-age lookup through RDAP; optional OpenPhish, Google Safe Browsing, and VirusTotal checks.
- **Message analysis:** identify phone numbers, links, and UPI IDs in pasted text, classify common scam themes and pressure tactics, and investigate up to three extracted contacts.
- **Screenshot analysis:** send an uploaded image to the configured AI provider for a short image description and text transcription, then investigate any contacts found in the transcription. Supported uploads are PNG, JPEG, and WEBP, up to 5 MB.
- **Possible fake-app check:** search Google Play results and flag some likely copies using app titles and developer names.
- **Progressive UI:** streamed progress updates for investigation, message analysis, and screenshot analysis.
- **Dashboard:** local usage counters, recent checks, provider status, SerpApi usage, and live scam-news results.
- **English, Hindi, and Marathi report language selection.**

## Technology stack

| Area | Technology |
| --- | --- |
| Backend/API | Python, FastAPI, Pydantic v2, Pydantic Settings |
| ASGI server | Uvicorn |
| Browser UI | Plain HTML, CSS, and JavaScript; no frontend framework or build step |
| Validation and data contracts | Pydantic request/response models |
| HTTP integrations | HTTPX |
| Phone parsing/intelligence | `phonenumbers` |
| Domain parsing | `tldextract`, with an offline suffix snapshot and extra Indian financial suffixes |
| Language models | Anthropic SDK or Gemini `generateContent` REST API |
| Local persistence | JSON files (`stats.json` and verified-registry data) |
| Tests | Python `unittest` checks, plus opt-in live checks |

Installable Python dependencies are listed in [requirements.txt](./requirements.txt). The repository does not include a frontend package manager or compile step.

## Investigation workflow

For a normal contact investigation, the backend follows this pipeline:

1. **Validate the request.** Pydantic constrains the query length and language.
2. **Classify and normalize.** The input is identified as `PHONE`, `UPI`, `URL`, or `BRAND_SEARCH`. Phone digits and URL domains are normalized for comparison.
3. **Resolve a brand.** The app checks the local registry. For unknown brands it may use search-result consensus to discover a candidate official domain and contact numbers.
4. **Optionally check official-domain search results.** For a known brand, live helpline lookup queries SerpApi with the brand’s registered domains and checks matching result snippets for known helplines. This is not a direct crawl of the brand’s website and does not establish that the number is genuine.
5. **Gather evidence.** Depending on input type, the app requests relevant web, news, Maps, forums, or brand-customer-care search results. URL inputs also trigger domain-age and configured threat-intelligence lookups. Search tasks are gathered concurrently and results are deduplicated by registered domain.
6. **Apply deterministic risk rules.** The scoring code combines the normalized input, brand registry, search evidence, domain age, and threat-feed results.
7. **Explain and return a report.** An enabled AI provider writes an explanation; if no provider is available or explanation generation fails, the app uses a built-in template. The report includes score, risk level, signals, evidence, warnings, and suggested actions.
8. **Record local statistics.** Counters and a capped list of recent checks are written to the configured stats JSON file.

### Message and screenshot workflows

**Messages:** a keyword-based extractor runs first and the optional AI may refine it. The application keeps extracted phones, URLs, and UPI IDs only when they appear verbatim in the original message, then investigates at most three contacts. The overall message score is based on the highest contact score, with a limited addition for detected tactics when the message is not classified as `NOT_SCAM_LIKE`.

**Screenshots:** the image bytes and an instruction prompt are sent together to the configured AI provider. The provider returns a JSON image description and a transcription. ScamShield investigates contact identifiers found in the transcription. If no usable phone, URL, or UPI ID is present, the UI can still show the description and transcription, but labels risk as `UNKNOWN` / not assessed. Images are not intentionally written to disk by this application; they are transmitted to the selected provider for analysis.

## Risk score

The rule-based scorer in `app/core/scoring.py` starts at 15 points, applies signal impacts, and clamps the result to 0–100:

| Risk level | Score |
| --- | ---: |
| LOW | 0–24 |
| MEDIUM | 25–49 |
| HIGH | 50–69 |
| CRITICAL | 70–100 |

Examples of implemented signal behavior:

- A contact matching a known official entry subtracts 30 points.
- A mismatch against a claimed curated brand generally adds 25; a discovered profile mismatch adds 15 because the discovered list may be incomplete.
- A threat-feed match adds 50.
- A suspicious lookalike domain adds the penalty selected by the domain-similarity rules.
- A very new domain can add 30 points if less than 30 days old, or 15 points if less than 180 days old, unless the contact already matched an official source.
- A claimed brand’s ordinary 10-digit mobile phone can add 15 points.
- A risky phone type (such as premium-rate or VoIP, when identified by the local phone library) can add 10 points.
- Search poisoning, third-party-only listings, and public scam reports can add points under their own relevance rules.
- A non-brand contact with no official match and no other positive-risk signal gets an `UNVERIFIED_CONTACT` addition of 10 points. Absence of reports is not treated as proof of safety.

The score is **not statistically calibrated** and should not be interpreted as a percentage chance of fraud. Search availability, provider quotas, changing web results, and the completeness of the curated registry all affect results. A low-risk result is not a guarantee of safety.

## Supported brands and registry verification

The built-in directory currently includes SBI, HDFC Bank, ICICI Bank, Axis Bank, Bank of Baroda, Paytm, PhonePe, Google Pay, Airtel, and Amazon. Aliases, official domains, and contact details are maintained in `app/services/brand_directory.py`.

Some verified helplines can additionally be loaded from `data/registry_verified.json`. `testing/verify_registry.py` checks numbers against official-domain search snippets and can optionally fetch result pages. A number “seen” in search snippets is not automatically proof of ownership; its output is advisory and must be manually checked on the organization’s own site or app.

## Run locally (Windows PowerShell)

Use Python and run these commands from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and add credentials for the services you want to use, then start the development server:

```powershell
python -m uvicorn app.main:app --reload
```

Open the UI at `http://127.0.0.1:8000`. Do not open `static/index.html` directly as a `file://` URL; browser restrictions can block its API requests. FastAPI’s interactive API docs are available at `http://127.0.0.1:8000/docs`.

## Configuration

Settings are loaded by `app/config.py` from environment variables and `.env`. See [.env.example](./.env.example) for the sample settings. Keep `.env` private and do not commit API credentials.

| Setting | Purpose |
| --- | --- |
| `SERPAPI_API_KEY` | Enables web, news, Maps, forums, Play Store, live brand discovery, and alert searches. |
| `GEMINI_API_KEY` | Enables Gemini explanations, message extraction refinement, and multimodal screenshot description/transcription. Current default model is `gemini-2.5-flash`. |
| `GEMINI_MODEL` | Selects the Gemini model. If a non-Flash configured model returns HTTP 429, the client retries once with `gemini-2.5-flash`; this cannot bypass project quota or billing limits. |
| `ANTHROPIC_API_KEY` | Enables Anthropic explanations, extraction refinement, and screenshot analysis. When configured, Anthropic takes precedence over Gemini. |
| `CLAUDE_MODEL` | Selects the Anthropic model used by the integration. |
| `SAFE_BROWSING_API_KEY` | Enables Google Safe Browsing URL checks. |
| `VIRUSTOTAL_API_KEY` | Enables VirusTotal domain checks. The scorer currently adds a VirusTotal hit only when at least two engines report malicious or suspicious. |
| `SERPAPI_TIMEOUT` | SerpApi request timeout in seconds. |
| `CACHE_TTL_SECONDS` | Lifetime of in-memory SerpApi query-cache entries. |
| `DAILY_SEARCH_BUDGET` | Per-process daily cap on SerpApi search calls; retries also consume budget. |
| `RATE_LIMIT_PER_MIN` | In-memory POST API request limit per client IP per minute. |
| `DATA_DIR` | Directory used for verified-registry JSON data. |
| `STATS_FILE` | Local JSON file used for dashboard statistics. |
| `HOST`, `PORT`, `LOG_LEVEL`, `ENVIRONMENT` | Server binding, logging, and environment behavior. |

Most integrations are optional. Without SerpApi, the app can still run its deterministic registry/rule-based checks, but it has no live search evidence. Without an AI key, explanation templates and keyword message extraction remain available; screenshot analysis requires an AI provider.

## API reference

All endpoints are hosted by the FastAPI application:

| Method and path | Description |
| --- | --- |
| `GET /` | Serves the browser UI. |
| `GET /health` | Reports app and provider configuration status. |
| `GET /api/v1/stats` | Returns local stats and SerpApi usage; account information may be queried when SerpApi is configured. |
| `GET /api/v1/alerts` | Retrieves scam-news results through SerpApi. |
| `POST /api/v1/investigate` | Investigates one query; JSON fields include `query`, optional `claimed_brand`, and `language`. |
| `POST /api/v1/investigate/stream` | Streaming version of one-contact investigation using Server-Sent Events. |
| `POST /api/v1/analyze-message` | Analyzes pasted message text. |
| `POST /api/v1/analyze-message/stream` | Streaming version of message analysis. |
| `POST /api/v1/analyze-screenshot` | Accepts multipart fields `file` and optional `language`. |
| `POST /api/v1/analyze-screenshot/stream` | Streaming version of screenshot analysis. |
| `POST /api/v1/check-app` | Searches for likely app copies by name; JSON fields include `app_name` and optional `claimed_brand`. |
| `GET /api/v1/debug/serpapi` | Development-only raw-response shape inspection; may consume a SerpApi search. |

The API request and response schemas are defined in `app/models/schemas.py`. Streaming routes emit progress, result, or error events.

## Project structure

```text
app/
  main.py                 FastAPI application, routes, investigation orchestration
  config.py               Environment-backed settings
  core/
    classifier.py         Input type detection
    normalizer.py         Canonical phone, UPI, and domain forms
    scoring.py            Rule-based score and signal generation
    lookalike.py          Domain similarity checks
    utils.py              Shared domain and phone normalization
  models/
    schemas.py            Request, response, and evidence models
  services/
    brand_directory.py    Curated registry and verified-data loading
    brand_resolver.py     Search-based discovery and live snippet checks
    official_crawler.py   Registry comparison (not a general website crawler)
    serpapi_service.py    Search-provider client, cache, budget, evidence parsing
    domain_intel.py       RDAP, OpenPhish, Safe Browsing, VirusTotal
    phone_intel.py        Local phone type, carrier, and region hints
    llm_service.py        Anthropic/Gemini provider adapter
    claude_service.py     Explanation, text extraction, screenshot analysis
    stats_service.py      Local JSON statistics and identifier masking
static/
  index.html              Responsive browser UI
testing/
  offline_checks.py       Network-free regression checks
  live_checks.py          Opt-in checks that can consume SerpApi credits
  verify_registry.py      Opt-in helpline search-result checker
data/
  registry_verified.json  Additional verified registry entries, when present
```

## Tests and validation

Run the network-free checks:

```powershell
python testing\offline_checks.py
```

The offline checks cover classification, registry matching, scoring rules, lookalike domains, screenshot processing with mocked AI responses, Gemini 429 fallback behavior, API validation, and other regression cases. The latest run recorded during this project work passed 21 tests.

Live checks require credentials and make external requests; they can consume SerpApi credits:

```powershell
python testing\live_checks.py
```

Check the brand directory against official-domain search results (also uses SerpApi):

```powershell
python testing\verify_registry.py
python testing\verify_registry.py --diagnose hdfc
```

Live results vary over time and should not be treated as fixed test fixtures. `testing/RESULTS.md` contains older live-check observations, not a guarantee of current provider or website behavior.

## Limitations and operational notes

- The risk engine uses explicit heuristics and fixed weights; it is not a trained or calibrated fraud classifier.
- Live web data can be missing, stale, poisoned, rate-limited, or unavailable when provider quotas/timeouts occur.
- The “live” helpline check searches snippets on listed official domains; it does not browse pages as a user or verify the number through a bank.
- Brand discovery and fake-app detection are heuristics. A top Play Store result is only presumed likely official, not verified.
- Phone carrier and region information can be incomplete or outdated, especially after number portability.
- The default POST rate limiter and SerpApi cache/budget counters are process-local in-memory state. They are not distributed controls and reset when the process restarts.
- `stats.json` stores aggregate counts and recent identifiers. Phone and UPI identifiers are masked, but URL and brand-search identifiers are not equivalently masked by the current implementation. Treat the stats file as potentially containing user-submitted data.
- CORS currently allows all origins. Review and restrict this before exposing the service publicly.
- Screenshot uploads are forwarded to whichever AI provider is configured. Review that provider’s terms and privacy settings before processing sensitive images.
- API keys are secrets. Keep them in `.env` or the deployment secret manager; never place them in the frontend or commit them.

## Safety guidance

If money was lost or banking credentials were shared in India, contact the bank through its official channel and call **1930** promptly. Do not share OTPs, UPI PINs, passwords, or remote-access codes with callers. Use the official government reporting channels listed in the app’s recommendations.