# 🛡️ ScamShield India
### Investigate suspicious contacts before you call, click, or pay.

ScamShield India is a cybersecurity web application and JSON API that helps users assess suspicious phone numbers, UPI IDs, websites, customer-care contacts, SMS/WhatsApp messages, screenshots, and mobile app listings.

It combines **live search evidence through SerpApi, a curated brand registry, deterministic risk-scoring rules, optional threat-intelligence services, and AI-assisted explanations** to help users make more informed decisions before trusting an unfamiliar contact.

**The problem:** Fraudsters use fake customer-care numbers, lookalike websites, misleading search results, impersonated brands, and urgent messages to trick people into sharing OTPs, revealing banking credentials, or transferring money. Finding a trustworthy contact can be difficult, especially when fraudulent listings appear alongside legitimate results.

**The solution:** ScamShield investigates the available evidence, compares submitted details against known brand information, identifies suspicious signals, and produces an explainable risk report with recommended next steps.

ScamShield is an investigative aid, not a fraud authority. Its scores are heuristic indicators, not probabilities or proof of fraud. A low-risk result does not guarantee that a contact is safe.

---

## ✨ Features

- **Contact investigation:** Check phone numbers, UPI IDs, URLs, domains, and brand/customer-care queries.
- **Live search evidence:** Use SerpApi to retrieve relevant Google Search, Google News, Google Maps, Google Forums, and Google Play results.
- **Brand and contact verification:** Compare submitted details against a curated registry of official domains, helplines, and UPI handles.
- **Brand discovery:** Attempt to discover unknown brands and candidate official domains using available search evidence.
- **Helpline investigation:** Search results from a brand's registered official domains can be checked for matching helpline information.
- **Lookalike-domain detection:** Identify suspicious domain similarities and investigate domain registration age.
- **Threat intelligence:** Integrate OpenPhish, Google Safe Browsing, and VirusTotal where supported and configured.
- **Message analysis:** Extract phone numbers, URLs, and UPI IDs; identify common scam themes and pressure tactics; investigate up to three extracted contacts.
- **Screenshot analysis:** Use a configured AI provider to describe an uploaded screenshot, transcribe its text, and investigate extracted contact details.
- **Possible fake-app detection:** Search Google Play listings and flag potential copies using title and developer-name heuristics.
- **Explainable risk reports:** Present a score, risk level, detected signals, supporting evidence, warnings, and recommended actions.
- **Progressive investigation UI:** Display investigation progress through streaming API endpoints.
- **Dashboard:** Show local usage statistics, recent checks, provider status, SerpApi usage information, and live scam-news results.
- **Multilingual reports:** Support English, Hindi, and Marathi report language selection.
- **JSON API:** Expose investigation and analysis capabilities through FastAPI endpoints.

## 🎯 How SerpApi Powers ScamShield

**SerpApi is the live-search integration that supplies external search evidence to ScamShield.** It helps the application investigate information that is not already available in its local brand registry.

| Search engine or service | Purpose |
|---|---|
| Google Search | Find information about submitted contacts, domains, UPI IDs, brand websites, customer-care listings, and potential search-result manipulation. |
| Google News | Find relevant news reports and retrieve scam-related news for the dashboard. |
| Google Maps | Examine business listings, contact details, and possible brand-discovery evidence. |
| Google Forums | Search for user complaints and discussions relevant to a suspicious contact. |
| Google Play | Find app listings and help identify possible impersonation or cloned apps. |
| SerpApi Account API | Retrieve account usage information for the dashboard when supported by the configured integration. |

The application can execute relevant searches concurrently, process the returned evidence, and remove duplicate results.

### Why this matters

A phone number or website may not exist in ScamShield's local registry. SerpApi allows the application to gather additional evidence from current search results instead of relying exclusively on hardcoded information.

However, **a search result is evidence, not proof of authenticity**. Results can be incomplete, outdated, manipulated, or misleading. ScamShield does not treat a number appearing in a search snippet as definitive proof that an organization owns it.

SerpApi powers the search integration; it is not itself a fraud-detection authority. Actual search engines and result types depend on the implemented integration and available provider access.

Without a working SerpApi configuration, ScamShield can still perform supported local registry and rule-based checks, but live search evidence and search-based discovery are unavailable.

## ⚙️ How It Works

A normal contact investigation follows this pipeline:

1. **Input validation:** Validate the submitted query and report language using Pydantic request models.
2. **Classification and normalization:** Identify the input as a phone number, UPI ID, URL, or brand search and normalize it for comparison.
3. **Brand resolution:** Check the local brand directory first. If the brand is unknown, attempt discovery using available search evidence.
4. **Evidence collection:** Query relevant SerpApi search engines and run supported domain-age and threat-intelligence checks. Independent tasks can run concurrently.
5. **Risk assessment:** Apply deterministic rules to the available evidence, registry matches, domain characteristics, and suspicious signals.
6. **AI-assisted explanation:** When configured, Gemini or Anthropic can help explain findings in user-friendly language. If explanation generation is unavailable, the application falls back to a built-in template.
7. **Report generation:** Return the score, risk level, evidence, detected signals, warnings, and recommended actions.
8. **Local statistics:** Record usage counters and recent investigation information in local JSON files.

The AI explanation is intended to communicate the findings, not establish authenticity independently. The deterministic scorer remains responsible for the numeric risk assessment.

### Message and screenshot workflows

**Message analysis**

ScamShield extracts candidate phone numbers, URLs, and UPI IDs from pasted text, detects common scam themes and pressure tactics, and investigates up to three extracted contacts. AI can optionally refine extraction. Extracted identifiers are retained only when they appear verbatim in the original message.

The overall message score is based primarily on the highest investigated contact score, with a limited adjustment for detected tactics under the implemented rules.

**Screenshot analysis**

An uploaded PNG, JPEG, or WEBP image (up to 5 MB) is sent to the configured AI provider for image description and text transcription. ScamShield then investigates usable phone numbers, URLs, and UPI IDs extracted from the transcription.

If no usable contact identifier is found, the application can display the transcription and description while marking the risk as `UNKNOWN / not assessed`.

Screenshot content is transmitted to the selected AI provider. Users should avoid uploading sensitive information they do not want processed by that provider.

## 📊 Risk Scoring

ScamShield uses a deterministic, rule-based scoring engine implemented in `app/core/scoring.py`.

The score starts at **15**, incorporates applicable signals, and is clamped to a range of 0–100.

| Risk level | Score |
|---|---:|
| LOW | 0–24 |
| MEDIUM | 25–49 |
| HIGH | 50–69 |
| CRITICAL | 70–100 |

### Examples of risk signals

| Signal | Example score impact |
|---|---:|
| Match with a known official contact | −30 |
| Mismatch against a claimed curated brand | +25 |
| Mismatch against a discovered brand profile | +15 |
| Threat-intelligence match | +50 |
| Suspicious lookalike domain | Rule-dependent penalty |
| Domain younger than 30 days | +30 |
| Domain younger than 180 days | +15 |
| Ordinary 10-digit mobile number presented as brand customer care | +15 |
| Identified risky phone type, such as VoIP or premium-rate | +10 |
| Unverified non-brand contact without another positive-risk signal | +10 |

Additional rules can account for search-result poisoning, third-party-only listings, and public scam reports. Individual conditions, exclusions, and caps are determined by the scoring implementation.

These values are rule weights, not statistically learned probabilities. A score of 80 does not mean an 80% chance of fraud. Missing evidence must not be interpreted as proof of safety.

## 🏦 Built-in Brand Registry

The built-in directory currently includes:

- State Bank of India (SBI)
- HDFC Bank
- ICICI Bank
- Axis Bank
- Bank of Baroda
- Paytm
- PhonePe
- Google Pay
- Airtel
- Amazon

Brand aliases, registered domains, and contact information are maintained in `app/services/brand_directory.py`. Additional verified-registry entries can be loaded from `data/registry_verified.json`.

Unknown brands may be investigated using live search evidence, but discovery is heuristic and can fail when results are ambiguous or incomplete.

A number found in search snippets is not automatically verified. Registry verification should be confirmed against the organization's own official website or application.

## 🧰 Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Request validation and schemas | Pydantic v2 |
| Development server | Uvicorn |
| Frontend | HTML, CSS, JavaScript |
| HTTP integrations | HTTPX |
| Phone parsing | phonenumbers |
| Domain parsing | tldextract |
| Live web search | SerpApi |
| AI explanations and image analysis | Google Gemini API or Anthropic API |
| Domain and threat intelligence | RDAP, OpenPhish, Google Safe Browsing, VirusTotal |
| Local persistence | JSON files |
| Testing | Python unittest-based checks and optional live integration checks |

The frontend uses plain HTML, CSS, and JavaScript. No frontend package manager or compilation step is required.

## 🚀 Installation and Setup

### Prerequisites

- Python installed on Windows or another supported operating system.
- Git, if cloning the repository.
- API credentials for the external integrations you want to enable.

### 1. Create and activate a virtual environment

Run these commands from the repository root in Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### 2. Configure environment variables

```powershell
Copy-Item .env.example .env
```

Open `.env` and configure the services you want to use.

| Environment variable | Purpose | Requirement |
|---|---|---|
| `SERPAPI_API_KEY` | Live search, news, Maps, forums, Play Store, discovery, and supported account-usage queries | Required for live search features |
| `GEMINI_API_KEY` | Gemini explanations, extraction refinement, and screenshot analysis | Optional |
| `GEMINI_MODEL` | Selects the Gemini model; the configured default is `gemini-2.5-flash` | Optional |
| `ANTHROPIC_API_KEY` | Anthropic explanations, extraction refinement, and screenshot analysis | Optional |
| `CLAUDE_MODEL` | Selects the Anthropic model | Optional |
| `SAFE_BROWSING_API_KEY` | Google Safe Browsing checks | Optional |
| `VIRUSTOTAL_API_KEY` | VirusTotal domain intelligence | Optional |
| `SERPAPI_TIMEOUT` | Search request timeout | Optional |
| `CACHE_TTL_SECONDS` | In-memory search-cache lifetime | Optional |
| `DAILY_SEARCH_BUDGET` | Per-process daily SerpApi request budget | Optional |
| `RATE_LIMIT_PER_MIN` | Per-IP POST request limit per minute | Optional |
| `DATA_DIR` | Verified-registry data directory | Optional |
| `STATS_FILE` | Local statistics file location | Optional |
| `HOST`, `PORT`, `LOG_LEVEL`, `ENVIRONMENT` | Server and runtime configuration | Optional |

When both AI providers are configured, Anthropic takes precedence in the current integration. AI explanations are optional, but screenshot analysis requires a configured AI provider.

Provider quotas, pricing, and free-tier availability can change. Check each provider's current account dashboard before relying on a particular quota.

**Security:** Keep `.env` private. Never commit API keys to Git or expose them in frontend JavaScript.

### 3. Start the application

```powershell
python -m uvicorn app.main:app --reload
```

Open the application at:

- Web interface: http://127.0.0.1:8000
- Interactive API documentation: http://127.0.0.1:8000/docs
- Health and provider status: http://127.0.0.1:8000/health

Open the application through the FastAPI server rather than opening `static/index.html` directly with a `file://` URL.

## 🔌 API Reference

All endpoints are served by the FastAPI application.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Serve the web interface |
| GET | `/health` | Report application and provider configuration status |
| GET | `/api/v1/stats` | Retrieve local statistics and supported SerpApi usage information |
| GET | `/api/v1/alerts` | Retrieve scam-news results through SerpApi |
| POST | `/api/v1/investigate` | Investigate one contact or brand query |
| POST | `/api/v1/investigate/stream` | Stream investigation progress and results |
| POST | `/api/v1/analyze-message` | Analyze pasted message text |
| POST | `/api/v1/analyze-message/stream` | Stream message-analysis progress |
| POST | `/api/v1/analyze-screenshot` | Analyze an uploaded screenshot |
| POST | `/api/v1/analyze-screenshot/stream` | Stream screenshot-analysis progress |
| POST | `/api/v1/check-app` | Search for possible app copies |
| GET | `/api/v1/debug/serpapi` | Inspect raw SerpApi response structure during development |

The investigation endpoint accepts JSON containing a `query` and optional `claimed_brand` and `language` fields. App-check requests accept `app_name` and an optional `claimed_brand`. Screenshot requests use multipart form data.

Request and response schemas are defined in `app/models/schemas.py`.

## 🧪 Testing

Run the network-free regression checks:

```powershell
python testing\offline_checks.py
```

The offline suite covers areas such as:

- Input classification and normalization.
- Registry matching and risk scoring.
- Lookalike-domain rules.
- API validation and other regression cases.
- Screenshot processing with mocked AI responses.
- Gemini rate-limit fallback behavior.

The latest reported offline test run for this project passed **21 tests**. Re-run the suite against your current checkout before claiming that result for a new release.

### Optional live checks

```powershell
python testing\live_checks.py
```

### Optional registry verification

```powershell
python testing\verify_registry.py
python testing\verify_registry.py --diagnose hdfc
```

Live checks and registry verification can make external requests and consume SerpApi credits. Their results can change over time and should not be treated as permanent test fixtures.

## 📁 Project Structure

```text
ScamShield/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── core/
│   │   ├── classifier.py
│   │   ├── normalizer.py
│   │   ├── scoring.py
│   │   ├── lookalike.py
│   │   └── utils.py
│   ├── models/
│   │   └── schemas.py
│   └── services/
│       ├── brand_directory.py
│       ├── brand_resolver.py
│       ├── official_crawler.py
│       ├── serpapi_service.py
│       ├── domain_intel.py
│       ├── phone_intel.py
│       ├── llm_service.py
│       ├── claude_service.py
│       └── stats_service.py
├── static/
│   └── index.html
├── data/
│   └── registry_verified.json
├── testing/
│   ├── offline_checks.py
│   ├── live_checks.py
│   └── verify_registry.py
├── requirements.txt
├── .env.example
└── README.md
```

The verified registry JSON file is optional when no additional entries are required. Runtime statistics are stored in the configured statistics file.

## ⚠️ Limitations and Security Considerations

- **Heuristic scoring:** The risk engine has not been statistically calibrated. False positives and false negatives are possible.
- **Search reliability:** Live evidence depends on search-provider availability, result quality, quotas, and timeouts.
- **Brand verification:** Search snippets and third-party listings cannot conclusively establish ownership of a contact number or domain.
- **Brand coverage:** The built-in directory is limited; discovery of other brands depends on available search evidence.
- **Phone intelligence:** Carrier and regional hints may be incomplete or outdated because of number portability and data limitations.
- **Threat intelligence:** External services can return incomplete or conflicting findings. A lack of threat-feed matches does not prove safety.
- **Fake-app detection:** App title and developer-name similarities are indicators, not definitive proof of impersonation.
- **Privacy:** Screenshot content is transmitted to the configured AI provider. Review the provider's data-handling policies before processing sensitive images.
- **Local statistics:** Phone and UPI identifiers are masked, but URL and brand-search identifiers may be stored without equivalent masking in the current implementation. Treat the statistics file as potentially sensitive.
- **Rate limiting:** The current in-memory limiter and search budget are process-local, reset after restarts, and are not distributed production controls.
- **CORS:** The current configuration allows all origins. Restrict allowed origins before public deployment.
- **Production readiness:** Authentication, persistent distributed rate limiting, hardened deployment settings, privacy controls, and broader accuracy evaluation should be reviewed before exposing the service publicly.

## 🆘 Safety Guidance

If you suspect fraud:

1. Do not share OTPs, UPI PINs, passwords, or remote-access codes.
2. Verify contact details using the organization's official application or website, accessed independently.
3. If you have lost money or shared banking credentials in India, contact your bank through its official channel and call **1930** promptly.
4. Use the official National Cyber Crime Reporting Portal at https://cybercrime.gov.in/.
5. Use official government services, including Sanchar Saathi, when relevant.

Never rely on a ScamShield score alone when deciding whether to transfer money or disclose sensitive information.

## 🤖 AI Tools Used

- **Google Gemini API:** Optional in-app explanations, message-extraction refinement, and screenshot description/transcription.
- **Anthropic API:** Optional alternative for in-app explanations, message-extraction refinement, and screenshot analysis.
- **AI-assisted development:** Claude was used for development assistance and code review.

AI output is supplementary. ScamShield's rule-based scorer determines the numeric risk score, while live search and threat-intelligence integrations provide supporting evidence when available.

## 🌱 Future Improvements

Potential areas for future development include:

- Expanding the curated registry using manually reviewed official sources.
- Improving privacy-preserving statistics and data retention controls.
- Adding broader automated tests for live investigation workflows.
- Evaluating false-positive and false-negative rates against a labeled dataset.
- Improving search-evidence provenance and confidence explanations.
- Strengthening production security, deployment configuration, and abuse prevention.

## 📜 Project Disclaimer

ScamShield India is designed to assist with preliminary fraud-risk assessment and cybersecurity awareness. It does not guarantee that a contact is legitimate or fraudulent, and it is not affiliated with or endorsed by the banks, payment providers, search engines, or threat-intelligence providers mentioned above.

Always independently verify important contact details before making payments or sharing sensitive information.