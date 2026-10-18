# PhishNet — Scam Spotter

> **"Spot the bait. See the hook. Skip the ask."**

[![CI — PhishNet](https://github.com/pgovila/PhishNet---Scam-Spotter/actions/workflows/ci.yml/badge.svg)](https://github.com/pgovila/PhishNet---Scam-Spotter/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12%20(recommended)-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.42+-FF4B4B.svg)](https://streamlit.io)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)


PhishNet is a production-ready, privacy-first cybersecurity tool tailored for Indian users (students, parents, and first-time UPI users) that detects and deconstructs deceptive SMS, WhatsApp, and email messages in **English**, **Hindi (हिन्दी)**, and **Hinglish**.

---

## 🎯 Key Highlights

- **Transparent Rules-Based Scoring**: The rules engine sets the score deterministically — **AI never sets or influences the score**.
- **Bait-Hook-Ask Mental Model**:
  - 🎣 **Bait**: Borrowed brand authority (SBI, India Post, Income Tax, etc.) or lures (lottery, cashback, free gifts).
  - 🪝 **Hook**: Artificial urgency (*"immediately"*, *"within 2 hours"*, *"aaj hi"*) or fear (*"account blocked"*, *"KYC incomplete"*, *"SIM deactivation"*).
  - ✋ **Ask**: Risky links, payment demands, or credential harvesting (OTP, PIN, CVV, password).
- **Protective Context Intelligence**: Recognizes defensive advisories (*"Never share your OTP with anyone"*) and voids the OTP finding instead of falsely penalizing legitimate banking alerts.
- **SSRF-Safe Offline Link Engine**: Evaluates domain structures, IDN homoglyphs (Cyrillic look-alikes), Levenshtein distance typosquatting against verified Indian institutions, and known shorteners without making outbound HTTP requests.
- **OCR Screenshot Ingestion**: Upload message screenshots via local Tesseract OCR (with bilingual `eng+hin` models) or Claude Vision fallback.
- **Official Incident Reporting**: Formats a standardized plain-text report ready to paste into [National Cyber Crime Reporting Portal (1930 / cybercrime.gov.in)](https://cybercrime.gov.in) and [DoT Sanchar Saathi Chakshu](https://sancharsaathi.gov.in/sfc/).
- **Dual Operating Modes**: Supports default production weights and hackathon organiser criteria via `RULEBOOK_MODE=1`.

---

## 📊 Scoring Architecture

```
                               Incoming Message
                                      │
                         Unicode NFKC Normalisation
                                      │
                  ┌───────────────────┴───────────────────┐
                  ▼                                       ▼
        Link Extraction & Analysis                Text Pattern Matching
      • Scheme, domain & odd TLDs               • Bait (Brands, Lures)
      • Levenshtein typosquatting               • Hook (Urgency, Fear)
      • Cyrillic / IDN homoglyphs               • Ask (Payment, Credentials)
      • Bundled Public Suffix List              • Protective Context Check
                  │                                       │
                  └───────────────────┬───────────────────┘
                                      │
                            Rules Engine Aggregation
                         (Loaded from config/rules.yaml)
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
             Default Mode                         Rulebook Mode
         • Bait: +10 / +20                     • Fake Urgency: +20
         • Hook: +15 / +15                     • Account Threat: +15
         • Ask:  +25 / +30 / +40               • Suspicious Link: +25
         • Act-now bonus: +15                  • OTP Request: +40
         • No-Ask Cap: Max 54                  • Low 0-29, Med 30-59, High 60-100
         • Low 0-24, Med 25-54, High 55-100
                                      │
                                      ▼
                        Risk Assessment & Tier Output
```

---

## 📁 Repository Structure

```
.
├── .env.example                     # Environment variables template
├── .github/workflows/ci.yml         # GitHub Actions CI workflow (lint + pytest)
├── .streamlit/config.toml           # Streamlit theme & UI settings
├── config/
│   ├── official_domains.yaml        # Whitelist of legitimate Indian institutions
│   ├── rules.yaml                   # Hot-reloadable rules configuration
│   └── shorteners.txt               # Bundled URL shorteners list
├── data/
│   ├── benchmark_dataset.json       # 100-message balanced ground truth test set
│   └── examples.json                # Test suite benchmark messages and scores
├── docs/
│   ├── ARCHITECTURE.md              # Deep-dive system design documentation
│   └── DEMO_SCRIPT.md               # 90-second video demo shot list
├── phishnet/
│   ├── __init__.py                  # Package exports
│   ├── engine.py                    # Scoring algorithms, normalisation & caps
│   ├── enrich.py                    # Optional external threat-intel integrations
│   ├── i18n.py                      # Bilingual UI strings (English/Hindi)
│   ├── links.py                     # Offline URL and typosquat engine
│   └── report.py                    # Formal police report builder
├── scripts/
│   ├── build_submission_pdf.py      # Automated 5-page submission PDF compiler
│   ├── capture_screenshots.py       # Playwright UI screenshot capture automation
│   └── entrypoint.sh                # Container entrypoint supporting multi-service
├── tests/
│   ├── test_api.py                  # FastAPI REST endpoint integration tests
│   ├── test_benchmark.py            # 100-message precision/recall evaluation
│   ├── test_engine.py               # Scoring engine & edge case tests
│   └── test_links.py                # URL analysis & homoglyph tests
├── api.py                           # FastAPI REST service (/v1/analyze, /health)
├── app.py                           # Streamlit web application & telemetry dashboard
├── Dockerfile                       # Multi-service production container (8501 & 8000)
├── packages.txt                     # System dependencies (tesseract-ocr)
├── pyproject.toml                   # Project metadata & Ruff configuration
├── requirements.txt                 # Fully pinned dependencies (==)
├── SECURITY.md                      # Security disclosure policy
└── submission.yaml                  # Hackathon metadata & video links
```

---

## 🚀 Getting Started

### Prerequisites

- **Python Version**: **Python 3.12** is **strongly recommended**.
  > [!IMPORTANT]
  > **Why Python 3.12 instead of Python 3.14?**  
  > If your system has both Python 3.12 and Python 3.14 installed, **always use Python 3.12** for PhishNet. Python 3.14 is an early development release where many ecosystem libraries (such as pre-compiled wheels for Streamlit, Pillow, Playwright, PyTorch, and PyYAML) do not yet have stable wheels or fail during build. Python 3.12 is fully stable, tested, and works out of the box with all dependencies.
- **Tesseract OCR** (optional, for screenshot scanning):
  - **Debian/Ubuntu**: `sudo apt install tesseract-ocr tesseract-ocr-hin`
  - **macOS**: `brew install tesseract tesseract-lang`
  - **Windows**: Install via [UB-Mannheim Tesseract Installer](https://github.com/UB-Mannheim/tesseract/wiki)

### Installation

```bash
# Clone repository
git clone https://github.com/pgovila/PhishNet---Scam-Spotter.git
cd PhishNet---Scam-Spotter

# Create virtual environment explicitly targeting Python 3.12:
# Windows (using the Python launcher):
py -3.12 -m venv .venv

# Linux / macOS:
python3.12 -m venv .venv

# Activate virtual environment:
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# Upgrade pip and install dependencies:
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Environment Configuration (Optional)

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
All core rules and link detection work **100% offline** without any API keys. External APIs (Anthropic Claude, Google Safe Browsing, VirusTotal, URLhaus) are strictly optional enhancements.

---

## 💻 Running the Applications

### 1. Web Application (Streamlit)
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

### 2. REST API (FastAPI)
```bash
uvicorn api:app --reload --port 8000
```
Interactive OpenAPI documentation will be available at [http://localhost:8000/docs](http://localhost:8000/docs).

### 3. Switch to Hackathon Rulebook Mode
```bash
# Linux / macOS
RULEBOOK_MODE=1 streamlit run app.py

# Windows PowerShell
$env:RULEBOOK_MODE="1"; streamlit run app.py
```

### 4. Docker Deployment
```bash
docker build -t phishnet:latest .
docker run -p 8501:8501 -p 8000:8000 phishnet:latest
```

---

## 🧪 Testing, Code Quality & Empirical Benchmark

PhishNet includes a comprehensive unit test suite covering scoring equations, Hindi/Hinglish tokenization, protective context exclusions, XSS prevention, homoglyphs, REST API endpoints, and a 100-message empirical ground truth benchmark.

```bash
# Run full pytest test suite (43 test cases)
pytest tests/ -v

# Run 100-message benchmark specifically
pytest tests/test_benchmark.py -v -s

# Run linting and style verification
ruff check .
ruff format --check .
```

---

## 🎯 Empirical Benchmark & Authenticity (Dual Evaluation)

To ensure real-world durability, eliminate evaluation bias, and provide transparent metrics, PhishNet is evaluated across two distinct datasets: our curated regression suite (`data/benchmark_dataset.json`) and an independent blind test of 30 fresh messages.

### Dual Benchmark Performance Comparison

| Metric | Curated Regression Suite (100 Messages) | Fresh / Blind Test (30 Messages) | Interpretation |
| :--- | :--- | :--- | :--- |
| **Dataset Size** | 100 messages (50 scam, 50 genuine) | 30 fresh messages (15 scam, 15 genuine) | Calibrated against Indian telecom & bank messages |
| **Accuracy** | **95.00%** | **87.00%** | Robust overall classification across deceptive and benign traffic |
| **Precision** | **95.92%** | **100.00%** | **0 false alarms** in 15 fresh genuine bank/academic communications |
| **Recall (Sensitivity)** | **94.00%** | **73.33%** | 11 of 15 scams detected out of the box in blind evaluation |
| **F1 Score** | **94.95%** | **84.62%** | Harmonic mean of precision and recall |
| **False Positive Rate** | **4.00%** | **0.00%** | High user trust: safe messages are not flooded with false panic |

### Lessons from Blind Evaluation
In initial blind evaluation of 30 un-tuned messages, four deceptive edge cases were originally missed (electricity disconnection "tonight", hotel review task lures, SIM KYC "6-digit code", and OTT subscription "update card" notices). We transparently documented these findings and incorporated them into our rulebook without inflating false positives or sacrificing 100% precision on benign traffic.

### Real-World Edge Cases Solved
1. **Zero-Width Character Evasions**: Attackers inserting invisible zero-width spaces (`\u200b`, `\ufeff`) or soft hyphens (`\u00ad`) into words like `O​T​P` or `k​y​c` are stripped during NFKC normalisation before regex execution.
2. **Devanagari Vowel Sign Boundaries**: Python's standard `\b` regex boundary fails on Hindi words ending in combining vowel signs (`ा`, `ी`, `े`) or anusvara (`ं`) because Python Unicode `\w` only treats letters and numbers as word characters. PhishNet uses a script-aware boundary that includes all Devanagari vowel signs (`\u0900-\u0963`) while strictly excluding sentence-ending danda (`।`).
3. **Sentence-Scoped Protective Context**: Previously, messages like *"Never share your OTP with anyone. Send OTP to 9876543210"* canceled the OTP finding because the protective phrase appeared in the first sentence. PhishNet now scopes protective context strictly to the clause/sentence containing the credential request.
4. **False Alarm Neutralisation for Verified Institutions**: Genuine university notifications (`.ac.in`, `.edu.in`) and government updates (`.gov.in`) with HTTPS links automatically neutralize generic urgency and payment flags, preventing real college fee reminders from being marked High risk.
5. **Legitimate Bank Transaction Alerts**: Authentic bank debit/credit messages signed by institutions (`-SBI`, `-HDFC`) containing mandatory dispute instructions (*"If not done by you, call immediately"*) are recognized as protective advisory context rather than penalized as high-pressure scam tactics.
6. **Emerging Indian Attack Vectors Covered**:
   - **Digital Arrest**: Police/CBI/Narcotics Control Bureau video-call threats.
   - **Remote Screen Sharing**: Coercion to install AnyDesk, TeamViewer, or RustDesk.
   - **UPI Collect Request Tricks**: Reverse refund scams claiming "enter PIN to receive cash back".
   - **Malicious APK Sideloading**: Direct `.apk` download prompts disguised as bank updates.
   - **Part-Time Work / Telegram Tasks**: Hotel rating and YouTube task lures promising daily ₹2,000–₹5,000.

---

## 💰 Commercialization & Monetization (For Colleges, Banks & Fintechs)

While PhishNet provides an uncompromising free tier for end-users, sustainable scaling is achieved through B2B institutional partnerships where fraud costs millions in direct liability and reputation loss.

### Target Buyers & Value Proposition
- **Engineering Colleges & Universities**: Student fee scams and phishing impersonating university registrars result in lost fees and reputational damage. PhishNet provides student portal integration and SMS verification before payment deadlines.
- **Regional Rural Banks & Credit Co-operatives**: First-time digital banking customers are prime targets for KYC deactivation and electricity bill scams. Banks integrate PhishNet into their customer support portals and automated SMS gateways.
- **Fintech & Payment Aggregators**: Real-time screening of inbound transaction remarks and merchant onboarding claims to block phishing landing pages and deceptive APK links.

### Pricing Structure *(Pilot Assumptions)*
| Tier | Pricing | Target Audience | Features Included |
| :--- | :--- | :--- | :--- |
| **Community Free** | **₹0 / Forever** | Students, parents, citizens | Unlimited personal scans, full Bait-Hook-Ask deconstruction, English/Hindi UI, instant 1930 police report generation. |
| **Family Shield** *(Roadmap)* | **₹99 / month** | Households & elderly family | WhatsApp forwarding bot, automated family alerts for high-risk SMS, elderly protection dashboard. |
| **Campus & Bank API** *(Pilot)* | **₹4,999 / month** | Universities, colleges, banks | High-throughput REST API (50,000 scans/mo), live threat telemetry dashboard, custom institutional domain whitelisting, SLA support. |

*Note: Pricing tiers reflect pilot design assumptions and are subject to commercial validation during campus/institutional beta trials.*

### Live Threat Telemetry Dashboard
The PhishNet application features a built-in read-only **Threat Trends & Telemetry** dashboard fed by local SQLite counters, displaying:
- Total scans and risk-tier distribution (High, Medium, Safe).
- High-frequency scam vectors (e.g. KYC fraud, digital arrest, fake electricity disconnection).
- Common evasion tactics observed (zero-width evasions, URL shorteners, typosquats).

*(Note: On ephemeral cloud hosting like Streamlit Community Cloud, local disk counters reset on redeployment or container restart. Production deployments attach to persistent external databases such as PostgreSQL or Supabase).*

---

## 📡 API Usage Example

Send a `POST` request to `/v1/analyze`:

```bash
curl -X POST "http://localhost:8000/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "SBI ALERT: Your KYC is incomplete and your account will be blocked today. Update immediately at http://sbi-kyc-update.example/verify",
    "mode": "default"
  }'
```

### Sample Response:
```json
{
  "findings": [
    {
      "rule_id": "bait_brand",
      "category": "bait",
      "label": "Named brand / authority",
      "points": 10,
      "matched_text": "SBI",
      "span_start": 0,
      "span_end": 3,
      "reason": "Impersonates a trusted bank or financial authority to lower your guard.",
      "protective": false
    },
    {
      "rule_id": "hook_fear",
      "category": "hook",
      "label": "Fear / threat",
      "points": 15,
      "matched_text": "account will be blocked",
      "span_start": 41,
      "span_end": 64,
      "reason": "Uses threats of account closure or legal action to induce panic.",
      "protective": false
    },
    {
      "rule_id": "ask_link",
      "category": "ask",
      "label": "Risky link",
      "points": 25,
      "matched_text": "http://sbi-kyc-update.example/verify",
      "span_start": 92,
      "span_end": 128,
      "reason": "Uses HTTP without encryption (no HTTPS); Contains 'sbi' but is not an official domain",
      "protective": false
    }
  ],
  "score": 65,
  "raw_score": 65,
  "tier": "high",
  "next_steps": [
    "🚫 Do NOT click any link in this message.",
    "🔒 Do NOT share OTP, PIN, CVV or passwords with anyone.",
    "📞 Contact your bank ONLY through its official app or card number.",
    "🆘 If money is lost, call cyber-crime helpline 1930 immediately.",
    "🌐 Report at https://cybercrime.gov.in"
  ],
  "mode": "default",
  "act_now_applied": true
}
```
---

## 🛡️ Privacy, DPDP Principles & Data Security Stance

PhishNet is designed around the principles of the **Digital Personal Data Protection Act, 2023 (DPDP Act)** (data minimisation and zero message retention):
- **Zero Message Body Retention**: Messages, OTPs, phone numbers, and URLs entered or uploaded are processed in volatile memory and are **never stored in the database or logged**.
- **Local Rules-First Engine**: Core Bait-Hook-Ask triage runs entirely offline on local rulebook algorithms without transmitting user message bodies to third-party endpoints.
- **Client-Side Privacy & PII Scrubbing**: If optional external features are explicitly enabled by the user (such as AI simplified explanations or external threat-intelligence lookups like Google Safe Browsing or VirusTotal), phone numbers, bank account numbers, and email addresses are automatically scrubbed (`[PHONE]`, `[EMAIL]`) before dispatch, and only bare domains are queried.
- **SSRF & Outbound Safe**: The offline link parser inspects domain anatomy, Unicode scripts, and Levenshtein distance against known Indian entities without performing active DNS lookups or outbound HTTP queries during evaluation.

> [!NOTE]
> **Heuristic Decision Support Disclaimer**: PhishNet is a heuristic risk evaluation and educational decision-support tool, not an absolute guarantee or legal determination. Scammers constantly vary messaging patterns. Always verify critical financial, institutional, or legal matters directly through verified official channels, mobile banking apps, or official institution hotlines.

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for full details.
