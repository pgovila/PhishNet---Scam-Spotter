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
│   └── capture_screenshots.py       # Playwright UI screenshot capture automation
├── tests/
│   ├── test_api.py                  # FastAPI REST endpoint integration tests
│   ├── test_engine.py               # Scoring engine & edge case tests
│   └── test_links.py                # URL analysis & homoglyph tests
├── api.py                           # FastAPI REST service (/v1/analyze, /health)
├── app.py                           # Streamlit web application
├── Dockerfile                       # Production container definition
├── packages.txt                     # System dependencies (tesseract-ocr)
├── pyproject.toml                   # Project metadata & Ruff configuration
├── requirements.txt                 # Pinned dependencies
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

## 🧪 Testing & Code Quality

PhishNet includes a full unit test suite covering scoring equations, Hindi/Hinglish tokenization, protective context exclusions, XSS prevention, homoglyphs, and API endpoints.

```bash
# Run pytest (42 test cases)
pytest tests/ -v

# Run linting and style verification
ruff check .
ruff format --check .
```

---

## 📡 API Usage Example

Send a `POST` request to `/v1/analyze`:

```bash
curl -X POST "http://localhost:8000/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "SBI ALERT: Your KYC is incomplete and your account will be blocked today. Update immediately at http://sbi-kyc-update.example/verify and share OTP.",
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
      "reason": "",
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
      "reason": "",
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
  "score": 100,
  "raw_score": 120,
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

## 🛡️ Privacy & Security Stance

- **No Data Retention**: Messages entered or scanned are never persisted or stored in databases.
- **Local Rules Engine**: Message text stays on the local runtime without third-party exposure.
- **PII Scrubbing**: Any optional AI explanation request automatically masks phone numbers and emails (`[PHONE]`, `[EMAIL]`).
- **SSRF Immunity**: The link parser does not resolve external DNS or perform outbound requests during core analysis.

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for full details.
