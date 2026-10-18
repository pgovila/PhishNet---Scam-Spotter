# PhishNet — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                           │
│                                                                 │
│  ┌──────────────────┐           ┌──────────────────┐            │
│  │   Streamlit UI   │           │   FastAPI API     │            │
│  │   (app.py)       │           │   (api.py)        │            │
│  │                  │           │                   │            │
│  │  • Input area    │           │  POST /v1/analyze  │           │
│  │  • Risk gauge    │           │  GET  /health      │           │
│  │  • Findings      │           │  X-API-Key auth    │           │
│  │  • Report copy   │           │  Rate limiting     │           │
│  │  • Hindi toggle  │           │  OpenAPI docs      │           │
│  └────────┬─────────┘           └────────┬──────────┘            │
│           │                              │                       │
│           └──────────┬───────────────────┘                       │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Shared Analysis Engine                       │    │
│  │              (phishnet/engine.py)                         │    │
│  │                                                          │    │
│  │  • NFKC normalisation                                    │    │
│  │  • Regex pattern matching (EN/HI/Hinglish)               │    │
│  │  • Protective context detection                          │    │
│  │  • Score calculation with caps & bonuses                 │    │
│  │  • Tier assignment                                       │    │
│  │  • config/rules.yaml driven                              │    │
│  └────────┬─────────────────────────┬───────────────────────┘    │
│           │                         │                            │
│           ▼                         ▼                            │
│  ┌────────────────────┐   ┌────────────────────────────┐        │
│  │  Link Analyser     │   │  Optional Enrichment       │        │
│  │  (phishnet/links.py│   │  (phishnet/enrich.py)      │        │
│  │                    │   │                            │        │
│  │  • URL extraction  │   │  • Google Safe Browsing    │        │
│  │  • tldextract      │   │  • VirusTotal              │        │
│  │  • Brand tokens    │   │  • URLhaus                 │        │
│  │  • Edit distance   │   │  • RDAP domain age         │        │
│  │  • Homoglyphs      │   │  • 3s timeout + caching    │        │
│  │  • Shorteners      │   │  • Never breaks analysis   │        │
│  │  • SSRF-safe       │   │                            │        │
│  └────────────────────┘   └────────────────────────────┘        │
│                                                                 │
│  ┌────────────────────┐   ┌────────────────────────────┐        │
│  │  i18n              │   │  Report Generator          │        │
│  │  (phishnet/i18n.py)│   │  (phishnet/report.py)      │        │
│  │                    │   │                            │        │
│  │  • EN/HI strings   │   │  • Plain-text report       │        │
│  └────────────────────┘   │  • Cybercrime.gov.in links │        │
│                           └────────────────────────────┘        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Optional AI Layer                           │    │
│  │              (Anthropic Claude API)                       │    │
│  │                                                          │    │
│  │  • OFF by default, behind consent toggle                 │    │
│  │  • Simplify findings for elders (Hindi/English)          │    │
│  │  • Screenshot OCR fallback (when Tesseract unavailable)  │    │
│  │  • PII stripped before sending                           │    │
│  │  • NEVER sets or changes scores                          │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │              Data Layer                                  │    │
│  │                                                          │    │
│  │  config/rules.yaml          – Scoring rules              │    │
│  │  config/official_domains.yaml – Official brand domains   │    │
│  │  config/shorteners.txt      – URL shortener list         │    │
│  │  data/examples.json         – Test examples              │    │
│  │  data/phishnet_stats.db     – Anonymous counters (SQLite)│    │
│  └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Rules Engine, Not ML
The score is **always** deterministic and transparent. Every point comes from a named rule with a visible pattern. This builds trust — the user sees exactly why a message was flagged.

### 2. Bait / Hook / Ask Framework
Every scam follows the same structure:
1. **Bait** — Borrow trust from a known brand
2. **Hook** — Create pressure or fear
3. **Ask** — Demand a risky action (click, pay, share OTP)

This maps directly to how social engineering works.

### 3. SSRF-Safe Link Analysis
We **never** fetch or visit user-submitted URLs. All link analysis is offline using `tldextract` with its bundled TLD snapshot. This eliminates server-side request forgery risks entirely.

### 4. Privacy by Design
- No message content is ever stored or logged
- Only anonymous aggregate counters (tier counts, rule-hit IDs) are kept
- AI layer is off by default, behind a consent toggle
- No trackers or third-party analytics

### 5. Multilingual by Design
Detection covers English, Hindi (Devanagari), and Hinglish (romanised Hindi). The UI supports English/Hindi toggle. All text is NFKC-normalised for consistent matching.

## Data Flow

```
User Input (text/screenshot)
    │
    ▼
NFKC Normalisation
    │
    ├──► Link Extraction (offline, SSRF-safe)
    │       │
    │       ├──► Domain classification
    │       ├──► Brand impersonation check
    │       ├──► Shortener / IP / homoglyph detection
    │       │
    │       ▼
    │    Link Findings
    │
    ├──► Pattern Matching (regex, case-insensitive)
    │       │
    │       ├──► Bait rules (brands, lures)
    │       ├──► Hook rules (urgency, fear)
    │       ├──► Ask rules (OTP, payment)
    │       │
    │       ▼
    │    Protective Context Check
    │       │
    │       ▼
    │    Rule Findings
    │
    ▼
Score Calculation
    │
    ├──► Sum points
    ├──► Apply act-now bonus
    ├──► Apply caps (max 100, no-ask cap 54)
    │
    ▼
Tier Assignment + Next Steps
    │
    ├──► Optional: Online Enrichment
    ├──► Optional: AI Simplification
    │
    ▼
Display Results
```

## File Map

| File | Purpose |
|------|---------|
| `app.py` | Streamlit UI |
| `api.py` | FastAPI REST API |
| `phishnet/engine.py` | Core scoring engine |
| `phishnet/links.py` | Offline link analysis |
| `phishnet/enrich.py` | Optional online enrichment |
| `phishnet/i18n.py` | English/Hindi translations |
| `phishnet/report.py` | Plain-text report generator |
| `config/rules.yaml` | Scoring rules (editable) |
| `config/official_domains.yaml` | Known legitimate domains |
| `config/shorteners.txt` | URL shortener list |
| `data/examples.json` | Test examples with expected scores |
| `tests/test_engine.py` | Engine tests |
| `tests/test_links.py` | Link analysis tests |
| `tests/test_api.py` | API endpoint tests |
