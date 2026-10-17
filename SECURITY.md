# PhishNet — Security Policy

## Threat Model

PhishNet analyses user-submitted text for scam indicators. The primary threats are:

### 1. Server-Side Request Forgery (SSRF)
**Risk:** A malicious URL in user input could trick the server into making requests to internal services.
**Mitigation:** PhishNet **never fetches or visits** any URL extracted from user input. All link analysis is purely offline using `tldextract` with its bundled TLD snapshot. Optional enrichment APIs (Safe Browsing, VirusTotal, URLhaus, RDAP) only send the URL string to external threat-intelligence services — they never navigate to the URL itself.

### 2. Cross-Site Scripting (XSS)
**Risk:** User-submitted text rendered as HTML could execute malicious scripts.
**Mitigation:** All user text is passed through `html.escape()` before any `unsafe_allow_html` rendering in Streamlit. The highlighted message view escapes text segment by segment.

### 3. Prompt Injection (AI Layer)
**Risk:** A crafted message could manipulate Claude's behaviour if the AI layer is enabled.
**Mitigation:** The AI layer is **off by default**, behind a user consent toggle. It is only used for two narrow tasks: (a) rewriting finding explanations in simpler language, and (b) reading text from screenshots when Tesseract is unavailable. The AI **never sets or changes the risk score**. Phone numbers and email addresses are stripped before sending text to the API.

### 4. Data Privacy
**Risk:** Sensitive message content could be logged or stored.
**Mitigation:**
- PhishNet **never stores or logs message content**.
- Only anonymous aggregate counters (tier counts, rule-hit counts by ID) are stored in a local SQLite database for institutional dashboards.
- No third-party analytics or trackers are included.
- The AI layer only sends text externally when the user explicitly enables it.

### 5. API Abuse
**Risk:** The REST API could be abused for mass scanning or denial of service.
**Mitigation:**
- API authentication via `X-API-Key` header.
- Per-key rate limiting (60 requests/minute).
- Per-session rate limiting in the Streamlit UI (20 analyses/minute).
- Input length validation (10–5000 characters).

### 6. Secret Management
**Risk:** API keys could be leaked in source code or logs.
**Mitigation:**
- All secrets are loaded exclusively from environment variables or Streamlit's `st.secrets`.
- `.env` is in `.gitignore`.
- `.streamlit/secrets.toml` is in `.gitignore`.
- No secrets are ever logged or displayed.

### 7. Dependency Supply Chain
**Risk:** Compromised dependencies could introduce vulnerabilities.
**Mitigation:**
- All dependencies are pinned to specific versions in `requirements.txt`.
- GitHub Actions CI runs on every push to verify build integrity.
- Docker image uses `python:3.11-slim` as the base.

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue.
2. Email the maintainers with details of the vulnerability.
3. Allow up to 72 hours for an initial response.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
