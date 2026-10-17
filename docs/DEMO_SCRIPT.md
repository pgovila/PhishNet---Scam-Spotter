# PhishNet Demo Script — 90 Seconds

## Shot List

### 0:00–0:10 — Intro
- Show the PhishNet home page with tagline: "Spot the bait. See the hook. Skip the ask."
- Brief explanation: "PhishNet analyses suspicious messages to protect you from scams."

### 0:10–0:25 — SBI KYC Scam (HIGH RISK)
- Click the **"SBI KYC scam"** example button.
- Message auto-fills: *"SBI ALERT: Your KYC is incomplete and your account will be blocked today…"*
- Click **"🔍 Analyse"**.
- Show results:
  - Score: **100/100** (raw: 120, capped)
  - Tier: **⛔ HIGH RISK**
  - Highlighted message with Bait (SBI), Hook (urgency, fear), Ask (link, OTP) marked
  - Findings table grouped by Bait / Hook / Ask
  - "Do not click", "Call 1930" next steps

### 0:25–0:35 — India Post Parcel Fee Scam (HIGH RISK)
- Paste: *"INDIA POST: Your parcel is held for an unpaid Rs 25 fee. Pay within 2 hours at indiapost-fee.example/pay."*
- Analyse → Score: **95**, Tier: **HIGH**
- Point out: brand impersonation in the link, payment demand, urgency

### 0:35–0:45 — Hinglish KYC Scam (HIGH RISK)
- Paste: *"Aapka bank account aaj band ho jayega. KYC turant update karein aur OTP bata dein."*
- Analyse → Score: **85**, Tier: **HIGH**
- Highlight: Hinglish detection works (aaj, turant, bata dein)

### 0:45–0:55 — No False Alarms
- **Class notice:** *"Class moved to 3 PM today, Room 204."*
  - Score: **15**, Tier: **✅ LOW RISK** — just "today" triggers mild pressure, no ask
- **Genuine OTP:** *"Your OTP is 482913 for SBI. Never share it with anyone."*
  - Score: **10**, Tier: **✅ LOW RISK** — protective context detected, OTP not flagged

### 0:55–1:05 — Hindi Toggle & Report
- Switch language to **हिन्दी** in the sidebar
- Show the UI in Hindi
- Scroll to the **"Copy Report"** section
- Show the plain-text report with date, findings, and cybercrime.gov.in links
- Toggle "Include message text" checkbox

### 1:05–1:15 — API Demo
- Switch to terminal
- Run:
  ```bash
  curl -X POST http://localhost:8000/v1/analyze \
    -H "Content-Type: application/json" \
    -H "X-API-Key: demo-key" \
    -d '{"text": "SBI ALERT: Your KYC is incomplete. Share OTP now."}'
  ```
- Show JSON response with findings, score, tier

### 1:15–1:30 — Summary
- "PhishNet uses transparent, rules-based scoring — you see exactly why a message is flagged."
- "Works in English, Hindi, and Hinglish."
- "Privacy-first: your messages are never stored."
- "Report scams directly to cybercrime.gov.in and DoT Chakshu."
- End on tagline: **"Spot the bait. See the hook. Skip the ask."**

---

## Recording Tips
- Use 1280×720 or higher resolution
- Dark theme makes the UI pop on recording
- Speak slowly and clearly
- Keep cursor movements deliberate
- Total runtime target: **90 seconds** (max 120 seconds)
