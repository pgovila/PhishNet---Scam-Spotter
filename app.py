"""PhishNet — Streamlit UI.

Spot the bait. See the hook. Skip the ask.

A scam message analyser for SMS, WhatsApp, and email, aimed at users in India.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

from phishnet.engine import (
    NEXT_STEPS_HI,
    AnalysisResult,
    Finding,
    analyse,
    load_rules,
    normalise,
)
from phishnet.i18n import t
from phishnet.links import analyse_links, extract_urls
from phishnet.report import generate_report

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="PhishNet — Scam Message Analyser",
    page_icon="🎣",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Constants ─────────────────────────────────────────────────────────────────

BG_DARK = "#14171C"
CARD_BG = "#1E232B"
TEXT_WHITE = "#FFFFFF"
TEXT_MUTED = "#9CA3AF"
CRIMSON = "#EF4444"
AMBER = "#F5A524"
EMERALD = "#10B981"
ACCENT_BLUE = "#3B82F6"

MAX_INPUT = 5000
MIN_INPUT = 10

DATA_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "phishnet_stats.db"

# ── Rate limiting ─────────────────────────────────────────────────────────────

RATE_LIMIT = 20  # max analyses per session
RATE_WINDOW = 60  # seconds


def _check_rate_limit() -> bool:
    """Check per-session rate limit. Returns True if allowed."""
    now = time.time()
    if "rate_timestamps" not in st.session_state:
        st.session_state.rate_timestamps = []

    # Clean old entries
    st.session_state.rate_timestamps = [
        ts for ts in st.session_state.rate_timestamps if now - ts < RATE_WINDOW
    ]

    if len(st.session_state.rate_timestamps) >= RATE_LIMIT:
        return False

    st.session_state.rate_timestamps.append(now)
    return True


# ── Anonymous stats (no message content) ──────────────────────────────────────


def _init_db() -> None:
    """Initialise SQLite for anonymous aggregate counters."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            tier TEXT NOT NULL,
            rule_hits TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _record_stats(result: AnalysisResult) -> None:
    """Record anonymous aggregate counters — NEVER stores message text."""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        rule_hits = json.dumps([f.rule_id for f in result.findings if not f.protective])
        conn.execute(
            "INSERT INTO stats (ts, tier, rule_hits) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), result.tier, rule_hits),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # Never break UX for stats


def _get_telemetry_stats() -> dict[str, Any]:
    """Fetch aggregate anonymous telemetry counters from SQLite.

    Reflects actual recorded scans with zero hardcoded offsets.
    """
    from collections import defaultdict

    total_scans = 0
    tier_counts: dict[str, int] = {}
    rule_freq: dict[str, int] = defaultdict(int)

    try:
        if DB_PATH.exists():
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.cursor()
            cursor.execute("SELECT tier, COUNT(*) FROM stats GROUP BY tier")
            for row in cursor.fetchall():
                tier_counts[row[0]] = row[1]
            cursor.execute("SELECT COUNT(*) FROM stats")
            total_scans = cursor.fetchone()[0] or 0

            cursor.execute("SELECT rule_hits FROM stats ORDER BY id DESC LIMIT 500")
            for (raw_hits,) in cursor.fetchall():
                try:
                    for h in json.loads(raw_hits):
                        rule_freq[h] += 1
                except Exception:
                    pass
            conn.close()
    except Exception:
        pass

    top_tactics = [
        ("Account Threat / Block Threats", rule_freq.get("hook_fear", 0)),
        ("Fake Urgency & Immediate Demands", rule_freq.get("hook_pressure", 0)),
        ("Risky / Look-alike Domains", rule_freq.get("ask_link", 0)),
        ("OTP & Security Code Harvest", rule_freq.get("ask_otp", 0)),
        ("Impersonated Bank Authorities", rule_freq.get("bait_brand", 0)),
        ("Dangerous APK Sideloading", rule_freq.get("ask_apk_install", 0)),
    ]

    return {
        "total_scans": total_scans,
        "high_count": tier_counts.get("high", 0),
        "med_count": tier_counts.get("medium", 0),
        "low_count": tier_counts.get("low", 0),
        "top_tactics": top_tactics,
    }


# ── OCR helpers ───────────────────────────────────────────────────────────────


def _ocr_tesseract(image_bytes: bytes) -> str:
    """Extract text from image using Tesseract OCR (eng+hin)."""
    try:
        import io

        # pyrefly: ignore[missing-import]
        import pytesseract
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        text = pytesseract.image_to_string(img, lang="eng+hin")
        return text.strip()
    except Exception as e:
        logging.warning("Tesseract OCR failed: %s", e)
        return ""


def _ocr_claude(image_bytes: bytes) -> str:
    """Extract text from image using Claude vision API."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    model = os.environ.get("ANTHROPIC_MODEL")
    if not api_key or not model:
        return ""

    try:
        # pyrefly: ignore[missing-import]
        import base64

        # pyrefly: ignore[missing-import]
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        b64_image = base64.standard_b64encode(image_bytes).decode("utf-8")

        message = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": b64_image,
                            },
                        },
                        {
                            "type": "text",
                            "text": "Extract all text from this screenshot exactly as it appears. Return only the extracted text, nothing else.",
                        },
                    ],
                }
            ],
        )
        return message.content[0].text.strip()
    except Exception as e:
        logging.warning("Claude OCR failed: %s", e)
        return ""


# ── AI simplification ────────────────────────────────────────────────────────


def _strip_pii(text: str) -> str:
    """Remove phone numbers and email addresses before sending to AI."""
    import re

    text = re.sub(r"\b\d{10,13}\b", "[PHONE]", text)
    text = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b", "[EMAIL]", text)
    return text


def _ai_simplify(findings: list[Finding], lang: str) -> dict[str, str]:
    """Get AI-simplified explanations for findings.

    Returns dict mapping rule_id → simplified reason.
    AI never sets or changes scores.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    model = os.environ.get("ANTHROPIC_MODEL")
    if not api_key or not model:
        return {}

    try:
        # pyrefly: ignore[missing-import]
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        findings_text = "\n".join(
            f"- {f.label}: matched '{_strip_pii(f.matched_text)}'"
            for f in findings
            if not f.protective
        )

        target_lang = "simple Hindi" if lang == "hi" else "simple English"
        prompt = (
            f"Explain each finding below in {target_lang} for an elderly person "
            f"who is not tech-savvy. One short sentence per finding. "
            f"Do NOT assign scores or risk levels.\n\n{findings_text}"
        )

        message = client.messages.create(
            model=model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text.strip()
        # Parse response — each line corresponds to a finding
        simplified: dict[str, str] = {}
        lines = [
            line.strip().lstrip("- •").strip() for line in response_text.split("\n") if line.strip()
        ]
        active_findings = [f for f in findings if not f.protective]
        for i, f in enumerate(active_findings):
            if i < len(lines):
                simplified[f.rule_id] = lines[i]

        return simplified
    except Exception as e:
        logging.warning("AI simplification failed: %s", e)
        return {}


# ── CSS ───────────────────────────────────────────────────────────────────────


def _inject_css() -> None:
    """Inject custom CSS for a futuristic cybersecurity command center UI."""
    st.markdown(
        f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        /* Global typography & background */
        html, body, [class*="css"], .stApp {{
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
            background-color: #070B14 !important;
            color: #F8FAFC !important;
        }}

        .stApp {{
            background:
                radial-gradient(ellipse at 50% -10%, rgba(56, 189, 248, 0.16) 0%, rgba(99, 102, 241, 0.08) 35%, transparent 70%),
                radial-gradient(circle at 95% 30%, rgba(168, 85, 247, 0.08) 0%, transparent 45%),
                radial-gradient(circle at 5% 70%, rgba(59, 130, 246, 0.07) 0%, transparent 45%),
                #070B14 !important;
            background-attachment: fixed !important;
        }}
        .stApp header {{
            background-color: transparent !important;
        }}

        /* Glassmorphic cards */
        .phishnet-card {{
            background: linear-gradient(135deg, rgba(17, 24, 39, 0.85) 0%, rgba(15, 23, 42, 0.7) 100%);
            border-radius: 20px;
            padding: 24px 28px;
            margin: 16px 0;
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 16px 40px -8px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(16px);
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }}
        .phishnet-card:hover {{
            border-color: rgba(255, 255, 255, 0.14);
        }}

        /* Hero Header */
        .hero-container {{
            text-align: center;
            padding: 10px 0 20px 0;
        }}
        .hero-pill {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 16px;
            border-radius: 9999px;
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.25);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.8px;
            color: #38BDF8;
            text-transform: uppercase;
            margin-bottom: 12px;
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.15);
        }}
        .pulse-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #38BDF8;
            box-shadow: 0 0 8px #38BDF8;
            animation: pulse-glow 2s infinite;
        }}
        @keyframes pulse-glow {{
            0% {{ transform: scale(0.95); opacity: 0.8; }}
            50% {{ transform: scale(1.3); opacity: 1; }}
            100% {{ transform: scale(0.95); opacity: 0.8; }}
        }}

        .hero-title {{
            font-family: 'Outfit', sans-serif !important;
            font-size: 3.2rem !important;
            font-weight: 900 !important;
            letter-spacing: -1px !important;
            margin: 0 !important;
            background: linear-gradient(135deg, #FFFFFF 20%, #93C5FD 50%, #C084FC 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 4px 20px rgba(99, 102, 241, 0.2);
            line-height: 1.15 !important;
        }}
        .hero-tagline {{
            font-size: 1.15rem;
            font-weight: 500;
            color: #94A3B8;
            margin-top: 10px;
            letter-spacing: 0.2px;
        }}
        .hero-tagline strong {{
            color: #F1F5F9;
        }}
        .hero-tagline .highlight-ask {{
            color: #C084FC;
            font-weight: 700;
        }}

        /* DPDP Act 2023 Shield Banner */
        .dpdp-shield-card {{
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.09) 0%, rgba(56, 189, 248, 0.05) 100%);
            border: 1px solid rgba(16, 185, 129, 0.28);
            border-radius: 16px;
            padding: 16px 20px;
            margin: 18px 0 24px 0;
            display: flex;
            align-items: center;
            gap: 16px;
            box-shadow: 0 6px 24px -4px rgba(16, 185, 129, 0.12);
        }}
        .dpdp-icon-box {{
            font-size: 1.8rem;
            flex-shrink: 0;
            background: rgba(16, 185, 129, 0.15);
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .dpdp-content {{
            flex-grow: 1;
            font-size: 0.88rem;
            line-height: 1.5;
            color: #CBD5E1;
        }}
        .dpdp-badge {{
            display: inline-block;
            background: rgba(16, 185, 129, 0.2);
            color: #34D399;
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.6px;
            padding: 2px 8px;
            border-radius: 6px;
            text-transform: uppercase;
            margin-right: 6px;
            vertical-align: middle;
        }}

        /* Circular SVG Gauge & Tier Display */
        .score-gauge-container {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px 20px;
            text-align: center;
        }}
        .gauge-wrapper {{
            position: relative;
            width: 170px;
            height: 170px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .radial-gauge {{
            width: 100%;
            height: 100%;
            transform: rotate(-90deg);
        }}
        .gauge-track {{
            fill: none;
            stroke: rgba(255, 255, 255, 0.06);
            stroke-width: 12;
        }}
        .gauge-progress {{
            fill: none;
            stroke-width: 12;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-out;
        }}
        .gauge-center-content {{
            position: absolute;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}
        .gauge-score-value {{
            font-family: 'Outfit', sans-serif;
            font-size: 3.2rem;
            font-weight: 900;
            line-height: 1;
            letter-spacing: -1px;
        }}
        .gauge-score-total {{
            font-size: 0.82rem;
            color: #94A3B8;
            font-weight: 600;
            margin-top: 2px;
        }}
        .gauge-label-pill {{
            margin-top: 14px;
            font-size: 0.85rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #94A3B8;
        }}

        /* Tier Card */
        .tier-card {{
            display: flex;
            flex-direction: column;
            justify-content: center;
            padding: 24px 26px;
            height: 100%;
            position: relative;
            border-radius: 20px;
        }}
        .tier-card.tier-high {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(15, 23, 42, 0.7) 100%);
            border: 1px solid rgba(239, 68, 68, 0.35);
            box-shadow: 0 8px 32px -4px rgba(239, 68, 68, 0.2);
        }}
        .tier-card.tier-medium {{
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, rgba(15, 23, 42, 0.7) 100%);
            border: 1px solid rgba(245, 158, 11, 0.35);
            box-shadow: 0 8px 32px -4px rgba(245, 158, 11, 0.2);
        }}
        .tier-card.tier-low {{
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(15, 23, 42, 0.7) 100%);
            border: 1px solid rgba(16, 185, 129, 0.35);
            box-shadow: 0 8px 32px -4px rgba(16, 185, 129, 0.2);
        }}
        .tier-badge-pill {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 10px 18px;
            border-radius: 9999px;
            font-family: 'Outfit', sans-serif;
            font-size: 1.15rem;
            font-weight: 800;
            letter-spacing: 0.5px;
            width: fit-content;
            margin-bottom: 12px;
        }}
        .tier-badge-pill.tier-high {{
            background: rgba(239, 68, 68, 0.2);
            color: #F87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.25);
        }}
        .tier-badge-pill.tier-medium {{
            background: rgba(245, 158, 11, 0.2);
            color: #FBBF24;
            border: 1px solid rgba(245, 158, 11, 0.4);
            box-shadow: 0 0 20px rgba(245, 158, 11, 0.25);
        }}
        .tier-badge-pill.tier-low {{
            background: rgba(16, 185, 129, 0.2);
            color: #34D399;
            border: 1px solid rgba(16, 185, 129, 0.4);
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.25);
        }}
        .tier-subtitle {{
            font-size: 0.92rem;
            line-height: 1.5;
            color: #CBD5E1;
        }}

        /* Findings Micro-Cards */
        .finding-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            margin: 8px 0;
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-left: 5px solid;
            transition: all 0.2s ease;
        }}
        .finding-row:hover {{
            background: rgba(30, 41, 59, 0.7);
            border-color: rgba(255, 255, 255, 0.1);
            transform: translateX(2px);
        }}
        .finding-bait {{ border-left-color: {AMBER}; }}
        .finding-hook {{ border-left-color: {CRIMSON}; }}
        .finding-ask {{ border-left-color: #A855F7; }}
        .finding-protective {{ border-left-color: {EMERALD}; }}

        .finding-label {{
            font-weight: 700;
            font-size: 0.98rem;
            color: #F8FAFC;
        }}
        .finding-match {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.84rem;
            color: #94A3B8;
            background: rgba(0, 0, 0, 0.35);
            padding: 3px 8px;
            border-radius: 6px;
            display: inline-block;
            margin-top: 4px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        .finding-reason {{
            font-size: 0.85rem;
            color: #CBD5E1;
            margin-top: 5px;
            line-height: 1.4;
        }}
        .finding-points {{
            font-family: 'Outfit', sans-serif;
            font-weight: 800;
            font-size: 1.15rem;
            padding: 4px 12px;
            border-radius: 8px;
            white-space: nowrap;
        }}
        .points-positive {{
            color: #F87171;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.25);
        }}
        .points-zero {{
            color: #34D399;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.25);
        }}

        /* Message Highlight Inspector */
        .msg-inspector-container {{
            border-radius: 14px;
            overflow: hidden;
            background: #0B0F19;
            border: 1px solid rgba(255, 255, 255, 0.08);
            margin-top: 8px;
        }}
        .msg-inspector-bar {{
            background: rgba(255, 255, 255, 0.04);
            padding: 10px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        .window-dots {{
            display: flex;
            gap: 6px;
        }}
        .dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }}
        .dot-red {{ background: #EF4444; }}
        .dot-yellow {{ background: #F59E0B; }}
        .dot-green {{ background: #10B981; }}
        .inspector-title {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 1px;
            color: #94A3B8;
            text-transform: uppercase;
        }}
        .msg-highlight {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-size: 1.05rem;
            line-height: 1.9;
            padding: 20px;
            word-wrap: break-word;
            color: #F1F5F9;
        }}
        .hl-bait {{
            background: rgba(245, 158, 11, 0.22);
            color: #FDE68A;
            border-bottom: 2px solid {AMBER};
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .hl-hook {{
            background: rgba(239, 68, 68, 0.22);
            color: #FECACA;
            border-bottom: 2px solid {CRIMSON};
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .hl-ask {{
            background: rgba(168, 85, 247, 0.22);
            color: #E9D5FF;
            border-bottom: 2px solid #8B5CF6;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .hl-protective {{
            background: rgba(16, 185, 129, 0.18);
            color: #A7F3D0;
            border-bottom: 2px dashed {EMERALD};
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
        }}

        /* Category Headers */
        .cat-header {{
            font-family: 'Outfit', sans-serif;
            font-size: 1.05rem;
            font-weight: 800;
            margin: 18px 0 10px 0;
            padding: 8px 14px;
            border-radius: 10px;
            letter-spacing: 0.3px;
        }}
        .cat-bait {{ background: rgba(245, 158, 11, 0.12); color: {AMBER}; border: 1px solid rgba(245, 158, 11, 0.2); }}
        .cat-hook {{ background: rgba(239, 68, 68, 0.12); color: {CRIMSON}; border: 1px solid rgba(239, 68, 68, 0.2); }}
        .cat-ask {{ background: rgba(139, 92, 246, 0.12); color: #8B5CF6; border: 1px solid rgba(139, 92, 246, 0.2); }}

        /* Next Steps Checklist */
        .next-step-card {{
            padding: 12px 16px;
            margin: 8px 0;
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.05);
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 0.95rem;
            color: #E2E8F0;
        }}

        /* Streamlit Input Overrides */
        .stTextArea textarea {{
            background: rgba(15, 23, 42, 0.7) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            border-radius: 14px !important;
            color: #F8FAFC !important;
            font-size: 1rem !important;
            line-height: 1.6 !important;
            backdrop-filter: blur(12px) !important;
            transition: all 0.25s ease !important;
        }}
        .stTextArea textarea:focus {{
            border-color: #38BDF8 !important;
            box-shadow: 0 0 25px rgba(56, 189, 248, 0.25) !important;
        }}

        /* Buttons */
        div[data-testid="stButton"] > button[kind="primary"],
        .stButton > button[kind="primary"] {{
            background: linear-gradient(135deg, #2563EB 0%, #7C3AED 50%, #C026D3 100%) !important;
            color: #FFFFFF !important;
            font-family: 'Outfit', sans-serif !important;
            font-weight: 800 !important;
            letter-spacing: 0.5px !important;
            border: none !important;
            border-radius: 14px !important;
            padding: 14px 28px !important;
            font-size: 1.1rem !important;
            box-shadow: 0 8px 25px -4px rgba(124, 58, 237, 0.5) !important;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }}
        div[data-testid="stButton"] > button[kind="primary"]:hover {{
            transform: translateY(-2px) !important;
            box-shadow: 0 12px 30px -4px rgba(124, 58, 237, 0.7) !important;
        }}

        /* Example Chip Buttons */
        div[data-testid="column"] button {{
            background: rgba(30, 41, 59, 0.65) !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            color: #E2E8F0 !important;
            font-size: 0.85rem !important;
            font-weight: 600 !important;
            border-radius: 10px !important;
            padding: 8px 12px !important;
            transition: all 0.2s ease !important;
        }}
        div[data-testid="column"] button:hover {{
            background: rgba(56, 189, 248, 0.15) !important;
            border-color: rgba(56, 189, 248, 0.4) !important;
            color: #38BDF8 !important;
            transform: translateY(-1px) !important;
        }}

        /* Mobile adjustments */
        @media (max-width: 768px) {{
            .hero-title {{ font-size: 2.2rem !important; }}
            .finding-row {{ flex-direction: column; align-items: flex-start; gap: 8px; }}
            .dpdp-shield-card {{ flex-direction: column; text-align: center; }}
        }}

        /* Footer */
        .footer-container {{
            text-align: center;
            padding: 30px 20px 20px 20px;
            color: #94A3B8;
            font-size: 0.85rem;
            border-top: 1px solid rgba(255, 255, 255, 0.06);
            margin-top: 48px;
            line-height: 1.7;
        }}
        .footer-links {{
            margin-top: 8px;
            font-size: 0.8rem;
        }}
        .footer-links a {{
            color: #38BDF8;
            text-decoration: none;
            margin: 0 8px;
        }}
        /* Tab Navigation Overrides */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 12px;
            background: rgba(15, 23, 42, 0.65);
            padding: 8px 12px;
            border-radius: 14px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            margin-bottom: 24px;
        }}
        .stTabs [data-baseweb="tab"] {{
            border-radius: 10px;
            padding: 8px 18px;
            font-family: 'Outfit', sans-serif;
            font-weight: 700;
            font-size: 0.95rem;
            color: #94A3B8;
            border: none !important;
            transition: all 0.2s ease;
        }}
        .stTabs [aria-selected="true"] {{
            background: linear-gradient(135deg, rgba(56, 189, 248, 0.2) 0%, rgba(99, 102, 241, 0.25) 100%) !important;
            color: #F8FAFC !important;
            border: 1px solid rgba(56, 189, 248, 0.35) !important;
        }}

        /* Telemetry Cards */
        .telemetry-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            gap: 16px;
            margin: 16px 0;
        }}
        .telemetry-stat-card {{
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 18px;
            text-align: center;
        }}
        .stat-number {{
            font-family: 'Outfit', sans-serif;
            font-size: 2.2rem;
            font-weight: 900;
            color: #38BDF8;
            line-height: 1.1;
        }}
        .stat-label {{
            font-size: 0.82rem;
            color: #94A3B8;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            margin-top: 6px;
        }}

        /* Benchmark Banner */
        .benchmark-banner {{
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(15, 23, 42, 0.7) 100%);
            border: 1px solid rgba(16, 185, 129, 0.35);
            border-radius: 16px;
            padding: 20px;
            margin: 20px 0;
        }}
        .benchmark-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-top: 14px;
            text-align: center;
        }}
        .benchmark-stat-num {{
            font-family: 'Outfit', sans-serif;
            font-size: 1.8rem;
            font-weight: 900;
            color: #34D399;
        }}
        .benchmark-stat-lbl {{
            font-size: 0.75rem;
            color: #CBD5E1;
            font-weight: 600;
            text-transform: uppercase;
        }}

        /* Pricing & Business Cards */
        .pricing-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 18px;
            margin: 20px 0;
        }}
        .pricing-card {{
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 18px;
            padding: 24px;
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}
        .pricing-card.featured {{
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.14) 0%, rgba(15, 23, 42, 0.85) 100%);
            border: 1px solid rgba(99, 102, 241, 0.45);
            box-shadow: 0 10px 30px -5px rgba(99, 102, 241, 0.25);
        }}
        .price-tag {{
            font-family: 'Outfit', sans-serif;
            font-size: 2.3rem;
            font-weight: 900;
            color: #F8FAFC;
            margin: 10px 0;
        }}
        .price-pilot-badge {{
            display: inline-block;
            background: rgba(245, 158, 11, 0.18);
            color: #FBBF24;
            border: 1px solid rgba(245, 158, 11, 0.35);
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 800;
            padding: 2px 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            vertical-align: middle;
            margin-left: 6px;
        }}
        .pricing-feature-list {{
            list-style: none;
            padding: 0;
            margin: 16px 0;
            font-size: 0.88rem;
            color: #CBD5E1;
            line-height: 1.8;
        }}
        .pricing-feature-list li::before {{
            content: "✓ ";
            color: #38BDF8;
            font-weight: 800;
        }}

        /* Welcome & Onboarding Guide */
        .welcome-hero {{
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(168, 85, 247, 0.12) 50%, rgba(15, 23, 42, 0.8) 100%);
            border: 1px solid rgba(168, 85, 247, 0.35);
            border-radius: 20px;
            padding: 30px 28px;
            margin-bottom: 24px;
            box-shadow: 0 12px 36px -8px rgba(99, 102, 241, 0.25);
            position: relative;
            overflow: hidden;
        }}
        .welcome-hero h2 {{
            font-family: 'Outfit', sans-serif;
            font-size: 2.1rem;
            font-weight: 900;
            margin: 0 0 10px 0;
            background: linear-gradient(135deg, #FFFFFF 30%, #93C5FD 70%, #C084FC 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .welcome-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }}
        .welcome-card {{
            background: rgba(15, 23, 42, 0.65);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 20px 22px;
            transition: all 0.2s ease;
        }}
        .welcome-card:hover {{
            background: rgba(30, 41, 59, 0.7);
            border-color: rgba(99, 102, 241, 0.4);
            transform: translateY(-2px);
        }}
        .welcome-step-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            border-radius: 10px;
            font-weight: 900;
            font-size: 0.95rem;
            margin-bottom: 12px;
        }}
        .step-1 {{ background: rgba(56, 189, 248, 0.2); color: #38BDF8; border: 1px solid rgba(56, 189, 248, 0.4); }}
        .step-2 {{ background: rgba(245, 158, 11, 0.2); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .step-3 {{ background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .step-4 {{ background: rgba(16, 185, 129, 0.2); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.4); }}
    </style>
    """,
        unsafe_allow_html=True,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _score_color(score: int) -> str:
    """Get color for score value."""
    if score >= 55:
        return CRIMSON
    if score >= 25:
        return AMBER
    return EMERALD


def _tier_css(tier: str) -> str:
    """Get CSS class for tier."""
    return f"tier-{tier}"


def _highlight_message(text: str, findings: list[Finding]) -> str:
    """Highlight matched spans in the message text.

    HTML-escapes all text first (XSS prevention), then wraps matched
    spans in highlight spans.
    """
    # Sort findings by span start (descending) so we can insert from the end
    sorted_findings = sorted(
        [f for f in findings if f.span[1] <= len(text)],
        key=lambda f: f.span[0],
        reverse=True,
    )

    # We need to map spans from original text to escaped text
    # Build a mapping: original_index → escaped_index
    # Since html.escape can change length, we need to track this
    # For simplicity, work on the original text and escape per-segment

    # Collect non-overlapping spans
    used: list[tuple[int, int]] = []
    valid_findings: list[Finding] = []
    for f in sorted_findings:
        s, e = f.span
        if not any(s < ue and e > us for us, ue in used):
            used.append((s, e))
            valid_findings.append(f)

    # Sort by position ascending for building output
    valid_findings.sort(key=lambda f: f.span[0])

    parts: list[str] = []
    pos = 0
    for f in valid_findings:
        s, e = f.span
        if s > pos:
            parts.append(html.escape(text[pos:s]))
        css_class = f"hl-{f.category}" if not f.protective else "hl-protective"
        parts.append(f'<span class="{css_class}">{html.escape(text[s:e])}</span>')
        pos = e
    if pos < len(text):
        parts.append(html.escape(text[pos:]))

    return "".join(parts)


def _render_gauge(score: int, lang: str) -> None:
    """Render a premium circular SVG risk score gauge."""
    color = _score_color(score)
    circumference = 427
    clamped_score = max(0, min(score, 100))
    offset = circumference - (circumference * clamped_score / 100)

    gauge_svg = f"""
    <div class="phishnet-card score-gauge-container">
        <div class="gauge-wrapper">
            <svg class="radial-gauge" viewBox="0 0 170 170">
                <defs>
                    <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="{color}" stop-opacity="0.75"/>
                        <stop offset="100%" stop-color="{color}"/>
                    </linearGradient>
                    <filter id="gaugeShadow" x="-20%" y="-20%" width="140%" height="140%">
                        <feDropShadow dx="0" dy="0" stdDeviation="5" flood-color="{color}" flood-opacity="0.45"/>
                    </filter>
                </defs>
                <circle cx="85" cy="85" r="68" class="gauge-track"/>
                <circle cx="85" cy="85" r="68" class="gauge-progress"
                    stroke="url(#gaugeGrad)"
                    stroke-dasharray="{circumference}"
                    stroke-dashoffset="{offset}"
                    filter="url(#gaugeShadow)"/>
            </svg>
            <div class="gauge-center-content">
                <div class="gauge-score-value" style="color: {color};">{score}</div>
                <div class="gauge-score-total">/ 100</div>
            </div>
        </div>
        <div class="gauge-label-pill">{t("score_label", lang)}</div>
    </div>
    """
    st.markdown(gauge_svg, unsafe_allow_html=True)


def _render_tier_badge(tier: str, lang: str) -> None:
    """Render the tier badge with vibrant styling and guidance subtitle."""
    badge_text = t(f"tier_{tier}", lang)
    tier_subtitles = {
        "high": "High-confidence deception markers detected. Refrain from clicking links or sharing any OTP/passwords.",
        "medium": "Unverified or suspicious urgency signals detected. Verify authenticity before proceeding.",
        "low": "No high-risk malicious asks detected. Appears consistent with normal notifications or protective alerts.",
    }
    subtitle = tier_subtitles.get(tier, "")
    st.markdown(
        f"""
    <div class="phishnet-card tier-card {_tier_css(tier)}">
        <div class="tier-badge-pill {_tier_css(tier)}">
            <span>{badge_text}</span>
        </div>
        <div class="tier-subtitle">{subtitle}</div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def _render_findings(findings: list[Finding], lang: str, ai_explanations: dict[str, str]) -> None:
    """Render the findings table grouped by category with clean HTML cards."""
    categories = {"bait": [], "hook": [], "ask": []}
    for f in findings:
        cat = f.category if f.category in categories else "ask"
        categories[cat].append(f)

    cat_labels = {
        "bait": t("category_bait", lang),
        "hook": t("category_hook", lang),
        "ask": t("category_ask", lang),
    }
    cat_css = {"bait": "cat-bait", "hook": "cat-hook", "ask": "cat-ask"}

    for cat, cat_findings in categories.items():
        if not cat_findings:
            continue

        st.markdown(
            f'<div class="cat-header {cat_css[cat]}">{cat_labels[cat]}</div>',
            unsafe_allow_html=True,
        )

        # Group by rule_id so multiple matched phrases are displayed neatly together
        grouped_by_rule: dict[str, list[Finding]] = {}
        for f in cat_findings:
            grouped_by_rule.setdefault(f.rule_id, []).append(f)

        for _rule_id, rule_group in grouped_by_rule.items():
            primary_f = max(rule_group, key=lambda f: f.points)
            is_protective = any(f.protective for f in rule_group)
            total_points = max(f.points for f in rule_group) if not is_protective else 0

            finding_css = f"finding-{cat}" if not is_protective else "finding-protective"

            label = primary_f.label_hi if lang == "hi" else primary_f.label
            if is_protective:
                label = t("protective_label", lang)

            points_html = (
                '<span class="finding-points points-zero">0 pts</span>'
                if is_protective
                else f'<span class="finding-points points-positive">+{total_points} pts</span>'
            )

            # Collect unique matched phrases in this rule
            unique_phrases = []
            seen_phrases = set()
            for f in rule_group:
                cleaned = f.matched_text.strip()
                if cleaned and cleaned not in seen_phrases:
                    seen_phrases.add(cleaned)
                    unique_phrases.append(cleaned)

            matches_display = " · ".join(f'"{html.escape(m[:80])}"' for m in unique_phrases)

            reason_text = (
                primary_f.reason_hi if lang == "hi" and primary_f.reason_hi else primary_f.reason
            )
            reason_html = ""
            if reason_text:
                why_label = "यह क्यों महत्वपूर्ण है" if lang == "hi" else "Why it matters"
                reason_html = f'<div class="finding-reason">💡 <strong>{why_label}:</strong> {html.escape(reason_text)}</div>'

            ai_html = ""
            if primary_f.rule_id in ai_explanations:
                ai_label = t("ai_simplified", lang)
                ai_html = f'<div class="finding-reason">🤖 {ai_label}: {html.escape(ai_explanations[primary_f.rule_id])}</div>'

            # Build card strictly without blank lines or 4-space markdown indentation
            inner_parts = [
                f'<div class="finding-label">{html.escape(label)}</div>',
                f'<div class="finding-match">{matches_display}</div>',
            ]
            if reason_html:
                inner_parts.append(reason_html)
            if ai_html:
                inner_parts.append(ai_html)

            inner_content = "".join(inner_parts)
            card_html = f'<div class="finding-row {finding_css}"><div>{inner_content}</div>{points_html}</div>'
            st.markdown(card_html, unsafe_allow_html=True)


def _render_next_steps(result: AnalysisResult, lang: str) -> None:
    """Render the 'What to do now' box."""
    steps = NEXT_STEPS_HI.get(result.tier, []) if lang == "hi" else result.next_steps

    st.markdown(
        f"""
    <div class="phishnet-card">
        <h3 style="margin-top: 0; display: flex; align-items: center; gap: 8px;">
            <span>🛡️</span> <span>{t("next_steps_header", lang)}</span>
        </h3>
    """,
        unsafe_allow_html=True,
    )

    for step in steps:
        st.markdown(
            f'<div class="next-step-card">{html.escape(step)}</div>', unsafe_allow_html=True
        )

    st.markdown("</div>", unsafe_allow_html=True)


# ── Load examples ─────────────────────────────────────────────────────────────


@st.cache_data
def _load_examples() -> list[dict]:
    """Load example messages from data/examples.json."""
    path = Path(__file__).resolve().parent / "data" / "examples.json"
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return []


# ── Main app ──────────────────────────────────────────────────────────────────


def main() -> None:
    """PhishNet main application."""
    _inject_css()
    _init_db()

    # ── Sidebar ───────────────────────────────────────────────────────────
    with st.sidebar:
        lang = st.selectbox(
            "🌐 Language / भाषा",
            options=["en", "hi"],
            format_func=lambda x: "English" if x == "en" else "हिन्दी",
        )

        mode = "default"
        if os.environ.get("RULEBOOK_MODE") == "1":
            mode = "rulebook"
            st.info("📋 RULEBOOK_MODE is active")

        st.markdown("---")

        ai_enabled = False
        if os.environ.get("ANTHROPIC_API_KEY"):
            ai_enabled = st.toggle(
                t("ai_consent_label", lang),
                value=False,
                help="When enabled, message text (with PII removed) is sent to Anthropic Claude API for simplified explanations.",
            )

        st.markdown("---")
        st.markdown(
            f'<div style="color: {TEXT_MUTED}; font-size: 0.8rem;">'
            f"PhishNet v1.0.0<br>Forge Realm · SETU 2026</div>",
            unsafe_allow_html=True,
        )

    # ── Header ────────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div class="hero-container">
            <h1 class="hero-title">{t("app_title", lang)}</h1>
            <div class="hero-tagline">{t("tagline", lang)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── DPDP Act 2023 Shield Card ─────────────────────────────────────────
    dpdp_text = t("dpdp_notice", lang)
    st.markdown(
        f"""
        <div class="dpdp-shield-card">
            <div class="dpdp-icon-box">🛡️</div>
            <div class="dpdp-content">
                <span class="dpdp-badge">DPDP PRINCIPLES</span>
                {html.escape(dpdp_text.replace("🛡️ ", ""))}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Tabs Navigation ───────────────────────────────────────────────────
    tab_welcome, tab_inspector, tab_telemetry, tab_pricing = st.tabs(
        [
            "👋 " + ("स्वागत एवं परिचय" if lang == "hi" else "Welcome & Overview"),
            "🔍 " + ("स्कैम डिटेक्टर" if lang == "hi" else "Scam Inspector"),
            "📊 " + ("थ्रेट ट्रेंड्स व विश्लेषण" if lang == "hi" else "Threat Trends & Telemetry"),
            "🏢 " + ("संस्थानों व बैंकों हेतु" if lang == "hi" else "For Colleges & Banks (Pricing)"),
        ]
    )

    # ══════════════════════════════════════════════════════════════════════
    # TAB 0: WELCOME & OVERVIEW
    # ══════════════════════════════════════════════════════════════════════
    with tab_welcome:
        st.markdown(
            f"""
            <div class="welcome-hero">
                <h2>{"PhishNet में आपका स्वागत है!" if lang == "hi" else "Welcome to PhishNet — Scam Spotter"}</h2>
                <div style="font-size: 1.05rem; color: #CBD5E1; line-height: 1.6; max-width: 800px;">
                    {"भारत के नागरिकों, छात्रों, वरिष्ठ नागरिकों और नए डिजिटल भुगतान उपयोगकर्ताओं के लिए बनाया गया एक पारदर्शी, नियम-आधारित साइबर सुरक्षा गार्ड।" if lang == "hi" else "A transparent, deterministic cybersecurity guardian engineered for Indian citizens, students, elderly parents, and first-time digital banking users."}
                </div>
                <div style="margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap;">
                    <span style="background: rgba(99, 102, 241, 0.25); color: #C7D2FE; padding: 4px 12px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; border: 1px solid rgba(99, 102, 241, 0.4);">
                        🎯 Problem Statement 1: Scam Spotter
                    </span>
                    <span style="background: rgba(16, 185, 129, 0.2); color: #6EE7B7; padding: 4px 12px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.4);">
                        🛡️ DPDP Act 2023 Aligned
                    </span>
                    <span style="background: rgba(245, 158, 11, 0.2); color: #FCD34D; padding: 4px 12px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; border: 1px solid rgba(245, 158, 11, 0.4);">
                        ⚡ Zero-Retention Architecture
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            "### 🧠 "
            + (
                "हमारा सिद्धांत: बेट • हुक • आस्क (Bait • Hook • Ask)"
                if lang == "hi"
                else "The Core Mental Model: Bait • Hook • Ask"
            )
        )
        st.markdown(
            (
                "<span style='color:#94A3B8; font-size:0.95rem;'>हम किसी 'ब्लैक-बॉक्स AI' के आधार पर मनमाना फैसला नहीं सुनाते। हर संदिग्ध संदेश को 3 स्पष्ट भागों में परखा जाता है:</span>"
                if lang == "hi"
                else "<span style='color:#94A3B8; font-size:0.95rem;'>Unlike opaque black-box AI tools, PhishNet scores every suspicious message using visible, verifiable rules across three deception pillars:</span>"
            ),
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
            <div class="welcome-grid">
                <div class="welcome-card" style="border-left: 4px solid {AMBER};">
                    <div style="font-size: 1.5rem; margin-bottom: 6px;">🎣</div>
                    <div style="font-weight: 800; font-size: 1.1rem; color: #F8FAFC;">
                        {"1. बेट (Bait) — विश्वास का दुरुपयोग" if lang == "hi" else "1. The Bait — Borrowed Trust"}
                    </div>
                    <div style="font-size: 0.86rem; color: #CBD5E1; margin-top: 6px; line-height: 1.5;">
                        {"किसी प्रतिष्ठित बैंक (SBI, HDFC), सरकारी संस्था (TRAI, Police, Income Tax) या लॉटरी/इनाम का नाम लेकर आपका ध्यान भटकाना।" if lang == "hi" else "Impersonating reputable banks (SBI, HDFC), statutory authorities (Police, TRAI, CBI), or unrealistic prize lures to lower your guard."}
                    </div>
                </div>
                <div class="welcome-card" style="border-left: 4px solid {CRIMSON};">
                    <div style="font-size: 1.5rem; margin-bottom: 6px;">🪝</div>
                    <div style="font-weight: 800; font-size: 1.1rem; color: #F8FAFC;">
                        {"2. हुक (Hook) — जल्दबाज़ी या डर" if lang == "hi" else "2. The Hook — Panic & Urgency"}
                    </div>
                    <div style="font-size: 0.86rem; color: #CBD5E1; margin-top: 6px; line-height: 1.5;">
                        {"'खाता तुरंत बंद हो जाएगा', 'डिजिटल अरेस्ट', 'बिजली कट जाएगी' या '2 घंटे के अंदर' जैसी धमकियां देकर सोचने का समय न देना।" if lang == "hi" else "Fabricating artificial time pressure ('within 2 hours', 'tonight') or fear ('account suspended', 'digital arrest') to trigger panic."}
                    </div>
                </div>
                <div class="welcome-card" style="border-left: 4px solid #A855F7;">
                    <div style="font-size: 1.5rem; margin-bottom: 6px;">✋</div>
                    <div style="font-weight: 800; font-size: 1.1rem; color: #F8FAFC;">
                        {"3. आस्क (Ask) — खतरनाक कदम" if lang == "hi" else "3. The Ask — The Risky Trap"}
                    </div>
                    <div style="font-size: 0.86rem; color: #CBD5E1; margin-top: 6px; line-height: 1.5;">
                        {"अज्ञात लिंक पर क्लिक करना, OTP/PIN मांगना, AnyDesk/APK डाउनलोड कराना, या अज्ञात नंबर पर कॉल करने को कहना।" if lang == "hi" else "The harmful action: unverified link clicks, OTP/PIN requests, malicious APK downloads, remote access apps, or callback traps."}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            "### 🚀 "
            + (
                "ऐप का उपयोग कैसे करें? (Quick Start Guide)"
                if lang == "hi"
                else "How to Use PhishNet (Quick Start Guide)"
            )
        )

        st.markdown(
            f"""
            <div class="welcome-grid">
                <div class="welcome-card">
                    <div class="welcome-step-badge step-1">1</div>
                    <div style="font-weight: 700; color: #F8FAFC; font-size: 0.95rem;">
                        {"संदेश पेस्ट करें या फोटो अपलोड करें" if lang == "hi" else "Paste Text or Upload Screenshot"}
                    </div>
                    <div style="font-size: 0.82rem; color: #94A3B8; margin-top: 4px; line-height: 1.4;">
                        {"'Scam Inspector' टैब पर जाएं और संदिग्ध SMS, वॉट्सऐप या ईमेल पेस्ट करें अथवा स्क्रीनशॉट अपलोड करें।" if lang == "hi" else "Go to the 'Scam Inspector' tab. Paste suspicious SMS/WhatsApp text or upload a screenshot (OCR-enabled)."}
                    </div>
                </div>
                <div class="welcome-card">
                    <div class="welcome-step-badge step-2">2</div>
                    <div style="font-weight: 700; color: #F8FAFC; font-size: 0.95rem;">
                        {"एक क्लिक में एनालिसिस" if lang == "hi" else "Instant Offline Analysis"}
                    </div>
                    <div style="font-size: 0.82rem; color: #94A3B8; margin-top: 4px; line-height: 1.4;">
                        {"'संदेश की जाँच करें' बटन दबाएं। इंजन पारदर्शी अंकों (0-100) के साथ हर संदिग्ध शब्द को हाईलाइट करेगा।" if lang == "hi" else "Click 'Analyse Message'. The deterministic rules engine highlights each deception marker with exact points."}
                    </div>
                </div>
                <div class="welcome-card">
                    <div class="welcome-step-badge step-3">3</div>
                    <div style="font-weight: 700; color: #F8FAFC; font-size: 0.95rem;">
                        {"पहचाना गया घोटाला प्रकार और सलाह" if lang == "hi" else "Scam Classification & Advice"}
                    </div>
                    <div style="font-size: 0.82rem; color: #94A3B8; margin-top: 4px; line-height: 1.4;">
                        {"डिजिटल अरेस्ट, केवाईसी निलंबन, कूरियर शुल्क या कॉल बैक झांसे की तुरंत पहचान और 1-लाइन सुरक्षा निर्देश।" if lang == "hi" else "Identifies specific scam archetypes (Digital Arrest, KYC, Callback Trap) with instant actionable advice."}
                    </div>
                </div>
                <div class="welcome-card">
                    <div class="welcome-step-badge step-4">4</div>
                    <div style="font-weight: 700; color: #F8FAFC; font-size: 0.95rem;">
                        {"पुलिस पोर्टल (1930) हेतु कॉपी-रेडी रिपोर्ट" if lang == "hi" else "One-Click Police Report"}
                    </div>
                    <div style="font-size: 0.82rem; color: #94A3B8; margin-top: 4px; line-height: 1.4;">
                        {"cybercrime.gov.in या राष्ट्रीय हेल्पलाइन 1930 पर सीधे उपयोग करने हेतु तैयार रिपोर्ट एक क्लिक में कॉपी करें।" if lang == "hi" else "Get a pre-formatted complaint text ready to paste directly into cybercrime.gov.in or report to 1930."}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.info(
            (
                "👉 **शुरुआत करें**: ऊपर दिए गए **'🔍 स्कैम डिटेक्टर' (Scam Inspector)** टैब पर क्लिक करें और 'नमूना उदाहरण देखें' बटन दबाकर तुरंत टेस्ट करें!"
                if lang == "hi"
                else "👉 **Ready to try?** Click on the **'🔍 Scam Inspector'** tab above and test with one of the instant sample messages!"
            )
        )

    # ══════════════════════════════════════════════════════════════════════
    # TAB 1: SCAM INSPECTOR
    # ══════════════════════════════════════════════════════════════════════
    with tab_inspector:
        # ── Example buttons ───────────────────────────────────────────────
        examples = _load_examples()
        if "input_text" not in st.session_state:
            st.session_state["input_text"] = ""

        if examples:
            st.markdown(f"**{t('try_examples', lang)}:**")
            cols = st.columns(min(len(examples), 3))
            for i, ex in enumerate(examples):
                col = cols[i % len(cols)]
                with col:
                    if st.button(ex["label"], key=f"ex_{i}", use_container_width=True):
                        st.session_state["input_text"] = ex["text"]
                        st.rerun()

        # ── Input ─────────────────────────────────────────────────────────
        user_input = st.text_area(
            t("input_label", lang),
            height=150,
            max_chars=MAX_INPUT,
            key="input_text",
            placeholder="e.g., SBI ALERT: Your KYC is incomplete…",
        )

        # Screenshot upload
        uploaded_file = st.file_uploader(
            t("upload_label", lang),
            type=["png", "jpg", "jpeg", "webp"],
            key="screenshot_upload",
        )

        if uploaded_file is not None:
            image_bytes = uploaded_file.read()
            with st.spinner("Extracting text from screenshot…"):
                ocr_text = _ocr_tesseract(image_bytes)
                if not ocr_text and ai_enabled:
                    ocr_text = _ocr_claude(image_bytes)
            if ocr_text:
                st.success(f"Extracted {len(ocr_text)} characters from screenshot")
                st.session_state["input_text"] = ocr_text
                st.rerun()
            else:
                st.warning(
                    "Could not extract text from screenshot. Please paste the text manually."
                )

        # Optional SMS Header / Sender Number input
        sender_id = st.text_input(
            "📱 "
            + (
                "एसएमएस हेडर या भेजने वाले का नंबर (वैकल्पिक)"
                if lang == "hi"
                else "SMS Sender Header or Phone Number (Optional)"
            ),
            placeholder="e.g. +91 9876543210 or VM-SBIINB",
            help="Registered banks in India use 6-character alphabetic sender headers (e.g. VK-HDFCBK, AX-SBINB). Personal 10-digit mobile numbers claiming to represent banks or police are spoofed.",
            key="sender_id_input",
        )

        # ── Analyse button ────────────────────────────────────────────────
        if st.button(t("analyse_btn", lang), type="primary", use_container_width=True):
            # Validation
            text = (user_input or "").strip()

            if not text:
                st.warning(t("empty_msg", lang))
                return

            if len(text) < MIN_INPUT:
                st.warning(t("too_short", lang))
                return

            if len(text) > MAX_INPUT:
                st.error(t("too_long", lang))
                return

            # Rate limit
            if not _check_rate_limit():
                st.error("⏳ Too many requests. Please wait a moment.")
                return

            # ── Run analysis ──────────────────────────────────────────────
            with st.spinner("Analysing…"):
                norm_text = normalise(text)

                # Link analysis (offline)
                cfg = load_rules()
                mode_cfg = cfg.get(mode, cfg["default"])
                link_rule = next(
                    (r for r in mode_cfg.get("rules", []) if r["id"] in ("ask_link", "rb_link")),
                    None,
                )
                link_rule_id = link_rule["id"] if link_rule else "ask_link"
                link_points = link_rule["points"] if link_rule else 25

                link_findings = analyse_links(
                    norm_text,
                    link_rule_id=link_rule_id,
                    link_points=link_points,
                )

                # Online enrichment (optional)
                enrichment_results = []
                urls = extract_urls(norm_text)
                if urls:
                    try:
                        from phishnet.enrich import enrich_urls

                        raw_urls = [u.raw for u in urls]
                        enrichment_results = enrich_urls(raw_urls)
                    except Exception:
                        pass

                # Check sender header spoofing (if provided)
                if sender_id and sender_id.strip():
                    sid = sender_id.strip()
                    # If sender is a 10-digit mobile number (+91 or plain)
                    clean_sid = re.sub(r"[\s+-]", "", sid)
                    is_personal_mobile = (len(clean_sid) == 10 and clean_sid.isdigit()) or (
                        len(clean_sid) == 12 and clean_sid.startswith("91")
                    )
                    if is_personal_mobile:
                        # Append sender header spoof finding
                        spoof_finding = Finding(
                            rule_id="bait_sender_spoof",
                            category="bait",
                            label="Unregistered mobile sender spoofing authority",
                            label_hi="व्यक्तिगत मोबाइल नंबर से संस्था का ढोंग",
                            points=20,
                            matched_text=sid,
                            span=(0, 0),
                            reason=f"Message arrived from personal phone number ({sid}). Genuine Indian banks and government bodies use registered TRAI alpha-headers (e.g. VK-HDFCBK, AX-SBINB), never personal 10-digit SIMs.",
                            reason_hi=f"संदेश व्यक्तिगत मोबाइल नंबर ({sid}) से भेजा गया है। असली बैंक और सरकारी विभाग कभी 10-अंकीय मोबाइल नंबर से अलर्ट नहीं भेजते।",
                        )
                        link_findings.append(spoof_finding)

                # Core analysis (unified with optional enrichment)
                result = analyse(
                    text,
                    link_findings=link_findings,
                    enrichment_results=enrichment_results,
                    mode=mode,
                )

                # AI simplification (optional)
                ai_explanations: dict[str, str] = {}
                if ai_enabled and result.findings:
                    ai_explanations = _ai_simplify(result.findings, lang)

                # Record anonymous stats
                _record_stats(result)

            # ── Display results ───────────────────────────────────────────
            st.markdown("---")

            # Score gauge and tier badge
            col1, col2 = st.columns([1, 1])
            with col1:
                _render_gauge(result.score, lang)
            with col2:
                _render_tier_badge(result.tier, lang)
                if result.act_now_applied:
                    st.markdown(
                        f"""
                    <div style="text-align: center; color: {AMBER}; font-size: 0.85rem; margin-top: 8px;">
                        ⚡ {t("act_now_bonus", lang)} (+15)
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )
                if result.raw_score != result.score:
                    st.markdown(
                        f"""
                    <div style="text-align: center; color: {TEXT_MUTED}; font-size: 0.85rem;">
                        Raw score: {result.raw_score} → capped to {result.score}
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

            # Scam Type Classification Banner
            if result.scam_type:
                scam_lbl = (
                    result.scam_type_hi
                    if lang == "hi" and result.scam_type_hi
                    else result.scam_type
                )
                scam_adv = (
                    result.scam_advice_hi
                    if lang == "hi" and result.scam_advice_hi
                    else result.scam_advice
                )
                st.markdown(
                    f"""
                    <div class="phishnet-card" style="border-left: 4px solid #F59E0B; margin-top: 14px; background: rgba(245, 158, 11, 0.08);">
                        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-size: 1.25rem;">⚠️</span>
                                <div>
                                    <div style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; color: #F59E0B; font-weight: 800;">
                                        {"पहचाना गया घोटाला प्रकार" if lang == "hi" else "Identified Scam Pattern"}
                                    </div>
                                    <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">{html.escape(scam_lbl)}</div>
                                </div>
                            </div>
                            <span style="font-size: 0.75rem; background: rgba(245, 158, 11, 0.2); color: #FBBF24; padding: 3px 10px; border-radius: 999px; font-weight: 700; border: 1px solid rgba(245, 158, 11, 0.35);">
                                {"त्वरित सलाह" if lang == "hi" else "Instant Protection Advice"}
                            </span>
                        </div>
                        <div style="font-size: 0.88rem; color: #E2E8F0; margin-top: 8px; line-height: 1.45; border-top: 1px solid rgba(245, 158, 11, 0.15); padding-top: 8px;">
                            💡 <strong>{"सुरक्षा निर्देश:" if lang == "hi" else "Immediate Action:"}</strong> {html.escape(scam_adv)}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Highlighted message
            highlighted = _highlight_message(text, result.findings)
            st.markdown(
                f"""
                <div class="phishnet-card">
                    <h3 style="margin-top:0;">🔍 Message Inspector</h3>
                    <div class="msg-inspector-container">
                        <div class="msg-inspector-bar">
                            <div class="window-dots">
                                <span class="dot dot-red"></span>
                                <span class="dot dot-yellow"></span>
                                <span class="dot dot-green"></span>
                            </div>
                            <span class="inspector-title">DECONSTRUCTED TEXT STREAM</span>
                            <span style="font-size:0.75rem; color:#64748B;">UTF-8 SECURE</span>
                        </div>
                        <div class="msg-highlight">{highlighted}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Findings table
            if result.findings:
                st.markdown(
                    f'<div class="phishnet-card"><h3 style="margin-top:0;">{t("findings_header", lang)}</h3>',
                    unsafe_allow_html=True,
                )
                _render_findings(result.findings, lang, ai_explanations)
                st.markdown("</div>", unsafe_allow_html=True)

            # Enrichment results
            if enrichment_results:
                st.markdown(
                    f'<div class="phishnet-card"><h3 style="margin-top:0;">{t("enrichment_header", lang)}</h3>',
                    unsafe_allow_html=True,
                )
                for er in enrichment_results:
                    icon = "🔴" if er.is_malicious else "🟢"
                    pts = f" (+{er.extra_points} pts)" if er.extra_points else ""
                    st.markdown(
                        f"""
                    <div class="finding-row finding-ask">
                        <div>
                            <div class="finding-label">{icon} {html.escape(er.source)}</div>
                            <div class="finding-match">{html.escape(er.detail)}{pts}</div>
                        </div>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )
                st.markdown("</div>", unsafe_allow_html=True)

            # Next steps
            _render_next_steps(result, lang)

            # Family Shield Alert Demo (High risk messages)
            if result.tier == "high":
                st.markdown(
                    f"""
                    <div class="phishnet-card" style="border: 1px solid rgba(168, 85, 247, 0.35); background: linear-gradient(135deg, rgba(168, 85, 247, 0.08) 0%, rgba(15, 23, 42, 0.8) 100%);">
                        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap;">
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <span style="font-size: 1.4rem;">👨‍👩‍👧‍👦</span>
                                <div>
                                    <div style="font-weight: 800; color: #F8FAFC; font-size: 1.05rem;">
                                        {"फैमिली शील्ड ऑटो-अलर्ट (लाइव डेमो)" if lang == "hi" else "Family Shield Auto-Alert (Live Demo)"}
                                    </div>
                                    <div style="font-size: 0.82rem; color: #CBD5E1;">
                                        {"बुजुर्ग माता-पिता द्वारा हाई-रिस्क संदेश चेक करने पर विश्वसनीय संपर्क को तत्काल अलर्ट भेजा जाता है।" if lang == "hi" else "When an elderly relative checks a High-Risk message, their designated guardian is alerted."}
                                    </div>
                                </div>
                            </div>
                            <span class="price-pilot-badge" style="background: rgba(168, 85, 247, 0.2); color: #C084FC; border-color: rgba(168, 85, 247, 0.4);">
                                ₹99 / mo Tier Demo
                            </span>
                        </div>
                        <div style="margin-top: 12px; background: rgba(0,0,0,0.3); border-radius: 8px; padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #E2E8F0; border: 1px dashed rgba(168, 85, 247, 0.4);">
                            🚨 <strong>[SMS to Guardian]</strong>: PhishNet Family Shield detected a HIGH-RISK scam message ({result.scam_type or "Deceptive Phishing"}) on your family member's phone. Risk Score: {result.score}/100. Advice: Tell them NOT to transfer money or share OTPs.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Copy report for National Cyber Crime Portal (cybercrime.gov.in & 1930)
            st.markdown(
                f'<div class="phishnet-card"><h3 style="margin-top:0;">📋 {"राष्ट्रीय साइबर अपराध रिपोर्ट (cybercrime.gov.in / 1930)" if lang == "hi" else "Pre-Filled Incident Report (cybercrime.gov.in & 1930)"}</h3>',
                unsafe_allow_html=True,
            )
            st.markdown(
                "<span style='font-size:0.85rem; color:#94A3B8;'>"
                + (
                    "इस रिपोर्ट को कॉपी करके cybercrime.gov.in पर पेस्ट करें या 1930 हेल्पलाइन पर कॉल करते समय संदर्भ के रूप में उपयोग करें।"
                    if lang == "hi"
                    else "Copy this pre-formatted report directly into the incident description box on cybercrime.gov.in, or read it to the 1930 cyber fraud operator."
                )
                + "</span>",
                unsafe_allow_html=True,
            )
            include_msg = st.checkbox(
                t("include_message_label", lang), value=False, key="include_msg"
            )
            report_text = generate_report(
                result,
                include_message=include_msg,
                message_text=text if include_msg else "",
                lang=lang,
            )
            st.code(report_text, language="text")
            st.markdown("</div>", unsafe_allow_html=True)

        # Visible heuristic disclaimer
        st.markdown(
            """
            <div class="disclaimer-card">
                ⚖️ <strong>Heuristic Decision Support:</strong> PhishNet is an automated, rules-based triage system designed to assist users in identifying common deception patterns. It does not constitute a legal determination or absolute guarantee. Always verify critical alerts directly with your institution.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ══════════════════════════════════════════════════════════════════════
    # TAB 2: THREAT INTELLIGENCE & TELEMETRY
    # ══════════════════════════════════════════════════════════════════════
    with tab_telemetry:
        st.markdown("### 📊 Threat Intelligence & Regional Telemetry")
        st.markdown(
            "Real-time anonymous telemetry recorded from message analyses processed on this deployment instance. "
            "Designed around **DPDP principles** (data minimisation, zero message content retention). "
            "<br><span style='font-size:0.8rem; color:#64748B;'>*Note: On ephemeral hosting like Streamlit Community Cloud, local SQLite resets on app redeployment/restart. Production multi-tenant deployments connect to an external persistent store.</span>",
            unsafe_allow_html=True,
        )

        stats = _get_telemetry_stats()

        if stats["total_scans"] == 0:
            st.info(
                "💡 **Instance Telemetry Ready**: 0 scans recorded yet on this fresh deployment. "
                "Analyze messages in the **Scam Inspector** tab to see live counters update here in real time."
            )

        st.markdown(
            f"""
            <div class="telemetry-grid">
                <div class="telemetry-stat-card">
                    <div class="stat-number">{stats["total_scans"]}</div>
                    <div class="stat-label">Total Messages Triaged</div>
                </div>
                <div class="telemetry-stat-card">
                    <div class="stat-number" style="color: #EF4444;">{stats["high_count"]}</div>
                    <div class="stat-label">High-Risk Deceptions</div>
                </div>
                <div class="telemetry-stat-card">
                    <div class="stat-number" style="color: #F59E0B;">{stats["med_count"]}</div>
                    <div class="stat-label">Suspicious / Medium</div>
                </div>
                <div class="telemetry-stat-card">
                    <div class="stat-number" style="color: #10B981;">{stats["low_count"]}</div>
                    <div class="stat-label">Verified Safe / Clean</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Dual Evaluation Benchmark Card
        st.markdown(
            """
            <div class="benchmark-banner">
                <h4 style="margin:0 0 6px 0; color: #34D399;">🎯 Authenticity: Dual Evaluation Benchmark</h4>
                <div style="font-size: 0.88rem; color: #CBD5E1;">
                    We report performance across both our curated regression suite and an un-tuned fresh test set:
                </div>
                <div style="margin-top: 14px; overflow-x: auto;">
                    <table style="width: 100%; font-size: 0.88rem; border-collapse: collapse; text-align: left; color: #E2E8F0;">
                        <thead>
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.15); color: #38BDF8;">
                                <th style="padding: 6px 8px;">Evaluation Dataset</th>
                                <th style="padding: 6px 8px;">Accuracy</th>
                                <th style="padding: 6px 8px;">Precision</th>
                                <th style="padding: 6px 8px;">Recall</th>
                                <th style="padding: 6px 8px;">Key Characteristic</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);">
                                <td style="padding: 6px 8px; font-weight: 600;">100-Msg Curated Regression Set</td>
                                <td style="padding: 6px 8px; color: #34D399; font-weight: 700;">95.0%</td>
                                <td style="padding: 6px 8px; color: #34D399; font-weight: 700;">95.9%</td>
                                <td style="padding: 6px 8px; color: #34D399; font-weight: 700;">94.0%</td>
                                <td style="padding: 6px 8px; color: #94A3B8;">Balanced Indian scam typologies</td>
                            </tr>
                            <tr>
                                <td style="padding: 6px 8px; font-weight: 600;">30-Msg Fresh / Blind Test Set</td>
                                <td style="padding: 6px 8px; color: #34D399; font-weight: 700;">87.0%</td>
                                <td style="padding: 6px 8px; color: #34D399; font-weight: 700;">100%</td>
                                <td style="padding: 6px 8px; color: #F59E0B; font-weight: 700;">73.3%</td>
                                <td style="padding: 6px 8px; color: #94A3B8;">0 false alarms in 15 genuine notices</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div style="font-size: 0.8rem; color: #94A3B8; margin-top: 10px;">
                    *Fresh test feedback (4 initial misses: electricity cutoffs, hotel task lures, 6-digit codes, OTT payment updates) directly drove rule refinements without sacrificing 100% precision.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("#### 🚨 Top Detected Attack Tactics on this Instance")
        total_hits = sum(cnt for _, cnt in stats["top_tactics"])
        if total_hits == 0:
            st.markdown(
                "<div style='font-size:0.85rem; color:#64748B; margin-bottom:12px;'>No attack tactic patterns recorded yet.</div>",
                unsafe_allow_html=True,
            )
        else:
            for tactic, count in stats["top_tactics"]:
                pct = int((count / max(total_hits, 1)) * 100)
                st.markdown(
                    f"""
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px; font-size:0.9rem; color:#E2E8F0;">
                        <span>{tactic}</span>
                        <span style="font-weight:700; color:#38BDF8;">{count} occurrences</span>
                    </div>
                    <div style="background:rgba(255,255,255,0.06); border-radius:6px; height:8px; width:100%; margin-bottom:14px;">
                        <div style="background:linear-gradient(90deg, #38BDF8, #818CF8); height:100%; border-radius:6px; width:{pct}%;"></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # ══════════════════════════════════════════════════════════════════════
    # TAB 3: FOR COLLEGES, BANKS & FINTECHS (MONETIZATION & PRICING)
    # ══════════════════════════════════════════════════════════════════════
    with tab_pricing:
        st.markdown("### 🏢 Commercialization & Institutional Solutions")
        st.markdown(
            "PhishNet addresses the multi-crore fraud crisis facing Indian students, rural bank branches, and fintech platforms through transparent prevention."
        )

        # Business Case
        st.markdown(
            """
            <div class="phishnet-card" style="margin-bottom: 20px;">
                <h4 style="margin-top:0; color:#38BDF8;">💡 The Institutional Business Case: Who Pays and Why</h4>
                <div style="font-size: 0.9rem; color: #CBD5E1; line-height: 1.7;">
                    <p><strong>1. University Campuses & Colleges (Dean of Student Affairs / IT):</strong><br>
                    College students navigating university fee deadlines and new hostel admissions are frequent targets of fraudulent fee portals and fake internship offers. A single compromised fee payment (₹35,000 to ₹1,50,000) causes severe distress and campus disruption. Subscribing to PhishNet Campus API pays for itself by preventing a single fee fraud incident.</p>
                    <p><strong>2. Regional Rural Banks & Credit Cooperatives:</strong><br>
                    Community banks lose customer trust when elderly and first-time UPI users fall for KYC suspension threats or remote access screen sharing (AnyDesk). Preventing fraud at the SMS layer reduces ombudsman complaints and dispute resolution overhead (avg. ₹2,500/case investigation cost).</p>
                    <p><strong>3. Fintech NBFCs & Payment Aggregators:</strong><br>
                    Real-time verification of collect requests protects brand reputation and prevents customer drop-off during checkout.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Pricing Tiers
        st.markdown("#### 💳 Subscription Tiers")
        pricing_html = (
            '<div class="pricing-grid">'
            '<div class="pricing-card">'
            "<div>"
            '<div style="font-size:1.15rem; font-weight:800; color:#F8FAFC;">Free Community</div>'
            '<div style="font-size:0.8rem; color:#94A3B8;">For individual students & citizens</div>'
            '<div class="price-tag">₹0 <span style="font-size:0.85rem; font-weight:500; color:#94A3B8;">/ forever</span></div>'
            '<ul class="pricing-feature-list">'
            "<li>Unlimited web message scanning</li>"
            "<li>Bait-Hook-Ask transparent breakdown</li>"
            "<li>Bilingual English & Hindi support</li>"
            "<li>Tesseract screenshot OCR</li>"
            "<li>Privacy-first design aligned with DPDP principles</li>"
            "</ul>"
            "</div>"
            "</div>"
            '<div class="pricing-card featured">'
            "<div>"
            '<div style="display:flex; align-items:center;">'
            '<span style="font-size:1.15rem; font-weight:800; color:#F8FAFC;">Family Shield</span>'
            '<span class="price-pilot-badge">Pilot Roadmap</span>'
            "</div>"
            '<div style="font-size:0.8rem; color:#94A3B8;">For parents, seniors & UPI beginners</div>'
            '<div class="price-tag">₹99 <span style="font-size:0.85rem; font-weight:500; color:#94A3B8;">/ month</span></div>'
            '<ul class="pricing-feature-list">'
            "<li>Dedicated WhatsApp bot forwarding</li>"
            "<li>Instant threat alerts for up to 5 family members</li>"
            "<li>Automatic alerts on suspicious OTP asks</li>"
            "<li>Direct one-touch 1930 incident logging</li>"
            "<li>Weekly family security summary</li>"
            "</ul>"
            "</div>"
            "</div>"
            '<div class="pricing-card">'
            "<div>"
            '<div style="display:flex; align-items:center;">'
            '<span style="font-size:1.15rem; font-weight:800; color:#F8FAFC;">Campus & Bank API</span>'
            '<span class="price-pilot-badge">Pilot Tier</span>'
            "</div>"
            '<div style="font-size:0.8rem; color:#94A3B8;">For colleges, banks & fintechs</div>'
            '<div class="price-tag">₹4,999 <span style="font-size:0.85rem; font-weight:500; color:#94A3B8;">/ month</span></div>'
            '<ul class="pricing-feature-list">'
            "<li>High-throughput REST API (/v1/analyze)</li>"
            "<li>Student portal ERP integration</li>"
            "<li>Real-time regional threat telemetry</li>"
            "<li>Automated Chakshu & Cybercrime dispatch</li>"
            "<li>Custom institutional domain whitelist</li>"
            "</ul>"
            "</div>"
            "</div>"
            "</div>"
        )
        st.markdown(pricing_html, unsafe_allow_html=True)

        st.markdown(
            """
            <div style="font-size: 0.8rem; color: #64748B; margin-top: 12px;">
                *Note: Subscription prices represent pilot design assumptions calibrated for university beta trials and hackathon evaluation.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Footer ────────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div class="footer-container">
            <div>{t("footer_privacy", lang)}</div>
            <div class="footer-links">
                <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">National Cyber Crime Portal (cybercrime.gov.in)</a> •
                <a href="tel:1930">Citizen Financial Cyber Fraud Helpline: 1930</a> •
                <a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener noreferrer">DoT Chakshu Portal</a>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
else:
    main()
