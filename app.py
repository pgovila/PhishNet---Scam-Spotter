"""PhishNet — Streamlit UI.

Spot the bait. See the hook. Skip the ask.

A scam message analyser for SMS, WhatsApp, and email, aimed at users in India.
"""

from __future__ import annotations

import html
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from phishnet.engine import (
    NEXT_STEPS,
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
    """Inject custom CSS for dark theme."""
    st.markdown(
        f"""
    <style>
        /* Global */
        .stApp {{
            background-color: {BG_DARK};
            color: {TEXT_WHITE};
        }}
        .stApp header {{
            background-color: {BG_DARK};
        }}

        /* Cards */
        .phishnet-card {{
            background: {CARD_BG};
            border-radius: 16px;
            padding: 24px;
            margin: 12px 0;
            border: 1px solid rgba(255,255,255,0.06);
            box-shadow: 0 4px 24px rgba(0,0,0,0.3);
        }}

        /* Tier badges */
        .tier-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 20px;
            border-radius: 999px;
            font-weight: 700;
            font-size: 1.1rem;
            letter-spacing: 0.5px;
        }}
        .tier-high {{
            background: rgba(239,68,68,0.15);
            color: {CRIMSON};
            border: 2px solid {CRIMSON};
        }}
        .tier-medium {{
            background: rgba(245,165,36,0.15);
            color: {AMBER};
            border: 2px solid {AMBER};
        }}
        .tier-low {{
            background: rgba(16,185,129,0.15);
            color: {EMERALD};
            border: 2px solid {EMERALD};
        }}

        /* Score gauge */
        .score-gauge {{
            text-align: center;
            padding: 20px;
        }}
        .score-number {{
            font-size: 4rem;
            font-weight: 800;
            line-height: 1;
        }}
        .score-label {{
            font-size: 0.9rem;
            color: {TEXT_MUTED};
            margin-top: 4px;
        }}

        /* Findings */
        .finding-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            margin: 4px 0;
            border-radius: 10px;
            background: rgba(255,255,255,0.03);
            border-left: 4px solid;
        }}
        .finding-bait {{ border-left-color: {AMBER}; }}
        .finding-hook {{ border-left-color: {CRIMSON}; }}
        .finding-ask {{ border-left-color: #8B5CF6; }}
        .finding-protective {{ border-left-color: {EMERALD}; opacity: 0.7; }}

        .finding-label {{
            font-weight: 600;
            font-size: 0.95rem;
        }}
        .finding-match {{
            font-size: 0.85rem;
            color: {TEXT_MUTED};
            font-style: italic;
            margin-top: 2px;
        }}
        .finding-reason {{
            font-size: 0.82rem;
            color: {TEXT_MUTED};
            margin-top: 2px;
        }}
        .finding-points {{
            font-weight: 700;
            font-size: 1.1rem;
            white-space: nowrap;
        }}
        .points-positive {{ color: {CRIMSON}; }}
        .points-zero {{ color: {EMERALD}; }}

        /* Highlighted message */
        .msg-highlight {{
            font-family: 'Segoe UI', sans-serif;
            font-size: 1rem;
            line-height: 1.8;
            padding: 16px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            word-wrap: break-word;
        }}
        .hl-bait {{
            background: rgba(245,165,36,0.25);
            border-bottom: 2px solid {AMBER};
            padding: 1px 4px;
            border-radius: 3px;
        }}
        .hl-hook {{
            background: rgba(239,68,68,0.25);
            border-bottom: 2px solid {CRIMSON};
            padding: 1px 4px;
            border-radius: 3px;
        }}
        .hl-ask {{
            background: rgba(139,92,246,0.25);
            border-bottom: 2px solid #8B5CF6;
            padding: 1px 4px;
            border-radius: 3px;
        }}
        .hl-protective {{
            background: rgba(16,185,129,0.15);
            border-bottom: 2px dashed {EMERALD};
            padding: 1px 4px;
            border-radius: 3px;
        }}

        /* Next steps */
        .next-step {{
            padding: 8px 0;
            font-size: 0.95rem;
        }}

        /* Category header */
        .cat-header {{
            font-size: 1rem;
            font-weight: 700;
            margin: 16px 0 8px 0;
            padding: 6px 12px;
            border-radius: 8px;
        }}
        .cat-bait {{ background: rgba(245,165,36,0.1); color: {AMBER}; }}
        .cat-hook {{ background: rgba(239,68,68,0.1); color: {CRIMSON}; }}
        .cat-ask {{ background: rgba(139,92,246,0.1); color: #8B5CF6; }}

        /* Tagline */
        .tagline {{
            text-align: center;
            font-size: 1.1rem;
            color: {TEXT_MUTED};
            font-style: italic;
            margin-bottom: 20px;
        }}

        /* Example buttons */
        .stButton > button {{
            border-radius: 10px;
        }}

        /* Mobile friendly */
        @media (max-width: 768px) {{
            .score-number {{ font-size: 3rem; }}
            .finding-row {{ flex-direction: column; align-items: flex-start; gap: 4px; }}
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 20px;
            color: {TEXT_MUTED};
            font-size: 0.85rem;
            border-top: 1px solid rgba(255,255,255,0.06);
            margin-top: 40px;
        }}
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
    """Render the risk score gauge."""
    color = _score_color(score)
    st.markdown(
        f"""
    <div class="phishnet-card score-gauge">
        <div class="score-number" style="color: {color};">{score}</div>
        <div class="score-label">{t("score_label", lang)} / 100</div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def _render_tier_badge(tier: str, lang: str) -> None:
    """Render the tier badge with text label."""
    badge_text = t(f"tier_{tier}", lang)
    st.markdown(
        f"""
    <div style="text-align: center; margin: 12px 0;">
        <span class="tier-badge {_tier_css(tier)}">{badge_text}</span>
    </div>
    """,
        unsafe_allow_html=True,
    )


def _render_findings(findings: list[Finding], lang: str, ai_explanations: dict[str, str]) -> None:
    """Render the findings table grouped by category."""
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

        for f in cat_findings:
            finding_css = f"finding-{cat}" if not f.protective else "finding-protective"

            label = f.label_hi if lang == "hi" else f.label
            if f.protective:
                label = t("protective_label", lang)

            points_html = (
                '<span class="finding-points points-zero">0 pts</span>'
                if f.protective
                else f'<span class="finding-points points-positive">+{f.points} pts</span>'
            )

            reason_html = ""
            if f.reason:
                reason_html = f'<div class="finding-reason">💡 {html.escape(f.reason)}</div>'

            ai_html = ""
            if f.rule_id in ai_explanations:
                ai_label = t("ai_simplified", lang)
                ai_html = f'<div class="finding-reason">🤖 {ai_label}: {html.escape(ai_explanations[f.rule_id])}</div>'

            st.markdown(
                f"""
            <div class="finding-row {finding_css}">
                <div>
                    <div class="finding-label">{html.escape(label)}</div>
                    <div class="finding-match">"{html.escape(f.matched_text[:80])}"</div>
                    {reason_html}
                    {ai_html}
                </div>
                {points_html}
            </div>
            """,
                unsafe_allow_html=True,
            )


def _render_next_steps(result: AnalysisResult, lang: str) -> None:
    """Render the 'What to do now' box."""
    steps = NEXT_STEPS_HI.get(result.tier, []) if lang == "hi" else result.next_steps

    st.markdown(
        f"""
    <div class="phishnet-card">
        <h3 style="margin-top: 0;">{"🛡️ " + t("next_steps_header", lang)}</h3>
    """,
        unsafe_allow_html=True,
    )

    for step in steps:
        st.markdown(f'<div class="next-step">{html.escape(step)}</div>', unsafe_allow_html=True)

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
        f"<h1 style='text-align: center; margin-bottom: 4px;'>{t('app_title', lang)}</h1>",
        unsafe_allow_html=True,
    )
    st.markdown(f'<div class="tagline">{t("tagline", lang)}</div>', unsafe_allow_html=True)

    # ── Example buttons ───────────────────────────────────────────────────
    examples = _load_examples()
    if examples:
        st.markdown(f"**{t('try_examples', lang)}:**")
        cols = st.columns(min(len(examples), 3))
        for i, ex in enumerate(examples):
            col = cols[i % len(cols)]
            with col:
                if st.button(ex["label"], key=f"ex_{i}", use_container_width=True):
                    st.session_state.input_text = ex["text"]

    # ── Input ─────────────────────────────────────────────────────────────
    default_text = st.session_state.get("input_text", "")

    user_input = st.text_area(
        t("input_label", lang),
        value=default_text,
        height=150,
        max_chars=MAX_INPUT,
        key="text_area_input",
        placeholder="e.g., SBI ALERT: Your KYC is incomplete…",
    )

    # Screenshot upload
    uploaded_file = st.file_uploader(
        t("upload_label", lang),
        type=["png", "jpg", "jpeg", "webp"],
        key="screenshot_upload",
    )

    ocr_text = ""
    if uploaded_file is not None:
        image_bytes = uploaded_file.read()
        with st.spinner("Extracting text from screenshot…"):
            ocr_text = _ocr_tesseract(image_bytes)
            if not ocr_text and ai_enabled:
                ocr_text = _ocr_claude(image_bytes)
        if ocr_text:
            st.success(f"Extracted {len(ocr_text)} characters from screenshot")
            user_input = ocr_text
        else:
            st.warning("Could not extract text from screenshot. Please paste the text manually.")

    # ── Analyse button ────────────────────────────────────────────────────
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

            # Core analysis
            result = analyse(
                text,
                link_findings=link_findings,
                mode=mode,
            )

            # Online enrichment (optional)
            enrichment_results = []
            urls = extract_urls(norm_text)
            if urls:
                try:
                    from phishnet.enrich import enrich_urls

                    raw_urls = [u.raw for u in urls]
                    enrichment_results = enrich_urls(raw_urls)
                    # Add extra points from enrichment
                    for er in enrichment_results:
                        if er.extra_points > 0:
                            result.score = min(result.score + er.extra_points, 100)
                            result.raw_score += er.extra_points
                except Exception:
                    pass  # Enrichment failure never breaks analysis

            # Re-compute tier after enrichment
            tiers = mode_cfg.get("tiers", {})
            for tier_name in ("high", "medium", "low"):
                bounds = tiers.get(tier_name)
                if bounds and bounds[0] <= result.score <= bounds[1]:
                    result.tier = tier_name
                    break
            if result.score >= tiers.get("high", [55, 100])[0]:
                result.tier = "high"
            result.next_steps = NEXT_STEPS.get(result.tier, [])

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

        # Highlighted message
        st.markdown(
            '<div class="phishnet-card"><h3 style="margin-top:0;">📝 Message</h3>',
            unsafe_allow_html=True,
        )
        highlighted = _highlight_message(text, result.findings)
        st.markdown(f'<div class="msg-highlight">{highlighted}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

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

        # Copy report
        st.markdown(
            f'<div class="phishnet-card"><h3 style="margin-top:0;">{t("copy_report", lang)}</h3>',
            unsafe_allow_html=True,
        )
        include_msg = st.checkbox(t("include_message_label", lang), value=False, key="include_msg")
        report_text = generate_report(
            result,
            include_message=include_msg,
            message_text=text if include_msg else "",
            lang=lang,
        )
        st.code(report_text, language="text")
        st.markdown("</div>", unsafe_allow_html=True)

    # ── Footer ────────────────────────────────────────────────────────────
    st.markdown(f'<div class="footer">{t("footer_privacy", lang)}</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
else:
    main()
