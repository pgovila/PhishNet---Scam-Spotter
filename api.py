"""PhishNet — FastAPI REST API.

POST /v1/analyze   Analyse a message and return JSON findings.
GET  /health       Health check endpoint.

Authentication via X-API-Key header. Per-key rate limiting.
Shares the exact same engine as the Streamlit UI.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict

# pyrefly: ignore[missing-import]
from fastapi import FastAPI, Header, HTTPException

# pyrefly: ignore[missing-import]
from fastapi.middleware.cors import CORSMiddleware

# pyrefly: ignore[missing-import]
from pydantic import BaseModel, Field

from phishnet.engine import analyse, load_rules, normalise
from phishnet.links import analyse_links, extract_urls

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishNet API",
    description="Scam message analysis API — Spot the bait. See the hook. Skip the ask.",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ── API Key management ────────────────────────────────────────────────────────

# Keys loaded from env: PHISHNET_API_KEYS (comma-separated)
# Enforce authentication if PHISHNET_REQUIRE_AUTH=1 or keys are specified


def _get_valid_keys() -> set[str]:
    """Load valid API keys from environment."""
    keys_str = os.environ.get("PHISHNET_API_KEYS", "")
    if not keys_str:
        return set()
    return {k.strip() for k in keys_str.split(",") if k.strip()}


def _validate_api_key(api_key: str | None) -> None:
    """Validate the API key."""
    valid_keys = _get_valid_keys()
    require_auth = os.environ.get("PHISHNET_REQUIRE_AUTH") == "1"

    if not valid_keys:
        if require_auth:
            raise HTTPException(
                status_code=401,
                detail="Authentication required: PHISHNET_REQUIRE_AUTH is set but no valid keys are configured.",
            )
        # Development mode — allow unauthenticated requests with anonymous rate limit
        return

    if not api_key or api_key not in valid_keys:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key. Provide a valid key in the X-API-Key header.",
        )


# ── Rate limiting ─────────────────────────────────────────────────────────────

_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 60  # requests per window
RATE_WINDOW = 60  # seconds


def _check_rate_limit(key: str) -> None:
    """Per-key rate limiting."""
    now = time.time()
    _rate_store[key] = [ts for ts in _rate_store[key] if now - ts < RATE_WINDOW]
    if len(_rate_store[key]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    _rate_store[key].append(now)


# ── Models ────────────────────────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    """Request body for message analysis."""

    text: str = Field(..., min_length=1, max_length=5000, description="Message text to analyse")
    mode: str | None = Field(None, description="Scoring mode: 'default' or 'rulebook'")
    enrich: bool = Field(False, description="Whether to run online threat intelligence enrichment")


class FindingResponse(BaseModel):
    """A single finding in the response."""

    rule_id: str
    category: str
    label: str
    label_hi: str = ""
    points: int
    matched_text: str
    span_start: int
    span_end: int
    reason: str
    reason_hi: str = ""
    protective: bool


class AnalyzeResponse(BaseModel):
    """Response body for message analysis."""

    findings: list[FindingResponse]
    score: int
    raw_score: int
    tier: str
    next_steps: list[str]
    mode: str
    act_now_applied: bool


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check."""
    return {"status": "ok", "service": "phishnet"}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze_message(
    body: AnalyzeRequest,
    x_api_key: str | None = Header(None),
) -> AnalyzeResponse:
    """Analyse a suspicious message for scam indicators.

    Returns scored findings, risk tier, and recommended next steps.
    The rules engine sets the score deterministically — AI never sets or influences the score.
    """
    _validate_api_key(x_api_key)
    _check_rate_limit(x_api_key or "anonymous")

    text = body.text.strip()
    if len(text) < 10:
        raise HTTPException(status_code=422, detail="Message too short (minimum 10 characters)")

    # Determine mode
    mode = body.mode
    if mode is None:
        mode = "rulebook" if os.environ.get("RULEBOOK_MODE") == "1" else "default"
    if mode not in ("default", "rulebook"):
        raise HTTPException(status_code=422, detail="Invalid mode. Use 'default' or 'rulebook'.")

    # Run analysis
    norm_text = normalise(text)

    # Link analysis
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

    # Optional online enrichment (Safe Browsing, VirusTotal, URLhaus)
    enrichment_results = None
    if body.enrich:
        urls = extract_urls(norm_text)
        if urls:
            try:
                from phishnet.enrich import enrich_urls

                raw_urls = [u.raw for u in urls]
                enrichment_results = enrich_urls(raw_urls)
            except Exception:
                pass  # Enrichment failure never breaks core analysis

    # Both API and UI run the exact same analyse logic
    result = analyse(
        text,
        link_findings=link_findings,
        enrichment_results=enrichment_results,
        mode=mode,
    )

    return AnalyzeResponse(
        findings=[
            FindingResponse(
                rule_id=f.rule_id,
                category=f.category,
                label=f.label,
                label_hi=f.label_hi,
                points=f.points,
                matched_text=f.matched_text,
                span_start=f.span[0],
                span_end=f.span[1],
                reason=f.reason,
                reason_hi=f.reason_hi,
                protective=f.protective,
            )
            for f in result.findings
        ],
        score=result.score,
        raw_score=result.raw_score,
        tier=result.tier,
        next_steps=result.next_steps,
        mode=result.mode,
        act_now_applied=result.act_now_applied,
    )
