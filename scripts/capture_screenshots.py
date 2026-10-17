"""Capture PhishNet screenshots using Playwright.

Usage:
    python scripts/capture_screenshots.py [--base-url http://localhost:8501]

Requires: playwright, with chromium browser installed.
    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

# pyrefly: ignore[missing-import]
from playwright.sync_api import sync_playwright

SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent / "screenshots"

CAPTURES = [
    {
        "name": "01_home",
        "description": "Home page with input area",
        "actions": [],
    },
    {
        "name": "02_analysis_high",
        "description": "High-risk SBI KYC scam analysis",
        "actions": [
            ("click", "button:has-text('SBI KYC scam')"),
            ("click", "button:has-text('Analyse')"),
            ("wait", 3),
        ],
    },
    {
        "name": "03_analysis_low",
        "description": "Low-risk class notice",
        "actions": [
            ("fill", "textarea", "Class moved to 3 PM today, Room 204."),
            ("click", "button:has-text('Analyse')"),
            ("wait", 3),
        ],
    },
    {
        "name": "04_hindi",
        "description": "Hindi language view",
        "actions": [
            ("select", "select", "hi"),
            ("wait", 2),
        ],
    },
    {
        "name": "05_report",
        "description": "Report copy view",
        "actions": [
            ("scroll", "bottom"),
            ("wait", 1),
        ],
    },
]


def capture(base_url: str) -> None:
    """Capture all screenshots."""
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})

        for cap in CAPTURES:
            print(f"Capturing: {cap['name']} — {cap['description']}")

            page.goto(base_url)
            page.wait_for_load_state("networkidle")
            time.sleep(2)

            for action in cap["actions"]:
                try:
                    if action[0] == "click":
                        page.click(action[1], timeout=5000)
                    elif action[0] == "fill":
                        page.fill(action[1], action[2])
                    elif action[0] == "select":
                        page.select_option(action[1], action[2])
                    elif action[0] == "wait":
                        time.sleep(action[1])
                    elif action[0] == "scroll":
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                except Exception as e:
                    print(f"  Warning: action {action} failed: {e}")

            path = SCREENSHOTS_DIR / f"{cap['name']}.png"
            page.screenshot(path=str(path), full_page=True)
            print(f"  Saved: {path}")

        browser.close()

    print(f"\nAll screenshots saved to {SCREENSHOTS_DIR}/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture PhishNet screenshots")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8501",
        help="Base URL of the running PhishNet app",
    )
    args = parser.parse_args()
    capture(args.base_url)
