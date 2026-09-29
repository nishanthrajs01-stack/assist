"""
alerts/notifier.py — Discord, Slack, and Telegram webhook dispatcher.

Reads DiffEvents from the DB that haven't been notified yet,
formats rich messages, dispatches them, and marks as notified.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx

from core.config import settings
from core.database import DiffEvent, Program, SessionLocal


# ---------------------------------------------------------------------------
# Severity → visual formatting
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

SEVERITY_COLOR = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFCC00,
    "low":      0x00AA00,
}

EVENT_LABEL = {
    "NEW_HOST":        "New Active Subdomain",
    "ACCESS_FLIP":     "Access Control Flip (403→200)",
    "TECH_CHANGE":     "Technology Stack Changed",
    "BODY_CHANGE":     "Response Body Modified",
    "NEW_ENDPOINT":    "New Endpoint Discovered",
    "NUCLEI_FINDING":  "Nuclei Vulnerability Found",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _severity_meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(threshold, 0)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _discord_embed(program_name: str, event: DiffEvent) -> Dict[str, Any]:
    emoji  = SEVERITY_EMOJI.get(event.severity, "⚪")
    label  = EVENT_LABEL.get(event.event_type, event.event_type)
    detail = json.loads(event.detail or "{}")

    fields = [{"name": k.replace("_", " ").title(), "value": f"`{v}`", "inline": True}
              for k, v in detail.items() if v is not None]

    created_str = event.created_at.strftime('%Y-%m-%d %H:%M UTC') if event.created_at else "Just now"
    return {
        "embeds": [{
            "title":       f"{emoji} [{event.event_type}] {label}",
            "description": f"**Asset:** `{event.asset}`",
            "color":       SEVERITY_COLOR.get(event.severity, 0x888888),
            "fields":      fields[:5],
            "footer":      {"text": f"ReconEngine • {program_name} • {created_str}"},
        }]
    }


def _slack_block(program_name: str, event: DiffEvent) -> Dict[str, Any]:
    emoji  = SEVERITY_EMOJI.get(event.severity, "⚪")
    label  = EVENT_LABEL.get(event.event_type, event.event_type)
    detail = json.loads(event.detail or "{}")
    detail_text = " | ".join(f"{k}: `{v}`" for k, v in detail.items() if v)

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {label}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Program:* {program_name}\n"
                        f"*Asset:* `{event.asset}`\n"
                        f"*Severity:* {event.severity.upper()}\n"
                        f"{detail_text}"
                    ),
                },
            },
            {"type": "divider"},
        ]
    }


def _telegram_text(program_name: str, event: DiffEvent) -> str:
    emoji  = SEVERITY_EMOJI.get(event.severity, "⚪")
    label  = EVENT_LABEL.get(event.event_type, event.event_type)
    detail = json.loads(event.detail or "{}")
    detail_lines = "\n".join(f"  • {k}: {v}" for k, v in detail.items() if v)

    return (
        f"{emoji} <b>[{event.event_type}] {label}</b>\n"
        f"<b>Program:</b> {program_name}\n"
        f"<b>Asset:</b> <code>{event.asset}</code>\n"
        f"<b>Severity:</b> {event.severity.upper()}\n"
        f"{detail_lines}"
    )


# ---------------------------------------------------------------------------
# HTTP sender
# ---------------------------------------------------------------------------

async def _post(client: httpx.AsyncClient, url: str, payload: Dict) -> bool:
    try:
        resp = await client.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as exc:
        print(f"[notifier] Webhook delivery failed ({url[:50]}…): {exc}")
        return False


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

async def dispatch_pending() -> int:
    """
    Fetch all un-notified DiffEvents, dispatch to enabled platforms,
    and mark them as notified. Returns the count of events processed.
    """
    cfg = settings.alerts
    dispatched = 0

    has_configured_platform = any([
        cfg.discord.enabled and cfg.discord.webhook_url and "YOUR_DISCORD" not in cfg.discord.webhook_url,
        cfg.slack.enabled and cfg.slack.webhook_url and "YOUR_SLACK" not in cfg.slack.webhook_url,
        cfg.telegram.enabled and cfg.telegram.bot_token and cfg.telegram.chat_id and "YOUR_TELEGRAM" not in cfg.telegram.bot_token,
    ])

    if not has_configured_platform:
        return 0

    with SessionLocal() as db:
        pending = (
            db.query(DiffEvent)
            .filter_by(notified=False)
            .order_by(DiffEvent.created_at.asc())
            .all()
        )
        if not pending:
            return 0

        # Build program name map
        prog_map = {p.id: p.name for p in db.query(Program).all()}

        async with httpx.AsyncClient() as client:
            for event in pending:
                prog_name = prog_map.get(event.program_id, "Unknown")
                any_sent = False
                below_threshold_for_all = True

                if (cfg.discord.enabled
                        and cfg.discord.webhook_url
                        and "YOUR_DISCORD" not in cfg.discord.webhook_url):
                    if _severity_meets_threshold(event.severity, cfg.discord.min_severity):
                        below_threshold_for_all = False
                        payload = _discord_embed(prog_name, event)
                        if await _post(client, cfg.discord.webhook_url, payload):
                            any_sent = True
                        await asyncio.sleep(0.3)   # Discord rate limit buffer

                if (cfg.slack.enabled
                        and cfg.slack.webhook_url
                        and "YOUR_SLACK" not in cfg.slack.webhook_url):
                    if _severity_meets_threshold(event.severity, cfg.slack.min_severity):
                        below_threshold_for_all = False
                        payload = _slack_block(prog_name, event)
                        if await _post(client, cfg.slack.webhook_url, payload):
                            any_sent = True

                if (cfg.telegram.enabled
                        and cfg.telegram.bot_token
                        and cfg.telegram.chat_id
                        and "YOUR_TELEGRAM" not in cfg.telegram.bot_token):
                    if _severity_meets_threshold(event.severity, cfg.telegram.min_severity):
                        below_threshold_for_all = False
                        tg_url = f"https://api.telegram.org/bot{cfg.telegram.bot_token}/sendMessage"
                        if await _post(client, tg_url, {
                            "chat_id":    cfg.telegram.chat_id,
                            "text":       _telegram_text(prog_name, event),
                            "parse_mode": "HTML",
                        }):
                            any_sent = True

                # Mark as notified if sent or if severity is below all configured thresholds
                if any_sent or below_threshold_for_all:
                    event.notified = True
                    if any_sent:
                        dispatched += 1

        db.commit()

    return dispatched
