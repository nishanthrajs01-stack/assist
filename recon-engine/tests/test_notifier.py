"""Unit tests for ReconEngine Notifier."""
import json
import pytest
from unittest.mock import AsyncMock, patch

from core.database import DiffEvent, Program, SessionLocal, init_db
from alerts.notifier import dispatch_pending, _discord_embed, _slack_block, _telegram_text


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_formatters():
    event = DiffEvent(
        id=1,
        program_id=1,
        severity="critical",
        event_type="NEW_HOST",
        asset="sub.example.com",
        detail=json.dumps({"status_code": 200, "title": "App"}),
        notified=False
    )
    discord = _discord_embed("TestProgram", event)
    assert "embeds" in discord
    assert len(discord["embeds"]) == 1

    slack = _slack_block("TestProgram", event)
    assert "blocks" in slack

    telegram = _telegram_text("TestProgram", event)
    assert "TestProgram" in telegram
    assert "sub.example.com" in telegram


def test_dispatch_pending_disabled_does_not_mark_notified(monkeypatch):
    """When alerts are not configured, events should remain un-notified in DB."""
    import asyncio
    import uuid
    from core.config import settings

    # Ensure all disabled or placeholder
    monkeypatch.setattr(settings.alerts.discord, "enabled", False)
    monkeypatch.setattr(settings.alerts.slack, "enabled", False)
    monkeypatch.setattr(settings.alerts.telegram, "enabled", False)

    uid = uuid.uuid4().hex[:8]
    prog_name = f"NotifierProg_Disabled_{uid}"

    with SessionLocal() as db:
        prog = Program(name=prog_name)
        db.add(prog)
        db.commit()
        db.refresh(prog)

        event = DiffEvent(
            program_id=prog.id,
            severity="critical",
            event_type="NEW_HOST",
            asset=f"pending-{uid}.example.com",
            detail="{}",
            notified=False
        )
        db.add(event)
        db.commit()
        event_id = event.id

    dispatched = asyncio.run(dispatch_pending())
    assert dispatched == 0

    with SessionLocal() as db:
        ev = db.query(DiffEvent).filter_by(id=event_id).first()
        assert ev.notified is False  # Must remain un-notified!

