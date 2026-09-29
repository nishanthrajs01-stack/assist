"""Unit tests for ReconEngine DiffEngine."""
import json
import uuid
from datetime import datetime, timedelta
import pytest

from core.database import DiffEvent, Domain, Endpoint, HttpService, Program, SessionLocal, init_db
from core.diff_engine import DiffEngine, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_diff_new_subdomain_detection():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"DiffTest_NewSub_{uid}"
    with SessionLocal() as db:
        prog = Program(name=prog_name)
        db.add(prog)
        db.commit()
        db.refresh(prog)
        prog_id = prog.id

        # Add domain created just now
        domain = Domain(
            program_id=prog_id,
            subdomain=f"fresh-{uid}.example.com",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            is_active=True
        )
        db.add(domain)
        db.commit()

    engine = DiffEngine(prog_id)
    events = engine.run(lookback_hours=1)

    new_host_events = [e for e in events if e["event_type"] == "NEW_HOST"]
    assert len(new_host_events) == 1
    assert new_host_events[0]["asset"] == f"fresh-{uid}.example.com"
    assert new_host_events[0]["severity"] == SEVERITY_CRITICAL


def test_diff_access_flip():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"DiffTest_AccessFlip_{uid}"
    sub = f"admin-{uid}.example.com"
    url = f"https://{sub}"
    with SessionLocal() as db:
        prog = Program(name=prog_name)
        db.add(prog)
        db.commit()
        db.refresh(prog)
        prog_id = prog.id

        domain = Domain(
            program_id=prog_id,
            subdomain=sub,
            first_seen=datetime.utcnow() - timedelta(days=2),
            is_active=True
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)

        # Historical event: was 403 Forbidden
        prev_event = DiffEvent(
            program_id=prog_id,
            severity=SEVERITY_CRITICAL,
            event_type="NEW_HOST",
            asset=sub,
            detail=json.dumps({"status_code": 403, "title": "Forbidden"}),
            created_at=datetime.utcnow() - timedelta(days=2)
        )
        db.add(prev_event)

        # Now: becomes 200 OK
        svc = HttpService(
            domain_id=domain.id,
            url=url,
            status_code=200,
            title="Dashboard",
            last_checked=datetime.utcnow()
        )
        db.add(svc)
        db.commit()

    engine = DiffEngine(prog_id)
    events = engine.run(lookback_hours=1)

    flip_events = [e for e in events if e["event_type"] == "ACCESS_FLIP"]
    assert len(flip_events) == 1
    assert flip_events[0]["detail"]["before"] == 403
    assert flip_events[0]["detail"]["after"] == 200


def test_diff_new_endpoint():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"DiffTest_NewEP_{uid}"
    sub = f"api-diff-ep-{uid}.example.com"
    ep_url = f"https://{sub}/secret/token"
    with SessionLocal() as db:
        prog = Program(name=prog_name)
        db.add(prog)
        db.commit()
        db.refresh(prog)
        prog_id = prog.id

        domain = Domain(
            program_id=prog_id,
            subdomain=sub,
            first_seen=datetime.utcnow() - timedelta(days=1),
            is_active=True
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)

        ep = Endpoint(
            domain_id=domain.id,
            endpoint_url=ep_url,
            source="katana",
            first_seen=datetime.utcnow()
        )
        db.add(ep)
        db.commit()

    engine = DiffEngine(prog_id)
    events = engine.run(lookback_hours=1)

    ep_events = [e for e in events if e["event_type"] == "NEW_ENDPOINT"]
    assert len(ep_events) == 1
    assert ep_events[0]["asset"] == ep_url
    assert ep_events[0]["severity"] == SEVERITY_HIGH

