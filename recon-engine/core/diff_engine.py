"""
core/diff_engine.py — Snapshot comparison and risk-tiered change detection.

Compares the current DB state against the previous scan snapshot,
emits DiffEvent records, and dispatches webhook alerts.
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from core.database import (
    DiffEvent, Domain, Endpoint, HttpService, Program, SessionLocal
)


# ---------------------------------------------------------------------------
# Severity tiers
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH     = "high"
SEVERITY_MEDIUM   = "medium"
SEVERITY_LOW      = "low"

SEVERITY_RANK = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH:     3,
    SEVERITY_MEDIUM:   2,
    SEVERITY_LOW:      1,
}


# ---------------------------------------------------------------------------
# Diff Engine
# ---------------------------------------------------------------------------

class DiffEngine:
    def __init__(self, program_id: int):
        self.program_id = program_id
        self._events: List[Dict] = []

    # ------------------------------------------------------------------
    # Public: Run full diff pass after a complete scan cycle
    # ------------------------------------------------------------------

    def run(self, lookback_hours: int = 25) -> List[Dict]:
        """
        Compare recently updated DB records against the previous baseline.
        Returns a list of diff event dicts that were created.
        :param lookback_hours: Assets updated within this window are treated as
                               candidates for new/changed detection.
        """
        self._events = []
        cutoff = datetime.utcnow() - timedelta(hours=lookback_hours)

        with SessionLocal() as db:
            self._check_new_subdomains(db, cutoff)
            self._check_status_flips(db, cutoff)
            self._check_tech_changes(db, cutoff)
            self._check_hash_changes(db, cutoff)
            self._check_new_endpoints(db, cutoff)
            db.commit()

        return self._events

    # ------------------------------------------------------------------
    # Diff rules
    # ------------------------------------------------------------------

    def _check_new_subdomains(self, db: Session, cutoff: datetime) -> None:
        """🔴 CRITICAL — Subdomains that appeared for the first time."""
        new_domains = (
            db.query(Domain)
            .filter(
                Domain.program_id == self.program_id,
                Domain.first_seen >= cutoff,
                Domain.is_active == True,
            )
            .all()
        )
        for d in new_domains:
            svc = d.http_service
            status = svc.status_code if svc else None
            self._emit(
                db,
                severity  = SEVERITY_CRITICAL,
                event_type= "NEW_HOST",
                asset     = d.subdomain,
                detail    = {
                    "status_code":   status,
                    "title":         svc.title if svc else None,
                    "tech":          svc.technologies if svc else None,
                    "response_hash": svc.response_hash if svc else None,
                    "first_seen":    d.first_seen.isoformat(),
                },
            )

    def _check_status_flips(self, db: Session, cutoff: datetime) -> None:
        """🔴 CRITICAL — HTTP status moved from 4xx/5xx to 2xx/3xx."""
        recent_services = (
            db.query(HttpService)
            .join(Domain)
            .filter(
                Domain.program_id == self.program_id,
                HttpService.last_checked >= cutoff,
            )
            .all()
        )
        for svc in recent_services:
            prev = self._prev_status(db, svc.domain_id)
            if prev is None:
                continue
            was_blocked = prev in range(400, 600)
            now_open    = svc.status_code in range(200, 400) if svc.status_code else False
            if was_blocked and now_open:
                self._emit(
                    db,
                    severity  = SEVERITY_CRITICAL,
                    event_type= "ACCESS_FLIP",
                    asset     = svc.url,
                    detail    = {
                        "before": prev,
                        "after":  svc.status_code,
                        "title":  svc.title,
                    },
                )

    def _check_tech_changes(self, db: Session, cutoff: datetime) -> None:
        """🟡 MEDIUM — Technology stack changed since last scan."""
        recent_services = (
            db.query(HttpService)
            .join(Domain)
            .filter(
                Domain.program_id == self.program_id,
                HttpService.last_checked >= cutoff,
            )
            .all()
        )
        for svc in recent_services:
            prev_tech = self._prev_tech(db, svc.domain_id)
            if prev_tech is None:
                continue
            curr_tech = set(json.loads(svc.technologies or "[]"))
            prev_set  = set(json.loads(prev_tech or "[]"))
            added   = curr_tech - prev_set
            removed = prev_set - curr_tech
            if added or removed:
                self._emit(
                    db,
                    severity  = SEVERITY_MEDIUM,
                    event_type= "TECH_CHANGE",
                    asset     = svc.url,
                    detail    = {
                        "added":   list(added),
                        "removed": list(removed),
                    },
                )

    def _check_hash_changes(self, db: Session, cutoff: datetime) -> None:
        """🟡 MEDIUM — Response body hash changed (silent content update)."""
        recent_services = (
            db.query(HttpService)
            .join(Domain)
            .filter(
                Domain.program_id == self.program_id,
                HttpService.last_checked >= cutoff,
                HttpService.status_code.in_([200, 201]),
            )
            .all()
        )
        for svc in recent_services:
            prev_hash = self._prev_hash(db, svc.domain_id)
            if prev_hash and prev_hash != svc.response_hash:
                self._emit(
                    db,
                    severity  = SEVERITY_MEDIUM,
                    event_type= "BODY_CHANGE",
                    asset     = svc.url,
                    detail    = {"prev_hash": prev_hash, "curr_hash": svc.response_hash},
                )

    def _check_new_endpoints(self, db: Session, cutoff: datetime) -> None:
        """🟠 HIGH — New URL endpoints discovered."""
        new_endpoints = (
            db.query(Endpoint)
            .join(Domain)
            .filter(
                Domain.program_id == self.program_id,
                Endpoint.first_seen >= cutoff,
            )
            .all()
        )
        for ep in new_endpoints:
            self._emit(
                db,
                severity  = SEVERITY_HIGH,
                event_type= "NEW_ENDPOINT",
                asset     = ep.endpoint_url,
                detail    = {"source": ep.source, "first_seen": ep.first_seen.isoformat()},
            )

    # ------------------------------------------------------------------
    # Nuclei finding recorder
    # ------------------------------------------------------------------

    def record_nuclei_finding(self, record: Dict[str, Any]) -> None:
        """Stores Nuclei findings directly as CRITICAL DiffEvents."""
        severity_map = {
            "critical": SEVERITY_CRITICAL,
            "high":     SEVERITY_HIGH,
            "medium":   SEVERITY_MEDIUM,
            "low":      SEVERITY_LOW,
            "info":     SEVERITY_LOW,
        }
        sev = severity_map.get(
            (record.get("info", {}).get("severity") or "").lower(), SEVERITY_MEDIUM
        )
        with SessionLocal() as db:
            self._emit(
                db,
                severity  = sev,
                event_type= "NUCLEI_FINDING",
                asset     = record.get("matched-at") or record.get("host", ""),
                detail    = {
                    "template":    record.get("template-id"),
                    "name":        record.get("info", {}).get("name"),
                    "description": record.get("info", {}).get("description"),
                    "severity":    sev,
                },
            )
            db.commit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _emit(self, db: Session, severity: str, event_type: str, asset: str, detail: dict) -> None:
        """Persist a DiffEvent and add it to the local event list for notification."""
        event = DiffEvent(
            program_id = self.program_id,
            severity   = severity,
            event_type = event_type,
            asset      = asset,
            detail     = json.dumps(detail),
            notified   = False,
        )
        db.add(event)
        self._events.append({
            "severity":   severity,
            "event_type": event_type,
            "asset":      asset,
            "detail":     detail,
        })

    def _prev_status(self, db: Session, domain_id: int) -> Optional[int]:
        """Look up the last recorded status code from older DiffEvents for this domain."""
        domain = db.query(Domain).filter_by(id=domain_id).first()
        if not domain:
            return None
        assets = [domain.subdomain]
        if domain.http_service and domain.http_service.url:
            assets.append(domain.http_service.url)

        last = (
            db.query(DiffEvent)
            .filter(
                DiffEvent.program_id == self.program_id,
                DiffEvent.asset.in_(assets),
                DiffEvent.event_type.in_(["ACCESS_FLIP", "NEW_HOST"]),
            )
            .order_by(DiffEvent.created_at.desc())
            .first()
        )
        if last and last.detail:
            d = json.loads(last.detail)
            return d.get("after") if last.event_type == "ACCESS_FLIP" else d.get("status_code")
        return None

    def _prev_tech(self, db: Session, domain_id: int) -> Optional[str]:
        domain = db.query(Domain).filter_by(id=domain_id).first()
        if not domain:
            return None
        assets = [domain.subdomain]
        if domain.http_service and domain.http_service.url:
            assets.append(domain.http_service.url)

        last = (
            db.query(DiffEvent)
            .filter(
                DiffEvent.program_id == self.program_id,
                DiffEvent.asset.in_(assets),
                DiffEvent.event_type.in_(["TECH_CHANGE", "NEW_HOST"]),
            )
            .order_by(DiffEvent.created_at.desc())
            .first()
        )
        if last and last.detail:
            d = json.loads(last.detail)
            if last.event_type == "TECH_CHANGE":
                return json.dumps(d.get("added", []))
            return d.get("tech")
        return None

    def _prev_hash(self, db: Session, domain_id: int) -> Optional[str]:
        domain = db.query(Domain).filter_by(id=domain_id).first()
        if not domain:
            return None
        assets = [domain.subdomain]
        if domain.http_service and domain.http_service.url:
            assets.append(domain.http_service.url)

        last = (
            db.query(DiffEvent)
            .filter(
                DiffEvent.program_id == self.program_id,
                DiffEvent.asset.in_(assets),
                DiffEvent.event_type.in_(["BODY_CHANGE", "NEW_HOST"]),
            )
            .order_by(DiffEvent.created_at.desc())
            .first()
        )
        if last and last.detail:
            d = json.loads(last.detail)
            return d.get("curr_hash") if last.event_type == "BODY_CHANGE" else d.get("response_hash")
        return None
