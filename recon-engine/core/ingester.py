"""
core/ingester.py — Parses tool JSONL output and normalizes records into the DB.

Called by runner.py via the on_result callback after each tool emits a record.
"""

import json
from datetime import datetime
from typing import Any, Dict

from sqlalchemy.orm import Session

from core.database import Domain, DnsRecord, Endpoint, HttpService, Program, SessionLocal


class Ingester:
    def __init__(self, program_name: str):
        self.program_name = program_name
        self._program_id: int | None = None

    def _get_or_create_program(self, db: Session) -> int:
        prog = db.query(Program).filter_by(name=self.program_name).first()
        if not prog:
            prog = Program(name=self.program_name)
            db.add(prog)
            db.commit()
            db.refresh(prog)
        return prog.id

    @property
    def program_id(self) -> int:
        if self._program_id is None:
            with SessionLocal() as db:
                self._program_id = self._get_or_create_program(db)
        return self._program_id

    # ------------------------------------------------------------------
    # Stage handlers
    # ------------------------------------------------------------------

    def ingest_subdomain(self, record: Dict[str, Any]) -> None:
        """Record a discovered subdomain."""
        subdomain = record.get("subdomain", "").strip().lower()
        if not subdomain:
            return

        with SessionLocal() as db:
            existing = db.query(Domain).filter_by(subdomain=subdomain).first()
            if existing:
                existing.is_active = True
                existing.last_seen = datetime.utcnow()
            else:
                db.add(Domain(
                    program_id=self.program_id,
                    subdomain=subdomain,
                    is_active=True,
                ))
            db.commit()

    def ingest_dns(self, record: Dict[str, Any]) -> None:
        """Record resolved DNS A/CNAME/AAAA entries."""
        host = record.get("host", "").strip().lower()
        if not host:
            return

        with SessionLocal() as db:
            domain = db.query(Domain).filter_by(subdomain=host).first()
            if not domain:
                domain = Domain(
                    program_id=self.program_id,
                    subdomain=host,
                    is_active=True,
                )
                db.add(domain)
                db.flush()

            # Process A records
            for ip in record.get("a", []):
                self._upsert_dns(db, domain.id, "A", ip)

            # Process CNAME
            for cname in record.get("cname", []):
                self._upsert_dns(db, domain.id, "CNAME", cname)

            # Process AAAA
            for ip6 in record.get("aaaa", []):
                self._upsert_dns(db, domain.id, "AAAA", ip6)

            db.commit()

    def _upsert_dns(self, db: Session, domain_id: int, record_type: str, value: str) -> None:
        existing = db.query(DnsRecord).filter_by(
            domain_id=domain_id, record_type=record_type, value=value
        ).first()
        if existing:
            existing.last_resolved = datetime.utcnow()
        else:
            db.add(DnsRecord(domain_id=domain_id, record_type=record_type, value=value))

    def ingest_http(self, record: Dict[str, Any]) -> None:
        """Record HTTP probe results. Stores previous hash for diff detection."""
        host = record.get("host") or record.get("input", "")
        url  = record.get("url", "")
        if not host and not url:
            return

        # Normalise host
        host = host.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]

        with SessionLocal() as db:
            domain = db.query(Domain).filter_by(subdomain=host).first()
            if not domain:
                domain = Domain(program_id=self.program_id, subdomain=host, is_active=True)
                db.add(domain)
                db.flush()

            technologies = json.dumps(record.get("tech", []) or record.get("technologies", []))
            new_hash     = (record.get("hash") or {}).get("sha256") or record.get("hash", "")

            existing = db.query(HttpService).filter_by(domain_id=domain.id).first()
            if existing:
                existing.url            = url or existing.url
                existing.status_code    = record.get("status_code") or record.get("status-code")
                existing.title          = record.get("title")
                existing.webserver      = record.get("webserver") or record.get("web-server")
                existing.technologies   = technologies
                existing.content_length = record.get("content_length") or record.get("content-length")
                existing.response_hash  = new_hash
                existing.last_checked   = datetime.utcnow()
            else:
                db.add(HttpService(
                    domain_id      = domain.id,
                    url            = url,
                    status_code    = record.get("status_code") or record.get("status-code"),
                    title          = record.get("title"),
                    webserver      = record.get("webserver") or record.get("web-server"),
                    technologies   = technologies,
                    content_length = record.get("content_length") or record.get("content-length"),
                    response_hash  = new_hash,
                ))
            db.commit()

    def ingest_endpoint(self, record: Dict[str, Any]) -> None:
        """Record a discovered URL endpoint."""
        url    = record.get("url") or record.get("output", "")
        source = record.get("source", "unknown")
        if not url:
            return

        # Derive domain from URL
        try:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ""
        except Exception:
            return

        with SessionLocal() as db:
            domain = db.query(Domain).filter_by(subdomain=hostname).first()
            if not domain:
                return   # Only track endpoints for known domains

            existing = db.query(Endpoint).filter_by(endpoint_url=url).first()
            if not existing:
                db.add(Endpoint(domain_id=domain.id, endpoint_url=url, source=source))
                db.commit()

    def ingest_nuclei(self, record: Dict[str, Any]) -> None:
        """
        Nuclei findings are passed directly to the diff engine as critical events.
        They are stored as DiffEvents rather than a separate table.
        """
        from core.diff_engine import DiffEngine
        engine = DiffEngine(self.program_id)
        engine.record_nuclei_finding(record)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    async def __call__(self, stage: str, record: Dict[str, Any]) -> None:
        """Async callback compatible with runner.py on_result."""
        dispatch = {
            "subdomain": self.ingest_subdomain,
            "dns":       self.ingest_dns,
            "http":      self.ingest_http,
            "endpoint":  self.ingest_endpoint,
            "nuclei":    self.ingest_nuclei,
        }
        handler = dispatch.get(stage)
        if handler:
            handler(record)
