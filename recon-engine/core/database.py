"""
core/database.py — SQLAlchemy models and database initialization.

Enables WAL mode for concurrent reads (dashboard) during active writes (scanner).
"""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, create_engine, event, text
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from core.config import settings


# ---------------------------------------------------------------------------
# Base model
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Program(Base):
    __tablename__ = "programs"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    name       = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    domains    = relationship("Domain", back_populates="program", cascade="all, delete-orphan")


class Domain(Base):
    __tablename__ = "domains"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    program_id  = Column(Integer, ForeignKey("programs.id"), nullable=False)
    subdomain   = Column(String(512), nullable=False, unique=True)
    is_active   = Column(Boolean, default=True)
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)

    program      = relationship("Program", back_populates="domains")
    dns_records  = relationship("DnsRecord",   back_populates="domain", cascade="all, delete-orphan")
    http_service = relationship("HttpService", back_populates="domain", uselist=False, cascade="all, delete-orphan")
    endpoints    = relationship("Endpoint",    back_populates="domain", cascade="all, delete-orphan")


class DnsRecord(Base):
    __tablename__ = "dns_records"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    domain_id     = Column(Integer, ForeignKey("domains.id"), nullable=False)
    record_type   = Column(String(10), nullable=False)   # A, AAAA, CNAME
    value         = Column(String(512), nullable=False)
    last_resolved = Column(DateTime, default=datetime.utcnow)

    domain = relationship("Domain", back_populates="dns_records")

    __table_args__ = (UniqueConstraint("domain_id", "record_type", "value"),)


class HttpService(Base):
    __tablename__ = "http_services"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    domain_id      = Column(Integer, ForeignKey("domains.id"), nullable=False, unique=True)
    url            = Column(Text, nullable=False)
    status_code    = Column(Integer)
    title          = Column(Text)
    webserver      = Column(String(255))
    technologies   = Column(Text)          # JSON array stored as string
    content_length = Column(Integer)
    response_hash  = Column(String(64))    # SHA-256 of body
    cdn            = Column(String(255))
    last_checked   = Column(DateTime, default=datetime.utcnow)

    domain = relationship("Domain", back_populates="http_service")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    domain_id    = Column(Integer, ForeignKey("domains.id"), nullable=False)
    endpoint_url = Column(Text, nullable=False, unique=True)
    source       = Column(String(64))      # wayback / katana / gau
    first_seen   = Column(DateTime, default=datetime.utcnow)

    domain = relationship("Domain", back_populates="endpoints")


class DiffEvent(Base):
    """Records every change-detection event for auditing and dashboard display."""
    __tablename__ = "diff_events"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    program_id  = Column(Integer, ForeignKey("programs.id"), nullable=False)
    severity    = Column(String(16), nullable=False)   # critical/high/medium/low
    event_type  = Column(String(64), nullable=False)   # e.g. NEW_HOST, ACCESS_FLIP
    asset       = Column(Text, nullable=False)          # subdomain or URL affected
    detail      = Column(Text)                          # JSON with before/after snapshot
    notified    = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------

def _enable_wal(dbapi_conn, _connection_record):
    """Enable WAL mode and foreign key support on every new connection."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def init_db() -> sessionmaker:
    db_path = Path(settings.database.path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _enable_wal)
    Base.metadata.create_all(engine)

    return sessionmaker(bind=engine, expire_on_commit=False)


# Singleton session factory used across the application
SessionLocal = init_db()


def get_db() -> Session:
    """Dependency-injectable DB session (used in FastAPI routes)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
