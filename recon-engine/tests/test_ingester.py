"""Unit tests for ReconEngine Ingester."""
import uuid
import pytest
from core.database import Base, Domain, DnsRecord, Endpoint, HttpService, Program, SessionLocal, init_db
from core.ingester import Ingester


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_ingest_subdomain():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"TestProgram_IngestSub_{uid}"
    sub1 = f"sub1-{uid}.testdomain.com"
    sub2 = f"sub2-{uid}.testdomain.com"
    ingester = Ingester(prog_name)
    ingester.ingest_subdomain({"subdomain": sub1})
    ingester.ingest_subdomain({"subdomain": sub2})

    with SessionLocal() as db:
        prog = db.query(Program).filter_by(name=prog_name).first()
        assert prog is not None
        domains = db.query(Domain).filter_by(program_id=prog.id).all()
        assert len(domains) == 2
        names = {d.subdomain for d in domains}
        assert sub1 in names
        assert sub2 in names


def test_ingest_dns():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"TestProgram_DNS_{uid}"
    host = f"dns-{uid}.testdomain.com"
    ingester = Ingester(prog_name)
    ingester.ingest_dns({
        "host": host,
        "a": ["1.1.1.1", "1.0.0.1"],
        "cname": ["cname.target.com"],
        "aaaa": ["2606:4700:4700::1111"]
    })

    with SessionLocal() as db:
        domain = db.query(Domain).filter_by(subdomain=host).first()
        assert domain is not None
        records = db.query(DnsRecord).filter_by(domain_id=domain.id).all()
        assert len(records) == 4
        types = {r.record_type for r in records}
        assert types == {"A", "CNAME", "AAAA"}


def test_ingest_http():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"TestProgram_HTTP_{uid}"
    host = f"http-{uid}.testdomain.com"
    url = f"https://{host}"
    ingester = Ingester(prog_name)
    ingester.ingest_http({
        "host": host,
        "url": url,
        "status_code": 200,
        "title": "Welcome Page",
        "webserver": "nginx/1.18",
        "tech": ["Nginx", "React"],
        "hash": {"sha256": "abcdef123456"}
    })

    with SessionLocal() as db:
        domain = db.query(Domain).filter_by(subdomain=host).first()
        assert domain is not None
        svc = db.query(HttpService).filter_by(domain_id=domain.id).first()
        assert svc is not None
        assert svc.status_code == 200
        assert svc.title == "Welcome Page"
        assert svc.webserver == "nginx/1.18"
        assert "React" in svc.technologies
        assert svc.response_hash == "abcdef123456"


def test_ingest_endpoint():
    uid = uuid.uuid4().hex[:8]
    prog_name = f"TestProgram_EP_{uid}"
    sub = f"api-{uid}.testdomain.com"
    ep_url = f"https://{sub}/v1/auth/login"
    ingester = Ingester(prog_name)
    # Ingest domain first so endpoint is associated
    ingester.ingest_subdomain({"subdomain": sub})
    ingester.ingest_endpoint({
        "url": ep_url,
        "source": "katana"
    })

    with SessionLocal() as db:
        ep = db.query(Endpoint).filter_by(endpoint_url=ep_url).first()
        assert ep is not None
        assert ep.source == "katana"

