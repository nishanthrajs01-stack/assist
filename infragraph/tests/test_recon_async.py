"""Async tests for InfraGraph recon modules and web API.

Run with:
    pytest tests/test_recon_async.py -v
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from infragraph.models.nodes import BaseNode, NodeType, RiskLevel
from infragraph.models.edges import BaseEdge, EdgeType
from infragraph.models.graph import InfraGraph
from infragraph.analyzer.dangling import DanglingAnalyzer
from infragraph.analyzer.signatures import match_cloud_signature
from infragraph.recon.dns_resolver import AsyncDNSScanner, DNSQueryResult


# ---------------------------------------------------------------------------
# DNS Resolver Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_txt_records_populated():
    """IG-1: TXT records should now be fetched by resolve_hostname."""
    scanner = AsyncDNSScanner(concurrency=5, timeout=5.0)
    result = await scanner.resolve_hostname("google.com")
    # google.com has many TXT records (SPF, verification tokens, etc.)
    assert isinstance(result.txt_records, list), "txt_records should be a list"
    assert len(result.txt_records) > 0, (
        "google.com should have TXT records — TXT resolution may still be broken"
    )
    spf_records = [r for r in result.txt_records if "v=spf1" in r.lower()]
    assert len(spf_records) > 0, "google.com should have an SPF record"


@pytest.mark.anyio
async def test_nxdomain_result():
    """NXDOMAIN response sets is_nxdomain and returns early."""
    scanner = AsyncDNSScanner(concurrency=5, timeout=5.0)
    result = await scanner.resolve_hostname("this-domain-definitely-does-not-exist-xyzxyz.com")
    assert result.is_nxdomain is True
    assert result.a_records == []
    assert result.txt_records == []


@pytest.mark.anyio
async def test_batch_resolve():
    """batch_resolve returns one result per input hostname."""
    scanner = AsyncDNSScanner(concurrency=10, timeout=5.0)
    hosts = ["google.com", "github.com"]
    results = await scanner.batch_resolve(hosts)
    assert len(results) == 2
    assert all(r.hostname in hosts for r in results)


# ---------------------------------------------------------------------------
# ASN Resolver Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_asn_lookup_known_ip():
    """ASN lookup returns a valid ASN for a well-known IP."""
    from infragraph.recon.asn_lookup import AsyncASNResolver
    resolver = AsyncASNResolver()
    info = await resolver.lookup_ip("8.8.8.8")
    assert info.asn.startswith("AS"), f"Expected ASN string, got: {info.asn}"
    assert info.owner != ""
    assert info.ip == "8.8.8.8"


@pytest.mark.anyio
async def test_asn_lookup_private_ip():
    """Private IPs should return PRIVATE or UNKNOWN ASN, not crash."""
    from infragraph.recon.asn_lookup import AsyncASNResolver
    resolver = AsyncASNResolver()
    info = await resolver.lookup_ip("192.168.1.1")
    assert info is not None
    assert info.asn in ("PRIVATE", "UNKNOWN", "") or info.asn.startswith("AS")


# ---------------------------------------------------------------------------
# Dangling Analyzer Tests (parallelized — IG-6)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_dangling_scan_parallel_noop():
    """Scan graph with no CNAME edges returns empty findings instantly."""
    scanner_mock = MagicMock()
    analyzer = DanglingAnalyzer(scanner_mock)

    graph = InfraGraph(name="No CNAME graph")
    graph.add_node(BaseNode(id="a.com", type=NodeType.DOMAIN, label="a.com"))
    graph.add_node(BaseNode(id="1.2.3.4", type=NodeType.IP, label="1.2.3.4"))
    graph.add_edge(BaseEdge(source_id="a.com", target_id="1.2.3.4", type=EdgeType.RESOLVES_TO))

    findings = await analyzer.scan_graph(graph)
    assert findings == []


@pytest.mark.anyio
async def test_dangling_scan_nxdomain_takeover():
    """CNAME pointing to NXDOMAIN cloud target should be flagged as takeover."""
    # Mock DNS scanner to report NXDOMAIN for the elasticbeanstalk target
    mock_dns = AsyncMock()
    mock_result = DNSQueryResult(hostname="myapp.elasticbeanstalk.com", is_nxdomain=True)
    mock_dns.resolve_hostname = AsyncMock(return_value=mock_result)

    analyzer = DanglingAnalyzer(mock_dns)

    graph = InfraGraph(name="CNAME Takeover Graph")
    graph.add_node(BaseNode(id="vuln.target.com", type=NodeType.SUBDOMAIN, label="vuln.target.com"))
    graph.add_node(BaseNode(id="myapp.elasticbeanstalk.com", type=NodeType.DOMAIN, label="myapp.elasticbeanstalk.com"))
    graph.add_edge(BaseEdge(
        source_id="vuln.target.com",
        target_id="myapp.elasticbeanstalk.com",
        type=EdgeType.ALIAS_OF
    ))

    findings = await analyzer.scan_graph(graph)
    assert len(findings) == 1
    assert findings[0].subdomain == "vuln.target.com"
    assert findings[0].provider == "AWS"
    assert findings[0].risk_level == RiskLevel.CRITICAL

    # Verify DANGLING_TARGET edge was added to graph
    dangling_edges = [e for e in graph.edges.values() if e.type == EdgeType.DANGLING_TARGET]
    assert len(dangling_edges) == 1


# ---------------------------------------------------------------------------
# Web API Tests (IG-2, IG-3, IG-5)
# ---------------------------------------------------------------------------

def test_api_stats_endpoint():
    """IG-2: GET /api/stats must exist and return graph stat fields."""
    from fastapi.testclient import TestClient
    from infragraph.web.server import app
    client = TestClient(app)
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_nodes" in data
    assert "total_edges" in data
    assert "dangling_records_count" in data


def test_api_snapshots_endpoint():
    """IG-5: GET /api/snapshots should list saved snapshots."""
    from fastapi.testclient import TestClient
    from infragraph.web.server import app
    client = TestClient(app)
    resp = client.get("/api/snapshots")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert len(data) > 0  # demo_snapshot always present
    for key, val in data.items():
        assert "name" in val
        assert "stats" in val


def test_api_snapshot_load():
    """GET /api/snapshots/{key} returns Cytoscape data for a saved snapshot."""
    from fastapi.testclient import TestClient
    from infragraph.web.server import app
    client = TestClient(app)
    resp = client.get("/api/snapshots/demo_snapshot")
    assert resp.status_code == 200
    data = resp.json()
    assert "elements" in data


def test_api_snapshot_missing():
    """GET /api/snapshots/{key} returns 404 for unknown snapshot."""
    from fastapi.testclient import TestClient
    from infragraph.web.server import app
    client = TestClient(app)
    resp = client.get("/api/snapshots/nonexistent_snapshot_xyz")
    assert resp.status_code == 404


def test_api_scan_no_auth_when_key_unset(monkeypatch):
    """IG-3: POST /api/scan should succeed with no API key when env var not set."""
    import os
    import infragraph.web.server as srv
    monkeypatch.setattr(srv, "_API_KEY", None)

    from fastapi.testclient import TestClient
    # We don't actually run a scan (that hits DNS), just check no 401
    # Use a mock to avoid network calls
    async def mock_scan(domain, extra_subdomains=None):
        return InfraGraph(name=f"mock:{domain}")

    from infragraph.web import server
    with patch("infragraph.web.server.InfraScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.scan_domain = AsyncMock(return_value=InfraGraph(name="mock"))
        client = TestClient(server.app)
        resp = client.post("/api/scan", json={"domain": "test.com"})
        # 200 expected (no auth required when _API_KEY is None)
        assert resp.status_code == 200


def test_api_scan_auth_enforced(monkeypatch):
    """IG-3: POST /api/scan must return 401 when API key env var is set but header is missing."""
    import infragraph.web.server as srv
    monkeypatch.setattr(srv, "_API_KEY", "supersecretkey")

    from fastapi.testclient import TestClient
    from infragraph.web import server
    client = TestClient(server.app, raise_server_exceptions=False)
    resp = client.post("/api/scan", json={"domain": "test.com"})
    assert resp.status_code == 401

    # Correct key should pass through to scanner (not 401)
    with patch("infragraph.web.server.InfraScanner") as MockScanner:
        instance = MockScanner.return_value
        instance.scan_domain = AsyncMock(return_value=InfraGraph(name="mock"))
        resp2 = client.post(
            "/api/scan",
            json={"domain": "test.com"},
            headers={"X-API-Key": "supersecretkey"}
        )
        assert resp2.status_code == 200
