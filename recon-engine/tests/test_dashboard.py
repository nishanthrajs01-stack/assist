"""Unit tests for ReconEngine Dashboard."""
import pytest
from fastapi.testclient import TestClient

from core.database import init_db
from dashboard.app import app


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


def test_dashboard_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ReconEngine" in resp.text


def test_dashboard_domains(client):
    resp = client.get("/domains")
    assert resp.status_code == 200


def test_dashboard_endpoints(client):
    resp = client.get("/endpoints")
    assert resp.status_code == 200


def test_dashboard_diffs(client):
    resp = client.get("/diffs")
    assert resp.status_code == 200


def test_dashboard_api_stats(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_domains" in data
    assert "active_domains" in data
    assert "total_endpoints" in data
    assert "unread_diffs" in data
