
import json
from unittest.mock import Mock

import httpx
import pytest

from vuln_risk_lakehouse.ingestion.fetch_kev import fetch_kev, save_kev


@pytest.fixture
def sample_kev():
    """Provide a small valid CISA KEV catalog."""

    return {
        "catalogVersion": "2026.11.24",
        "dateReleased": "2026-11-24T19:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {"cveID": "CVE-2026-1234"},
            {"cveID": "CVE-2026-5678"},
        ],
    }


def test_fetch_kev_valid_response(monkeypatch, sample_kev):
    """Verify a valid API response is returned."""

    mock_response = Mock()
    mock_response.json.return_value = sample_kev
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: mock_response)

    result = fetch_kev()

    assert result == sample_kev
    mock_response.raise_for_status.assert_called_once()


@pytest.mark.parametrize("missing_field", ["catalogVersion", "dateReleased", "count", "vulnerabilities"])
def test_fetch_kev_missing_fields(monkeypatch, sample_kev, missing_field):
    """Verify missing required fields raise an error."""

    sample_kev.pop(missing_field)

    mock_response = Mock()
    mock_response.json.return_value = sample_kev
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: mock_response)

    with pytest.raises(ValueError, match="missing required field"):
        fetch_kev()


def test_fetch_kev_invalid_count(monkeypatch, sample_kev):
    """Verify the catalog count matches the number of records."""

    sample_kev["count"] = 100

    mock_response = Mock()
    mock_response.json.return_value = sample_kev
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: mock_response)

    with pytest.raises(ValueError, match="count does not match"):
        fetch_kev()


def test_fetch_kev_http_error(monkeypatch):
    """Verify HTTP failures are propagated."""

    request = httpx.Request("GET", "https://example.com")
    response = httpx.Response(500, request=request)

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: response)

    with pytest.raises(httpx.HTTPStatusError):
        fetch_kev()


def test_save_kev_creates_snapshot(tmp_path, sample_kev):
    """Verify a snapshot is written to the correct directory."""

    target = save_kev(sample_kev, out_dir=tmp_path)

    assert target.exists()
    assert target.suffix == ".json"
    assert target.parent.name.startswith("ingest_date=")
    assert target.parent.parent.name == "kev"

    saved_data = json.loads(target.read_text(encoding="utf-8"))
    assert saved_data == sample_kev


def test_save_kev_preserves_snapshots(tmp_path, sample_kev):
    """Verify repeated ingestions preserve separate snapshots."""

    first = save_kev(sample_kev, out_dir=tmp_path)
    second = save_kev(sample_kev, out_dir=tmp_path)

    assert first != second
    assert first.exists()
    assert second.exists()
    assert len(list(tmp_path.rglob("*.json"))) == 2
