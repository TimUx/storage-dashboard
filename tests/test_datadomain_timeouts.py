"""DataDomain timeout handling tests."""

from unittest.mock import patch

import pytest
from requests.exceptions import ReadTimeout


def _make_client():
    from app.api.storage_clients import DellDataDomainClient

    client = DellDataDomainClient.__new__(DellDataDomainClient)
    client.ip_address = "10.112.228.71"
    client.port = 3009
    client.username = "user"
    client.password = "pass"
    client.token = "token"
    client.resolved_address = "ddp13.itscare.prod.dom"
    client.base_url = "https://ddp13.itscare.prod.dom:3009"
    return client


class _TimeoutSession:
    def get(self, url, **kwargs):
        raise ReadTimeout(f"GET {url} timed out")

    def post(self, url, **kwargs):
        raise ReadTimeout(f"POST {url} timed out")


def test_get_health_status_returns_structured_timeout_error():
    import app.api.storage_clients as sc

    client = _make_client()
    with patch.object(sc, "_local_session", _TimeoutSession()):
        with patch("app.ssl_utils.get_ssl_verify", return_value=False):
            status = client.get_health_status()

    assert status["status"] == "error"
    assert "timeout" in (status.get("error") or "").lower()


def test_authenticate_timeout_returns_none():
    import app.api.storage_clients as sc

    client = _make_client()
    with patch.object(sc, "_local_session", _TimeoutSession()):
        with patch("app.ssl_utils.get_ssl_verify", return_value=False):
            token = client.authenticate()

    assert token is None
