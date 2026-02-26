"""Tests for atlas.httpx.Client."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from atlas.httpx import Client as AtlsClient
from atlas.httpx.transport import AtlsNetworkStream
from atlas.policy import dev_policy


class TestAtlsClient:
    """Tests for the atlas.httpx.Client class."""

    def test_init_basic(self):
        """Test basic AtlsClient initialization."""
        client = AtlsClient(atls_policy_per_hostname={"host.example.com": dev_policy()})
        assert isinstance(client, httpx.Client)

    def test_init_empty_hostnames(self):
        """Test AtlsClient with empty hostname map."""
        client = AtlsClient(atls_policy_per_hostname={})
        assert isinstance(client, httpx.Client)

    def test_init_none_hostnames(self):
        """Test AtlsClient with None hostname map."""
        client = AtlsClient(atls_policy_per_hostname=None)
        assert isinstance(client, httpx.Client)

    def test_init_with_transport_raises_error(self):
        """Test that passing transport argument raises ValueError."""
        with pytest.raises(
            ValueError, match="setting transport argument isn't possible"
        ):
            AtlsClient(
                atls_policy_per_hostname={"host.example.com": dev_policy()},
                transport=httpx.HTTPTransport(),
            )

    def test_context_manager(self):
        """Test AtlsClient as context manager."""
        with AtlsClient(
            atls_policy_per_hostname={"host.example.com": dev_policy()}
        ) as client:
            assert isinstance(client, httpx.Client)

    def test_is_httpx_client_subclass(self):
        """Test that AtlsClient is a subclass of httpx.Client."""
        assert issubclass(AtlsClient, httpx.Client)

    def test_send_populates_attestation_extension(self):
        """Test that attestation is extracted from aTLS network stream."""
        mock_conn = MagicMock()
        mock_conn.attestation = {"trusted": True, "tee_type": "tdx"}
        mock_stream = AtlsNetworkStream(mock_conn)

        client = AtlsClient(atls_policy_per_hostname={"atls.example.com": dev_policy()})

        # Build a mock response with network_stream in extensions
        mock_response = httpx.Response(
            status_code=200,
            content=b"ok",
            extensions={"network_stream": mock_stream},
        )

        with patch.object(httpx.Client, "send", return_value=mock_response):
            request = httpx.Request("GET", "https://atls.example.com/api")
            response = client.send(request)

        assert response.extensions["attestation"] == {
            "trusted": True,
            "tee_type": "tdx",
        }

    def test_send_no_attestation_for_regular_hosts(self):
        """Test that attestation is not set for non-aTLS responses."""
        client = AtlsClient(atls_policy_per_hostname={"atls.example.com": dev_policy()})

        mock_response = httpx.Response(
            status_code=200,
            content=b"ok",
            extensions={"network_stream": MagicMock()},  # not an AtlsNetworkStream
        )

        with patch.object(httpx.Client, "send", return_value=mock_response):
            request = httpx.Request("GET", "https://other.example.com/api")
            response = client.send(request)

        assert "attestation" not in response.extensions
