"""Tests for atlas.httpx.transport module."""

from unittest.mock import MagicMock, patch

import pytest

from atlas.httpx.transport import AtlsNetworkBackend, AtlsNetworkStream
from atlas.policy import dev_policy
from atlas.verifiers.errors import AtlsVerificationError


class TestAtlsNetworkStream:
    """Tests for the AtlsNetworkStream class."""

    def test_read_delegates_to_conn(self):
        mock_conn = MagicMock()
        mock_conn.read.return_value = b"hello"
        stream = AtlsNetworkStream(mock_conn)

        result = stream.read(1024)

        mock_conn.read.assert_called_once_with(1024)
        assert result == b"hello"

    def test_write_delegates_to_conn(self):
        mock_conn = MagicMock()
        stream = AtlsNetworkStream(mock_conn)

        stream.write(b"data")

        mock_conn.write.assert_called_once_with(b"data")

    def test_close_delegates_to_conn(self):
        mock_conn = MagicMock()
        stream = AtlsNetworkStream(mock_conn)

        stream.close()

        mock_conn.close.assert_called_once()

    def test_start_tls_returns_self(self):
        mock_conn = MagicMock()
        stream = AtlsNetworkStream(mock_conn)

        result = stream.start_tls(ssl_context=None, server_hostname="example.com")

        assert result is stream

    def test_get_extra_info_returns_none(self):
        mock_conn = MagicMock()
        stream = AtlsNetworkStream(mock_conn)

        assert stream.get_extra_info("ssl_object") is None
        assert stream.get_extra_info("anything") is None


class TestAtlsNetworkBackend:
    """Tests for the AtlsNetworkBackend class."""

    def test_non_atls_host_delegates_to_default(self):
        mock_default = MagicMock()
        mock_stream = MagicMock()
        mock_default.connect_tcp.return_value = mock_stream

        backend = AtlsNetworkBackend(
            policies={"atls.example.com": dev_policy()},
            default_backend=mock_default,
        )

        result = backend.connect_tcp("other.example.com", 443)

        mock_default.connect_tcp.assert_called_once_with(
            "other.example.com",
            443,
            timeout=None,
            local_address=None,
            socket_options=None,
        )
        assert result is mock_stream

    def test_atls_host_connects_via_rust(self):
        backend = AtlsNetworkBackend(
            policies={"atls.example.com": dev_policy()},
        )

        with patch("atlas.httpx.transport.atls_connect") as mock_connect:
            mock_conn = MagicMock()
            mock_conn.attestation = {"trusted": True}
            mock_connect.return_value = mock_conn

            result = backend.connect_tcp("atls.example.com", 443)

            mock_connect.assert_called_once()
            assert isinstance(result, AtlsNetworkStream)
            assert result._conn is mock_conn

    def test_connection_failure_raises_verification_error(self):
        backend = AtlsNetworkBackend(
            policies={"unreachable.example.com": dev_policy()},
        )

        with patch("atlas.httpx.transport.atls_connect") as mock_connect:
            mock_connect.side_effect = ConnectionError("connection refused")
            with pytest.raises(AtlsVerificationError, match="aTLS connection"):
                backend.connect_tcp("unreachable.example.com", 443)

    def test_empty_policies_always_delegates(self):
        mock_default = MagicMock()
        backend = AtlsNetworkBackend(policies={}, default_backend=mock_default)

        backend.connect_tcp("any.example.com", 443)

        mock_default.connect_tcp.assert_called_once()
