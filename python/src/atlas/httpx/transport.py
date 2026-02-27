"""
httpcore NetworkBackend that routes aTLS connections through Rust.

For hostnames with an aTLS policy, connections are established through
the Rust core (TCP + TLS + EKM binding + attestation). For other hostnames,
requests fall through to the default httpcore backend (standard TLS).

httpcore handles all HTTP/1.1 framing over the attested stream.
"""

import json

import httpcore

from .._atlas import atls_connect
from ..utils import _get_default_logger
from ..verifiers.errors import AtlsVerificationError

logger = _get_default_logger()


class AtlsNetworkStream(httpcore.NetworkStream):
    """NetworkStream wrapping a Rust AtlsConnection.

    Rust owns the TLS session. This stream proxies read/write to it.
    ``start_tls`` is a no-op because TLS was already established by Rust.

    **Limitation**: ``timeout`` parameters on ``read``/``write`` are not
    forwarded to the Rust side. The Rust tokio runtime manages its own I/O
    scheduling. httpx-level timeouts (e.g. ``httpx.Timeout``) will not be
    enforced on aTLS streams.
    """

    def __init__(self, conn):
        self._conn = conn

    def read(self, max_bytes, timeout=None):
        # timeout is not forwarded to Rust; the Rust side blocks on tokio I/O.
        return bytes(self._conn.read(max_bytes))

    def write(self, buffer, timeout=None):
        # timeout is not forwarded to Rust; the Rust side blocks on tokio I/O.
        self._conn.write(bytes(buffer))

    def close(self):
        self._conn.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return self  # TLS already established by Rust

    def get_extra_info(self, info):
        return None  # No Python ssl_object → httpcore uses HTTP/1.1


class AtlsNetworkBackend(httpcore.NetworkBackend):
    """Routes aTLS hostnames through Rust, others through the default backend."""

    def __init__(self, policies, default_backend=None):
        self._policies = policies
        self._default_backend = default_backend or httpcore.SyncBackend()

    def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        if host not in self._policies:
            return self._default_backend.connect_tcp(
                host,
                port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )

        policy_json = json.dumps(self._policies[host])
        logger.debug(f"aTLS connecting to {host}:{port}")

        try:
            conn = atls_connect(host, port, host, policy_json)
        except Exception as e:
            raise AtlsVerificationError(
                f"aTLS connection to {host}:{port} failed: {e}"
            ) from e

        logger.debug(
            f"aTLS connected to {host}:{port}, attestation: {conn.attestation}"
        )
        return AtlsNetworkStream(conn)
