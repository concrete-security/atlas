"""
httpx.Client with aTLS verification.
"""

import httpx

from ..utils import _get_default_logger
from .transport import AtlsNetworkBackend, AtlsNetworkStream

logger = _get_default_logger()


class Client(httpx.Client):
    """httpx.Client with aTLS verification.

    Connections to hostnames in ``atls_policy_per_hostname`` are routed through
    Rust aTLS (TLS + EKM binding + attestation). Other hostnames use standard HTTPS.

    You should never set the ``transport`` keyword argument as it's used by
    the aTLS transport.
    """

    def __init__(
        self,
        *args,
        atls_policy_per_hostname: dict[str, dict] | None = None,
        **kwargs,
    ):
        if kwargs.get("transport") is not None:
            raise ValueError(
                "setting transport argument isn't possible. aTLS uses its own transport"
            )
        transport = httpx.HTTPTransport()
        # Accessing httpcore internals to inject our network backend.
        # httpx is pinned to >=0.28.1,<0.29 in pyproject.toml to guard against breakage.
        transport._pool._network_backend = AtlsNetworkBackend(
            atls_policy_per_hostname or {},
            default_backend=transport._pool._network_backend,
        )
        kwargs["transport"] = transport
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        response = super().send(request, **kwargs)
        # httpcore includes network_stream in response extensions (http11.py:129)
        # httpx passes extensions through (default.py:258)
        stream = response.extensions.get("network_stream")
        if isinstance(stream, AtlsNetworkStream):
            response.extensions["attestation"] = stream._conn.attestation
        return response
