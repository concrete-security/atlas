"""Type stubs for the Rust _atlas extension module (PyO3)."""

class ReattestationError(Exception):
    """Re-attestation of an established aTLS connection failed.

    The connection has been closed (fail closed); reconnecting performs a
    full fresh attestation.
    """

class AtlsConnection:
    """An attested TLS connection backed by Rust."""

    @property
    def attestation(self) -> dict[str, object]: ...
    def read(self, size: int) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...

def atls_connect(
    host: str, port: int, server_name: str, policy_json: str
) -> AtlsConnection: ...
def merge_with_default_app_compose_py(user_compose_json: str) -> str: ...
