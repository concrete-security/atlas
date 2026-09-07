from .._atlas import ReattestationError


class AtlsVerificationError(Exception):
    """Exception raised when aTLS verification fails."""

    pass


__all__ = ["AtlsVerificationError", "ReattestationError"]
