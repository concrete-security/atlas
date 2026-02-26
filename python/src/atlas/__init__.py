import logging
import os

from . import httpx
from .policy import dev_policy, dstack_tdx_policy, merge_with_default_app_compose
from .utils import _get_default_logger
from .verifiers.errors import AtlsVerificationError

logger = _get_default_logger()

if os.getenv("DEBUG_ATLS", "").lower() in ("1", "true"):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.ERROR)


__all__ = [
    "httpx",
    "dstack_tdx_policy",
    "dev_policy",
    "merge_with_default_app_compose",
    "AtlsVerificationError",
]
