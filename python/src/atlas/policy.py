"""
Policy helpers for building aTLS attestation policies.

Policies are JSON-serializable dicts that map directly to the Rust core's
Policy enum. They configure what verification checks to perform during
attestation.
"""

import json
from typing import Optional

from atlas._atlas import merge_with_default_app_compose_py


def merge_with_default_app_compose(user_compose: dict) -> dict:
    """Merge a user-provided app_compose dict with default values.

    This allows users to provide only the fields they care about (typically
    ``docker_compose_file`` and ``allowed_envs``) and get a complete
    app_compose configuration with all required default fields filled in.

    Args:
        user_compose: Dict with user-provided fields.

    Returns:
        Complete app_compose dict with all default fields filled in.
    """
    result_json = merge_with_default_app_compose_py(json.dumps(user_compose))
    return json.loads(result_json)


def dstack_tdx_policy(
    app_compose: Optional[dict] = None,
    expected_bootchain: Optional[dict] = None,
    os_image_hash: Optional[str] = None,
    allowed_tcb_status: Optional[list[str]] = None,
    disable_runtime_verification: bool = False,
    app_compose_docker_compose_file: Optional[str] = None,
    app_compose_allowed_envs: Optional[list[str]] = None,
    pccs_url: Optional[str] = None,
    cache_collateral: bool = False,
) -> dict:
    """Build a DstackTdx attestation policy dict.

    The returned dict is JSON-serializable and matches the Rust
    core's ``Policy::DstackTdx`` variant.

    Args:
        app_compose: Base application compose configuration.
            If not provided, uses defaults via ``merge_with_default_app_compose``.
        expected_bootchain: Bootchain measurements to verify. Dict with keys
            ``mrtd``, ``rtmr0``, ``rtmr1``, ``rtmr2``. Must be used together
            with ``os_image_hash``.
        os_image_hash: Expected OS image hash (SHA256 hex string).
            Must be used together with ``expected_bootchain``.
        allowed_tcb_status: List of acceptable TCB status values.
            Defaults to ``["UpToDate"]``.
        disable_runtime_verification: Skip runtime checks (bootchain,
            app_compose, os_image_hash). NOT recommended for production.
        app_compose_docker_compose_file: Override the ``docker_compose_file``
            key in app_compose.
        app_compose_allowed_envs: Override the ``allowed_envs`` key in
            app_compose.
        pccs_url: PCCS URL for Intel collateral fetching.
        cache_collateral: Cache Intel collateral between verifications.

    Returns:
        Policy dict like ``{"type": "dstack_tdx", ...}``.

    Raises:
        ValueError: If ``expected_bootchain`` or ``os_image_hash`` is provided
            without the other (they must be used together).
    """
    if (expected_bootchain is None) != (os_image_hash is None):
        raise ValueError(
            "expected_bootchain and os_image_hash must be provided together"
        )

    if allowed_tcb_status is None:
        allowed_tcb_status = ["UpToDate"]

    policy: dict = {
        "type": "dstack_tdx",
        "allowed_tcb_status": allowed_tcb_status,
        "cache_collateral": cache_collateral,
        "disable_runtime_verification": disable_runtime_verification,
    }

    if pccs_url is not None:
        policy["pccs_url"] = pccs_url

    if not disable_runtime_verification:
        # Build app_compose
        if app_compose is None:
            compose = merge_with_default_app_compose({})
        else:
            compose = app_compose.copy()

        if app_compose_docker_compose_file is not None:
            compose["docker_compose_file"] = app_compose_docker_compose_file
        if app_compose_allowed_envs is not None:
            compose["allowed_envs"] = app_compose_allowed_envs

        policy["app_compose"] = compose

        if expected_bootchain is not None:
            policy["expected_bootchain"] = expected_bootchain
        if os_image_hash is not None:
            policy["os_image_hash"] = os_image_hash

    return policy


def dev_policy() -> dict:
    """Build a relaxed development policy.

    Disables runtime verification (bootchain, app_compose, os_image_hash
    checks are skipped) and accepts common TCB statuses.

    NOT recommended for production use.

    Returns:
        Policy dict suitable for development/testing.
    """
    return dstack_tdx_policy(
        disable_runtime_verification=True,
        allowed_tcb_status=["UpToDate", "SWHardeningNeeded", "OutOfDate"],
    )
