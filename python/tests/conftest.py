import pytest


@pytest.fixture
def os_image_hash():
    """OS image hash for testing.

    This is the hash observed in production for vllm.concrete-security.com
    and should be updated if the OS image changes.
    """
    return "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a"


@pytest.fixture
def bootchain():
    """Bootchain measurements for testing.

    These are the measurements for Dstack 0.5.4.1-nvidia.
    """
    return {
        "mrtd": "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
        "rtmr0": "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
        "rtmr1": "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
        "rtmr2": "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57",
    }


@pytest.fixture
def dev_policy_dict():
    """A dev policy dict for testing."""
    return {
        "type": "dstack_tdx",
        "disable_runtime_verification": True,
        "allowed_tcb_status": ["UpToDate", "SWHardeningNeeded", "OutOfDate"],
        "cache_collateral": False,
    }


@pytest.fixture
def prod_policy_dict(bootchain, os_image_hash):
    """A production-like policy dict for testing."""
    return {
        "type": "dstack_tdx",
        "expected_bootchain": bootchain,
        "os_image_hash": os_image_hash,
        "app_compose": {
            "docker_compose_file": "test-compose",
            "runner": "docker-compose",
        },
        "allowed_tcb_status": ["UpToDate"],
        "cache_collateral": False,
        "disable_runtime_verification": False,
    }
