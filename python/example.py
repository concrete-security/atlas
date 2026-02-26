import os

os.environ["DEBUG_ATLS"] = "true"

from atlas import httpx
from atlas.policy import dstack_tdx_policy

if __name__ == "__main__":
    docker_compose_path = os.path.join(
        os.path.dirname(__file__), "../core/tests/data/vllm_docker_compose.yml"
    )
    with open(docker_compose_path, "r") as f:
        docker_compose_file = f.read()

    # Bootchain measurements depend on hardware configuration (CPU count, memory size, etc.)
    # These values must be computed for your specific deployment
    # See core/BOOTCHAIN-VERIFICATION.md for instructions
    expected_bootchain = {
        "mrtd": "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
        "rtmr0": "24c15e08c07aa01c531cbd7e8ba28f8cb62e78f6171bf6a8e0800714a65dd5efd3a06bf0cf5433c02bbfac839434b418",
        "rtmr1": "6e1afb7464ed0b941e8f5bf5b725cf1df9425e8105e3348dca52502f27c453f3018a28b90749cf05199d5a17820101a7",
        "rtmr2": "89e73cedf48f976ffebe8ac1129790ff59a0f52d54d969cb73455b1a79793f1dc16edc3b1fccc0fd65ea5905774bbd57",
    }
    os_image_hash = "86b181377635db21c415f9ece8cc8505f7d4936ad3be7043969005a8c4690c1a"

    policy = dstack_tdx_policy(
        # Makes sure the TEE is running this docker-compose
        app_compose_docker_compose_file=docker_compose_file,
        # Allow env vars
        app_compose_allowed_envs=["EKM_SHARED_SECRET", "AUTH_SERVICE_TOKEN"],
        # Verify full bootchain (MRTD, RTMR0-2) and OS image hash
        expected_bootchain=expected_bootchain,
        os_image_hash=os_image_hash,
    )

    with httpx.Client(
        atls_policy_per_hostname={"vllm.concrete-security.com": policy}
    ) as client:
        # No aTLS policy for httpbin, uses standard HTTPS
        response = client.get("https://httpbin.org/get")
        print(f"Response status: {response.status_code}")

        response = client.get("https://vllm.concrete-security.com/health")
        print(f"Response status: {response.status_code}")

        response = client.get("https://vllm.concrete-security.com/v1/models")
        print(f"Response status: {response.status_code}")
