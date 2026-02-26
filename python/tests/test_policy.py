"""Tests for atlas.policy module."""

import json

import pytest

from atlas.policy import dev_policy, dstack_tdx_policy, merge_with_default_app_compose


class TestDstackTdxPolicy:
    """Tests for the dstack_tdx_policy() builder function."""

    def test_dev_policy_structure(self):
        """Test that dev_policy returns expected structure."""
        policy = dev_policy()
        assert policy["type"] == "dstack_tdx"
        assert policy["disable_runtime_verification"] is True
        assert "UpToDate" in policy["allowed_tcb_status"]
        assert "SWHardeningNeeded" in policy["allowed_tcb_status"]

    def test_dev_policy_is_json_serializable(self):
        """Test that dev_policy output is JSON-serializable."""
        policy = dev_policy()
        json_str = json.dumps(policy)
        parsed = json.loads(json_str)
        assert parsed["type"] == "dstack_tdx"

    def test_dstack_tdx_policy_defaults(self):
        """Test default values for dstack_tdx_policy."""
        policy = dstack_tdx_policy(disable_runtime_verification=True)
        assert policy["type"] == "dstack_tdx"
        assert policy["allowed_tcb_status"] == ["UpToDate"]
        assert policy["cache_collateral"] is False
        assert policy["disable_runtime_verification"] is True

    def test_dstack_tdx_policy_with_bootchain(self, bootchain, os_image_hash):
        """Test dstack_tdx_policy with bootchain and OS image hash."""
        policy = dstack_tdx_policy(
            expected_bootchain=bootchain,
            os_image_hash=os_image_hash,
            app_compose_docker_compose_file="test-compose",
        )
        assert policy["expected_bootchain"] == bootchain
        assert policy["os_image_hash"] == os_image_hash
        assert policy["app_compose"]["docker_compose_file"] == "test-compose"

    def test_dstack_tdx_policy_with_custom_tcb(self):
        """Test dstack_tdx_policy with custom TCB status list."""
        policy = dstack_tdx_policy(
            allowed_tcb_status=["UpToDate", "SWHardeningNeeded"],
            disable_runtime_verification=True,
        )
        assert policy["allowed_tcb_status"] == ["UpToDate", "SWHardeningNeeded"]

    def test_dstack_tdx_policy_with_pccs_url(self):
        """Test dstack_tdx_policy with custom PCCS URL."""
        policy = dstack_tdx_policy(
            pccs_url="https://custom-pccs.example.com",
            disable_runtime_verification=True,
        )
        assert policy["pccs_url"] == "https://custom-pccs.example.com"

    def test_bootchain_without_os_image_hash_raises(self, bootchain):
        """Test that providing bootchain without os_image_hash raises ValueError."""
        with pytest.raises(ValueError, match="must be provided together"):
            dstack_tdx_policy(expected_bootchain=bootchain)

    def test_os_image_hash_without_bootchain_raises(self, os_image_hash):
        """Test that providing os_image_hash without bootchain raises ValueError."""
        with pytest.raises(ValueError, match="must be provided together"):
            dstack_tdx_policy(os_image_hash=os_image_hash)

    def test_dstack_tdx_policy_app_compose_overrides(self):
        """Test that app_compose overrides work correctly."""
        policy = dstack_tdx_policy(
            app_compose_docker_compose_file="my-compose.yml",
            app_compose_allowed_envs=["API_KEY", "SECRET"],
            disable_runtime_verification=True,
        )
        # When runtime verification is disabled, app_compose is not included
        assert "app_compose" not in policy

    def test_dstack_tdx_policy_app_compose_overrides_with_runtime(
        self, bootchain, os_image_hash
    ):
        """Test that app_compose overrides work when runtime verification is enabled."""
        policy = dstack_tdx_policy(
            expected_bootchain=bootchain,
            os_image_hash=os_image_hash,
            app_compose_docker_compose_file="my-compose.yml",
            app_compose_allowed_envs=["API_KEY", "SECRET"],
        )
        assert policy["app_compose"]["docker_compose_file"] == "my-compose.yml"
        assert policy["app_compose"]["allowed_envs"] == ["API_KEY", "SECRET"]

    def test_dstack_tdx_policy_is_json_serializable(self, bootchain, os_image_hash):
        """Test that full policy is JSON-serializable."""
        policy = dstack_tdx_policy(
            expected_bootchain=bootchain,
            os_image_hash=os_image_hash,
            app_compose_docker_compose_file="test",
            allowed_tcb_status=["UpToDate"],
        )
        json_str = json.dumps(policy)
        parsed = json.loads(json_str)
        assert parsed["type"] == "dstack_tdx"


class TestMergeWithDefaultAppCompose:
    """Tests for merge_with_default_app_compose."""

    def test_merge_empty_dict(self):
        """Test merging empty dict gets all defaults."""
        result = merge_with_default_app_compose({})
        assert "runner" in result
        assert result["runner"] == "docker-compose"

    def test_merge_preserves_user_values(self):
        """Test that user-provided values override defaults."""
        result = merge_with_default_app_compose(
            {"docker_compose_file": "my-compose.yml"}
        )
        assert result["docker_compose_file"] == "my-compose.yml"
        # Defaults should still be present
        assert "runner" in result
