"""Tests for atlas module initialization."""

import logging
import os
from unittest.mock import patch

import pytest


class TestModuleInit:
    """Tests for the atlas module initialization."""

    @pytest.mark.parametrize("true_value", ["1", "true", "TRUE", "True"])
    def test_debug_atls_env_var_true_sets_debug_level(self, true_value):
        """Test that DEBUG_ATLS=true sets logger to DEBUG level."""
        with patch.dict(os.environ, {"DEBUG_ATLS": true_value}):
            import importlib

            import atlas

            importlib.reload(atlas)

            from atlas.utils import _get_default_logger

            logger = _get_default_logger()
            assert logger.level == logging.DEBUG

    @pytest.mark.parametrize(
        "false_value", ["0", "false", "FALSE", "False", "something_else", ""]
    )
    def test_debug_atls_env_var_false_sets_error_level(self, false_value):
        """Test that DEBUG_ATLS=false keeps logger at ERROR level."""
        with patch.dict(os.environ, {"DEBUG_ATLS": false_value}, clear=False):
            import importlib

            import atlas

            importlib.reload(atlas)

            from atlas.utils import _get_default_logger

            logger = _get_default_logger()
            assert logger.level == logging.ERROR

    def test_no_debug_atls_env_var_sets_error_level(self):
        """Test that without DEBUG_ATLS, logger is at ERROR level."""
        env = os.environ.copy()
        env.pop("DEBUG_ATLS", None)
        with patch.dict(os.environ, env, clear=True):
            import importlib

            import atlas

            importlib.reload(atlas)

            from atlas.utils import _get_default_logger

            logger = _get_default_logger()
            assert logger.level == logging.ERROR

    def test_module_exports(self):
        """Test that module exports expected attributes."""
        import atlas

        assert hasattr(atlas, "httpx")
        assert hasattr(atlas, "dstack_tdx_policy")
        assert hasattr(atlas, "dev_policy")
        assert hasattr(atlas, "merge_with_default_app_compose")
        assert hasattr(atlas, "AtlsVerificationError")
