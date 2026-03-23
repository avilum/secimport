import unittest
from unittest.mock import patch, MagicMock
import importlib.util
from secimport.sandbox_helper import secure_import
from secimport.backends.common.instrumentation_backend import InstrumentationBackend

# Check if stapsdt is available for testing
STAPSDT_AVAILABLE = importlib.util.find_spec("stapsdt") is not None


class TestStapsdtSupport(unittest.TestCase):
    def setUp(self):
        # Clear global singleton state before each test to ensure isolation
        import secimport.sandbox_helper

        secimport.sandbox_helper._GLOBAL_STAPS_PROVIDER = None
        secimport.sandbox_helper._GLOBAL_ENTRY_PROBE = None

    @unittest.skipIf(not STAPSDT_AVAILABLE, "stapsdt package not installed")
    @patch("stapsdt.Provider")
    @patch(
        "secimport.backends.bpftrace_backend.bpftrace_backend.run_bpftrace_script_for_module"
    )
    def test_secure_import_with_stapsdt_fires_probe_when_static_dtrace_missing(
        self, mock_run_bpftrace, mock_provider_class
    ):
        """Verify stapsdt fires when static DTrace is missing."""
        import stapsdt
        mock_provider = MagicMock()
        mock_probe = MagicMock()
        mock_provider_class.return_value = mock_provider
        mock_provider.add_probe.return_value = mock_probe
        mock_run_bpftrace.return_value = True

        # Simulate static DTrace MISSING
        with patch("secimport.sandbox_helper.HAS_STATIC_DTRACE", False):
            secure_import("math", backend=InstrumentationBackend.EBPF)

            # Verify stapsdt WAS used with the standard "python" provider and "function__entry" probe
            mock_provider_class.assert_called_with("python")
            mock_provider.add_probe.assert_called_with("function__entry", stapsdt.ArgTypes.uint64)
            mock_provider.load.assert_called_once()
            mock_probe.fire.assert_called_once_with("math")

    @unittest.skipIf(not STAPSDT_AVAILABLE, "stapsdt package not installed")
    @patch("stapsdt.Provider")
    @patch(
        "secimport.backends.bpftrace_backend.bpftrace_backend.run_bpftrace_script_for_module"
    )
    def test_secure_import_skips_stapsdt_when_static_dtrace_exists(
        self, mock_run_bpftrace, mock_provider_class
    ):
        """Verify stapsdt is NOT used when static DTrace exists."""
        mock_run_bpftrace.return_value = True

        # Simulate static DTrace EXISTS
        with patch("secimport.sandbox_helper.HAS_STATIC_DTRACE", True):
            secure_import("math", backend=InstrumentationBackend.EBPF)

            # Verify stapsdt was NOT used
            mock_provider_class.assert_not_called()

    @patch("importlib.util.find_spec")
    def test_stapsdt_not_available_does_not_fail(self, mock_find_spec):
        # Simulate stapsdt not being installed
        mock_find_spec.return_value = None

        with patch("secimport.sandbox_helper.STAPSDT_AVAILABLE", False):
            with patch(
                "secimport.backends.bpftrace_backend.bpftrace_backend.run_bpftrace_script_for_module"
            ) as mock_run:
                mock_run.return_value = True
                module = secure_import("math", backend=InstrumentationBackend.EBPF)
                self.assertIsNotNone(module)
                self.assertEqual(module.__name__, "math")


if __name__ == "__main__":
    unittest.main()
