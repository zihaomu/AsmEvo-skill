from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "asmevo" / "scripts"))

import preflight


class PreflightTests(unittest.TestCase):
    def test_invalid_mode_is_rejected(self) -> None:
        with self.assertRaises(preflight.PreflightInputError):
            preflight.inspect(
                mode="unknown",
                artifact=None,
                capabilities={},
                required_files=[],
                require_gpu=False,
                target_arch=None,
                detected_arches=[],
            )

    def test_audit_mode_has_no_execution_requirements(self) -> None:
        report = preflight.inspect(
            mode="audit",
            artifact=None,
            capabilities={},
            required_files=[],
            require_gpu=False,
            target_arch=None,
            detected_arches=[],
        )

        self.assertTrue(report["ready"])
        self.assertEqual(report["required_capabilities"], [])

    def test_source_mode_fails_closed_without_adapters(self) -> None:
        report = preflight.inspect(
            mode="source",
            artifact=Path("missing-kernel.cpp"),
            capabilities={},
            required_files=[],
            require_gpu=False,
            target_arch="gfx942",
            detected_arches=["gfx942"],
        )

        self.assertFalse(report["ready"])
        self.assertIn("artifact not found", report["failures"][0])
        missing = next(
            failure
            for failure in report["failures"]
            if "missing capabilities" in failure
        )
        self.assertTrue(
            all(name in missing for name in ("build", "benchmark", "oracle"))
        )

    def test_source_mode_resolves_complete_adapter_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifact = directory / "kernel.cpp"
            artifact.write_text('extern "C" __global__ void k() {}\n', encoding="utf-8")
            adapter = directory / "adapter"
            adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            adapter.chmod(adapter.stat().st_mode | 0o111)
            capabilities = {
                "build": str(adapter),
                "oracle": str(adapter),
                "benchmark": str(adapter),
            }

            report = preflight.inspect(
                mode="source",
                artifact=artifact,
                capabilities=capabilities,
                required_files=[artifact],
                require_gpu=False,
                target_arch="gfx942",
                detected_arches=["gfx942"],
            )

        self.assertTrue(report["ready"])
        self.assertEqual(len(report["artifact"]["sha256"]), 64)
        self.assertTrue(
            all(item["resolved"] for item in report["capabilities"].values())
        )

    def test_non_executable_path_does_not_satisfy_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tool = Path(temporary) / "not-executable"
            tool.write_text("noop", encoding="utf-8")
            self.assertFalse(os.access(tool, os.X_OK))

            report = preflight.inspect(
                mode="source",
                artifact=tool,
                capabilities={
                    "build": str(tool),
                    "oracle": str(tool),
                    "benchmark": str(tool),
                },
                required_files=[],
                require_gpu=False,
                target_arch=None,
                detected_arches=[],
            )

        self.assertFalse(report["ready"])
        self.assertTrue(
            any("missing capabilities" in failure for failure in report["failures"])
        )

    def test_execution_mode_requires_target_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "kernel.cpp"
            artifact.write_text("kernel", encoding="utf-8")

            report = preflight.inspect(
                mode="source",
                artifact=artifact,
                capabilities={},
                required_files=[],
                require_gpu=False,
                target_arch=None,
                detected_arches=[],
            )

        self.assertFalse(report["ready"])
        self.assertIn("source mode requires --target-arch", report["failures"])

    def test_execution_mode_cannot_skip_target_architecture_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "kernel.hsaco"
            artifact.write_bytes(b"binary")

            report = preflight.inspect(
                mode="binary",
                artifact=artifact,
                capabilities={},
                required_files=[],
                require_gpu=False,
                target_arch="gfx942",
                detected_arches=["gfx1150"],
            )

        self.assertFalse(report["ready"])
        self.assertFalse(report["gpu"]["target_arch_verified"])
        self.assertTrue(
            any("gfx942 not found" in failure for failure in report["failures"])
        )

    def test_execution_mode_requires_independent_architecture_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "kernel.cpp"
            artifact.write_text("kernel", encoding="utf-8")

            report = preflight.inspect(
                mode="source",
                artifact=artifact,
                capabilities={},
                required_files=[],
                require_gpu=False,
                target_arch="gfx942",
                detected_arches=[],
            )

        self.assertFalse(report["ready"])
        self.assertIn(
            "target GPU architecture was not independently detected",
            report["failures"],
        )


if __name__ == "__main__":
    unittest.main()
