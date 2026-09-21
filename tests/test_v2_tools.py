from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "asmevo" / "scripts"))

import profile

import assemble
import capability_probe
import code_object_diff
import disassemble
import preflight
import resource_check
from backends import common


class V2ToolTests(unittest.TestCase):
    def _executable(self, directory: Path, name: str, body: str) -> Path:
        path = directory / name
        path.write_text(
            "#!/usr/bin/env python3\n" + textwrap.dedent(body),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def test_assembly_preflight_requires_complete_tool_and_adapter_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifact = directory / "K0.hsaco"
            artifact.write_bytes(b"K0")
            executable = self._executable(
                directory, "adapter", "import sys\nsys.exit(0)\n"
            )
            capabilities = {
                name: str(executable) for name in common.V2_ASSEMBLY_CAPABILITIES
            }
            tools = {name: str(executable) for name in preflight.ASM_TOOL_ROLES}

            ready = preflight.inspect(
                mode="source",
                artifact=artifact,
                capabilities=capabilities,
                required_files=[],
                require_gpu=False,
                target_arch="gfx1151",
                detected_arches=["gfx1151"],
                optimization_surface="amdgcn_assembly",
                tools=tools,
                software_components={"rocm": "10.0", "llvm": "24"},
            )
            tools.pop("profiler")
            blocked = preflight.inspect(
                mode="source",
                artifact=artifact,
                capabilities=capabilities,
                required_files=[],
                require_gpu=False,
                target_arch="gfx1151",
                detected_arches=["gfx1151"],
                optimization_surface="amdgcn_assembly",
                tools=tools,
            )

        self.assertTrue(ready["ready"])
        self.assertEqual(ready["schema_version"], 2)
        self.assertEqual(ready["optimization_surface"], "amdgcn_assembly")
        self.assertEqual(ready["architecture"]["architecture_generation"], "RDNA 3.5")
        self.assertEqual(ready["software_stack"]["declared_components"]["rocm"], "10.0")
        self.assertFalse(blocked["ready"])
        self.assertTrue(any("profiler" in failure for failure in blocked["failures"]))

    def test_capability_probe_binds_tools_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            tool = self._executable(
                directory,
                "tool",
                "print('fake tool 1.0')\n",
            )
            tool_digest = hashlib.sha256(tool.read_bytes()).hexdigest()
            requested = {
                role: str(tool)
                for role in capability_probe.SURFACE_REQUIRED_TOOLS["amdgcn_assembly"]
            }
            report = capability_probe.probe(
                target_arch="gfx1201",
                detected_arches=["gfx1201"],
                optimization_surface="amdgcn_assembly",
                requested_tools=requested,
                native_load=True,
                binary_roundtrip=False,
                declared_components={"rocm": "10.0", "profiler": "3.8"},
            )
            requested.pop("profiler")
            blocked = capability_probe.probe(
                target_arch="gfx1201",
                detected_arches=["gfx1201"],
                optimization_surface="amdgcn_assembly",
                requested_tools=requested,
                native_load=True,
                binary_roundtrip=False,
            )

        self.assertTrue(report["ready"])
        self.assertEqual(
            report["tools"]["assembler"]["sha256"],
            tool_digest,
        )
        self.assertEqual(report["architecture"]["architecture_family"], "RDNA")
        self.assertEqual(report["architecture"]["architecture_generation"], "RDNA 4")
        self.assertEqual(
            report["software_stack"]["declared_components"]["profiler"], "3.8"
        )
        self.assertFalse(blocked["ready"])
        self.assertIn("missing tools: profiler", blocked["failures"])

    def test_hsaco_binary_remains_audit_only_until_backend_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            tool = self._executable(directory, "tool", "print('tool 1.0')\n")
            report = capability_probe.probe(
                target_arch="gfx1201",
                detected_arches=["gfx1201"],
                optimization_surface="hsaco_binary",
                requested_tools={
                    role: str(tool)
                    for role in capability_probe.SURFACE_REQUIRED_TOOLS["hsaco_binary"]
                },
                native_load=True,
                binary_roundtrip=True,
            )

        self.assertFalse(report["ready"])
        self.assertTrue(
            any("not implemented" in failure for failure in report["failures"])
        )

    def test_assemble_creates_a_fresh_code_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "candidate.s"
            source.write_text("s_endpgm\n", encoding="utf-8")
            assembler_tool = self._executable(
                directory,
                "fake-assembler",
                """
                import sys
                from pathlib import Path
                output = Path(sys.argv[sys.argv.index("-o") + 1])
                source = Path(sys.argv[sys.argv.index("-c") + 1])
                output.write_bytes(b"OBJECT:" + source.read_bytes())
                """,
            )
            linker_tool = self._executable(
                directory,
                "fake-linker",
                """
                import sys
                from pathlib import Path
                output = Path(sys.argv[sys.argv.index("-o") + 1])
                object_file = Path(sys.argv[sys.argv.index("-o") - 1])
                output.write_bytes(b"HSACO:" + object_file.read_bytes())
                """,
            )
            output = directory / "candidate.hsaco"

            report = assemble.build(
                source=source,
                target_arch="gfx1151",
                assembler=str(assembler_tool),
                linker=str(linker_tool),
                output=output,
                assembler_args=[],
                linker_args=[],
            )

        self.assertTrue(report["compiled"])
        self.assertFalse(report["precompiled_variant"])
        self.assertEqual(report["artifact_kind"], "hsaco")
        self.assertTrue(report["code_object"]["sha256"])

    def test_disassembly_normalization_and_window_diff(self) -> None:
        original_text = """
        0000000000000040 <test_kernel>:
          40: BF800000 s_nop 0 // comment
          44: BF810000 s_endpgm
        """
        candidate_text = """
        0000000000000040 <test_kernel>:
          40: BF800001 s_nop 1
          44: BF810000 s_endpgm
        """
        _, before_records = disassemble.normalize(original_text, "test_kernel")
        _, after_records = disassemble.normalize(candidate_text, "test_kernel")
        before = {
            "target_arch": "gfx1151",
            "kernel_symbol": "test_kernel",
            "artifact": {"sha256": "1" * 64},
            "normalized": {"sha256": "2" * 64},
            "instructions": before_records,
        }
        after = {
            "target_arch": "gfx1151",
            "kernel_symbol": "test_kernel",
            "artifact": {"sha256": "3" * 64},
            "normalized": {"sha256": "4" * 64},
            "instructions": after_records,
        }

        within = code_object_diff.compare(before, after, [(0x40, 0x40)])
        outside = code_object_diff.compare(before, after, [(0x44, 0x48)])

        self.assertTrue(within["nonempty"])
        self.assertTrue(within["within_declared_windows"])
        self.assertFalse(outside["within_declared_windows"])

    def test_resource_parser_does_not_invent_missing_values(self) -> None:
        parsed = resource_check.parse_resources(
            """
            .amdhsa_next_free_vgpr 24
            .amdhsa_next_free_sgpr 16
            .amdhsa_group_segment_fixed_size 4096
            .amdhsa_private_segment_fixed_size 0
            .amdhsa_kernarg_size 32
            .amdhsa_wavefront_size32 1
            """
        )

        self.assertEqual(parsed["vgpr_count"], 24)
        self.assertEqual(parsed["wave_size"], 32)
        self.assertIsNone(parsed["agpr_count"])

    def test_profile_capture_binds_raw_output_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            artifact = directory / "candidate.hsaco"
            artifact.write_bytes(b"candidate")
            profiler_tool = self._executable(
                directory,
                "fake-profiler",
                """
                from pathlib import Path
                Path("counters.csv").write_text("counter,value\\nVMEM,1\\n")
                """,
            )
            summary = directory / "summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "dispatch_count": 3,
                        "sampled_time_ms": 1.5,
                        "hotspots": [
                            {
                                "start_pc": "0x40",
                                "end_pc": "0x78",
                                "weight": 0.8,
                            }
                        ],
                        "resources": {"vgpr_count": 24},
                        "bottleneck_class": "long_latency_memory",
                        "counters": {"VMEM": 1},
                        "unavailable_counters": ["LDS_BANK_CONFLICT"],
                    }
                ),
                encoding="utf-8",
            )
            report = profile.capture(
                artifact=artifact,
                target_arch="gfx1201",
                kernel_symbol="test_kernel",
                contract_sha256="1" * 64,
                environment_sha256="2" * 64,
                profiler=str(profiler_tool),
                profiler_args=[],
                workload_command=["python3", "workload.py"],
                raw_directory=directory / "raw",
                summary_json=summary,
            )

        self.assertEqual(
            report["artifact_sha256"], hashlib.sha256(b"candidate").hexdigest()
        )
        self.assertEqual(report["bottleneck_class"], "long_latency_memory")
        self.assertTrue(
            any(item["relative_path"] == "counters.csv" for item in report["raw_files"])
        )


if __name__ == "__main__":
    unittest.main()
