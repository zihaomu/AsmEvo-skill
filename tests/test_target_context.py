from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "asmevo" / "scripts"))

import target_context


class TargetContextTests(unittest.TestCase):
    def test_exact_targets_route_to_the_expected_architecture(self) -> None:
        expected = {
            "gfx1151": ("RDNA", "RDNA 3.5"),
            "gfx1200": ("RDNA", "RDNA 4"),
            "gfx1201": ("RDNA", "RDNA 4"),
            "gfx1250": ("CDNA", "CDNA 5"),
        }

        for target, (family, generation) in expected.items():
            with self.subTest(target=target):
                result = target_context.resolve_architecture(target)
                self.assertEqual(result["mapping_status"], "known")
                self.assertEqual(result["architecture_family"], family)
                self.assertEqual(result["architecture_generation"], generation)
                self.assertTrue(result["architecture_specific_guidance"])
                self.assertEqual(len(result["knowledge_sha256"]), 64)

    def test_gfx1250_never_inherits_rdna4_context(self) -> None:
        result = target_context.resolve_architecture("gfx1250")

        self.assertEqual(result["architecture_generation"], "CDNA 5")
        self.assertEqual(
            result["knowledge_reference"], "references/architectures/cdna5.md"
        )
        self.assertNotIn("rdna4", result["knowledge_reference"])

    def test_unknown_target_stays_generic_instead_of_using_prefix_matching(
        self,
    ) -> None:
        result = target_context.resolve_architecture("gfx1299")

        self.assertEqual(result["mapping_status"], "unknown")
        self.assertIsNone(result["architecture_family"])
        self.assertIsNone(result["knowledge_reference"])
        self.assertFalse(result["architecture_specific_guidance"])

    def test_registry_and_knowledge_are_content_bound(self) -> None:
        result = target_context.resolve_architecture("gfx1201")
        registry = ROOT / "asmevo" / "assets" / "architectures" / "targets.json"
        knowledge = ROOT / "asmevo" / result["knowledge_reference"]

        self.assertEqual(
            result["registry"]["sha256"],
            hashlib.sha256(registry.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            result["knowledge_sha256"],
            hashlib.sha256(knowledge.read_bytes()).hexdigest(),
        )

    def test_registry_rejects_non_exact_match_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            registry = Path(temporary) / "targets.json"
            registry.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "asmevo.architecture-target-registry.v1",
                        "match_policy": "prefix",
                        "targets": {},
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(target_context.TargetContextError):
                target_context.resolve_architecture("gfx1201", registry_path=registry)

    def test_software_stack_separates_declared_versions_from_observed_tools(
        self,
    ) -> None:
        result = target_context.software_stack(
            {"rocm": "10.0", "kernel_driver": "amdgpu 6.18"},
            {
                "assembler": {
                    "path": "/opt/rocm/bin/clang",
                    "sha256": "a" * 64,
                    "version": "clang 24",
                }
            },
        )

        self.assertEqual(result["declared_components"]["rocm"], "10.0")
        self.assertEqual(result["observed_tools"]["assembler"]["version"], "clang 24")
        self.assertIn("not proof", result["compatibility_policy"])

    def test_unknown_software_component_is_rejected(self) -> None:
        with self.assertRaises(target_context.TargetContextError):
            target_context.software_stack({"mystery": "1"}, {})

    def test_malformed_programmatic_inputs_are_rejected(self) -> None:
        with self.assertRaises(target_context.TargetContextError):
            target_context.resolve_architecture(None)  # type: ignore[arg-type]
        with self.assertRaises(target_context.TargetContextError):
            target_context.software_stack(["rocm=10"], {})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
