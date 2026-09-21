from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "asmevo"


class SkillLayoutTests(unittest.TestCase):
    def test_required_skill_files_exist(self) -> None:
        expected = [
            "SKILL.md",
            "LICENSE.txt",
            "VERSION",
            "agents/openai.yaml",
            "scripts/gate.py",
            "scripts/controller.py",
            "scripts/lineage.py",
            "scripts/preflight.py",
            "scripts/capability_probe.py",
            "scripts/target_context.py",
            "scripts/assemble.py",
            "scripts/disassemble.py",
            "scripts/code_object_diff.py",
            "scripts/resource_check.py",
            "scripts/profile.py",
            "scripts/backends/common.py",
            "scripts/backends/source.py",
            "scripts/backends/amdgcn_assembly.py",
            "scripts/backends/hsaco_binary.py",
            "references/acceptance-contract.md",
            "references/adapter-contract.md",
            "references/assembly-backend.md",
            "references/binary-backend.md",
            "references/controller-contract.md",
            "references/failure-taxonomy.md",
            "references/optimization-playbook.md",
            "references/profiling-contract.md",
            "references/architecture-and-rocm-context.md",
            "references/architectures/rdna35.md",
            "references/architectures/rdna4.md",
            "references/architectures/cdna5.md",
            "assets/evaluation-template.json",
            "assets/contract-template.json",
            "assets/example-environment.json",
            "assets/schemas/capability-report.schema.json",
            "assets/schemas/asm-candidate.schema.json",
            "assets/schemas/profile-evidence.schema.json",
            "assets/architectures/gfx11.json",
            "assets/architectures/gfx12.json",
            "assets/architectures/targets.json",
        ]
        for relative in expected:
            with self.subTest(relative=relative):
                self.assertTrue((SKILL / relative).is_file())

    def test_frontmatter_and_trigger_are_narrow(self) -> None:
        contents = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(contents.startswith("---\nname: asmevo\ndescription: "))
        self.assertIn("AMDGPU HSACO/code objects", contents)
        self.assertIn("Do not use for NVIDIA", contents)
        self.assertIn("ordinary source-only tuning", contents)

    def test_local_markdown_links_resolve(self) -> None:
        for markdown in SKILL.rglob("*.md"):
            contents = markdown.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", contents):
                if "://" in target or target.startswith("#"):
                    continue
                clean_target = target.split("#", 1)[0]
                with self.subTest(markdown=markdown.name, target=target):
                    self.assertTrue((markdown.parent / clean_target).resolve().exists())

    def test_no_unresolved_placeholders(self) -> None:
        markers = ("TODO", "FIXME", "TBD", "INSERT HERE")
        for path in SKILL.rglob("*"):
            if not path.is_file() or path.suffix not in {
                ".md",
                ".yaml",
                ".py",
                ".json",
            }:
                continue
            contents = path.read_text(encoding="utf-8")
            for marker in markers:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, contents)

    def test_agent_prompt_invokes_skill(self) -> None:
        contents = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn('display_name: "AsmEvo"', contents)
        self.assertIn("$asmevo", contents)

    def test_import_only_helpers_do_not_claim_cli_entry_points(self) -> None:
        contents = (SKILL / "scripts" / "target_context.py").read_text(encoding="utf-8")
        self.assertFalse(contents.startswith("#!"))

    def test_release_versions_match_and_controller_is_executable(self) -> None:
        root_version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        skill_version = (SKILL / "VERSION").read_text(encoding="utf-8").strip()

        self.assertEqual(root_version, "0.4.0.0")
        self.assertEqual(skill_version, root_version)
        for script in (
            "controller.py",
            "gate.py",
            "lineage.py",
            "preflight.py",
            "capability_probe.py",
            "assemble.py",
            "disassemble.py",
            "code_object_diff.py",
            "resource_check.py",
            "profile.py",
        ):
            with self.subTest(script=script):
                self.assertTrue((SKILL / "scripts" / script).stat().st_mode & 0o111)

    def test_evaluation_example_binds_its_environment_manifest(self) -> None:
        evaluation = json.loads(
            (SKILL / "assets" / "evaluation-template.json").read_text(encoding="utf-8")
        )
        environment = SKILL / "assets" / "example-environment.json"
        digest = hashlib.sha256(environment.read_bytes()).hexdigest()
        self.assertEqual(evaluation["contract"]["environment_sha256"], digest)

    def test_contract_template_forces_environment_replacement(self) -> None:
        contract = json.loads(
            (SKILL / "assets" / "contract-template.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            contract["environment_sha256"],
            "REPLACE_WITH_SHA256_OF_ENVIRONMENT_MANIFEST",
        )

    def test_installed_skill_subdirectory_is_self_contained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            installed = Path(temporary) / "asmevo"
            shutil.copytree(SKILL, installed)
            gate_result = subprocess.run(
                [
                    sys.executable,
                    str(installed / "scripts" / "gate.py"),
                    str(installed / "assets" / "evaluation-template.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            lineage_help = subprocess.run(
                [sys.executable, str(installed / "scripts" / "lineage.py"), "--help"],
                check=False,
                capture_output=True,
                text=True,
            )
            controller_help = subprocess.run(
                [
                    sys.executable,
                    str(installed / "scripts" / "controller.py"),
                    "--help",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(gate_result.returncode, 0, gate_result.stderr)
        self.assertTrue(json.loads(gate_result.stdout)["accepted"])
        self.assertEqual(lineage_help.returncode, 0, lineage_help.stderr)
        self.assertEqual(controller_help.returncode, 0, controller_help.stderr)
        self.assertEqual(
            (SKILL / "LICENSE.txt").read_bytes(), (ROOT / "LICENSE").read_bytes()
        )


if __name__ == "__main__":
    unittest.main()
