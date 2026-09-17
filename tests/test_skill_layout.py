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
            "scripts/lineage.py",
            "scripts/preflight.py",
            "references/acceptance-contract.md",
            "references/adapter-contract.md",
            "references/binary-backend.md",
            "references/failure-taxonomy.md",
            "references/optimization-playbook.md",
            "assets/evaluation-template.json",
            "assets/contract-template.json",
            "assets/example-environment.json",
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

        self.assertEqual(gate_result.returncode, 0, gate_result.stderr)
        self.assertTrue(json.loads(gate_result.stdout)["accepted"])
        self.assertEqual(lineage_help.returncode, 0, lineage_help.stderr)
        self.assertEqual(
            (SKILL / "LICENSE.txt").read_bytes(), (ROOT / "LICENSE").read_bytes()
        )


if __name__ == "__main__":
    unittest.main()
