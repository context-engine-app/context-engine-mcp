from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts import check_prepare_package_channels_workflow as checker


FIXTURE = Path(__file__).parent / "fixtures" / "prepare-package-channels-valid.yml"


class PackageWorkflowCheckerTests(unittest.TestCase):
    def _mutate(self, transform: Callable[[str], str]) -> list[str]:
        source = FIXTURE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            _ = path.write_text(transform(source), encoding="utf-8")
            return checker.check_workflow(path)

    def test_valid_workflow_passes(self) -> None:
        self.assertEqual(checker.check_workflow(FIXTURE), [])

    def test_package_channels_uses_package_provenance_mode(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("validate_release_provenance.py package-channels", source)
        self.assertNotIn("validate_release_provenance.py public-publish", source)

    def test_reader_token_and_retrieval_are_conditional(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("inputs.homebrew_repair_run_id", source)
        self.assertIn("inputs.scoop_repair_run_id", source)
        self.assertIn("actions/runs", source)
        self.assertIn("context-engine-channel-repair", source)

    def test_publish_uses_release_channel_environment(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("environment: release-channel", source)

    def test_each_stage_proves_release_immutability_before_candidate_use(self) -> None:
        errors = self._mutate(
            lambda value: value.replace(
                '          gh release verify "$TAG_NAME" --repo "$GITHUB_REPOSITORY"\n',
                "          true\n",
                1,
            )
        )
        self.assertTrue(any("release verification" in error for error in errors))

    def test_repair_run_binding_uses_official_workflow_ref_shape(self) -> None:
        source = (
            Path(__file__).parents[2]
            / ".github"
            / "workflows"
            / "prepare-package-channels.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("prepare-channel-repair.yml@", source)
        self.assertNotIn(".head_branch == $tag", source)

    def test_repair_api_calls_pin_version(self) -> None:
        source = (
            Path(__file__).parents[2]
            / ".github"
            / "workflows"
            / "prepare-package-channels.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("X-GitHub-Api-Version: 2026-03-10"), 3)
        errors = self._mutate(
            lambda value: value.replace(
                'gh api -H "X-GitHub-Api-Version: 2026-03-10"',
                "gh api",
                1,
            )
        )
        self.assertTrue(any("pinned version" in error for error in errors))

    def test_reauthorization_ref_and_workflow_ref_are_exact_in_both_jobs(self) -> None:
        source = (
            Path(__file__).parents[2]
            / ".github"
            / "workflows"
            / "prepare-package-channels.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(
            source.count(
                'test "$GITHUB_REF" = "refs/tags/release-reauthorization/$TAG_NAME/package-channels/$runtime_commit"'
            ),
            2,
        )
        self.assertGreaterEqual(
            source.count(
                'test "$GITHUB_WORKFLOW_REF" = "$GITHUB_REPOSITORY/.github/workflows/prepare-package-channels.yml@$GITHUB_REF"'
            ),
            2,
        )

    def test_repair_inputs_are_optional_exact_pairs(self) -> None:
        errors = self._mutate(
            lambda value: value.replace(
                "      homebrew_repair_attempt:\n",
                "      extra:\n        required: false\n        type: string\n      homebrew_repair_attempt:\n",
                1,
            )
        )
        self.assertTrue(any("inputs" in error for error in errors))

    def test_preflight_has_no_credentials_or_write_token(self) -> None:
        errors = self._mutate(
            lambda value: value.replace(
                "  preflight:\n",
                "  preflight:\n    env:\n      GH_TOKEN: ${{ secrets.BAD }}\n",
                1,
            )
        )
        self.assertTrue(any("preflight" in error for error in errors))

    def test_destination_repositories_are_exact(self) -> None:
        errors = self._mutate(
            lambda value: value.replace(
                "context-engine-app/homebrew-tap",
                "attacker/homebrew-tap",
                1,
            )
        )
        self.assertTrue(any("destination" in error for error in errors))

    def test_direct_mutation_and_auto_merge_are_rejected(self) -> None:
        for command in ("git push --force", "gh pr merge --auto", "gh release upload"):
            with self.subTest(command=command):
                errors = self._mutate(
                    lambda value, added=command: value.replace(
                        "      - name: Create channel pull requests\n",
                        "      - name: Create channel pull requests\n        run: "
                        + added
                        + "\n",
                        1,
                    )
                )
                self.assertTrue(any("mutation" in error for error in errors))

    def test_gh_api_mutations_are_rejected_in_coordinator_step(self) -> None:
        for method in ("POST", "PATCH", "DELETE"):
            with self.subTest(method=method):
                errors = self._mutate(
                    lambda value, method=method: value.replace(
                        "          .venv/bin/python scripts/prepare_package_channels.py apply",
                        f"          gh api --method {method} /repos/example\n"
                        + "          .venv/bin/python scripts/prepare_package_channels.py apply",
                        1,
                    )
                )
                self.assertTrue(any("mutation" in error for error in errors))

    def test_coordinator_run_and_environment_are_canonical(self) -> None:
        run_errors = self._mutate(
            lambda value: value.replace(
                "scripts/prepare_package_channels.py apply",
                "scripts/other.py apply",
                1,
            )
        )
        self.assertTrue(any("coordinator" in error for error in run_errors))
        env_errors = self._mutate(
            lambda value: value.replace(
                "HOMEBREW_GH_TOKEN: ${{ steps.homebrew.outputs.token }}",
                "HOMEBREW_GH_TOKEN: attacker-token",
                1,
            )
        )
        self.assertTrue(any("coordinator" in error for error in env_errors))

    def test_revocation_commands_are_canonical(self) -> None:
        errors = self._mutate(
            lambda value: value.replace(
                'gh api --method DELETE -H "X-GitHub-Api-Version: 2026-03-10" /installation/token',
                'gh api --method DELETE -H "X-GitHub-Api-Version: 2026-03-10" /installation/token/other',
                1,
            )
        )
        self.assertTrue(any("revoke" in error for error in errors))

    def test_publish_job_env_and_writer_output_reuse_are_rejected(self) -> None:
        job_env_errors = self._mutate(
            lambda value: value.replace(
                "  publish:\n    name:",
                "  publish:\n    env:\n      BAD: value\n    name:",
                1,
            )
        )
        self.assertTrue(any("job-level env" in error for error in job_env_errors))
        reuse_errors = self._mutate(
            lambda value: value.replace(
                "      - name: Restore anonymous preflight plan\n",
                "      - name: Restore anonymous preflight plan\n"
                + "        env:\n"
                + "          GH_TOKEN: ${{ steps.homebrew.outputs.token }}\n",
                1,
            )
        )
        self.assertTrue(any("token" in error for error in reuse_errors))


if __name__ == "__main__":
    _ = unittest.main()
