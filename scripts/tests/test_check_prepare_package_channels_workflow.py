from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts import check_prepare_package_channels_workflow as checker


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/prepare-package-channels.yml"


class PackageWorkflowCheckerTests(unittest.TestCase):
    def _mutate(self, transform: Callable[[str], str]) -> list[str]:
        source = transform(WORKFLOW.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workflow.yml"
            _ = path.write_text(source, encoding="utf-8")
            return checker.check_workflow(path)

    def test_current_workflow_passes(self) -> None:
        self.assertEqual(checker.check_workflow(WORKFLOW), [])

    def test_workflow_has_one_protected_publish_job(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  publish:\n", source)
        self.assertIn("environment: release-channel", source)
        self.assertNotIn("  preflight:\n", source)

    def test_workflow_has_no_obsolete_publication_mechanisms(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").lower()
        for forbidden in (
            "repair",
            "reauthorization",
            "anonymous",
            "artifact-reader",
            "preflight-plan",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_validation_precedes_destination_credentials(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        validation = source.index("Validate immutable release and channel candidates")
        homebrew = source.index("Create Homebrew installation token")
        scoop = source.index("Create Scoop installation token")
        mutation = source.index("Create channel pull requests")
        self.assertLess(validation, homebrew)
        self.assertLess(validation, scoop)
        self.assertLess(homebrew, mutation)
        self.assertLess(scoop, mutation)

    def test_extra_dispatch_input_is_rejected(self) -> None:
        errors = self._mutate(
            lambda source: source.replace(
                "      tag:\n",
                "      repair:\n        required: false\n        type: string\n      tag:\n",
                1,
            )
        )
        self.assertTrue(errors)

    def test_tag_dispatch_is_rejected(self) -> None:
        errors = self._mutate(
            lambda source: source.replace(
                'test "$GITHUB_REF" = "refs/heads/main"',
                'test "$GITHUB_REF" = "refs/tags/$TAG_NAME"',
            )
        )
        self.assertTrue(any("protected main" in error for error in errors))

    def test_unpinned_action_is_rejected(self) -> None:
        errors = self._mutate(
            lambda source: source.replace(
                "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                "actions/checkout@v4",
                1,
            )
        )
        self.assertTrue(errors)

    def test_wrong_destination_repository_is_rejected(self) -> None:
        errors = self._mutate(
            lambda source: source.replace(
                "repositories: homebrew-tap", "repositories: context-engine-mcp", 1
            )
        )
        self.assertTrue(errors)

    def test_missing_candidate_validation_is_rejected(self) -> None:
        errors = self._mutate(
            lambda source: source.replace("validate_channel_candidates.py", "true", 1)
        )
        self.assertTrue(errors)

    def test_shared_token_in_mutation_environment_is_rejected(self) -> None:
        errors = self._mutate(
            lambda source: source.replace(
                "          SCOOP_GH_TOKEN: ${{ steps.scoop.outputs.token }}\n"
                + "          TAG_NAME: ${{ inputs.tag }}\n",
                "          SCOOP_GH_TOKEN: ${{ steps.scoop.outputs.token }}\n"
                + "          TAG_NAME: ${{ inputs.tag }}\n"
                + "          GH_TOKEN: ${{ github.token }}\n",
                1,
            )
        )
        self.assertTrue(errors)


if __name__ == "__main__":
    _ = unittest.main()
