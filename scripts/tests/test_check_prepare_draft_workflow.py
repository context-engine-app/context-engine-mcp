from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts.check_prepare_draft_workflow import check_workflow


FIXTURE = Path(__file__).parent / "fixtures" / "prepare-draft-release-valid.yml"


class PrepareDraftWorkflowCheckerTests(unittest.TestCase):
    def _check_mutation(self, transform: Callable[[str], str]) -> list[str]:
        source = FIXTURE.read_text(encoding="utf-8")
        mutated = transform(source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            _ = path.write_text(mutated, encoding="utf-8")
            return check_workflow(path)

    def test_valid_workflow_passes(self) -> None:
        errors = check_workflow(FIXTURE)
        self.assertEqual(errors, [])

    def test_trigger_must_have_only_stable_dispatch_inputs(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "on:\n  workflow_dispatch:",
                'on:\n  push:\n    tags: ["v*"]\n  workflow_dispatch:',
            )
        )
        self.assertTrue(any("workflow_dispatch" in error for error in errors))

    def test_concurrency_serializes_draft_and_publication_for_the_tag(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "group: release-draft-${{ inputs.tag }}",
                "group: prepare-draft-${{ inputs.tag }}",
                1,
            )
        )
        self.assertTrue(any("release-draft" in error for error in errors))

    def test_unpinned_remote_action_is_rejected(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
                "actions/download-artifact@v4",
            )
        )
        self.assertTrue(any("pinned" in error for error in errors))

    def test_cosign_action_must_use_approved_pin(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
                "sigstore/cosign-installer@0000000000000000000000000000000000000000",
                1,
            )
        )
        self.assertTrue(
            any("pinned" in error or "approved" in error for error in errors)
        )

    def test_checkout_must_disable_persisted_credentials(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "persist-credentials: false", "persist-credentials: true", 1
            )
        )
        self.assertTrue(any("persisted credentials" in error for error in errors))

    def test_writer_token_must_follow_reader_revocation_and_validation(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "        id: release-writer\n",
                "        id: artifact-reader\n",
                1,
            )
        )
        self.assertTrue(any("writer" in error or "token" in error for error in errors))

    def test_app_tokens_must_skip_verified_existing_drafts(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                (
                    "        id: artifact-reader\n"
                    "        if: ${{ steps.preflight.outputs.skip_source != 'true' }}"
                ),
                "        id: artifact-reader\n        if: true",
                1,
            )
        )
        self.assertTrue(any("skipped" in error for error in errors))

    def test_release_mutation_controls_are_rejected(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                'gh api --method DELETE -H "X-GitHub-Api-Version: 2026-03-10" /installation/token',
                'gh release delete "$TAG_NAME" --repo context-engine-app/context-engine-mcp',
                1,
            )
        )
        self.assertTrue(
            any("forbidden" in error or "delete" in error for error in errors)
        )

    def test_github_api_version_header_is_required(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "X-GitHub-Api-Version: 2026-03-10",
                "X-GitHub-Api-Version: 2025-01-01",
                1,
            )
        )
        self.assertTrue(any("Api-Version" in error for error in errors))

    def test_download_must_use_exact_artifact_id_output(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "artifact-ids: ${{ steps.source-artifact.outputs.artifact_id }}",
                "name: staging-envelope",
            )
        )
        self.assertTrue(any("artifact" in error or "id" in error for error in errors))

    def test_download_must_flatten_exact_artifact_into_expected_root(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "merge-multiple: true",
                "merge-multiple: false",
            )
        )
        self.assertTrue(any("flatten" in error for error in errors))

    def test_tag_ref_peel_is_required(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                "git/ref/tags/$TAG_NAME", "git/ref/other/$TAG_NAME"
            )
        )
        self.assertTrue(any("source verification" in error for error in errors))

    def test_expiry_window_is_rechecked_before_writer_token(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                'expires=$(date -u -d "$ARTIFACT_EXPIRES_AT" +%s)',
                "expires=$(date -u +%s)",
                1,
            )
        )
        self.assertTrue(any("expiry" in error for error in errors))

    def test_verified_preflight_branch_is_required_for_skip(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace("verified)", "partial)", 1)
        )
        self.assertTrue(any("inspect and validate" in error for error in errors))

    def test_verified_preflight_rebinds_plan_to_runtime(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                ".public_workflow.path", ".public_workflow.other", 1
            )
        )
        self.assertTrue(any("inspect and validate" in error for error in errors))

    def test_channel_candidates_must_be_profile_gated(self) -> None:
        errors = self._check_mutation(
            lambda source: source.replace(
                'if [[ "$profile" != "repository-bootstrap" ]]; then',
                "if true; then",
            )
        )
        self.assertTrue(
            any("profile" in error and "candidate" in error for error in errors)
        )


if __name__ == "__main__":
    _ = unittest.main()
