from __future__ import annotations

import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from scripts import check_publish_draft_workflow as checker

FIXTURE = Path(__file__).parent / "fixtures" / "publish-draft-release-valid.yml"


class PublishDraftWorkflowCheckerTests(unittest.TestCase):
    def _check_mutation(self, transform: Callable[[str], str]) -> list[str]:
        source = FIXTURE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.yml"
            _ = path.write_text(transform(source), encoding="utf-8")
            return checker.check_workflow(path)

    def test_valid_workflow_passes(self) -> None:
        self.assertEqual(checker.check_workflow(FIXTURE), [])

    def test_preflight_rejects_a_static_draft_run_name(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                '             .path == ".github/workflows/prepare-draft-release.yml" and\n',
                '             .name == "Prepare draft release" and\n'
                + '             .path == ".github/workflows/prepare-draft-release.yml" and\n',
                1,
            )
        )
        self.assertTrue(
            any("must not assume a static draft run name" in error for error in errors)
        )

    def test_workflow_token_permissions_include_attestation_verification(
        self,
    ) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("  attestations: read", source)
        errors = self._check_mutation(
            lambda value: value.replace(
                "  attestations: read # Verify immutable release and asset attestations.\n",
                "",
                1,
            )
        )
        self.assertTrue(any("permissions" in error for error in errors))

    def test_trigger_accepts_only_tag_and_draft_run_id(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "      draft_run_id:\n",
                "      source_run_id:\n        required: true\n        type: string\n"
                + "      draft_run_id:\n",
                1,
            )
        )
        self.assertTrue(any("inputs" in error for error in errors))

    def test_concurrency_serializes_draft_and_publication_for_the_tag(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "group: release-draft-${{ inputs.tag }}",
                "group: publish-draft-${{ inputs.tag }}",
                1,
            )
        )
        self.assertTrue(any("release-draft" in error for error in errors))

    def test_preflight_cannot_use_environment_or_secrets(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "  preflight:\n",
                "  preflight:\n    environment: release-publish\n",
                1,
            )
        )
        self.assertTrue(any("preflight" in error for error in errors))

    def test_publisher_token_requires_all_validation_and_reader_revocation(
        self,
    ) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "      - name: Create final publisher App token\n",
                "      - name: Create final publisher App token early\n",
                1,
            )
        )
        self.assertTrue(any("exact approved sequence" in error for error in errors))

    def test_app_token_permissions_and_inputs_are_exact(self) -> None:
        source = FIXTURE.read_text(encoding="utf-8")
        self.assertIn("          permission-administration: read\n", source)
        for existing, replacement in (
            (
                "          permission-actions: read\n",
                "          permission-actions: read\n"
                + "          permission-issues: write\n",
            ),
            (
                "          permission-contents: write\n",
                "          permission-contents: write\n"
                + "          permission-actions: write\n",
            ),
            (
                "          permission-administration: read\n",
                "",
            ),
        ):
            with self.subTest(existing=existing):
                errors = self._check_mutation(
                    lambda value, old=existing, new=replacement: value.replace(
                        old, new, 1
                    )
                )
                self.assertTrue(any("App token inputs" in error for error in errors))

    def test_immutable_release_preflight_uses_the_final_publisher_token(
        self,
    ) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "      - name: Require immutable releases\n"
                + "        env:\n"
                + "          GH_TOKEN: ${{ steps.final-publisher.outputs.token }}\n",
                "      - name: Require immutable releases\n"
                + "        env:\n"
                + "          GH_TOKEN: ${{ github.token }}\n",
                1,
            )
        )
        self.assertTrue(any("immutable release preflight" in error for error in errors))

    def test_live_tag_target_is_checked_before_and_after_publication(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                '"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG_NAME"',
                '"repos/$GITHUB_REPOSITORY/git/ref/heads/$TAG_NAME"',
                1,
            )
        )
        self.assertTrue(any("live tag target" in error for error in errors))

    def test_reauthorization_binds_original_publish_workflow_digest(self) -> None:
        source = (
            Path(__file__).parents[2]
            / ".github"
            / "workflows"
            / "publish-draft-release.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(
            source.count(
                'printf \'%s\\n\' "$original_sha256" > "$RUNNER_TEMP/publish-workflow.sha256"'
            ),
            2,
        )

    def test_reauthorization_ref_and_workflow_ref_are_exact_in_both_jobs(self) -> None:
        source = (
            Path(__file__).parents[2]
            / ".github"
            / "workflows"
            / "publish-draft-release.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(
            source.count(
                'test "$GITHUB_REF" = "refs/tags/release-reauthorization/$TAG_NAME/public-publish/$runtime_commit"'
            ),
            2,
        )
        self.assertGreaterEqual(
            source.count(
                'test "$GITHUB_WORKFLOW_REF" = "$GITHUB_REPOSITORY/.github/workflows/publish-draft-release.yml@$GITHUB_REF"'
            ),
            2,
        )

    def test_publisher_token_cannot_be_used_by_an_added_mutation_step(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "      - name: Publish exact verified draft\n",
                "      - name: Unauthorized publisher mutation\n"
                + "        env:\n"
                + "          GH_TOKEN: ${{ steps.final-publisher.outputs.token }}\n"
                + "        run: gh api --method DELETE repos/example/releases/1\n"
                + "      - name: Publish exact verified draft\n",
                1,
            )
        )
        self.assertTrue(any("publisher token" in error for error in errors))
        self.assertTrue(any("mutation" in error for error in errors))

    def test_publisher_step_must_be_the_exact_canonical_mutation(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                '          jq -e \'.status == "published"\' "$RUNNER_TEMP/publication-result.json" > /dev/null\n',
                '          jq -e \'.status == "published"\' "$RUNNER_TEMP/publication-result.json" > /dev/null\n'
                + '          gh release delete "$TAG_NAME" --yes\n',
                1,
            )
        )
        self.assertTrue(any("mutation" in error for error in errors))
        self.assertTrue(any("not canonical" in error for error in errors))

    def test_direct_mutation_alternatives_are_rejected(self) -> None:
        for command in (
            "gh api -X DELETE repos/example/releases/1",
            "gh api -f draft=false repos/example/releases/1",
            "gh release upload v1.2.3 payload",
            "curl https://api.github.com/repos/example -d draft=false",
            "git push origin :refs/tags/v1.2.3",
        ):
            with self.subTest(command=command):
                errors = self._check_mutation(
                    lambda value, added=command: value.replace(
                        '          gh release verify "$TAG_NAME" --repo "$GITHUB_REPOSITORY"\n',
                        '          gh release verify "$TAG_NAME" --repo "$GITHUB_REPOSITORY"\n'
                        + f"          {added}\n",
                        1,
                    )
                )
                self.assertTrue(any("mutation" in error for error in errors))

    def test_job_level_permissions_and_variables_are_rejected(self) -> None:
        for addition in (
            "    permissions:\n      contents: write\n",
            "    env:\n      GH_TOKEN: ${{ secrets.EXTRA_TOKEN }}\n",
        ):
            with self.subTest(addition=addition):
                errors = self._check_mutation(
                    lambda value, inserted=addition: value.replace(
                        "  publish:\n",
                        "  publish:\n" + inserted,
                        1,
                    )
                )
                self.assertTrue(
                    any(
                        "override workflow permissions" in error
                        or "job-wide variables" in error
                        for error in errors
                    )
                )

    def test_unknown_or_duplicate_steps_are_rejected(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "      - name: Publish exact verified draft\n",
                "      - name: Extra read step\n"
                + "        run: true\n"
                + "      - name: Publish exact verified draft\n",
                1,
            )
        )
        self.assertTrue(any("exact approved sequence" in error for error in errors))

    def test_post_publication_verification_uses_read_only_token(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace(
                "      - name: Verify immutable release and every asset\n"
                + "        env:\n"
                + "          GH_TOKEN: ${{ github.token }}\n",
                "      - name: Verify immutable release and every asset\n"
                + "        env:\n"
                + "          GH_TOKEN: ${{ steps.final-publisher.outputs.token }}\n",
                1,
            )
        )
        self.assertTrue(any("read-only token" in error for error in errors))
        self.assertTrue(any("publisher token" in error for error in errors))

    def test_post_publication_verification_is_required(self) -> None:
        errors = self._check_mutation(
            lambda value: value.replace('gh release verify "$TAG_NAME"', "true", 1)
        )
        self.assertTrue(
            any("immutable release verification" in error for error in errors)
        )

    def test_release_contract_covers_publication_workflow_and_tools(self) -> None:
        contract = (
            Path(__file__).parents[2] / ".github/workflows/release-contract.yml"
        ).read_text(encoding="utf-8")
        for marker in (
            "scripts/check_publish_draft_workflow.py .github/workflows/publish-draft-release.yml",
            '".github/workflows/publish-draft-release.yml":',
            '"scripts/publish_draft_release.py":',
            '"scripts/check_publish_draft_workflow.py":',
            "scripts/check_prepare_package_channels_workflow.py .github/workflows/prepare-package-channels.yml",
            '".github/workflows/prepare-package-channels.yml":',
            "-m scripts.publish_draft_release --help",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, contract)


if __name__ == "__main__":
    _ = unittest.main()
