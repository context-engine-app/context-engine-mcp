from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.check_prepare_draft_workflow import check_workflow


WORKFLOW = (
    Path(__file__).parents[2] / ".github" / "workflows" / "prepare-draft-release.yml"
)


class ReleaseWorkflowCheckerTests(unittest.TestCase):
    def test_single_workflow_passes(self) -> None:
        self.assertEqual(check_workflow(WORKFLOW), [])

    def test_marker_protocol_is_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").replace(
            "run: .venv/bin/python -m scripts.prepare_draft_release --plan",
            "run: echo marker && .venv/bin/python -m scripts.prepare_draft_release --plan",
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", encoding="utf-8"
        ) as handle:
            _ = handle.write(source)
            handle.flush()
            errors = check_workflow(Path(handle.name))
        self.assertTrue(any("marker" in error for error in errors))

    def test_tag_dispatch_is_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").replace(
            'test "$GITHUB_REF" = "refs/heads/main"',
            'test "$GITHUB_REF" = "refs/tags/$TAG_NAME"',
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", encoding="utf-8"
        ) as handle:
            _ = handle.write(source)
            handle.flush()
            errors = check_workflow(Path(handle.name))
        self.assertTrue(any("protected main" in error for error in errors))

    def test_non_source_changelog_is_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").replace(
            "contents/CHANGELOG.md?ref=$source_commit",
            "contents/CHANGELOG.md",
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", encoding="utf-8"
        ) as handle:
            _ = handle.write(source)
            handle.flush()
            errors = check_workflow(Path(handle.name))
        self.assertTrue(
            any("exact source commit changelog" in error for error in errors)
        )

    def test_unknown_publisher_credentials_are_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").replace(
            "IMMUTABLE_RELEASE_PUBLISHER_APP_CLIENT_ID",
            "UNKNOWN_PUBLISHER_APP_CLIENT_ID",
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", encoding="utf-8"
        ) as handle:
            _ = handle.write(source)
            handle.flush()
            errors = check_workflow(Path(handle.name))
        self.assertTrue(any("publisher credentials" in error for error in errors))

    def test_two_jobs_are_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8").replace(
            "  release-publish:\n",
            "  other:\n    name: Other\n    steps: []\n  release-publish:\n",
            1,
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yml", encoding="utf-8"
        ) as handle:
            _ = handle.write(source)
            handle.flush()
            errors = check_workflow(Path(handle.name))
        self.assertTrue(
            any("only the release-publish job" in error for error in errors)
        )


if __name__ == "__main__":
    _ = unittest.main()
