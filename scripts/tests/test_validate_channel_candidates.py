"""Focused tests for repository-bootstrap candidate validation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import validate_channel_candidates


class RepositoryBootstrapCandidateTests(unittest.TestCase):
    def test_bootstrap_release_has_no_candidate_payload(self) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _ = (root / "release-manifest.json").write_text(
                '{"profile":"repository-bootstrap"}', encoding="utf-8"
            )

            validate_channel_candidates.validate_channel_candidates(root, schemas)

            _ = (root / "bucket/context-engine.json").parent.mkdir()
            _ = (root / "bucket/context-engine.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(
                validate_channel_candidates.CandidateValidationError
            ):
                validate_channel_candidates.validate_channel_candidates(root, schemas)


if __name__ == "__main__":
    _ = unittest.main()
