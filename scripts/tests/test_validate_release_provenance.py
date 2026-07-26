"""Public-layout smoke tests for the byte-identical portable validators."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from scripts import validate_channel_candidates
from scripts import validate_release_provenance

ReadCandidateArchive = Callable[
    [Path, Mapping[str, Mapping[str, object]], str], dict[str, bytes]
]


class PortableValidatorLayoutTests(unittest.TestCase):
    def test_public_publish_plan_requires_atomic_orchestration_bindings(self) -> None:
        draft = {
            "path": ".github/workflows/prepare-draft-release.yml",
            "commit": "a" * 40,
            "sha256": "b" * 64,
        }
        publish = {
            "path": ".github/workflows/publish-draft-release.yml",
            "commit": "a" * 40,
            "sha256": "c" * 64,
        }
        channels = {
            "path": ".github/workflows/prepare-package-channels.yml",
            "commit": "a" * 40,
            "sha256": "d" * 64,
        }
        authorized_stages: list[object] = [
            "source-release",
            "public-draft",
            "public-publish",
            "package-channels",
        ]
        workflow_bindings: dict[str, object] = {
            "draft": draft,
            "publish": publish,
            "channels": channels,
        }
        manifest: dict[str, object] = {
            "authorized_stages": authorized_stages,
            "workflow_bindings": workflow_bindings,
        }
        marker = {"verified_run_id": 55, "verified_run_attempt": 2}

        plan = validate_release_provenance.build_publication_plan(
            {"distribution_commit": "a" * 40, "public_workflow": draft},
            manifest,
            marker,
        )

        self.assertEqual(
            plan["public_workflows"],
            {"draft": draft, "publish": publish, "channels": channels},
        )
        self.assertEqual(plan["draft_run"], {"id": 55, "attempt": 2})
        for mutation in ("missing", "reordered"):
            with self.subTest(mutation=mutation):
                invalid_bindings = workflow_bindings.copy()
                invalid_stages = authorized_stages.copy()
                invalid: dict[str, object] = {
                    "workflow_bindings": invalid_bindings,
                    "authorized_stages": invalid_stages,
                }
                if mutation == "missing":
                    del invalid_bindings["channels"]
                else:
                    invalid_stages[2:4] = [
                        "package-channels",
                        "public-publish",
                    ]
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_release_provenance.build_publication_plan(
                        {"distribution_commit": "a" * 40, "public_workflow": draft},
                        invalid,
                        marker,
                    )

    def test_public_layout_imports_both_validators(self) -> None:
        self.assertTrue(callable(validate_release_provenance.validate_staging))
        self.assertTrue(callable(validate_release_provenance.validate_public_draft))
        self.assertTrue(
            callable(validate_channel_candidates.validate_channel_candidates)
        )

    def test_validators_pin_the_canonical_schema_bytes(self) -> None:
        self.assertEqual(
            validate_release_provenance.MANIFEST_SCHEMA_SHA256,
            "055a20ee520fbffc27dc3527c548eb50a76e1aa247072132d0f685ed40fdf395",
        )
        self.assertEqual(
            validate_release_provenance.PROVENANCE_SCHEMA_SHA256,
            "2cae7a72248fd279f4ba06e905daf7c5693393b74b3b0e24d7b9c0092fbed051",
        )
        self.assertEqual(
            validate_release_provenance.STAGING_SCHEMA_SHA256,
            "b8f1017ce278f762772e236eb08bf18a3c52b65f0e1e30c1d27cace51d305a6d",
        )
        self.assertEqual(
            validate_channel_candidates.CHANNEL_SCHEMA_SHA256,
            "7ce660193dc346c70fd0c8db57bd1d91d1743d3b6059959b96f76443d037d57a",
        )
        self.assertEqual(
            validate_channel_candidates.MANIFEST_SCHEMA_SHA256,
            "055a20ee520fbffc27dc3527c548eb50a76e1aa247072132d0f685ed40fdf395",
        )

    def test_gnu_archive_without_extensions_is_rejected(self) -> None:
        member_name = "formula/context-engine.rb"
        member_data = b"candidate\n"
        output = io.BytesIO()
        with gzip.GzipFile(
            fileobj=output, mode="wb", filename="", mtime=0
        ) as gzip_stream:
            with tarfile.open(
                fileobj=gzip_stream, mode="w", format=tarfile.GNU_FORMAT
            ) as archive:
                info = tarfile.TarInfo(member_name)
                info.size = len(member_data)
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.type = tarfile.REGTYPE
                archive.addfile(info, io.BytesIO(member_data))

        archive_bytes = output.getvalue()
        records: dict[str, Mapping[str, object]] = {
            member_name: {
                "size": len(member_data),
                "sha256": hashlib.sha256(member_data).hexdigest(),
            }
        }
        read_candidate_archive = cast(
            ReadCandidateArchive,
            getattr(validate_channel_candidates, "_read_candidate_archive"),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "channel-candidates.tar.gz"
            _ = archive_path.write_bytes(archive_bytes)
            archive_path.chmod(0o644)
            with self.assertRaises(
                validate_channel_candidates.CandidateValidationError
            ):
                _ = read_candidate_archive(
                    archive_path,
                    records,
                    hashlib.sha256(archive_bytes).hexdigest(),
                )


if __name__ == "__main__":
    _ = unittest.main()
