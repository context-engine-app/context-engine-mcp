"""Public-layout smoke tests for the byte-identical portable validators."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast
from unittest.mock import patch

from scripts import validate_channel_candidates
from scripts import validate_release_provenance

ReadCandidateArchive = Callable[
    [Path, Mapping[str, Mapping[str, object]], str], dict[str, bytes]
]
BuildPlan = Callable[
    [
        Mapping[str, object],
        Mapping[str, tuple[str, int]],
        str,
        str,
        Mapping[str, object],
        str,
    ],
    dict[str, object],
]
ValidateManifest = Callable[
    [Mapping[str, object], dict[str, object]], dict[str, object]
]
ValidateProvenance = Callable[
    [
        Mapping[str, object],
        dict[str, object],
        Mapping[str, object],
        bytes,
        Mapping[str, object],
    ],
    dict[str, object],
]
ValidateCommon = Callable[
    [Path, Path],
    tuple[dict[str, object], bytes, dict[str, tuple[str, int]], str],
]
ExpectedAssetNames = Callable[[Mapping[str, object]], set[str]]


def _canonical_sha256(value: object) -> str:
    serialized = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


def _repository_bootstrap_manifest() -> dict[str, object]:
    package = {
        "id": "context-engine-release",
        "version": "1.2.3",
        "filename": "context-engine-release-1.2.3-1.noarch.rpm",
        "suite": "stable",
        "package_format": "rpm",
        "repository_source_format": "repo",
        "architecture": "noarch",
    }
    package_binding: dict[str, object] = {
        "mode": "bootstrap",
        "packages": [package],
    }
    bootstrap: dict[str, object] = {"mode": "none"}
    distribution_commit = "c" * 40
    source_workflow = {
        "path": ".github/workflows/release.yml",
        "commit": "a" * 40,
        "sha256": "b" * 64,
    }
    workflow_bindings = {
        "draft": {
            "path": ".github/workflows/prepare-draft-release.yml",
            "commit": distribution_commit,
            "sha256": "d" * 64,
        },
        "publish": {
            "path": ".github/workflows/publish-draft-release.yml",
            "commit": distribution_commit,
            "sha256": "e" * 64,
        },
        "channels": {
            "path": ".github/workflows/prepare-package-channels.yml",
            "commit": distribution_commit,
            "sha256": "f" * 64,
        },
    }
    return {
        "schema_version": 1,
        "profile": "repository-bootstrap",
        "version": "1.2.3",
        "tag": "repository-bootstrap-v1.2.3",
        "source_repository": "context-engine-app/context-engine",
        "source_commit": "a" * 40,
        "distribution_repository": "context-engine-app/context-engine-mcp",
        "distribution_commit": distribution_commit,
        "distribution_tag_target": distribution_commit,
        "release_descriptor": {
            "path": "packaging/releases/repository-bootstrap-v1.2.3.json",
            "sha256": "1" * 64,
            "package_binding_sha256": _canonical_sha256(
                {"package_binding": package_binding, "bootstrap": bootstrap}
            ),
        },
        "assembly_facts": {
            "path": "repository-bootstrap-assembly-facts.json",
            "sha256": "2" * 64,
        },
        "license_identity": {"mode": "not-applicable"},
        "schemas": {
            "release_provenance": {
                "path": "packaging/release-provenance.schema.json",
                "sha256": "341d27e2074aebfdc539ef157d9d8fa449bff5504f7fb55014b74983c1506130",
            }
        },
        "source_workflows": {"release": source_workflow},
        "authorized_stages": [
            "source-release",
            "public-draft",
            "public-publish",
            "package-channels",
        ],
        "workflow_bindings": workflow_bindings,
        "build_mode": "not-applicable",
        "package_binding": package_binding,
        "bootstrap": bootstrap,
        "builds": [],
        "payloads": [],
        "grammar_inventory": {"status": "not-applicable"},
        "artifacts": [
            {
                "kind": "bootstrap-package",
                "package_id": "context-engine-release",
                "package_format": "rpm",
                "repository_source_format": "repo",
                "package_suite": "stable",
                "package_version": "1.2.3",
                "platform": "repository",
                "architecture": "noarch",
                "filename": "context-engine-release-1.2.3-1.noarch.rpm",
                "url": "https://github.com/context-engine-app/context-engine-mcp/releases/download/repository-bootstrap-v1.2.3/context-engine-release-1.2.3-1.noarch.rpm",
                "sha256": "3" * 64,
                "size": 1,
                "package_manifest_sha256": "4" * 64,
                "package_verification_sha256": "5" * 64,
            }
        ],
    }


class PortableValidatorLayoutTests(unittest.TestCase):
    def test_package_channels_mode_does_not_require_a_public_marker(self) -> None:
        arguments = validate_release_provenance.parse_arguments(
            [
                "package-channels",
                "--root",
                "/tmp/release",
                "--schemas",
                "/tmp/schemas",
                "--output-plan",
                "-",
            ]
        )
        self.assertEqual(cast(str, arguments.mode), "package-channels")

    def test_repository_bootstrap_profile_requires_no_candidate_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _ = (root / "release-manifest.json").write_text(
                '{"profile":"repository-bootstrap"}', encoding="utf-8"
            )
            validate_channel_candidates.validate_channel_candidates(
                root, Path(__file__).parents[2] / "schemas"
            )
            _ = (root / "channel-candidates.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(
                validate_channel_candidates.CandidateValidationError
            ):
                validate_channel_candidates.validate_channel_candidates(
                    root, Path(__file__).parents[2] / "schemas"
                )

    def test_repository_bootstrap_manifest_is_portably_valid(self) -> None:
        schema_path = (
            Path(__file__).parents[2] / "schemas" / "release-manifest.schema.json"
        )
        schema = cast(
            dict[str, object],
            validate_release_provenance.parse_json(
                schema_path.read_text(encoding="utf-8"), str(schema_path)
            ),
        )
        validate_manifest = cast(
            ValidateManifest,
            getattr(validate_release_provenance, "_validate_manifest"),
        )

        result = validate_manifest(_repository_bootstrap_manifest(), schema)

        self.assertEqual(result["tag"], "repository-bootstrap-v1.2.3")

    def test_repository_bootstrap_asset_closure_excludes_candidates(self) -> None:
        expected_asset_names = cast(
            ExpectedAssetNames,
            getattr(validate_release_provenance, "_expected_asset_names"),
        )

        names = expected_asset_names(_repository_bootstrap_manifest())

        self.assertIn("context-engine-release-1.2.3-1.noarch.rpm", names)
        self.assertNotIn("channel-candidates.json", names)
        self.assertNotIn("channel-candidates.tar.gz", names)

    def test_repository_bootstrap_provenance_requires_not_applicable_candidates(
        self,
    ) -> None:
        manifest = _repository_bootstrap_manifest()
        manifest_raw = b"repository-bootstrap manifest"
        source_workflow = cast(
            Mapping[str, object],
            cast(Mapping[str, object], manifest["source_workflows"])["release"],
        )
        public_workflows = cast(
            Mapping[str, Mapping[str, object]], manifest["workflow_bindings"]
        )
        expected: dict[str, object] = {
            "descriptor": manifest["release_descriptor"],
            "source_workflow": source_workflow,
            "public_workflows": public_workflows,
            "artifacts": manifest["artifacts"],
        }
        workflows: dict[str, object] = {
            "source-release": {"stage": "source-release", **source_workflow},
            "public-draft": {
                "stage": "public-draft",
                **public_workflows["draft"],
            },
            "public-publish": {
                "stage": "public-publish",
                **public_workflows["publish"],
            },
            "package-channels": {
                "stage": "package-channels",
                **public_workflows["channels"],
            },
        }
        provenance: dict[str, object] = {
            "profile": manifest["profile"],
            "version": manifest["version"],
            "tag": manifest["tag"],
            "source_commit": manifest["source_commit"],
            "distribution_commit": manifest["distribution_commit"],
            "distribution_tag_target": manifest["distribution_tag_target"],
            "manifest": {
                "path": "packaging/release-manifest.json",
                "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            },
            "release_descriptor": manifest["release_descriptor"],
            "workflows": workflows,
            "artifacts": manifest["artifacts"],
            "candidates": {"status": "not-applicable"},
        }
        validate_provenance = cast(
            ValidateProvenance,
            getattr(validate_release_provenance, "_validate_provenance"),
        )

        with patch.object(validate_release_provenance, "_validate_schema"):
            result = validate_provenance(
                provenance, {}, manifest, manifest_raw, expected
            )

        self.assertEqual(
            cast(Mapping[str, object], result["candidates"])["status"],
            "not-applicable",
        )

    def test_repository_bootstrap_common_validation_skips_candidate_files(
        self,
    ) -> None:
        manifest = _repository_bootstrap_manifest()
        validate_common = cast(
            ValidateCommon,
            getattr(validate_release_provenance, "_validate_common"),
        )
        with (
            patch.object(
                validate_release_provenance,
                "_validate_manifest_and_provenance",
                return_value=(manifest, b"manifest", {}, b"provenance", {}),
            ),
            patch.object(
                validate_release_provenance, "_validate_candidates"
            ) as validate_candidates,
            patch.object(
                validate_release_provenance,
                "_asset_facts",
                return_value=([], {}),
            ),
            patch.object(validate_release_provenance, "_validate_asset_facts"),
            patch.object(validate_release_provenance, "_validate_checksums"),
        ):
            _ = validate_common(Path("."), Path("."))

        validate_candidates.assert_not_called()

    def test_package_channel_plan_binds_channel_workflow_and_profile(self) -> None:
        manifest = _repository_bootstrap_manifest()
        channels = cast(
            Mapping[str, object],
            cast(Mapping[str, object], manifest["workflow_bindings"])["channels"],
        )
        build_plan = cast(
            BuildPlan,
            getattr(validate_release_provenance, "_plan"),
        )

        plan = build_plan(manifest, {}, "1" * 64, "", {}, "channels")

        self.assertEqual(plan["profile"], "repository-bootstrap")
        self.assertEqual(plan["public_workflow"], channels)

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

    def test_workflow_reauthorization_requires_exact_tag_ref_and_evidence(self) -> None:
        original = {
            "path": ".github/workflows/publish-draft-release.yml",
            "commit": "a" * 40,
            "sha256": "b" * 64,
        }
        replacement = {
            "path": ".github/workflows/publish-draft-release.yml",
            "commit": "c" * 40,
            "sha256": "d" * 64,
        }
        record = {
            "schema_version": 1,
            "tag": "v1.2.3",
            "stage": "public-publish",
            "execution_ref": "refs/tags/release-reauthorization/v1.2.3/public-publish/"
            + "c" * 40,
            "original": original,
            "replacement": replacement,
            "reason": "critical workflow repair",
            "approval_evidence": {
                "issue": "https://github.com/context-engine-app/context-engine-mcp/issues/1"
            },
        }
        _ = validate_release_provenance.validate_workflow_reauthorization(record)
        invalid = dict(record)
        invalid["execution_ref"] = "refs/tags/v1.2.3"
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_release_provenance.validate_workflow_reauthorization(invalid)

    def test_public_layout_imports_both_validators(self) -> None:
        self.assertTrue(callable(validate_release_provenance.validate_staging))
        self.assertTrue(callable(validate_release_provenance.validate_public_draft))
        self.assertTrue(
            callable(validate_channel_candidates.validate_channel_candidates)
        )

    def test_validators_pin_the_canonical_schema_bytes(self) -> None:
        self.assertEqual(
            validate_release_provenance.MANIFEST_SCHEMA_SHA256,
            "1b793cdebab9c3741eccd3aa280c4bb32ec0555fa1aa43c0f09210842a82d76c",
        )
        self.assertEqual(
            validate_release_provenance.PROVENANCE_SCHEMA_SHA256,
            "341d27e2074aebfdc539ef157d9d8fa449bff5504f7fb55014b74983c1506130",
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
            "1b793cdebab9c3741eccd3aa280c4bb32ec0555fa1aa43c0f09210842a82d76c",
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
