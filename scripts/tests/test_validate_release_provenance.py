"""Public-layout and profile-contract tests for release provenance validators."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from copy import deepcopy
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
                "sha256": "c13bf530c6fe4befc00b398c2274b3ffeb7e6cbcfb78c38bc1a5da0b8bf4db60",
            },
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
            },
            {
                "kind": "common",
                "filename": "LICENSE",
                "url": "https://github.com/context-engine-app/context-engine-mcp/releases/download/repository-bootstrap-v1.2.3/LICENSE",
                "sha256": "6" * 64,
                "size": 1,
            },
            {
                "kind": "common",
                "filename": "THIRD_PARTY_NOTICES.md",
                "url": "https://github.com/context-engine-app/context-engine-mcp/releases/download/repository-bootstrap-v1.2.3/THIRD_PARTY_NOTICES.md",
                "sha256": "7" * 64,
                "size": 1,
            },
        ],
    }


def _cli_manifest(profile: str) -> dict[str, object]:
    target_specs = {
        "x86_64-apple-darwin": (
            "macos",
            "x86_64",
            "context-engine",
            "scripts/build_mac.sh",
        ),
        "aarch64-apple-darwin": (
            "macos",
            "arm64",
            "context-engine",
            "scripts/build_mac.sh",
        ),
        "x86_64-pc-windows-msvc": (
            "windows",
            "x86_64",
            "context-engine.exe",
            "scripts/build_win.sh",
        ),
        "x86_64-unknown-linux-gnu": (
            "linux",
            "x86_64",
            "context-engine",
            "scripts/build_linux.sh",
        ),
    }
    targets = (
        tuple(target_specs)[:3]
        if profile == "desktop"
        else tuple(target_specs)
        if profile == "desktop-linux"
        else ()
    )
    manifest = _repository_bootstrap_manifest()
    manifest["profile"] = profile
    manifest["tag"] = "v1.2.3"
    descriptor = cast(dict[str, object], manifest["release_descriptor"])
    descriptor["path"] = "packaging/releases/v1.2.3.json"
    manifest["license_identity"] = {
        "key_id": "preview-2026-01",
        "public_key_sha256": "6" * 64,
    }
    manifest["build_mode"] = "license-enforced"
    bootstrap_package = cast(
        dict[str, object],
        cast(
            list[object],
            cast(dict[str, object], manifest["package_binding"])["packages"],
        )[0],
    )
    native_packages: list[dict[str, object]] = [
        {
            "id": "context-engine",
            "version": "1.2.3",
            "filename": "context-engine_1.2.3-1_amd64.deb",
            "suite": "linux",
            "package_format": "deb",
            "architecture": "amd64",
        },
        {
            "id": "context-engine",
            "version": "1.2.3",
            "filename": "context-engine-1.2.3-1.x86_64.rpm",
            "suite": "linux",
            "package_format": "rpm",
            "architecture": "x86_64",
        },
    ]
    package_binding: dict[str, object]
    bootstrap_binding: dict[str, object]
    if profile == "desktop":
        package_binding = {"mode": "none"}
        bootstrap_binding = {"mode": "none"}
    else:
        package_binding = {"mode": "embedded", "packages": native_packages}
        bootstrap_binding = {"mode": "embedded", "packages": [bootstrap_package]}
    manifest["package_binding"] = package_binding
    manifest["bootstrap"] = bootstrap_binding
    manifest["grammar_inventory"] = {
        "path": "grammar-inventory.json",
        "sha256": "7" * 64,
    }
    builds: list[dict[str, object]] = []
    payloads: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    for index, target in enumerate(targets, start=1):
        platform, architecture, payload_filename, script = target_specs[target]
        payload_id = f"context-engine-{target}"
        payloads.append(
            {
                "id": payload_id,
                "filename": payload_filename,
                "target": target,
                "platform": platform,
                "architecture": architecture,
                "sha256": f"{index:064x}",
                "size": 1,
                "executable_mode": "0755",
                "license_mode": "enforced",
                "version_output": "context-engine 1.2.3",
            }
        )
        builds.append(
            {
                "payload_id": payload_id,
                "script": script,
                "script_sha256": "8" * 64,
                "build_record_sha256": "9" * 64,
                "payload_verification_sha256": "a" * 64,
            }
        )
        archive_suffix = ".zip" if target == "x86_64-pc-windows-msvc" else ".tar.gz"
        for kind, suffix in (
            ("archive", archive_suffix),
            ("sbom", ".cdx.json"),
        ):
            filename = f"{payload_id}{suffix}"
            artifacts.append(
                {
                    "kind": kind,
                    "payload_id": payload_id,
                    "platform": platform,
                    "architecture": architecture,
                    "target": target,
                    "filename": filename,
                    "url": f"https://github.com/context-engine-app/context-engine-mcp/releases/download/v1.2.3/{filename}",
                    "sha256": f"{index + (0 if kind == 'archive' else 4):064x}",
                    "size": 1,
                }
            )
    if profile == "desktop-linux":
        native_package_artifacts: list[dict[str, object]] = []
        for package_index, native_package in enumerate(native_packages):
            filename = cast(str, native_package["filename"])
            native_package_artifacts.append(
                {
                    "kind": "native-package",
                    "platform": "linux",
                    "architecture": native_package["architecture"],
                    "package_id": native_package["id"],
                    "package_format": native_package["package_format"],
                    "package_suite": native_package["suite"],
                    "package_version": native_package["version"],
                    "package_manifest_sha256": f"{11 + package_index:064x}",
                    "package_verification_sha256": f"{13 + package_index:064x}",
                    "filename": filename,
                    "url": f"https://github.com/context-engine-app/context-engine-mcp/releases/download/v1.2.3/{filename}",
                    "sha256": f"{15 + package_index:064x}",
                    "size": 1,
                }
            )
        bootstrap_package_artifact: dict[str, object] = {
            "kind": "bootstrap-package",
            "platform": "repository",
            "architecture": bootstrap_package["architecture"],
            "package_id": bootstrap_package["id"],
            "package_format": bootstrap_package["package_format"],
            "repository_source_format": bootstrap_package["repository_source_format"],
            "package_suite": bootstrap_package["suite"],
            "package_version": bootstrap_package["version"],
            "package_manifest_sha256": "e" * 64,
            "package_verification_sha256": "f" * 64,
            "filename": bootstrap_package["filename"],
            "url": "https://github.com/context-engine-app/context-engine-mcp/releases/download/v1.2.3/context-engine-release-1.2.3-1.noarch.rpm",
            "sha256": "1" * 64,
            "size": 1,
        }
        artifacts.extend([*native_package_artifacts, bootstrap_package_artifact])
    if profile in {"desktop", "desktop-linux"}:
        for filename, digest in (
            ("LICENSE", "2" * 64),
            ("THIRD_PARTY_NOTICES.md", "3" * 64),
            ("context-engine-release.cdx.json", "4" * 64),
        ):
            artifacts.append(
                {
                    "kind": "common",
                    "filename": filename,
                    "url": f"https://github.com/context-engine-app/context-engine-mcp/releases/download/v1.2.3/{filename}",
                    "sha256": digest,
                    "size": 1,
                }
            )
    manifest["builds"] = builds
    manifest["payloads"] = payloads
    manifest["artifacts"] = artifacts
    descriptor["package_binding_sha256"] = _canonical_sha256(
        {"package_binding": package_binding, "bootstrap": bootstrap_binding}
    )
    return manifest


class PortableValidatorLayoutTests(unittest.TestCase):
    def test_expected_asset_closure_is_profile_aware(self) -> None:
        expected_asset_names = cast(
            ExpectedAssetNames,
            getattr(validate_release_provenance, "_expected_asset_names"),
        )
        for profile in ("desktop", "desktop-linux", "repository-bootstrap"):
            manifest = {
                "profile": profile,
                "artifacts": [{"filename": "artifact.bin"}],
            }
            names = expected_asset_names(manifest)
            self.assertEqual(
                {
                    "release-manifest.json",
                    "release-provenance.json",
                    "SHA256SUMS",
                    "SHA256SUMS.sigstore.json",
                    "artifact.bin",
                }
                | (
                    {"channel-candidates.json", "channel-candidates.tar.gz"}
                    if profile != "repository-bootstrap"
                    else set()
                ),
                names,
            )

    def test_marker_profile_must_match_manifest(self) -> None:
        manifest: dict[str, object] = {
            "profile": "repository-bootstrap",
            "tag": "repository-bootstrap-v1.2.3",
            "version": "1.2.3",
            "source_commit": "a" * 40,
            "distribution_commit": "b" * 40,
            "source_workflows": {"release": {"sha256": "c" * 64}},
            "workflow_bindings": {"draft": {"sha256": "d" * 64}},
        }
        marker: dict[str, object] = {
            key: None for key in validate_release_provenance.MARKER_KEYS
        }
        marker.update(
            {
                "marker_version": 1,
                "profile": "desktop",
                "tag": manifest["tag"],
                "release_version": manifest["version"],
                "source_commit": manifest["source_commit"],
                "distribution_commit": manifest["distribution_commit"],
                "public_workflow_sha256": "d" * 64,
                "source_workflow_sha256": "c" * 64,
                "release_asset_set_sha256": "e" * 64,
                "staging_attestation_sha256": "f" * 64,
                "source_run_id": 1,
                "source_run_attempt": 1,
                "staging_artifact_id": 1,
                "staging_artifact_digest": "sha256:" + "1" * 64,
                "staging_artifact_expires_at": "2099-01-01T00:00:00Z",
                "state": "preparing",
            }
        )
        validate_marker = cast(
            Callable[
                [Mapping[str, object], Mapping[str, object], str], dict[str, object]
            ],
            getattr(validate_release_provenance, "_validate_marker"),
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_marker(marker, manifest, "e" * 64)

    def test_checksums_follow_the_supplied_asset_closure(self) -> None:
        validate_checksums = cast(
            Callable[[Path, Mapping[str, tuple[str, int]]], None],
            getattr(validate_release_provenance, "_validate_checksums"),
        )
        assets = {
            "release-manifest.json": b"manifest",
            "release-provenance.json": b"provenance",
            "SHA256SUMS": b"",
            "SHA256SUMS.sigstore.json": b"{}",
        }
        facts = {
            name: (hashlib.sha256(content).hexdigest(), len(content))
            for name, content in assets.items()
        }
        lines = (
            "\n".join(
                f"{facts[name][0]}  {name}"
                for name in sorted({"release-manifest.json", "release-provenance.json"})
            )
            + "\n"
        )
        assets["SHA256SUMS"] = lines.encode()
        facts["SHA256SUMS"] = (
            hashlib.sha256(assets["SHA256SUMS"]).hexdigest(),
            len(assets["SHA256SUMS"]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in assets.items():
                _ = (root / name).write_bytes(content)
            with patch.object(
                validate_release_provenance,
                "_read_json",
                return_value=({"bundle": True}, b"{}"),
            ):
                validate_checksums(root, facts)

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
                json.dumps(_repository_bootstrap_manifest()), encoding="utf-8"
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

    def test_manifest_profile_payload_and_build_sets_are_exact(self) -> None:
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

        for profile in ("desktop", "desktop-linux", "repository-bootstrap"):
            with self.subTest(profile=profile, mutation="valid"):
                manifest = (
                    _repository_bootstrap_manifest()
                    if profile == "repository-bootstrap"
                    else _cli_manifest(profile)
                )
                _ = validate_manifest(manifest, schema)

        for profile in ("desktop", "desktop-linux"):
            base = _cli_manifest(profile)
            for field in ("builds", "payloads"):
                for mutation in ("missing", "extra", "duplicate", "wrong-id"):
                    with self.subTest(profile=profile, field=field, mutation=mutation):
                        invalid = deepcopy(base)
                        values = cast(list[object], invalid[field])
                        if mutation == "missing":
                            invalid[field] = values[1:]
                        elif mutation == "extra":
                            extra = deepcopy(
                                cast(
                                    list[object], _cli_manifest("desktop-linux")[field]
                                )[-1]
                            )
                            values.append(extra)
                        elif mutation == "duplicate":
                            duplicate = deepcopy(values[0])
                            cast(dict[str, object], duplicate)["script_sha256"] = (
                                "b" * 64
                            )
                            cast(dict[str, object], duplicate)["sha256"] = "b" * 64
                            values.append(duplicate)
                        else:
                            cast(dict[str, object], values[0])["payload_id"] = (
                                "context-engine-unexpected"
                            )
                        with self.assertRaises(
                            validate_release_provenance.ReleaseProvenanceValidationError
                        ):
                            _ = validate_manifest(invalid, schema)

                with self.subTest(
                    profile=profile, field=field, mutation="bootstrap-extra"
                ):
                    invalid = deepcopy(_repository_bootstrap_manifest())
                    invalid["profile"] = profile
                    invalid[field] = deepcopy(
                        cast(list[object], _cli_manifest("desktop")[field])[0:1]
                    )
                    with self.assertRaises(
                        validate_release_provenance.ReleaseProvenanceValidationError
                    ):
                        _ = validate_manifest(invalid, schema)

            payloads = cast(list[object], base["payloads"])
            wrong_target = deepcopy(payloads[0])
            cast(dict[str, object], wrong_target)["target"] = "x86_64-unknown-linux-gnu"
            invalid = deepcopy(base)
            cast(list[object], invalid["payloads"])[0] = wrong_target
            with self.subTest(
                profile=profile, field="payloads", mutation="wrong-target"
            ):
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        bootstrap = _repository_bootstrap_manifest()
        with self.subTest(profile="repository-bootstrap", mutation="nonempty"):
            bootstrap["builds"] = deepcopy(
                cast(list[object], _cli_manifest("desktop")["builds"])[0:1]
            )
            with self.assertRaises(
                validate_release_provenance.ReleaseProvenanceValidationError
            ):
                _ = validate_manifest(bootstrap, schema)

    def test_cli_manifest_requires_one_archive_and_sbom_per_payload(self) -> None:
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
        for profile in ("desktop", "desktop-linux"):
            base = _cli_manifest(profile)
            artifacts = cast(list[object], base["artifacts"])
            archive_index = next(
                index
                for index, value in enumerate(artifacts)
                if cast(dict[str, object], value)["kind"] == "archive"
            )
            with self.subTest(profile=profile, mutation="missing-archive"):
                invalid = deepcopy(base)
                del cast(list[object], invalid["artifacts"])[archive_index]
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

            with self.subTest(profile=profile, mutation="extra-archive"):
                invalid = deepcopy(base)
                extra = deepcopy(
                    cast(list[object], invalid["artifacts"])[archive_index]
                )
                extra_mapping = cast(dict[str, object], extra)
                extra_mapping["filename"] = "context-engine-extra.tar.gz"
                extra_mapping["url"] = (
                    "https://github.com/context-engine-app/context-engine-mcp/releases/"
                    "download/v1.2.3/context-engine-extra.tar.gz"
                )
                cast(list[object], invalid["artifacts"]).append(extra)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

            with self.subTest(profile=profile, mutation="wrong-payload"):
                invalid = deepcopy(base)
                wrong = cast(
                    dict[str, object],
                    cast(list[object], invalid["artifacts"])[archive_index],
                )
                wrong["payload_id"] = "context-engine-unexpected"
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

    def test_manifest_payload_metadata_matches_target_contract(self) -> None:
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
        mutations = (
            ("script", "builds", "x86_64-apple-darwin", "scripts/build_win.sh"),
            ("filename", "payloads", "aarch64-apple-darwin", "context-engine.exe"),
            ("platform", "payloads", "x86_64-apple-darwin", "windows"),
            ("architecture", "payloads", "aarch64-apple-darwin", "x86_64"),
        )
        for profile in ("desktop", "desktop-linux"):
            for field, collection_name, target, value in mutations:
                with self.subTest(profile=profile, field=field, target=target):
                    invalid = deepcopy(_cli_manifest(profile))
                    values = cast(list[object], invalid[collection_name])
                    item = next(
                        cast(dict[str, object], value_item)
                        for value_item in values
                        if cast(dict[str, object], value_item).get(
                            "payload_id", cast(dict[str, object], value_item).get("id")
                        )
                        == f"context-engine-{target}"
                    )
                    item[field] = value
                    with self.assertRaises(
                        validate_release_provenance.ReleaseProvenanceValidationError
                    ):
                        _ = validate_manifest(invalid, schema)

    def test_common_artifact_filenames_are_exact_per_profile(self) -> None:
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
        for profile in ("desktop", "desktop-linux"):
            with self.subTest(profile=profile):
                invalid = deepcopy(_cli_manifest(profile))
                artifacts = cast(list[object], invalid["artifacts"])
                artifacts[:] = [
                    value
                    for value in artifacts
                    if cast(dict[str, object], value).get("filename")
                    != "context-engine-release.cdx.json"
                ]
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        invalid = _repository_bootstrap_manifest()
        common = next(
            value
            for value in cast(list[object], invalid["artifacts"])
            if cast(dict[str, object], value)["kind"] == "common"
        )
        cast(dict[str, object], common)["filename"] = "context-engine-release.cdx.json"
        cast(dict[str, object], common)["url"] = (
            "https://github.com/context-engine-app/context-engine-mcp/releases/"
            "download/repository-bootstrap-v1.2.3/context-engine-release.cdx.json"
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

    def test_cli_artifacts_bind_canonical_target_and_payload_identity(self) -> None:
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
        for artifact_kind in ("archive", "sbom"):
            filename_suffix = ".zip" if artifact_kind == "archive" else ".cdx.json"
            for field, value in (
                (
                    "filename",
                    f"context-engine-aarch64-apple-darwin{filename_suffix}",
                ),
                ("platform", "windows"),
                ("architecture", "arm64"),
                ("target", "aarch64-apple-darwin"),
                ("payload_id", "context-engine-aarch64-apple-darwin"),
            ):
                with self.subTest(artifact_kind=artifact_kind, artifact_field=field):
                    invalid = deepcopy(_cli_manifest("desktop-linux"))
                    artifact = next(
                        cast(dict[str, object], value_item)
                        for value_item in cast(list[object], invalid["artifacts"])
                        if cast(dict[str, object], value_item)["kind"] == artifact_kind
                        and cast(dict[str, object], value_item)["target"]
                        == "x86_64-apple-darwin"
                    )
                    artifact[field] = value
                    if field == "filename":
                        artifact["url"] = (
                            "https://github.com/context-engine-app/context-engine-mcp/releases/"
                            f"download/v1.2.3/context-engine-aarch64-apple-darwin{filename_suffix}"
                        )
                    with self.assertRaises(
                        validate_release_provenance.ReleaseProvenanceValidationError
                    ):
                        _ = validate_manifest(invalid, schema)

        for field, value in (
            ("executable_mode", "0644"),
            ("version_output", "context-engine 9.9.9"),
        ):
            with self.subTest(payload_field=field):
                invalid = deepcopy(_cli_manifest("desktop-linux"))
                payload = next(
                    cast(dict[str, object], value_item)
                    for value_item in cast(list[object], invalid["payloads"])
                    if cast(dict[str, object], value_item)["target"]
                    == "x86_64-apple-darwin"
                )
                payload[field] = value
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

    def test_desktop_linux_native_packages_require_canonical_linux_pair(self) -> None:
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

        invalid = deepcopy(_cli_manifest("desktop-linux"))
        package = cast(
            dict[str, object],
            cast(
                list[object],
                cast(dict[str, object], invalid["package_binding"])["packages"],
            )[0],
        )
        native = next(
            cast(dict[str, object], value)
            for value in cast(list[object], invalid["artifacts"])
            if cast(dict[str, object], value)["kind"] == "native-package"
        )
        package["id"] = "context-engine-other"
        native["package_id"] = "context-engine-other"
        descriptor = cast(dict[str, object], invalid["release_descriptor"])
        descriptor["package_binding_sha256"] = _canonical_sha256(
            {
                "package_binding": invalid["package_binding"],
                "bootstrap": invalid["bootstrap"],
            }
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

        invalid = deepcopy(_cli_manifest("desktop-linux"))
        package = cast(
            dict[str, object],
            cast(
                list[object],
                cast(dict[str, object], invalid["package_binding"])["packages"],
            )[0],
        )
        native = next(
            cast(dict[str, object], value)
            for value in cast(list[object], invalid["artifacts"])
            if cast(dict[str, object], value)["kind"] == "native-package"
        )
        package["package_format"] = "rpm"
        package["architecture"] = "x86_64"
        native["package_format"] = "rpm"
        descriptor = cast(dict[str, object], invalid["release_descriptor"])
        descriptor["package_binding_sha256"] = _canonical_sha256(
            {
                "package_binding": invalid["package_binding"],
                "bootstrap": invalid["bootstrap"],
            }
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

        invalid = deepcopy(_cli_manifest("desktop-linux"))
        packages = cast(
            list[dict[str, object]],
            cast(dict[str, object], invalid["package_binding"])["packages"],
        )
        packages[0]["architecture"] = "x86_64"
        packages[1]["architecture"] = "amd64"
        descriptor = cast(dict[str, object], invalid["release_descriptor"])
        descriptor["package_binding_sha256"] = _canonical_sha256(
            {
                "package_binding": invalid["package_binding"],
                "bootstrap": invalid["bootstrap"],
            }
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

        invalid = deepcopy(_cli_manifest("desktop-linux"))
        native_packages = [
            cast(dict[str, object], value)
            for value in cast(list[object], invalid["artifacts"])
            if cast(dict[str, object], value)["kind"] == "native-package"
        ]
        native_packages[0]["architecture"] = "x86_64"
        native_packages[1]["architecture"] = "amd64"
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

        invalid = deepcopy(_cli_manifest("desktop-linux"))
        bootstrap_packages = cast(
            list[object], cast(dict[str, object], invalid["bootstrap"])["packages"]
        )
        invalid["package_binding"] = {
            "mode": "bootstrap",
            "packages": [
                cast(
                    dict[str, object],
                    bootstrap_packages[0],
                )
            ],
        }
        invalid["artifacts"] = [
            value
            for value in cast(list[object], invalid["artifacts"])
            if cast(dict[str, object], value)["kind"] != "native-package"
        ]
        descriptor = cast(dict[str, object], invalid["release_descriptor"])
        descriptor["package_binding_sha256"] = _canonical_sha256(
            {
                "package_binding": invalid["package_binding"],
                "bootstrap": invalid["bootstrap"],
            }
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

        invalid = deepcopy(_cli_manifest("desktop-linux"))
        native = next(
            cast(dict[str, object], value)
            for value in cast(list[object], invalid["artifacts"])
            if cast(dict[str, object], value)["kind"] == "native-package"
        )
        native.update(
            {
                "payload_id": "context-engine-x86_64-apple-darwin",
                "target": "x86_64-apple-darwin",
                "platform": "macos",
            }
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(invalid, schema)

    def test_manifest_artifact_kinds_follow_profile_bindings(self) -> None:
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

        def artifact_for(kind: str, tag: str) -> dict[str, object]:
            if kind == "bootstrap-package":
                artifact = deepcopy(
                    cast(list[object], _repository_bootstrap_manifest()["artifacts"])[0]
                )
            elif kind == "common":
                common_artifacts = [
                    value
                    for value in cast(
                        list[object], _repository_bootstrap_manifest()["artifacts"]
                    )
                    if cast(dict[str, object], value)["kind"] == "common"
                ]
                artifact = deepcopy(common_artifacts[0])
            elif kind in {"archive", "sbom"}:
                artifact = deepcopy(
                    cast(list[object], _cli_manifest("desktop")["artifacts"])[0]
                )
                cast(dict[str, object], artifact)["kind"] = kind
            else:
                artifact = deepcopy(
                    cast(list[object], _cli_manifest("desktop")["artifacts"])[0]
                )
                artifact_mapping = cast(dict[str, object], artifact)
                _ = artifact_mapping.pop("payload_id", None)
                _ = artifact_mapping.pop("target", None)
                artifact_mapping.update(
                    {
                        "kind": "native-package",
                        "platform": "linux",
                        "architecture": "amd64",
                        "package_id": "context-engine",
                        "package_format": "deb",
                        "package_suite": "stable",
                        "package_version": "1.2.3",
                        "package_manifest_sha256": "b" * 64,
                        "package_verification_sha256": "c" * 64,
                        "filename": "context-engine-1.2.3.deb",
                    }
                )
            artifact_mapping = cast(dict[str, object], artifact)
            filename = cast(str, artifact_mapping["filename"])
            artifact_mapping["url"] = (
                "https://github.com/context-engine-app/context-engine-mcp/releases/"
                f"download/{tag}/{filename}"
            )
            return artifact_mapping

        for kind in ("archive", "sbom", "native-package"):
            with self.subTest(profile="repository-bootstrap", kind=kind):
                invalid = _repository_bootstrap_manifest()
                invalid["artifacts"] = [artifact_for(kind, cast(str, invalid["tag"]))]
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        for kind in ("native-package", "bootstrap-package"):
            with self.subTest(profile="desktop", kind=kind):
                invalid = _cli_manifest("desktop")
                artifacts = cast(list[object], invalid["artifacts"])
                artifacts.append(artifact_for(kind, cast(str, invalid["tag"])))
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        for profile in ("desktop", "desktop-linux", "repository-bootstrap"):
            with self.subTest(profile=profile, kind="common"):
                valid = (
                    _repository_bootstrap_manifest()
                    if profile == "repository-bootstrap"
                    else _cli_manifest(profile)
                )
                _ = validate_manifest(valid, schema)

        _ = validate_manifest(_cli_manifest("desktop-linux"), schema)
        native_wrong_target = _cli_manifest("desktop-linux")
        native_artifact = artifact_for(
            "native-package", cast(str, native_wrong_target["tag"])
        )
        native_artifact["target"] = "x86_64-unknown-linux-gnu"
        cast(list[object], native_wrong_target["artifacts"]).append(native_artifact)
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(native_wrong_target, schema)

        referenced = _cli_manifest("desktop-linux")
        referenced_package = {
            "id": "context-engine-release",
            "version": "1.2.3",
            "filename": "context-engine-release-1.2.3-1.noarch.rpm",
            "sha256": "3" * 64,
            "suite": "stable",
            "package_format": "rpm",
            "repository_source_format": "repo",
            "architecture": "noarch",
        }
        referenced_tag = "repository-bootstrap-v1.2.3"
        referenced_binding = {
            "mode": "referenced",
            "release_tag": referenced_tag,
            "manifest_sha256": "4" * 64,
            "packages": [referenced_package],
        }
        referenced_bootstrap = {
            "mode": "referenced",
            "release_tag": referenced_tag,
            "url": (
                "https://github.com/context-engine-app/context-engine-mcp/releases/download/"
                f"{referenced_tag}/release-manifest.json"
            ),
            "manifest_sha256": "5" * 64,
            "packages": [referenced_package],
        }
        referenced["package_binding"] = referenced_binding
        referenced["bootstrap"] = referenced_bootstrap
        cast(dict[str, object], referenced["release_descriptor"])[
            "package_binding_sha256"
        ] = _canonical_sha256(
            {"package_binding": referenced_binding, "bootstrap": referenced_bootstrap}
        )
        referenced["artifacts"] = [
            value
            for value in cast(list[object], referenced["artifacts"])
            if cast(dict[str, object], value)["kind"]
            not in {"native-package", "bootstrap-package"}
        ]
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(referenced, schema)

    def test_manifest_package_bindings_require_exact_local_artifacts(self) -> None:
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

        def refresh_digest(document: dict[str, object]) -> None:
            descriptor = cast(dict[str, object], document["release_descriptor"])
            descriptor["package_binding_sha256"] = _canonical_sha256(
                {
                    "package_binding": document["package_binding"],
                    "bootstrap": document["bootstrap"],
                }
            )

        base = _cli_manifest("desktop-linux")
        _ = validate_manifest(base, schema)
        package_fields = (
            ("package_binding", "id", "context-engine-other"),
            ("package_binding", "version", "9.9.9"),
            ("package_binding", "filename", "context-engine-other.deb"),
            ("package_binding", "suite", "testing"),
            ("package_binding", "package_format", "rpm"),
            ("package_binding", "architecture", "arm64"),
            ("package_binding", "repository_source_format", "list"),
            ("bootstrap", "id", "context-engine-archive-keyring"),
            ("bootstrap", "version", "9.9.9"),
            ("bootstrap", "filename", "context-engine-other.rpm"),
            ("bootstrap", "suite", "testing"),
            ("bootstrap", "package_format", "deb"),
            ("bootstrap", "architecture", "all"),
            ("bootstrap", "repository_source_format", "list"),
        )
        for binding_name, field, value in package_fields:
            with self.subTest(binding=binding_name, field=field):
                invalid = deepcopy(base)
                binding = cast(dict[str, object], invalid[binding_name])
                package = cast(list[dict[str, object]], binding["packages"])[0]
                package[field] = value
                refresh_digest(invalid)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        for kind in ("native-package", "bootstrap-package"):
            with self.subTest(kind=kind, mutation="missing"):
                invalid = deepcopy(base)
                artifacts = cast(list[object], invalid["artifacts"])
                artifact = next(
                    value
                    for value in artifacts
                    if cast(dict[str, object], value)["kind"] == kind
                )
                artifacts.remove(artifact)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

            with self.subTest(kind=kind, mutation="extra"):
                invalid = deepcopy(base)
                artifacts = cast(list[object], invalid["artifacts"])
                artifact = deepcopy(
                    next(
                        value
                        for value in artifacts
                        if cast(dict[str, object], value)["kind"] == kind
                    )
                )
                mapping = cast(dict[str, object], artifact)
                mapping["package_id"] = "context-engine-extra"
                mapping["filename"] = f"context-engine-extra-{kind}.pkg"
                mapping["url"] = (
                    "https://github.com/context-engine-app/context-engine-mcp/releases/"
                    f"download/v1.2.3/{mapping['filename']}"
                )
                artifacts.append(artifact)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

            with self.subTest(kind=kind, mutation="duplicate"):
                invalid = deepcopy(base)
                artifacts = cast(list[object], invalid["artifacts"])
                artifact = deepcopy(
                    next(
                        value
                        for value in artifacts
                        if cast(dict[str, object], value)["kind"] == kind
                    )
                )
                mapping = cast(dict[str, object], artifact)
                mapping["filename"] = f"context-engine-copy-{kind}.pkg"
                mapping["url"] = (
                    "https://github.com/context-engine-app/context-engine-mcp/releases/"
                    f"download/v1.2.3/{mapping['filename']}"
                )
                artifacts.append(artifact)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        referenced = deepcopy(base)
        referenced_package_binding = {
            "mode": "referenced",
            "release_tag": "repository-bootstrap-v1.2.3",
            "manifest_sha256": "1" * 64,
            "packages": [
                {
                    "id": "context-engine",
                    "version": "1.2.3",
                    "filename": "context-engine-1.2.3.deb",
                    "sha256": "2" * 64,
                    "suite": "stable",
                    "package_format": "deb",
                    "architecture": "amd64",
                }
            ],
        }
        referenced_bootstrap = {
            "mode": "referenced",
            "release_tag": "repository-bootstrap-v1.2.3",
            "url": "https://github.com/context-engine-app/context-engine-mcp/releases/download/repository-bootstrap-v1.2.3/release-manifest.json",
            "manifest_sha256": "3" * 64,
            "packages": [
                {
                    "id": "context-engine-release",
                    "version": "1.2.3",
                    "filename": "context-engine-release-1.2.3-1.noarch.rpm",
                    "sha256": "4" * 64,
                    "suite": "stable",
                    "package_format": "rpm",
                    "repository_source_format": "repo",
                    "architecture": "noarch",
                }
            ],
        }
        referenced["package_binding"] = referenced_package_binding
        referenced["bootstrap"] = referenced_bootstrap
        refresh_digest(referenced)
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(referenced, schema)
        referenced["artifacts"] = [
            value
            for value in cast(list[object], referenced["artifacts"])
            if cast(dict[str, object], value)["kind"]
            not in {"native-package", "bootstrap-package"}
        ]
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(referenced, schema)

        bootstrap_mode = deepcopy(base)
        bootstrap_package = cast(
            list[dict[str, object]],
            cast(dict[str, object], bootstrap_mode["bootstrap"])["packages"],
        )[0]
        bootstrap_mode["package_binding"] = {
            "mode": "bootstrap",
            "packages": [bootstrap_package],
        }
        bootstrap_mode["artifacts"] = [
            value
            for value in cast(list[object], bootstrap_mode["artifacts"])
            if cast(dict[str, object], value)["kind"] != "native-package"
        ]
        refresh_digest(bootstrap_mode)
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_manifest(bootstrap_mode, schema)

    def test_repository_bootstrap_binding_requires_exact_local_artifacts(self) -> None:
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

        def refresh_digest(document: dict[str, object]) -> None:
            descriptor = cast(dict[str, object], document["release_descriptor"])
            descriptor["package_binding_sha256"] = _canonical_sha256(
                {
                    "package_binding": document["package_binding"],
                    "bootstrap": document["bootstrap"],
                }
            )

        base = _repository_bootstrap_manifest()
        _ = validate_manifest(base, schema)
        for field, value in (
            ("id", "context-engine-release-other"),
            ("version", "9.9.9"),
            ("filename", "context-engine-other.rpm"),
            ("suite", "testing"),
            ("package_format", "deb"),
            ("architecture", "all"),
            ("repository_source_format", "list"),
        ):
            with self.subTest(field=field):
                invalid = deepcopy(base)
                package_binding = cast(dict[str, object], invalid["package_binding"])
                package = cast(list[dict[str, object]], package_binding["packages"])[0]
                package[field] = value
                refresh_digest(invalid)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

        for mutation in ("missing", "extra", "duplicate"):
            with self.subTest(mutation=mutation):
                invalid = deepcopy(base)
                artifacts = cast(list[object], invalid["artifacts"])
                artifact = next(
                    value
                    for value in artifacts
                    if cast(dict[str, object], value)["kind"] == "bootstrap-package"
                )
                if mutation == "missing":
                    artifacts.remove(artifact)
                else:
                    duplicate = deepcopy(artifact)
                    duplicate_mapping = cast(dict[str, object], duplicate)
                    duplicate_mapping["filename"] = (
                        "context-engine-release-copy-1.2.3-1.noarch.rpm"
                    )
                    duplicate_mapping["url"] = (
                        "https://github.com/context-engine-app/context-engine-mcp/releases/download/"
                        "repository-bootstrap-v1.2.3/context-engine-release-copy-1.2.3-1.noarch.rpm"
                    )
                    if mutation == "extra":
                        duplicate_mapping["package_id"] = (
                            "context-engine-archive-keyring"
                        )
                    artifacts.append(duplicate)
                with self.assertRaises(
                    validate_release_provenance.ReleaseProvenanceValidationError
                ):
                    _ = validate_manifest(invalid, schema)

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

    def test_repository_bootstrap_candidate_symlink_counts_as_extra_presence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "channel-candidates.json").symlink_to("missing-candidates.json")
            validate_root_closure = cast(
                Callable[[Path, set[str]], None],
                getattr(validate_release_provenance, "_validate_root_closure"),
            )
            with self.assertRaisesRegex(
                validate_release_provenance.ReleaseProvenanceValidationError,
                "release root closure differs",
            ):
                validate_root_closure(root, set())

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

    def test_workflow_reauthorization_accepts_bootstrap_tag_and_exact_ref(self) -> None:
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
        tag = "repository-bootstrap-v1.2.3"
        record = {
            "schema_version": 1,
            "tag": tag,
            "stage": "public-publish",
            "execution_ref": f"refs/tags/release-reauthorization/{tag}/public-publish/"
            + "c" * 40,
            "original": original,
            "replacement": replacement,
            "reason": "critical workflow repair",
            "approval_evidence": {
                "issue": "https://github.com/context-engine-app/context-engine-mcp/issues/1"
            },
        }
        result = validate_release_provenance.validate_workflow_reauthorization(record)
        self.assertEqual(result["tag"], tag)

        schema_path = (
            Path(__file__).parents[2]
            / "schemas"
            / "workflow-reauthorization.schema.json"
        )
        schema = cast(
            dict[str, object],
            validate_release_provenance.parse_json(
                schema_path.read_text(encoding="utf-8"), str(schema_path)
            ),
        )
        validate_schema = cast(
            Callable[[Mapping[str, object], dict[str, object], str], None],
            getattr(validate_release_provenance, "_validate_schema"),
        )
        validate_schema(record, schema, "workflow reauthorization")

        mismatched = dict(record)
        mismatched["execution_ref"] = (
            "refs/tags/release-reauthorization/v1.2.3/public-publish/" + "c" * 40
        )
        with self.assertRaises(
            validate_release_provenance.ReleaseProvenanceValidationError
        ):
            _ = validate_release_provenance.validate_workflow_reauthorization(
                mismatched
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
            "2e398c70916e86ab58734cc77622bdf7e04e756c1ebdef73e9cc903ffb62baa8",
        )
        self.assertEqual(
            validate_release_provenance.PROVENANCE_SCHEMA_SHA256,
            "c13bf530c6fe4befc00b398c2274b3ffeb7e6cbcfb78c38bc1a5da0b8bf4db60",
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
            "2e398c70916e86ab58734cc77622bdf7e04e756c1ebdef73e9cc903ffb62baa8",
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
