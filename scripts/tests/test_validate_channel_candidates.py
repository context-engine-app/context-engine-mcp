"""Focused tests for repository-bootstrap candidate validation."""

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
from unittest import mock

from scripts import validate_channel_candidates


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _expect_manifest_inputs_rejection(manifest: Mapping[str, object]) -> None:
    manifest_inputs = cast(
        Callable[[Mapping[str, object]], object],
        getattr(validate_channel_candidates, "_manifest_inputs"),
    )
    _ = manifest_inputs(manifest)


def _desktop_linux_manifest() -> dict[str, object]:
    targets = (
        ("x86_64-apple-darwin", "macos", "x86_64", "context-engine"),
        ("aarch64-apple-darwin", "macos", "arm64", "context-engine"),
        ("x86_64-pc-windows-msvc", "windows", "x86_64", "context-engine.exe"),
        ("x86_64-unknown-linux-gnu", "linux", "x86_64", "context-engine"),
        ("aarch64-unknown-linux-gnu", "linux", "arm64", "context-engine"),
    )
    payloads: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    for target, platform, architecture, filename in targets:
        payload_id = f"context-engine-{target}"
        payload_bytes = f"payload:{payload_id}".encode()
        payloads.append(
            {
                "id": payload_id,
                "filename": filename,
                "target": target,
                "platform": platform,
                "architecture": architecture,
                "sha256": _sha(payload_bytes),
                "size": len(payload_bytes),
                "executable_mode": "0755",
                "license_mode": "enforced",
                "version_output": "context-engine 1.2.3",
            }
        )
        archive_filename = f"{payload_id}.tar.gz"
        artifacts.append(
            {
                "kind": "archive",
                "payload_id": payload_id,
                "platform": platform,
                "architecture": architecture,
                "target": target,
                "filename": archive_filename,
                "url": (
                    "https://github.com/context-engine-app/context-engine-mcp/"
                    f"releases/download/v1.2.3/{archive_filename}"
                ),
                "sha256": _sha(f"archive:{payload_id}".encode()),
                "size": len(f"archive:{payload_id}".encode()),
            }
        )

    package = {
        "id": "context-engine-release",
        "version": "1.2.3",
        "filename": "context-engine-release-1.2.3-1.noarch.rpm",
        "suite": "stable",
        "package_format": "rpm",
        "repository_source_format": "repo",
        "architecture": "noarch",
    }
    workflow = {
        "path": ".github/workflows/prepare-draft-release.yml",
        "commit": "b" * 40,
        "sha256": "7" * 64,
    }
    return {
        "schema_version": 1,
        "profile": "desktop-linux",
        "version": "1.2.3",
        "tag": "v1.2.3",
        "source_repository": "context-engine-app/context-engine",
        "source_commit": "a" * 40,
        "distribution_repository": "context-engine-app/context-engine-mcp",
        "distribution_commit": "b" * 40,
        "distribution_tag_target": "b" * 40,
        "release_descriptor": {
            "path": "packaging/releases/v1.2.3.json",
            "sha256": "1" * 64,
            "package_binding_sha256": "2" * 64,
        },
        "assembly_facts": {
            "path": "packaging/assembly-facts.json",
            "sha256": "3" * 64,
        },
        "license_identity": {
            "key_id": "preview-2026-01",
            "public_key_sha256": "4" * 64,
        },
        "schemas": {
            "release_provenance": {
                "path": "packaging/release-provenance.schema.json",
                "sha256": "5" * 64,
            }
        },
        "source_workflows": {
            "release": {
                "path": ".github/workflows/release.yml",
                "commit": "a" * 40,
                "sha256": "6" * 64,
            }
        },
        "authorized_stages": [
            "source-release",
            "public-draft",
            "public-publish",
            "package-channels",
        ],
        "workflow_bindings": {
            "draft": workflow,
            "publish": {
                "path": ".github/workflows/publish-draft-release.yml",
                "commit": "c" * 40,
                "sha256": "8" * 64,
            },
            "channels": {
                "path": ".github/workflows/prepare-package-channels.yml",
                "commit": "d" * 40,
                "sha256": "9" * 64,
            },
        },
        "build_mode": "license-enforced",
        "package_binding": {"mode": "embedded", "packages": [package]},
        "bootstrap": {"mode": "embedded", "packages": [package]},
        "builds": [
            {
                "payload_id": payload["id"],
                "script": script,
                "script_sha256": "a" * 64,
                "build_record_sha256": "b" * 64,
                "payload_verification_sha256": "c" * 64,
            }
            for payload, script in zip(
                payloads,
                (
                    "scripts/build_mac.sh",
                    "scripts/build_mac.sh",
                    "scripts/build_win.sh",
                    "scripts/build_linux.sh",
                    "scripts/build_linux.sh",
                ),
                strict=True,
            )
        ],
        "payloads": payloads,
        "grammar_inventory": {
            "path": "resources/manifest.json",
            "sha256": "e" * 64,
        },
        "artifacts": artifacts,
    }


def _write_desktop_linux_candidate_fixture(root: Path) -> None:
    manifest = _desktop_linux_manifest()
    payloads = cast(list[object], manifest["payloads"])
    artifacts = cast(list[object], manifest["artifacts"])
    archive_by_id = {
        cast(str, cast(Mapping[str, object], artifact)["payload_id"]): cast(
            str, cast(Mapping[str, object], artifact)["url"]
        )
        for artifact in artifacts
    }
    candidates_data = {
        "Formula/context-engine.rb": (
            f"{archive_by_id['context-engine-x86_64-apple-darwin']}\n"
            f"{archive_by_id['context-engine-aarch64-apple-darwin']}\n"
        ).encode(),
        "bucket/context-engine.json": (
            f"{archive_by_id['context-engine-x86_64-pc-windows-msvc']}\n"
        ).encode(),
    }
    candidate_records: list[dict[str, object]] = []
    coordinates = (
        ("homebrew", "formula", "Formula/context-engine.rb"),
        ("scoop", "manifest", "bucket/context-engine.json"),
    )
    for kind, file_kind, path in coordinates:
        data = candidates_data[path]
        candidate_records.append(
            {
                "kind": kind,
                "file_kind": file_kind,
                "path": path,
                "sha256": _sha(data),
                "size": len(data),
                "mode": "0644",
            }
        )
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
        with tarfile.open(
            fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            for path in sorted(candidates_data):
                data = candidates_data[path]
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    archive_bytes = output.getvalue()
    templates = [
        {"path": path, "sha256": "f" * 64}
        for path in sorted(validate_channel_candidates.EXPECTED_TEMPLATES)
    ]
    sources = [
        {"path": path, "sha256": "0" * 64}
        for path in sorted(validate_channel_candidates.EXPECTED_GENERATOR_SOURCES)
    ]
    candidate_document: dict[str, object] = {
        "schema_version": 1,
        "release_tag": "v1.2.3",
        "version": "1.2.3",
        "profile": "desktop-linux",
        "source_manifest_sha256": "",
        "archive": {
            "path": "channel-candidates.tar.gz",
            "sha256": _sha(archive_bytes),
        },
        "generator": {
            "release_source_commit": cast(str, manifest["source_commit"]),
            "generator_commit": "e" * 40,
            "schema_path": "packaging/channel-candidates.schema.json",
            "schema_sha256": validate_channel_candidates.CHANNEL_SCHEMA_SHA256,
            "templates": templates,
            "generator_path": "scripts/release/render_package_metadata.py",
            "generator_sha256": "1" * 64,
            "sources": sources,
        },
        "inputs": {
            "payloads": [
                {
                    "id": cast(str, cast(Mapping[str, object], payload)["id"]),
                    "filename": cast(
                        str, cast(Mapping[str, object], payload)["filename"]
                    ),
                    "sha256": cast(str, cast(Mapping[str, object], payload)["sha256"]),
                }
                for payload in sorted(
                    payloads,
                    key=lambda item: cast(str, cast(Mapping[str, object], item)["id"]),
                )
            ],
            "archives": [
                {
                    "id": cast(str, cast(Mapping[str, object], archive)["payload_id"]),
                    "filename": cast(
                        str, cast(Mapping[str, object], archive)["filename"]
                    ),
                    "sha256": cast(str, cast(Mapping[str, object], archive)["sha256"]),
                }
                for archive in sorted(
                    artifacts,
                    key=lambda item: cast(
                        str, cast(Mapping[str, object], item)["payload_id"]
                    ),
                )
            ],
        },
        "candidates": candidate_records,
    }
    manifest_bytes = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    candidate_document["source_manifest_sha256"] = _sha(manifest_bytes)
    _ = (root / "release-manifest.json").write_bytes(manifest_bytes)
    _ = (root / "channel-candidates.json").write_bytes(
        json.dumps(
            candidate_document, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode()
    )
    _ = (root / "channel-candidates.tar.gz").write_bytes(archive_bytes)


def _write_legacy_v010_candidate_fixture(root: Path) -> None:
    _write_desktop_linux_candidate_fixture(root)
    manifest = cast(
        dict[str, object],
        json.loads(
            (root / "release-manifest.json")
            .read_text(encoding="utf-8")
            .replace("1.2.3", "0.1.0")
        ),
    )
    arm_payload_id = "context-engine-aarch64-unknown-linux-gnu"
    for field, identity in (
        ("builds", "payload_id"),
        ("payloads", "id"),
        ("artifacts", "payload_id"),
    ):
        manifest[field] = [
            item
            for item in cast(list[dict[str, object]], manifest[field])
            if item.get(identity) != arm_payload_id
        ]
    manifest_bytes = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    _ = (root / "release-manifest.json").write_bytes(manifest_bytes)

    archive_urls = {
        cast(str, item["payload_id"]): cast(str, item["url"])
        for item in cast(list[dict[str, object]], manifest["artifacts"])
        if item.get("kind") == "archive"
    }
    candidates_data = {
        "Formula/context-engine.rb": (
            f"{archive_urls['context-engine-x86_64-apple-darwin']}\n"
            f"{archive_urls['context-engine-aarch64-apple-darwin']}\n"
        ).encode(),
        "bucket/context-engine.json": (
            f"{archive_urls['context-engine-x86_64-pc-windows-msvc']}\n"
        ).encode(),
    }
    windows_url = archive_urls["context-engine-x86_64-pc-windows-msvc"]
    for path in validate_channel_candidates.LEGACY_EXPECTED_CANDIDATES.values():
        candidate_path = path.format(version="0.1.0")
        if candidate_path not in candidates_data:
            candidates_data[candidate_path] = f"{windows_url}\n".encode()

    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
        with tarfile.open(
            fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            for path in sorted(candidates_data):
                data = candidates_data[path]
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    archive_bytes = output.getvalue()

    candidate_document = cast(
        dict[str, object],
        json.loads((root / "channel-candidates.json").read_text(encoding="utf-8")),
    )
    candidate_document["release_tag"] = "v0.1.0"
    candidate_document["version"] = "0.1.0"
    candidate_document["source_manifest_sha256"] = _sha(manifest_bytes)
    candidate_document["archive"] = {
        "path": "channel-candidates.tar.gz",
        "sha256": _sha(archive_bytes),
    }
    generator = cast(dict[str, object], candidate_document["generator"])
    generator["schema_sha256"] = (
        validate_channel_candidates.LEGACY_CHANNEL_SCHEMA_SHA256
    )
    generator["templates"] = [
        {"path": path, "sha256": "f" * 64}
        for path in sorted(validate_channel_candidates.LEGACY_EXPECTED_TEMPLATES)
    ]
    generator["sources"] = [
        {"path": path, "sha256": "0" * 64}
        for path in sorted(
            validate_channel_candidates.LEGACY_EXPECTED_GENERATOR_SOURCES
        )
    ]
    inputs = cast(dict[str, object], candidate_document["inputs"])
    for field in ("payloads", "archives"):
        inputs[field] = [
            item
            for item in cast(list[dict[str, object]], inputs[field])
            if item.get("id") != arm_payload_id
        ]
    candidate_document["candidates"] = [
        {
            "kind": kind,
            "file_kind": file_kind,
            "path": path.format(version="0.1.0"),
            "sha256": _sha(candidates_data[path.format(version="0.1.0")]),
            "size": len(candidates_data[path.format(version="0.1.0")]),
            "mode": "0644",
        }
        for (kind, file_kind), path in sorted(
            validate_channel_candidates.LEGACY_EXPECTED_CANDIDATES.items()
        )
    ]
    _ = (root / "channel-candidates.json").write_bytes(
        json.dumps(
            candidate_document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    _ = (root / "channel-candidates.tar.gz").write_bytes(archive_bytes)


class RepositoryBootstrapCandidateTests(unittest.TestCase):
    def test_desktop_linux_candidate_bundle_passes(self) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_desktop_linux_candidate_fixture(root)
            validate_channel_candidates.validate_channel_candidates(root, schemas)

    def test_exact_legacy_v010_bundle_passes_and_later_versions_reject_it(
        self,
    ) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_legacy_v010_candidate_fixture(root)
            validate_channel_candidates.validate_channel_candidates(root, schemas)

            candidate_path = root / "channel-candidates.json"
            candidate_document = cast(
                dict[str, object],
                json.loads(candidate_path.read_text(encoding="utf-8")),
            )
            candidate_document["version"] = "0.1.1"
            candidate_document["release_tag"] = "v0.1.1"
            _ = candidate_path.write_text(
                json.dumps(candidate_document, sort_keys=True), encoding="utf-8"
            )
            with self.assertRaises(
                validate_channel_candidates.CandidateValidationError
            ):
                validate_channel_candidates.validate_channel_candidates(root, schemas)

    def test_each_profile_rejects_missing_extra_and_duplicate_archives(self) -> None:
        for profile in ("desktop", "desktop-linux"):
            manifest = _desktop_linux_manifest()
            manifest["profile"] = profile
            all_artifacts = cast(list[object], manifest["artifacts"])
            base_artifacts = (
                all_artifacts[:3] if profile == "desktop" else all_artifacts
            )

            with self.subTest(profile=profile, mutation="missing"):
                manifest["artifacts"] = base_artifacts[:-1]
                with self.assertRaises(
                    validate_channel_candidates.CandidateValidationError
                ):
                    _expect_manifest_inputs_rejection(manifest)

            with self.subTest(profile=profile, mutation="extra"):
                extra = dict(cast(Mapping[str, object], base_artifacts[0]))
                extra["payload_id"] = "context-engine-extra"
                extra["filename"] = "context-engine-extra.tar.gz"
                manifest["artifacts"] = [*base_artifacts, extra]
                with self.assertRaises(
                    validate_channel_candidates.CandidateValidationError
                ):
                    _expect_manifest_inputs_rejection(manifest)

            with self.subTest(profile=profile, mutation="duplicate"):
                duplicate = dict(cast(Mapping[str, object], base_artifacts[-2]))
                manifest["artifacts"] = [*base_artifacts[:-1], duplicate]
                with self.assertRaises(
                    validate_channel_candidates.CandidateValidationError
                ):
                    _expect_manifest_inputs_rejection(manifest)

    def test_bootstrap_manifest_is_validated_against_pinned_schema(self) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _ = (root / "release-manifest.json").write_text(
                '{"profile":"repository-bootstrap"}', encoding="utf-8"
            )
            with (
                mock.patch.object(
                    validate_channel_candidates,
                    "_load_schema",
                    return_value={},
                ),
                mock.patch.object(
                    validate_channel_candidates,
                    "_validate_schema",
                    side_effect=validate_channel_candidates.CandidateValidationError(
                        "manifest schema violation"
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    validate_channel_candidates.CandidateValidationError,
                    "manifest schema violation",
                ):
                    validate_channel_candidates.validate_channel_candidates(
                        root, schemas
                    )

    def test_desktop_linux_is_a_cli_profile(self) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _ = (root / "release-manifest.json").write_text(
                '{"profile":"desktop-linux"}', encoding="utf-8"
            )

            with (
                mock.patch.object(
                    validate_channel_candidates,
                    "_load_schema",
                    return_value={},
                ),
                mock.patch.object(
                    validate_channel_candidates,
                    "_validate_schema",
                ),
            ):
                with self.assertRaisesRegex(
                    validate_channel_candidates.CandidateValidationError,
                    "channel candidates",
                ):
                    validate_channel_candidates.validate_channel_candidates(
                        root, schemas
                    )

    def test_bootstrap_release_has_no_candidate_payload(self) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _ = (root / "release-manifest.json").write_text(
                '{"profile":"repository-bootstrap"}', encoding="utf-8"
            )

            with (
                mock.patch.object(
                    validate_channel_candidates,
                    "_load_schema",
                    return_value={},
                ),
                mock.patch.object(
                    validate_channel_candidates,
                    "_validate_schema",
                ),
            ):
                validate_channel_candidates.validate_channel_candidates(root, schemas)

            _ = (root / "bucket/context-engine.json").parent.mkdir()
            _ = (root / "bucket/context-engine.json").write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(
                    validate_channel_candidates,
                    "_load_schema",
                    return_value={},
                ),
                mock.patch.object(
                    validate_channel_candidates,
                    "_validate_schema",
                ),
            ):
                with self.assertRaises(
                    validate_channel_candidates.CandidateValidationError
                ):
                    validate_channel_candidates.validate_channel_candidates(
                        root, schemas
                    )

    def test_bootstrap_release_rejects_broken_candidate_symlink(self) -> None:
        schemas = Path(__file__).parents[2] / "schemas"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _ = (root / "release-manifest.json").write_text(
                '{"profile":"repository-bootstrap"}', encoding="utf-8"
            )
            bucket = root / "bucket"
            bucket.mkdir()
            (bucket / "context-engine.json").symlink_to("missing.json")
            with (
                mock.patch.object(
                    validate_channel_candidates,
                    "_load_schema",
                    return_value={},
                ),
                mock.patch.object(
                    validate_channel_candidates,
                    "_validate_schema",
                ),
            ):
                with self.assertRaisesRegex(
                    validate_channel_candidates.CandidateValidationError,
                    "must not contain channel candidates",
                ):
                    validate_channel_candidates.validate_channel_candidates(
                        root, schemas
                    )


if __name__ == "__main__":
    _ = unittest.main()
