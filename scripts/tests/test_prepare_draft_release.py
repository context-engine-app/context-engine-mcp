from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import cast

from scripts import prepare_draft_release as MODULE


NAMES = tuple(
    sorted(
        (
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "channel-candidates.json",
            "channel-candidates.tar.gz",
            "context-engine-aarch64-apple-darwin.cdx.json",
            "context-engine-aarch64-apple-darwin.tar.gz",
            "context-engine-release.cdx.json",
            "context-engine-x86_64-apple-darwin.cdx.json",
            "context-engine-x86_64-apple-darwin.tar.gz",
            "context-engine-x86_64-pc-windows-msvc.cdx.json",
            "context-engine-x86_64-pc-windows-msvc.zip",
            "release-manifest.json",
            "release-provenance.json",
            "SHA256SUMS",
            "SHA256SUMS.sigstore.json",
        )
    )
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _plan() -> dict[str, object]:
    assets = [
        {
            "name": name,
            "sha256": _sha(f"asset:{name}".encode()),
            "size": len(f"asset:{name}".encode()),
        }
        for name in NAMES
    ]
    canonical_asset_facts = [
        {
            "filename": asset["name"],
            "sha256": asset["sha256"],
            "size": asset["size"],
        }
        for asset in assets
    ]
    release_asset_set_sha256 = _sha(
        json.dumps(
            canonical_asset_facts,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    return {
        "schema_version": 1,
        "profile": "desktop",
        "tag": "v1.2.3",
        "version": "1.2.3",
        "source_repository": "context-engine-app/context-engine",
        "source_commit": "a" * 40,
        "distribution_repository": "context-engine-app/context-engine-mcp",
        "distribution_commit": "b" * 40,
        "distribution_tag_target": "b" * 40,
        "release_asset_set_sha256": release_asset_set_sha256,
        "staging_attestation_sha256": _sha(b"attestation"),
        "source_workflow": {
            "path": ".github/workflows/release.yml",
            "commit": "a" * 40,
            "sha256": "c" * 64,
        },
        "public_workflow": {
            "path": ".github/workflows/prepare-draft-release.yml",
            "commit": "b" * 40,
            "sha256": "d" * 64,
        },
        "source_run": {
            "id": 12,
            "attempt": 2,
            "url": "https://github.com/context-engine-app/context-engine/actions/runs/12",
        },
        "assets": assets,
    }


def _plan_for_profile(profile: str) -> dict[str, object]:
    plan = _plan()
    plan["profile"] = profile
    plan["tag"] = (
        "repository-bootstrap-v1.2.3" if profile == "repository-bootstrap" else "v1.2.3"
    )
    if profile == "repository-bootstrap":
        asset_values: list[object] = [
            asset
            for asset in cast(list[object], plan["assets"])
            if cast(Mapping[str, object], asset)["name"]
            not in {"channel-candidates.json", "channel-candidates.tar.gz"}
        ]
    elif profile == "desktop-linux":
        asset_values = cast(list[object], plan["assets"]) + [
            {
                "name": "context-engine-x86_64-unknown-linux-gnu.tar.gz",
                "sha256": _sha(b"asset:context-engine-x86_64-unknown-linux-gnu.tar.gz"),
                "size": len(b"asset:context-engine-x86_64-unknown-linux-gnu.tar.gz"),
            }
        ]
    else:
        asset_values = cast(list[object], plan["assets"])
    assets = sorted(
        asset_values,
        key=lambda item: cast(str, cast(Mapping[str, object], item)["name"]),
    )
    plan["assets"] = assets
    canonical_asset_facts: list[dict[str, object]] = []
    for asset in assets:
        asset_mapping = cast(Mapping[str, object], asset)
        canonical_asset_facts.append(
            {
                "filename": asset_mapping["name"],
                "sha256": asset_mapping["sha256"],
                "size": asset_mapping["size"],
            }
        )
    plan["release_asset_set_sha256"] = _sha(
        json.dumps(
            canonical_asset_facts,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    return plan


def _staged(root: Path, plan: Mapping[str, object]) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    raw_assets = cast(list[object], plan["assets"])
    for asset_value in raw_assets:
        asset = cast(Mapping[str, object], asset_value)
        name = cast(str, asset["name"])
        content = f"asset:{name}".encode()
        _ = (root / name).write_bytes(content)
        contents[name] = content
    attestation = b"attestation"
    _ = (root / "staging-attestation.json").write_bytes(attestation)
    _ = (root / "staging-attestation.sigstore.json").write_bytes(b"bundle")
    return contents


def _manifest_bytes(plan: MODULE.ValidatedPlan) -> bytes:
    artifact_names = sorted(
        plan.asset_names()
        - MODULE.RELEASE_DOCUMENT_NAMES
        - MODULE.CHECKSUM_NAMES
        - MODULE.CANDIDATE_NAMES
    )
    return json.dumps(
        {
            "profile": plan.profile,
            "version": plan.version,
            "tag": plan.tag,
            "artifacts": [{"filename": name} for name in artifact_names],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Mapping[str, str] | None, bytes | None]] = []
        self.release: dict[str, object] | None = None
        self.assets: dict[str, tuple[int, bytes]] = {}
        self.next_id: int = 100
        self.failures: dict[tuple[str, str], list[Exception]] = {}
        self.fail_after_create: bool = False
        self.create_attempts: int = 0
        self.fail_after_upload: bool = False
        self.upload_attempts: int = 0
        self.fail_after_patch: bool = False
        self.patch_attempts: int = 0
        self.asset_states: dict[str, str] = {}
        self.asset_digest_overrides: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> MODULE.Response:
        del headers
        self.calls.append((method, path, query, body))
        key = (method, path)
        failures = self.failures.get(key)
        if failures:
            failure = failures.pop(0)
            raise failure
        if method == "GET" and "/releases/tags/" in path:
            if self.release is None:
                return MODULE.Response(404, {}, b"{}")
            return MODULE.Response(200, {}, json.dumps(self.release).encode())
        if (
            method == "GET"
            and "/releases/" in path
            and "/assets/" not in path
            and path.rsplit("/", 1)[-1].isdigit()
        ):
            if self.release is None:
                return MODULE.Response(404, {}, b"{}")
            return MODULE.Response(200, {}, json.dumps(self.release).encode())
        if method == "POST" and path.endswith("/releases"):
            data = cast(
                dict[str, object], MODULE.parse_json(body or b"{}", "fake request")
            )
            self.create_attempts += 1
            self.release = {
                "id": 1,
                "tag_name": data["tag_name"],
                "name": data["name"],
                "target_commitish": data["target_commitish"],
                "draft": True,
                "immutable": False,
                "published_at": None,
                "prerelease": False,
                "body": data["body"],
                "assets": [],
            }
            response = MODULE.Response(201, {}, json.dumps(self.release).encode())
            if self.fail_after_create and self.create_attempts == 1:
                raise MODULE.TransportError(
                    "connection lost after create", ambiguous=True
                )
            return response
        if method == "GET" and path.endswith("/assets"):
            rows: list[dict[str, object]] = []
            for name, (asset_id, content) in self.assets.items():
                rows.append(
                    {
                        "id": asset_id,
                        "name": name,
                        "size": len(content),
                        "state": self.asset_states.get(name, "uploaded"),
                        "digest": self.asset_digest_overrides.get(
                            name, f"sha256:{_sha(content)}"
                        ),
                    }
                )
            return MODULE.Response(
                200,
                {},
                json.dumps(rows).encode(),
            )
        if method == "POST" and path.endswith("/assets"):
            assert query is not None
            name = query["name"]
            self.upload_attempts += 1
            if name in self.assets:
                return MODULE.Response(422, {}, b"duplicate")
            asset_id = self.next_id
            self.next_id += 1
            self.assets[name] = (asset_id, body or b"")
            response = MODULE.Response(
                201, {}, json.dumps({"id": asset_id, "name": name}).encode()
            )
            if self.fail_after_upload and self.upload_attempts == 1:
                raise MODULE.TransportError(
                    "connection lost after upload", ambiguous=True
                )
            return response
        if method == "GET" and "/releases/assets/" in path:
            asset_id = int(path.rsplit("/", 1)[1])
            for current_id, content in self.assets.values():
                if current_id == asset_id:
                    return MODULE.Response(200, {}, content)
            return MODULE.Response(404, {}, b"missing")
        if method == "PATCH" and "/releases/" in path:
            assert self.release is not None
            data = cast(
                dict[str, object], MODULE.parse_json(body or b"{}", "fake patch")
            )
            self.patch_attempts += 1
            self.release.update(data)
            response = MODULE.Response(200, {}, json.dumps(self.release).encode())
            if self.fail_after_patch and self.patch_attempts == 1:
                raise MODULE.TransportError(
                    "connection lost after patch", ambiguous=True
                )
            return response
        raise AssertionError((method, path))


def _verified_transport(
    plan: MODULE.ValidatedPlan, *, visible_prefix: str = MODULE.VISIBLE_RELEASE_LINE
) -> FakeTransport:
    transport = FakeTransport()
    marker = MODULE.marker_metadata(
        plan,
        artifact_id=7,
        artifact_digest="sha256:" + "e" * 64,
        artifact_expires_at="2099-01-01T00:00:00Z",
        state="verified",
        verified_run_id=55,
        verified_run_attempt=1,
    )
    transport.release = {
        "id": 1,
        "tag_name": plan.tag,
        "name": plan.tag,
        "target_commitish": plan.distribution_commit,
        "draft": True,
        "immutable": False,
        "published_at": None,
        "prerelease": False,
        "body": MODULE.render_body(marker, visible_prefix=visible_prefix),
    }
    for name in NAMES:
        content = (
            _manifest_bytes(plan)
            if name == "release-manifest.json"
            else f"asset:{name}".encode()
        )
        transport.assets[name] = (transport.next_id, content)
        transport.next_id += 1
    return transport


def _preparing_transport(
    plan: MODULE.ValidatedPlan, *, content: bytes | None = None
) -> FakeTransport:
    transport = FakeTransport()
    transport.release = {
        "id": 1,
        "tag_name": plan.tag,
        "name": plan.tag,
        "target_commitish": plan.distribution_commit,
        "draft": True,
        "immutable": False,
        "published_at": None,
        "prerelease": False,
        "body": MODULE.render_body(
            MODULE.marker_metadata(
                plan,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2099-01-01T00:00:00Z",
                state="preparing",
            )
        ),
    }
    name = NAMES[0]
    transport.assets[name] = (
        transport.next_id,
        f"asset:{name}".encode() if content is None else content,
    )
    transport.next_id += 1
    return transport


class CoordinatorTests(unittest.TestCase):
    def test_plan_accepts_all_profiles_and_rejects_cross_profile_tags(self) -> None:
        for profile in ("desktop", "desktop-linux", "repository-bootstrap"):
            with self.subTest(profile=profile):
                plan = MODULE.ValidatedPlan.from_mapping(_plan_for_profile(profile))
                self.assertEqual(plan.profile, profile)
        for profile, tag in (
            ("desktop", "repository-bootstrap-v1.2.3"),
            ("desktop-linux", "repository-bootstrap-v1.2.3"),
            ("repository-bootstrap", "v1.2.3"),
            ("desktop", "v01.2.3"),
        ):
            with self.subTest(profile=profile, tag=tag):
                invalid = _plan_for_profile(profile)
                invalid["tag"] = tag
                with self.assertRaises(MODULE.PlanError):
                    _ = MODULE.ValidatedPlan.from_mapping(invalid)

    def test_plan_rejects_profile_incompatible_candidate_closure(self) -> None:
        bootstrap = _plan_for_profile("repository-bootstrap")
        bootstrap["assets"] = cast(list[object], _plan()["assets"])
        bootstrap["release_asset_set_sha256"] = _sha(
            json.dumps(
                bootstrap["assets"],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        with self.assertRaises(MODULE.PlanError):
            _ = MODULE.ValidatedPlan.from_mapping(bootstrap)

    def test_plan_requires_core_assets_and_safe_flat_names(self) -> None:
        for mutation in ("missing-core", "traversal", "control"):
            with self.subTest(mutation=mutation):
                invalid = _plan_for_profile("desktop")
                assets = cast(list[object], invalid["assets"])
                if mutation == "missing-core":
                    assets = [
                        asset
                        for asset in assets
                        if cast(Mapping[str, object], asset)["name"]
                        != "release-manifest.json"
                    ]
                else:
                    replacement = (
                        "../escape" if mutation == "traversal" else "bad\x7fname"
                    )
                    assets = [
                        {
                            **cast(Mapping[str, object], asset),
                            "name": replacement,
                        }
                        if index == 0
                        else asset
                        for index, asset in enumerate(assets)
                    ]
                assets = sorted(
                    assets,
                    key=lambda item: cast(
                        str, cast(Mapping[str, object], item)["name"]
                    ),
                )
                invalid["assets"] = assets
                invalid["release_asset_set_sha256"] = _sha(
                    json.dumps(
                        assets,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                )
                with self.assertRaises(MODULE.PlanError):
                    _ = MODULE.ValidatedPlan.from_mapping(invalid)

    def test_manifest_asset_names_reject_traversal_and_control_bytes(self) -> None:
        coordinator = MODULE.DraftReleaseCoordinator(
            FakeTransport(), repository=MODULE.PUBLIC_RELEASE_REPOSITORY
        )
        manifest_asset_names = cast(
            Callable[[bytes, str], tuple[str, set[str]]],
            getattr(coordinator, "_manifest_asset_names"),
        )
        for name in ("../escape", "bad\nname", "bad\x7fname", ""):
            with self.subTest(name=repr(name)):
                raw = json.dumps(
                    {
                        "profile": "desktop",
                        "version": "1.2.3",
                        "tag": "v1.2.3",
                        "artifacts": [{"filename": name}],
                    }
                ).encode()
                with self.assertRaises(MODULE.ReleaseMismatchError):
                    _ = manifest_asset_names(raw, "v1.2.3")
        for artifacts in (
            [{"filename": "artifact.bin"}, {"filename": "artifact.bin"}],
            [{"filename": "release-manifest.json"}],
        ):
            with self.subTest(artifacts=artifacts):
                raw = json.dumps(
                    {
                        "profile": "desktop",
                        "version": "1.2.3",
                        "tag": "v1.2.3",
                        "artifacts": artifacts,
                    }
                ).encode()
                with self.assertRaises(MODULE.ReleaseMismatchError):
                    _ = manifest_asset_names(raw, "v1.2.3")
        raw = _manifest_bytes(MODULE.ValidatedPlan.from_mapping(_plan()))
        for tag in ("v01.2.3", "not-a-release-tag"):
            with self.subTest(tag=tag):
                with self.assertRaises(MODULE.ReleaseMismatchError):
                    _ = manifest_asset_names(raw, tag)
        mismatched_manifest = cast(dict[str, object], json.loads(raw))
        mismatched_manifest["tag"] = "v9.9.9"
        with self.assertRaises(MODULE.ReleaseMismatchError):
            _ = manifest_asset_names(json.dumps(mismatched_manifest).encode(), "v1.2.3")

    def test_plan_and_marker_are_canonical(self) -> None:
        plan = MODULE.ValidatedPlan.from_mapping(_plan())
        marker = MODULE.marker_metadata(
            plan,
            artifact_id=7,
            artifact_digest="sha256:" + "e" * 64,
            artifact_expires_at="2099-01-01T00:00:00Z",
            state="preparing",
        )
        self.assertEqual(tuple(marker), MODULE.MARKER_KEYS)
        self.assertEqual(marker["verified_run_id"], None)
        body = MODULE.render_body(marker)
        self.assertIn("Release notes will be added manually before publication.", body)
        self.assertEqual(body.count("context-engine-draft:v1"), 1)
        self.assertEqual(MODULE.parse_marker_body(body), marker)

    def test_plan_contract_rejects_wrong_bindings_and_duplicate_keys(self) -> None:
        plan_data = _plan()
        invalid_plans: list[dict[str, object]] = []
        for field, value in (
            ("source_repository", "example/source"),
            ("distribution_repository", "example/distribution"),
            (
                "source_workflow",
                {
                    "path": "wrong.yml",
                    "commit": "a" * 40,
                    "sha256": "c" * 64,
                },
            ),
            (
                "public_workflow",
                {
                    "path": "wrong-public.yml",
                    "commit": "b" * 40,
                    "sha256": "d" * 64,
                },
            ),
            (
                "source_run",
                {
                    "id": 12,
                    "attempt": 2,
                    "url": "https://github.com/example/source/actions/runs/12",
                },
            ),
        ):
            invalid = deepcopy(plan_data)
            invalid[field] = value
            invalid_plans.append(invalid)
        for invalid in invalid_plans:
            with self.assertRaises(MODULE.PlanError):
                _ = MODULE.ValidatedPlan.from_mapping(invalid)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            _ = path.write_text(
                '{"schema_version":1,"schema_version":1}', encoding="utf-8"
            )
            with self.assertRaises(MODULE.PlanError):
                _ = MODULE.ValidatedPlan.from_file(path)

    def test_prepare_creates_only_missing_assets_and_verifies(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            contents = _staged(staged, plan_data)
            transport = FakeTransport()
            result = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            ).prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2099-01-01T00:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
        self.assertEqual(result["state"], "verified")
        self.assertFalse(result["read_only"])
        self.assertEqual(
            sum(
                call[0] == "POST" and call[1].endswith("/assets")
                for call in transport.calls
            ),
            len(NAMES),
        )
        self.assertNotIn("DELETE", {call[0] for call in transport.calls})
        self.assertNotIn("?clobber=true", {call[1] for call in transport.calls})
        self.assertEqual(len(contents), len(NAMES))

    def test_staged_symlink_is_rejected_before_mutation(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            symlink = staged / NAMES[0]
            _ = symlink.unlink()
            symlink.symlink_to(staged / NAMES[1])
            transport = FakeTransport()
            coordinator = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            )
            with self.assertRaises(MODULE.PlanError):
                _ = coordinator.prepare(
                    plan,
                    staged,
                    artifact_id=7,
                    artifact_digest="sha256:" + "e" * 64,
                    artifact_expires_at="2099-01-01T00:00:00Z",
                    public_run_id=88,
                    public_run_attempt=1,
                )
        self.assertEqual(transport.calls, [])

    def test_existing_preparing_assets_are_compared_and_resume_uploads_missing(
        self,
    ) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            transport.release = {
                "id": 1,
                "tag_name": plan.tag,
                "name": plan.tag,
                "target_commitish": plan.distribution_commit,
                "draft": True,
                "immutable": False,
                "published_at": None,
                "prerelease": False,
                "body": MODULE.render_body(
                    MODULE.marker_metadata(
                        plan,
                        artifact_id=7,
                        artifact_digest="sha256:" + "e" * 64,
                        artifact_expires_at="2099-01-01T00:00:00Z",
                        state="preparing",
                    )
                ),
            }
            for name in NAMES[:3]:
                transport.assets[name] = (transport.next_id, f"asset:{name}".encode())
                transport.next_id += 1
            _ = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            ).prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2099-01-01T00:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
        uploads = [
            call
            for call in transport.calls
            if call[0] == "POST" and call[1].endswith("/assets")
        ]
        self.assertEqual(len(uploads), 12)

    def test_existing_asset_bytes_metadata_and_state_fail_without_clobber(self) -> None:
        plan = MODULE.ValidatedPlan.from_mapping(_plan())
        name = NAMES[0]
        expected = f"asset:{name}".encode()
        for mismatch in ("bytes", "size", "digest", "state"):
            with (
                self.subTest(mismatch=mismatch),
                tempfile.TemporaryDirectory() as directory,
            ):
                staged = Path(directory)
                _ = _staged(staged, _plan())
                content = expected
                transport = _preparing_transport(plan, content=content)
                if mismatch == "bytes":
                    transport.assets[name] = (
                        transport.assets[name][0],
                        b"x" * len(expected),
                    )
                    transport.asset_digest_overrides[name] = f"sha256:{_sha(expected)}"
                elif mismatch == "size":
                    transport.assets[name] = (
                        transport.assets[name][0],
                        expected + b"x",
                    )
                elif mismatch == "digest":
                    transport.asset_digest_overrides[name] = "sha256:" + "f" * 64
                else:
                    transport.asset_states[name] = "pending"
                coordinator = MODULE.DraftReleaseCoordinator(
                    transport,
                    repository=plan.distribution_repository,
                    now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                    sleep=lambda _: None,
                )
                with self.assertRaises(MODULE.ReleaseMismatchError):
                    _ = coordinator.prepare(
                        plan,
                        staged,
                        artifact_id=7,
                        artifact_digest="sha256:" + "e" * 64,
                        artifact_expires_at="2099-01-01T00:00:00Z",
                        public_run_id=88,
                        public_run_attempt=1,
                    )
                self.assertFalse(
                    any(
                        call[0] == "POST" and call[1].endswith("/assets")
                        for call in transport.calls
                    )
                )

    def test_verified_rerun_is_read_only(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            marker = MODULE.marker_metadata(
                plan,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2020-01-01T00:00:00Z",
                state="verified",
                verified_run_id=55,
                verified_run_attempt=1,
            )
            transport.release = {
                "id": 1,
                "tag_name": plan.tag,
                "name": plan.tag,
                "target_commitish": plan.distribution_commit,
                "draft": True,
                "immutable": False,
                "published_at": None,
                "prerelease": False,
                "body": MODULE.render_body(marker),
            }
            for name in NAMES:
                transport.assets[name] = (transport.next_id, f"asset:{name}".encode())
                transport.next_id += 1
            result = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2090-01-01T00:00:00Z"),
                sleep=lambda _: None,
            ).prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2020-01-01T00:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
        self.assertEqual(result["state"], "verified")
        self.assertTrue(result["read_only"])
        self.assertNotIn("POST", {call[0] for call in transport.calls})
        self.assertNotIn("PATCH", {call[0] for call in transport.calls})

    def test_inspect_requires_target_and_accepts_manual_verified_prefix(self) -> None:
        plan = MODULE.ValidatedPlan.from_mapping(_plan())
        for missing_target in (True, False):
            transport = _verified_transport(
                plan, visible_prefix="## Manually authored release notes"
            )
            assert transport.release is not None
            if missing_target:
                _ = transport.release.pop("target_commitish")
            else:
                transport.release["target_commitish"] = "c" * 40
            coordinator = MODULE.DraftReleaseCoordinator(
                transport, repository=plan.distribution_repository
            )
            with self.assertRaises(MODULE.ReleaseMismatchError):
                _ = coordinator.inspect(plan.tag)

        transport = _verified_transport(
            plan, visible_prefix="## Manually authored release notes"
        )
        result = MODULE.DraftReleaseCoordinator(
            transport, repository=plan.distribution_repository
        ).inspect(plan.tag)
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["read_only"])
        marker = cast(Mapping[str, object], result["marker"])
        self.assertEqual(marker["state"], "verified")
        self.assertNotIn("POST", {call[0] for call in transport.calls})
        self.assertNotIn("PATCH", {call[0] for call in transport.calls})

    def test_published_and_unexpected_assets_are_rejected(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            transport.release = {
                "id": 1,
                "tag_name": plan.tag,
                "name": plan.tag,
                "target_commitish": plan.distribution_commit,
                "draft": False,
                "immutable": False,
                "published_at": "2025-01-02T00:00:00Z",
                "prerelease": False,
                "body": "published",
            }
            coordinator = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            )
            with self.assertRaises(MODULE.PublishedReleaseError):
                _ = coordinator.prepare(
                    plan,
                    staged,
                    artifact_id=7,
                    artifact_digest="sha256:" + "e" * 64,
                    artifact_expires_at="2099-01-01T00:00:00Z",
                    public_run_id=88,
                    public_run_attempt=1,
                )

            transport.release["draft"] = True
            transport.release["body"] = MODULE.render_body(
                MODULE.marker_metadata(
                    plan,
                    artifact_id=7,
                    artifact_digest="sha256:" + "e" * 64,
                    artifact_expires_at="2099-01-01T00:00:00Z",
                    state="preparing",
                )
            )
            transport.assets["unexpected.bin"] = (9, b"unexpected")
            with self.assertRaises(MODULE.ReleaseMismatchError):
                _ = coordinator.prepare(
                    plan,
                    staged,
                    artifact_id=7,
                    artifact_digest="sha256:" + "e" * 64,
                    artifact_expires_at="2099-01-01T00:00:00Z",
                    public_run_id=88,
                    public_run_attempt=1,
                )

    def test_ambiguous_create_is_reconciled_without_second_create(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            transport.fail_after_create = True
            result = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            ).prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2099-01-01T00:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
        self.assertEqual(result["state"], "verified")
        self.assertEqual(transport.create_attempts, 1)

    def test_mutation_statuses_fail_closed_and_ambiguous_outcomes_reconcile(
        self,
    ) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        release_path = f"/repos/{plan.distribution_repository}/releases"
        for status in (401, 403, 404):
            with (
                self.subTest(status=status),
                tempfile.TemporaryDirectory() as directory,
            ):
                staged = Path(directory)
                _ = _staged(staged, plan_data)
                transport = FakeTransport()
                transport.failures[("POST", release_path)] = [
                    MODULE.HttpError(status, ambiguous=False)
                ]
                coordinator = MODULE.DraftReleaseCoordinator(
                    transport,
                    repository=plan.distribution_repository,
                    now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                    sleep=lambda _: None,
                )
                with self.assertRaises(MODULE.HttpError):
                    _ = coordinator.prepare(
                        plan,
                        staged,
                        artifact_id=7,
                        artifact_digest="sha256:" + "e" * 64,
                        artifact_expires_at="2099-01-01T00:00:00Z",
                        public_run_id=88,
                        public_run_attempt=1,
                    )
                self.assertEqual(
                    sum(
                        call[0] == "POST" and call[1] == release_path
                        for call in transport.calls
                    ),
                    1,
                )
                self.assertFalse(any(call[0] == "PATCH" for call in transport.calls))

        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            transport.fail_after_upload = True
            result = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            ).prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2099-01-01T00:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
        self.assertEqual(result["state"], "verified")
        self.assertEqual(transport.upload_attempts, len(NAMES))

        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            transport.fail_after_patch = True
            result = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2025-01-01T00:00:00Z"),
                sleep=lambda _: None,
            ).prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2099-01-01T00:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
        self.assertEqual(result["state"], "verified")
        self.assertEqual(transport.patch_attempts, 1)

    def test_expiry_stops_before_create(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            transport = FakeTransport()
            coordinator = MODULE.DraftReleaseCoordinator(
                transport,
                repository=plan.distribution_repository,
                now=lambda: MODULE.parse_timestamp("2099-01-01T00:00:00Z"),
                sleep=lambda _: None,
            )
            with self.assertRaises(MODULE.ExpiredArtifactError):
                _ = coordinator.prepare(
                    plan,
                    staged,
                    artifact_id=7,
                    artifact_digest="sha256:" + "e" * 64,
                    artifact_expires_at="2098-01-01T00:00:00Z",
                    public_run_id=88,
                    public_run_attempt=1,
                )
        self.assertFalse(any(call[0] in {"POST", "PATCH"} for call in transport.calls))

    def test_mutation_window_accepts_exact_boundary_and_rejects_shorter(self) -> None:
        plan_data = _plan()
        plan = MODULE.ValidatedPlan.from_mapping(plan_data)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            _ = _staged(staged, plan_data)
            now = datetime.fromisoformat("2025-01-01T00:00:00+00:00")
            coordinator = MODULE.DraftReleaseCoordinator(
                FakeTransport(),
                repository=plan.distribution_repository,
                now=lambda: now,
                sleep=lambda _: None,
            )
            result = coordinator.prepare(
                plan,
                staged,
                artifact_id=7,
                artifact_digest="sha256:" + "e" * 64,
                artifact_expires_at="2025-01-01T01:00:00Z",
                public_run_id=88,
                public_run_attempt=1,
            )
            self.assertEqual(result["state"], "verified")

            short_coordinator_transport = FakeTransport()
            short_coordinator = MODULE.DraftReleaseCoordinator(
                short_coordinator_transport,
                repository=plan.distribution_repository,
                now=lambda: now,
                sleep=lambda _: None,
            )
            with self.assertRaises(MODULE.ExpiredArtifactError):
                _ = short_coordinator.prepare(
                    plan,
                    staged,
                    artifact_id=7,
                    artifact_digest="sha256:" + "e" * 64,
                    artifact_expires_at="2025-01-01T00:59:59Z",
                    public_run_id=88,
                    public_run_attempt=1,
                )

    def test_allowlist_rejects_publish_delete_and_clobber_routes(self) -> None:
        for method, path in (
            ("DELETE", "/repos/context-engine-app/context-engine-mcp/releases/1"),
            ("POST", "/repos/context-engine-app/context-engine-mcp/releases/1/publish"),
            (
                "POST",
                "/repos/context-engine-app/context-engine-mcp/releases/1/assets/one",
            ),
        ):
            with self.assertRaises(MODULE.CoordinatorError):
                MODULE.assert_allowed_endpoint(method, path)


if __name__ == "__main__":
    _ = unittest.main()
