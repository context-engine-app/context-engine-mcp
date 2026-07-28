from __future__ import annotations

import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from unittest import mock

from scripts import prepare_package_channels as channels


def _response(status: int, value: object) -> channels.Response:
    return channels.Response(status=status, body=json.dumps(value).encode())


def _blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


class FakeTransport:
    """Small in-memory GitHub transport used to prove the mutation boundary."""

    def __init__(self, *, scoop: bool = True) -> None:
        self.calls: list[tuple[str, str]] = []
        self.scoop: bool = scoop
        self.default_sha: str = "a" * 40
        self.repository_full_name: str = "context-engine-app/homebrew-tap"
        self.repository_private: bool = False
        self.repository_disabled: bool = False
        self.repository_archived: bool = False
        self.branch_sha: dict[str, str] = {}
        self.prs: dict[str, dict[str, object]] = {}
        self.pull_details: dict[str, dict[str, object]] = {}
        self.files: dict[str, bytes] = {}
        self.extra_tree: bool = False
        self.tree_ancestors: bool = False
        self.truncated_tree: bool = False
        self.wrap_content: bool = False
        self.wrap_separator: str = "\n"
        self.invalid_content: bool = False
        self.content_type: str = "file"
        self.content_encoding: str = "base64"
        self.merged_data: bytes | None = None
        self.merged_content_type: str = "file"
        self.merged_content_encoding: str = "base64"

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> channels.Response:
        del headers
        self.calls.append(
            (method, path + ("?" + json.dumps(query, sort_keys=True) if query else ""))
        )
        if path.endswith("homebrew-tap"):
            return _response(
                200,
                {
                    "full_name": self.repository_full_name,
                    "private": self.repository_private,
                    "disabled": self.repository_disabled,
                    "archived": self.repository_archived,
                    "default_branch": "main",
                },
            )
        if path.endswith("scoop-bucket"):
            if not self.scoop:
                return _response(404, {"message": "Not Found"})
            return _response(
                200,
                {
                    "full_name": "context-engine-app/scoop-bucket",
                    "private": self.repository_private,
                    "disabled": self.repository_disabled,
                    "archived": self.repository_archived,
                    "default_branch": "main",
                },
            )
        if path.endswith("/git/ref/heads/main"):
            return _response(200, {"object": {"sha": self.default_sha}})
        if "/git/ref/heads/automation/context-engine-v1.2.3" in path:
            branch = path.split("/git/ref/heads/", 1)[1]
            if branch not in self.branch_sha:
                return _response(404, {"message": "Not Found"})
            return _response(200, {"object": {"sha": self.branch_sha[branch]}})
        if method == "GET" and path.endswith("/pulls"):
            key = "scoop" if "scoop-bucket" in path else "homebrew-tap"
            pull = self.prs.get(key)
            return _response(200, [] if pull is None else [pull])
        if method == "GET" and "/pulls/" in path:
            key = "scoop" if "scoop-bucket" in path else "homebrew-tap"
            pull = self.pull_details.get(key, self.prs.get(key))
            return _response(200, pull) if pull is not None else _response(404, {})
        if method == "GET" and "/git/commits/" in path:
            commit = path.rsplit("/", 1)[-1]
            if commit == "c" * 40:
                return _response(
                    200,
                    {"parents": [{"sha": self.default_sha}], "tree": {"sha": "d" * 40}},
                )
            if commit == self.default_sha:
                return _response(200, {"parents": [], "tree": {"sha": "e" * 40}})
        if method == "GET" and "/git/trees/" in path:
            tree = path.rsplit("/", 1)[-1]
            if tree == "e" * 40:
                return _response(200, {"tree": []})
            if tree == "d" * 40:
                destination_path = (
                    "Formula/context-engine.rb"
                    if "homebrew-tap" in path
                    else "bucket/context-engine.json"
                )
                data = (
                    b"class Formula\n"
                    if destination_path.startswith("Formula")
                    else b'{"version":"1.2.3"}\n'
                )
                entries: list[dict[str, object]] = [
                    {
                        "path": destination_path,
                        "mode": "100644",
                        "type": "blob",
                        "sha": _blob_sha(data),
                    }
                ]
                if self.extra_tree:
                    entries.append(
                        {
                            "path": "README.md",
                            "mode": "100644",
                            "type": "blob",
                            "sha": "f" * 40,
                        }
                    )
                if self.tree_ancestors:
                    entries.insert(
                        0,
                        {
                            "path": destination_path.split("/", 1)[0],
                            "mode": "040000",
                            "type": "tree",
                            "sha": ("b" * 40 if tree == "d" * 40 else "a" * 40),
                        },
                    )
                return _response(
                    200, {"tree": entries, "truncated": self.truncated_tree}
                )
        if method == "GET" and (
            path.endswith("/contents/README.md")
            or path.endswith("/contents/.github/workflows/test.yml")
        ):
            return _response(
                200,
                {
                    "type": "file",
                    "encoding": "base64",
                    "content": "",
                    "sha": "b" * 40,
                },
            )
        if method == "GET" and "/contents/" in path:
            candidate_path = path.split("/contents/", 1)[1]
            is_merged_read = query is not None and query.get("ref") == "main"
            if is_merged_read and self.merged_data is not None:
                data = self.merged_data
                content_type = self.merged_content_type
                content_encoding = self.merged_content_encoding
            elif candidate_path in self.files:
                data = self.files[candidate_path]
                content_type = self.content_type
                content_encoding = self.content_encoding
            else:
                return _response(404, {"message": "Not Found"})
            encoded = base64.b64encode(data).decode()
            if self.wrap_content:
                encoded = self.wrap_separator.join(
                    encoded[index : index + 4] for index in range(0, len(encoded), 4)
                )
            if self.invalid_content:
                encoded = encoded[:-1] + "!"
            return _response(
                200,
                {
                    "type": content_type,
                    "encoding": content_encoding,
                    "content": encoded,
                    "sha": hashlib.sha1(data).hexdigest(),
                },
            )
        if method == "POST" and path.endswith("/git/blobs"):
            value = cast(dict[str, object], json.loads(cast(bytes, body)))
            data = base64.b64decode(cast(str, value["content"]))
            return _response(201, {"sha": _blob_sha(data)})
        if method == "POST" and path.endswith("/git/trees"):
            return _response(201, {"sha": "b" * 40})
        if method == "POST" and path.endswith("/git/commits"):
            return _response(201, {"sha": "c" * 40})
        if method == "POST" and path.endswith("/git/refs"):
            self.branch_sha["automation/context-engine-v1.2.3"] = "c" * 40
            return _response(
                201, {"ref": "refs/heads/automation/context-engine-v1.2.3"}
            )
        if method == "POST" and path.endswith("/pulls"):
            value = cast(dict[str, object], json.loads(cast(bytes, body)))
            pull = {
                "number": 7,
                "state": "open",
                "title": value["title"],
                "body": value["body"],
                "head": {
                    "ref": "automation/context-engine-v1.2.3",
                    "sha": self.branch_sha.get(
                        "automation/context-engine-v1.2.3", "c" * 40
                    ),
                },
            }
            self.prs["scoop" if "scoop-bucket" in path else "homebrew-tap"] = pull
            return _response(201, pull)
        raise AssertionError(f"unexpected API request: {method} {path}")


class PublicPreflightTransport:
    """Public unauthenticated transport fixture for destination preflight."""

    def __init__(self, *, scoop: bool = True) -> None:
        self.calls: list[tuple[str, str, Mapping[str, str] | None]] = []
        self.scoop: bool = scoop
        self.default_sha: str = "a" * 40
        self.bootstrap_sha: str = "b" * 40
        self.repository_full_name: str = "context-engine-app/homebrew-tap"
        self.repository_private: bool = False
        self.repository_disabled: bool = False
        self.repository_archived: bool = False
        self.candidate_data: dict[str, bytes] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> channels.Response:
        del headers, body
        self.calls.append((method, path, query))
        if path.endswith("homebrew-tap"):
            return _response(
                200,
                {
                    "full_name": self.repository_full_name,
                    "private": self.repository_private,
                    "disabled": self.repository_disabled,
                    "archived": self.repository_archived,
                    "default_branch": "main",
                },
            )
        if path.endswith("scoop-bucket"):
            if not self.scoop:
                return _response(404, {"message": "Not Found"})
            return _response(
                200,
                {
                    "full_name": "context-engine-app/scoop-bucket",
                    "private": self.repository_private,
                    "disabled": self.repository_disabled,
                    "archived": self.repository_archived,
                    "default_branch": "main",
                },
            )
        if path.endswith("/git/ref/heads/main"):
            return _response(200, {"object": {"sha": self.default_sha}})
        if (
            "/contents/README.md" in path
            or "/contents/.github/workflows/test.yml" in path
        ):
            return _response(
                200,
                {"type": "file", "sha": self.bootstrap_sha, "content": ""},
            )
        if "/contents/" in path:
            candidate_path = path.split("/contents/", 1)[1]
            if candidate_path in self.candidate_data:
                data = self.candidate_data[candidate_path]
                return _response(
                    200,
                    {
                        "type": "file",
                        "encoding": "base64",
                        "content": base64.b64encode(data).decode(),
                        "sha": hashlib.sha1(data).hexdigest(),
                    },
                )
            return _response(404, {"message": "Not Found"})
        raise AssertionError(f"unexpected preflight API request: {method} {path}")


class TestableChannelCoordinator(channels.ChannelCoordinator):
    """Expose one request path for validating the public mutation boundary."""

    def request_for_test(
        self,
        destination: str,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
    ) -> channels.Response:
        return self._request(destination, method, path, body=body)


def _candidate_root(directory: Path, *, profile: str = "desktop") -> Path:
    homebrew = b"class Formula\n"
    scoop = b'{"version":"1.2.3"}\n'
    files = {
        "Formula/context-engine.rb": homebrew,
        "bucket/context-engine.json": scoop,
    }
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
        with tarfile.open(
            fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            for path, data in files.items():
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    archive_bytes = output.getvalue()
    candidates: dict[str, object] = {
        "release_tag": "v1.2.3",
        "version": "1.2.3",
        "profile": profile,
        "source_manifest_sha256": "d" * 64,
        "candidates": [
            {
                "kind": "homebrew",
                "file_kind": "formula",
                "path": "Formula/context-engine.rb",
                "sha256": hashlib.sha256(homebrew).hexdigest(),
                "size": len(homebrew),
                "mode": "0644",
            },
            {
                "kind": "scoop",
                "file_kind": "manifest",
                "path": "bucket/context-engine.json",
                "sha256": hashlib.sha256(scoop).hexdigest(),
                "size": len(scoop),
                "mode": "0644",
            },
        ],
    }
    candidates["archive"] = {
        "path": "channel-candidates.tar.gz",
        "sha256": hashlib.sha256(archive_bytes).hexdigest(),
    }
    _ = (directory / "channel-candidates.json").write_text(
        json.dumps(candidates), encoding="utf-8"
    )
    _ = (directory / "channel-candidates.tar.gz").write_bytes(archive_bytes)
    return directory


class PackageChannelTests(unittest.TestCase):
    def test_desktop_linux_candidates_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary), profile="desktop-linux")
            candidates = channels.load_baseline_candidates(root, expected_tag="v1.2.3")
            self.assertEqual(candidates.profile, "desktop-linux")

    def test_repair_schema_is_canonical_private_contract(self) -> None:
        self.assertEqual(
            channels.CHANNEL_REPAIR_SCHEMA_SHA256,
            "5afe8a86eb580553d40158c9fa910cf6ad8f0cd88625673ecc3c3cb592201b26",
        )
        schema_path = (
            Path(__file__).parents[2] / "schemas" / "channel-repair.schema.json"
        )
        self.assertEqual(
            hashlib.sha256(schema_path.read_bytes()).hexdigest(),
            channels.CHANNEL_REPAIR_SCHEMA_SHA256,
        )

    def test_apply_cli_requires_anonymous_preflight_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                result = channels.main(
                    ["apply", "--tag", "v1.2.3", "--candidate-root", str(root)]
                )
            self.assertEqual(result, 1)
            self.assertIn("preflight plan is required", error.getvalue())

    def test_apply_cli_rejects_shared_token_without_scoped_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            plan = Path(temporary) / "preflight.json"
            _ = plan.write_text("{}", encoding="utf-8")
            error = io.StringIO()
            with mock.patch.dict(os.environ, {"GH_TOKEN": "shared"}, clear=False):
                _ = os.environ.pop("HOMEBREW_GH_TOKEN", None)
                _ = os.environ.pop("SCOOP_GH_TOKEN", None)
                with mock.patch.object(
                    channels.ChannelCoordinator,
                    "prepare",
                    return_value={"status": "prepared"},
                ):
                    with contextlib.redirect_stderr(error):
                        result = channels.main(
                            [
                                "apply",
                                "--tag",
                                "v1.2.3",
                                "--candidate-root",
                                str(root),
                                "--preflight-plan",
                                str(plan),
                            ]
                        )
            self.assertEqual(result, 1)
            self.assertIn("HOMEBREW_GH_TOKEN is required", error.getvalue())

    def test_nonbaseline_repair_requires_verified_generator_commit(self) -> None:
        data = b"baseline"
        digest = hashlib.sha256(data).hexdigest()
        baseline = channels.CandidateSet(
            "v1.2.3",
            "1.2.3",
            "desktop",
            "a" * 64,
            {
                "Formula/context-engine.rb": channels.CandidateFile(
                    "Formula/context-engine.rb", data, digest, len(data), "0644"
                )
            },
            {},
            {"source_commit": "b" * 40},
        )
        repair = {
            "release_tag": "v1.2.3",
            "version": "1.2.3",
            "destination": {
                "kind": "homebrew",
                "repository": "context-engine-app/homebrew-tap",
                "channel": "stable",
            },
            "baseline": {"path": "Formula/context-engine.rb", "sha256": digest},
            "replacement": {
                "path": "Formula/context-engine.rb",
                "sha256": "c" * 64,
            },
            "generator": {"release_source_commit": "b" * 40},
        }
        with self.assertRaisesRegex(
            channels.ChannelPlanError, "verified repair generator commit is required"
        ):
            channels.validate_locked_fields(repair, baseline, destination="homebrew")

    def test_binding_steps_have_read_token_before_github_api(self) -> None:
        workflow = (
            Path(__file__).parents[2]
            / ".github"
            / "workflows"
            / "prepare-package-channels.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(workflow.count("GH_TOKEN: ${{ github.token }}"), 2)
        self.assertIn(
            "repair_sha256=_sha256(repair_bytes)",
            Path(__file__)
            .parents[1]
            .joinpath("prepare_package_channels.py")
            .read_text(encoding="utf-8"),
        )

    def test_contents_api_wrapped_base64_is_decoded_strictly(self) -> None:
        data = b"class Formula\n"
        for separator in ("\n", "\r\n"):
            with self.subTest(separator=repr(separator)):
                desired = channels.CandidateFile(
                    "Formula/context-engine.rb",
                    data,
                    hashlib.sha256(data).hexdigest(),
                    len(data),
                    "0644",
                )
                transport = FakeTransport()
                transport.files[desired.path] = data
                transport.files["bucket/context-engine.json"] = b'{"version":"1.2.3"}\n'
                transport.wrap_content = True
                transport.wrap_separator = separator
                with tempfile.TemporaryDirectory() as temporary:
                    result = channels.ChannelCoordinator(transport).prepare(
                        tag="v1.2.3",
                        candidate_root=_candidate_root(Path(temporary)),
                    )
                destinations = cast(dict[str, object], result["destinations"])
                homebrew_result = cast(dict[str, object], destinations["homebrew"])
                self.assertEqual(homebrew_result["status"], "up-to-date")

    def test_endpoint_allowlist_rejects_cross_destination_candidate_paths(
        self,
    ) -> None:
        rejected = (
            (
                channels.DESTINATIONS["homebrew"],
                channels.CANDIDATE_PATHS["scoop"],
            ),
            (
                channels.DESTINATIONS["scoop"],
                channels.CANDIDATE_PATHS["homebrew"],
            ),
        )
        for repository, candidate_path in rejected:
            path = f"/repos/{repository}/contents/{candidate_path}"
            with self.subTest(repository=repository, path=path):
                with self.assertRaises(channels.ChannelMutationError):
                    channels.assert_allowed_endpoint(repository, "GET", path)

    def test_merged_pr_rejects_well_formed_wrong_candidate_bytes(self) -> None:
        transport = FakeTransport()
        transport.merged_data = b"class WrongFormula\n"
        transport.prs["homebrew-tap"] = {
            "number": 2,
            "state": "closed",
            "head": {"ref": "automation/context-engine-v1.2.3"},
        }
        transport.pull_details["homebrew-tap"] = {
            "number": 2,
            "state": "closed",
            "merged": True,
            "merged_at": "2026-07-26T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(channels.ChannelMutationError):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3",
                    candidate_root=_candidate_root(Path(temporary)),
                )

    def test_contents_api_malformed_base64_is_rejected(self) -> None:
        data = b"class Formula\n"
        desired = channels.CandidateFile(
            "Formula/context-engine.rb",
            data,
            hashlib.sha256(data).hexdigest(),
            len(data),
            "0644",
        )
        transport = FakeTransport()
        transport.files[desired.path] = data
        transport.invalid_content = True
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(channels.ChannelMutationError):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3", candidate_root=_candidate_root(Path(temporary))
                )

    def test_contents_api_requires_base64_encoding(self) -> None:
        data = b"class Formula\n"
        desired = channels.CandidateFile(
            "Formula/context-engine.rb",
            data,
            hashlib.sha256(data).hexdigest(),
            len(data),
            "0644",
        )
        transport = FakeTransport()
        transport.files[desired.path] = data
        transport.content_encoding = "utf-8"
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(channels.ChannelMutationError):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3", candidate_root=_candidate_root(Path(temporary))
                )

    def test_merged_contents_api_requires_regular_base64_file(self) -> None:
        data = b"class Formula\n"
        transport = FakeTransport()
        transport.merged_data = data
        transport.merged_content_type = "directory"
        transport.prs["homebrew-tap"] = {
            "number": 2,
            "state": "closed",
            "head": {"ref": "automation/context-engine-v1.2.3"},
        }
        transport.pull_details["homebrew-tap"] = {
            "number": 2,
            "state": "closed",
            "merged": True,
            "merged_at": "2026-07-26T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(channels.ChannelMutationError):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3", candidate_root=_candidate_root(Path(temporary))
                )

    def test_coordinator_endpoint_allowlist_rejects_unrelated_paths(self) -> None:
        repository = channels.DESTINATIONS["homebrew"]
        rejected = (
            ("GET", f"/repos/{repository}/issues"),
            ("GET", f"/repos/{repository}/deployments"),
            ("POST", f"/repos/{repository}/git/refs/tags/v1.2.3"),
            ("POST", f"/repos/{repository}/git/refs/heads/main"),
        )
        for method, path in rejected:
            with self.subTest(method=method, path=path):
                with self.assertRaises(channels.ChannelMutationError):
                    channels.assert_allowed_endpoint(repository, method, path)

    def test_coordinator_ref_creation_requires_automation_branch_and_commit(
        self,
    ) -> None:
        repository = channels.DESTINATIONS["homebrew"]
        transport = FakeTransport()
        coordinator = TestableChannelCoordinator(transport)
        path = f"/repos/{repository}/git/refs"
        for body in (
            {"ref": "refs/heads/main", "sha": "a" * 40},
            {"ref": "v1.2.3", "sha": "a" * 40},
            {
                "ref": "refs/heads/automation/context-engine-v1.2.3",
                "sha": "not-a-commit",
            },
        ):
            with self.subTest(body=body):
                with self.assertRaises(channels.ChannelMutationError):
                    _ = coordinator.request_for_test(
                        "homebrew", "POST", path, body=json.dumps(body).encode()
                    )

    def test_branch_uses_automation_namespace(self) -> None:
        self.assertEqual(channels.BRANCH_PREFIX, "automation/context-engine-")

    def test_anonymous_preflight_captures_both_destination_heads(self) -> None:
        transport = PublicPreflightTransport()
        coordinator = channels.ChannelCoordinator(transport)

        plan = coordinator.preflight()

        self.assertEqual(plan["status"], "preflight")
        destinations = cast(dict[str, object], plan["destinations"])
        for destination in ("homebrew", "scoop"):
            snapshot = cast(dict[str, object], destinations[destination])
            self.assertEqual(snapshot["default_sha"], "a" * 40)
        self.assertTrue(
            all(
                query is None or "Authorization" not in query
                for _, _, query in transport.calls
            )
        )

    def test_anonymous_preflight_missing_scoop_has_no_writes(self) -> None:
        transport = PublicPreflightTransport(scoop=False)
        coordinator = channels.ChannelCoordinator(transport)

        with self.assertRaises(channels.ChannelPlanError):
            _ = coordinator.preflight()
        self.assertEqual(
            [method for method, _, _ in transport.calls if method != "GET"], []
        )

    def test_authenticated_preflight_rejects_repository_state_change(self) -> None:
        transport = PublicPreflightTransport()
        coordinator = channels.ChannelCoordinator(transport)
        plan = coordinator.preflight(tag="v1.2.3")
        transport.repository_private = True
        with self.assertRaises(channels.ChannelMutationError):
            coordinator.verify_preflight(plan, tag="v1.2.3")

    def test_authenticated_preflight_rejects_default_branch_race(self) -> None:
        transport = PublicPreflightTransport()
        coordinator = channels.ChannelCoordinator(transport)
        plan = coordinator.preflight(tag="v1.2.3")
        transport.default_sha = "c" * 40
        with self.assertRaises(channels.ChannelMutationError):
            coordinator.verify_preflight(plan, tag="v1.2.3")

    def test_preflight_fetches_bootstrap_and_candidate_at_resolved_sha(self) -> None:
        transport = PublicPreflightTransport()
        _ = channels.ChannelCoordinator(transport).preflight(tag="v1.2.3")
        content_calls = [
            query for _, path, query in transport.calls if "/contents/" in path
        ]
        self.assertTrue(content_calls)
        self.assertTrue(all(query == {"ref": "a" * 40} for query in content_calls))

    def test_mutation_preflight_fetches_candidate_at_resolved_sha(self) -> None:
        data = b"class Formula\n"
        desired = channels.CandidateFile(
            "Formula/context-engine.rb",
            data,
            hashlib.sha256(data).hexdigest(),
            len(data),
            "0644",
        )
        transport = PublicPreflightTransport()
        transport.candidate_data[desired.path] = data
        transport.candidate_data["bucket/context-engine.json"] = (
            b'{"version":"1.2.3"}\n'
        )
        with tempfile.TemporaryDirectory() as temporary:
            _ = channels.ChannelCoordinator(transport).prepare(
                tag="v1.2.3", candidate_root=_candidate_root(Path(temporary))
            )
        candidate_calls = [
            query
            for method, path, query in transport.calls
            if method == "GET" and "/contents/Formula/context-engine.rb" in path
        ]
        self.assertTrue(candidate_calls)
        self.assertEqual(candidate_calls[-1], {"ref": "a" * 40})

    def test_mutation_preflight_requires_complete_repository_state(self) -> None:
        for attribute, value in (
            ("repository_full_name", "context-engine-app/other"),
            ("repository_private", True),
            ("repository_disabled", True),
            ("repository_archived", True),
        ):
            with self.subTest(attribute=attribute):
                transport = PublicPreflightTransport()
                setattr(transport, attribute, value)
                with tempfile.TemporaryDirectory() as temporary:
                    with self.assertRaises(channels.ChannelPlanError):
                        _ = channels.ChannelCoordinator(transport).prepare(
                            tag="v1.2.3",
                            candidate_root=_candidate_root(Path(temporary)),
                        )

    def test_prepare_rejects_mutation_candidate_binding_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = PublicPreflightTransport()
            coordinator = channels.ChannelCoordinator(transport)
            plan = coordinator.preflight(tag="v1.2.3")
            transport.candidate_data["Formula/context-engine.rb"] = b"stale\n"
            with self.assertRaises(channels.ChannelMutationError):
                _ = coordinator.prepare(
                    tag="v1.2.3", candidate_root=root, preflight_plan=plan
                )

    def test_prepare_rejects_mutation_bootstrap_binding_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = PublicPreflightTransport()
            coordinator = channels.ChannelCoordinator(transport)
            plan = coordinator.preflight(tag="v1.2.3")
            transport.bootstrap_sha = "c" * 40
            with self.assertRaises(channels.ChannelMutationError):
                _ = coordinator.prepare(
                    tag="v1.2.3", candidate_root=root, preflight_plan=plan
                )

    def test_repair_pair_requires_both_positive_or_both_empty(self) -> None:
        self.assertTrue(channels.parse_repair_pair("", "").baseline)
        self.assertEqual(channels.parse_repair_pair("12", "3").run_id, 12)
        for pair in (("12", ""), ("", "3"), ("0", "1"), ("x", "1")):
            with self.subTest(pair=pair):
                with self.assertRaises(channels.ChannelPlanError):
                    _ = channels.parse_repair_pair(*pair)

    def test_missing_scoop_is_rejected_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = FakeTransport(scoop=False)
            coordinator = channels.ChannelCoordinator(transport)
            with self.assertRaises(channels.ChannelPlanError):
                _ = coordinator.prepare(tag="v1.2.3", candidate_root=root)
            self.assertFalse(
                any(
                    method in {"POST", "PATCH", "DELETE"}
                    for method, _ in transport.calls
                )
            )

    def test_baseline_creates_one_commit_and_pr_per_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            homebrew = FakeTransport()
            scoop = FakeTransport()
            result = channels.ChannelCoordinator(
                {"homebrew": homebrew, "scoop": scoop}
            ).prepare(tag="v1.2.3", candidate_root=root)
            self.assertEqual(result["status"], "prepared")
            writes = [
                method
                for transport in (homebrew, scoop)
                for method, _ in transport.calls
                if method in {"POST", "PATCH", "DELETE"}
            ]
            self.assertEqual(writes.count("POST"), 10)

    def test_matching_open_pr_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = FakeTransport()
            transport.branch_sha["automation/context-engine-v1.2.3"] = "c" * 40
            baseline = channels.load_baseline_candidates(root, expected_tag="v1.2.3")
            transport.prs["homebrew-tap"] = {
                "number": 2,
                "state": "open",
                "title": "Context Engine v1.2.3",
                "body": "Generated from verified public channel candidate bytes;\n"
                + channels.candidate_marker(
                    "v1.2.3", baseline.files["Formula/context-engine.rb"]
                ),
                "head": {"ref": "automation/context-engine-v1.2.3", "sha": "c" * 40},
            }
            result = channels.ChannelCoordinator(transport).prepare(
                tag="v1.2.3", candidate_root=root
            )
            self.assertEqual(result["status"], "prepared")
            destinations = cast(dict[str, object], result["destinations"])
            homebrew_result = cast(dict[str, object], destinations["homebrew"])
            self.assertEqual(homebrew_result["status"], "open-pr")

    def test_closed_unmerged_pr_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = FakeTransport()
            transport.prs["homebrew-tap"] = {
                "number": 2,
                "state": "closed",
                "merged": False,
                "head": {"ref": "automation/context-engine-v1.2.3"},
            }
            with self.assertRaises(channels.ChannelMutationError):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3", candidate_root=root
                )

    def test_closed_pr_detail_binds_merged_state_and_default_bytes(self) -> None:
        data = b"class Formula\n"
        transport = FakeTransport()
        transport.merged_data = data
        transport.prs["homebrew-tap"] = {
            "number": 2,
            "state": "closed",
            "head": {"ref": "automation/context-engine-v1.2.3"},
        }
        transport.pull_details["homebrew-tap"] = {
            "number": 2,
            "state": "closed",
            "merged": True,
            "merged_at": "2026-07-26T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = channels.ChannelCoordinator(transport).prepare(
                tag="v1.2.3", candidate_root=_candidate_root(Path(temporary))
            )
        destinations = cast(dict[str, object], result["destinations"])
        homebrew_result = cast(dict[str, object], destinations["homebrew"])
        self.assertEqual(homebrew_result["status"], "merged")

    def test_baseline_requires_both_destination_candidate_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            metadata = cast(
                dict[str, object],
                json.loads(
                    (root / "channel-candidates.json").read_text(encoding="utf-8")
                ),
            )
            candidates = cast(list[object], metadata["candidates"])
            metadata["candidates"] = [candidates[0]]
            _ = (root / "channel-candidates.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )
            with self.assertRaises(channels.ChannelPlanError):
                _ = channels.load_baseline_candidates(root, expected_tag="v1.2.3")

    def test_repair_metadata_without_candidate_bytes_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            baseline = channels.load_baseline_candidates(root, expected_tag="v1.2.3")
            repair_root = Path(temporary) / "repair"
            repair_root.mkdir()
            record = {
                "release_tag": "v1.2.3",
                "version": "1.2.3",
                "profile": "desktop",
                "destination": "homebrew",
                "source_run": {"id": 12, "attempt": 3},
                "locked_fields": {
                    "release_tag": "v1.2.3",
                    "version": "1.2.3",
                    "profile": "desktop",
                    "source_manifest_sha256": baseline.source_manifest_sha256,
                    "destination": "homebrew",
                },
                "replacement": {
                    "path": "Formula/context-engine.rb",
                    "sha256": "e" * 64,
                    "size": 1,
                    "mode": "0644",
                },
            }
            _ = (repair_root / "channel-repair.json").write_text(
                json.dumps(record), encoding="utf-8"
            )
            with self.assertRaises(channels.ChannelPlanError):
                _ = channels.load_repair_candidate(
                    repair_root,
                    channels.parse_repair_pair("12", "3"),
                    baseline,
                    destination="homebrew",
                )

    def test_resumable_branch_with_extra_changed_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = FakeTransport()
            transport.branch_sha["automation/context-engine-v1.2.3"] = "c" * 40
            transport.prs["homebrew-tap"] = {
                "number": 2,
                "state": "open",
                "title": "Context Engine v1.2.3",
                "body": "Generated from verified public channel candidate bytes;\n"
                + channels.candidate_marker(
                    "v1.2.3",
                    channels.load_baseline_candidates(
                        root, expected_tag="v1.2.3"
                    ).files["Formula/context-engine.rb"],
                ),
                "head": {"ref": "automation/context-engine-v1.2.3", "sha": "c" * 40},
            }
            transport.extra_tree = True
            with self.assertRaises(channels.ChannelMutationError):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3", candidate_root=root
                )

    def test_resumable_branch_ignores_recursive_tree_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = FakeTransport()
            transport.tree_ancestors = True
            transport.branch_sha["automation/context-engine-v1.2.3"] = "c" * 40
            transport.prs["homebrew-tap"] = {
                "number": 2,
                "state": "open",
                "title": "Context Engine v1.2.3",
                "body": "Generated from verified public channel candidate bytes;\n"
                + channels.candidate_marker(
                    "v1.2.3",
                    channels.load_baseline_candidates(
                        root, expected_tag="v1.2.3"
                    ).files["Formula/context-engine.rb"],
                ),
                "head": {
                    "ref": "automation/context-engine-v1.2.3",
                    "sha": "c" * 40,
                },
            }
            result = channels.ChannelCoordinator(transport).prepare(
                tag="v1.2.3", candidate_root=root
            )
            destinations = cast(dict[str, object], result["destinations"])
            homebrew_result = cast(dict[str, object], destinations["homebrew"])
            self.assertEqual(homebrew_result["status"], "open-pr")

    def test_truncated_recursive_tree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _candidate_root(Path(temporary))
            transport = FakeTransport()
            transport.truncated_tree = True
            transport.branch_sha["automation/context-engine-v1.2.3"] = "c" * 40
            transport.prs["homebrew-tap"] = {
                "number": 2,
                "state": "open",
                "title": "Context Engine v1.2.3",
                "body": "Generated from verified public channel candidate bytes;\n"
                + channels.candidate_marker(
                    "v1.2.3",
                    channels.load_baseline_candidates(
                        root, expected_tag="v1.2.3"
                    ).files["Formula/context-engine.rb"],
                ),
                "head": {
                    "ref": "automation/context-engine-v1.2.3",
                    "sha": "c" * 40,
                },
            }
            with self.assertRaisesRegex(channels.ChannelMutationError, "truncated"):
                _ = channels.ChannelCoordinator(transport).prepare(
                    tag="v1.2.3", candidate_root=root
                )


if __name__ == "__main__":
    _ = unittest.main()
