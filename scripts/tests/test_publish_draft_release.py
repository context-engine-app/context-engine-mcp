from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import unittest
from collections.abc import Mapping
from email.message import Message
from http import client as http_client
from pathlib import Path
from typing import cast, final
from unittest.mock import patch
from urllib import error as urllib_error

from typing_extensions import override

from scripts import prepare_draft_release as draft
from scripts import publish_draft_release as publisher


@final
class IncompleteResponse:
    def __init__(self) -> None:
        self.status = 200
        self.headers = Message()

    def read(self, amount: int = -1) -> bytes:
        del amount
        raise http_client.IncompleteRead(b"partial", 10)

    def __enter__(self) -> IncompleteResponse:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        del exc_type, exc_value, traceback


@final
class IncompleteStream(io.BytesIO):
    name = "<incomplete-stream>"

    @override
    def read(self, size: int | None = -1) -> bytes:
        del size
        raise http_client.IncompleteRead(b"partial", 10)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _publication_plan() -> dict[str, object]:
    assets = [
        {
            "name": name,
            "sha256": _sha(f"asset:{name}".encode()),
            "size": len(f"asset:{name}".encode()),
        }
        for name in NAMES
    ]
    workflow = {
        "path": ".github/workflows/prepare-draft-release.yml",
        "commit": "b" * 40,
        "sha256": "c" * 64,
    }
    return {
        "schema_version": 1,
        "profile": "desktop",
        "authorized_stages": [
            "source-release",
            "public-draft",
            "public-publish",
            "package-channels",
        ],
        "tag": "v1.2.3",
        "version": "1.2.3",
        "source_repository": "context-engine-app/context-engine",
        "source_commit": "a" * 40,
        "distribution_repository": "context-engine-app/context-engine-mcp",
        "distribution_commit": "b" * 40,
        "distribution_tag_target": "b" * 40,
        "release_asset_set_sha256": draft.canonical_sha256(assets),
        "staging_attestation_sha256": "e" * 64,
        "source_workflow": {
            "path": ".github/workflows/release.yml",
            "commit": "a" * 40,
            "sha256": "f" * 64,
        },
        "public_workflow": workflow,
        "source_run": {
            "id": 44,
            "attempt": 2,
            "url": "https://github.com/context-engine-app/context-engine/actions/runs/44",
        },
        "assets": assets,
        "public_workflows": {
            "draft": workflow,
            "publish": {
                "path": ".github/workflows/publish-draft-release.yml",
                "commit": "b" * 40,
                "sha256": "1" * 64,
            },
            "channels": {
                "path": ".github/workflows/prepare-package-channels.yml",
                "commit": "b" * 40,
                "sha256": "2" * 64,
            },
        },
        "draft_run": {"id": 55, "attempt": 1},
    }


@final
class FakeTransport:
    def __init__(self, plan: publisher.PublicationPlan) -> None:
        marker = draft.marker_metadata(
            plan.release,
            artifact_id=7,
            artifact_digest="sha256:" + "3" * 64,
            artifact_expires_at="2099-01-01T00:00:00Z",
            state="verified",
            verified_run_id=plan.draft_run_id,
            verified_run_attempt=plan.draft_run_attempt,
        )
        self.release: dict[str, object] = {
            "id": 9,
            "tag_name": plan.release.tag,
            "name": plan.release.tag,
            "target_commitish": plan.release.distribution_commit,
            "draft": True,
            "immutable": False,
            "published_at": None,
            "prerelease": False,
            "body": draft.render_body(marker),
        }
        self.assets = {
            fact.name: {
                "id": index,
                "name": fact.name,
                "size": fact.size,
                "state": "uploaded",
                "digest": f"sha256:{fact.sha256}",
            }
            for index, fact in enumerate(plan.release.assets, start=100)
        }
        self.calls: list[tuple[str, str, bytes | None]] = []
        self.ambiguous_patch = False
        self.change_after_patch = False
        self.stale_reconciliation_reads = 0
        self.reconciliation_release_bodies: list[bytes] = []
        self.reconciliation_asset_bodies: list[bytes] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> draft.Response:
        del query, headers
        self.calls.append((method, path, body))
        if method == "GET" and "/releases/tags/" in path:
            return draft.Response(200, {}, json.dumps(self.release).encode())
        if method == "GET" and path.endswith("/assets"):
            if self.release["draft"] is False and self.reconciliation_asset_bodies:
                return draft.Response(
                    200,
                    {},
                    self.reconciliation_asset_bodies.pop(0),
                )
            return draft.Response(
                200, {}, json.dumps(list(self.assets.values())).encode()
            )
        if method == "GET" and path.endswith("/releases/9"):
            if self.reconciliation_release_bodies:
                return draft.Response(
                    200,
                    {},
                    self.reconciliation_release_bodies.pop(0),
                )
            if self.stale_reconciliation_reads > 0:
                self.stale_reconciliation_reads -= 1
                stale = dict(self.release)
                stale["draft"] = True
                stale["immutable"] = False
                stale["published_at"] = None
                return draft.Response(200, {}, json.dumps(stale).encode())
            return draft.Response(200, {}, json.dumps(self.release).encode())
        if method == "PATCH" and path.endswith("/releases/9"):
            self.release["draft"] = False
            self.release["immutable"] = True
            self.release["published_at"] = "2026-07-26T12:00:00Z"
            if self.change_after_patch:
                self.release["name"] = "changed"
            response = draft.Response(200, {}, json.dumps(self.release).encode())
            if self.ambiguous_patch:
                raise publisher.TransportError("connection closed", ambiguous=True)
            return response
        raise AssertionError((method, path))


@final
class PublisherTests(unittest.TestCase):
    @override
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.plan = publisher.PublicationPlan.from_mapping(_publication_plan())
        self.transport = FakeTransport(self.plan)
        self.coordinator = publisher.Publisher(
            self.transport,
            repository="context-engine-app/context-engine-mcp",
        )

    def test_module_help_matches_release_contract_invocation(self) -> None:
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, "-m", "scripts.publish_draft_release", "--help"],
            cwd=root,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: publish_draft_release.py", result.stdout)

    def test_publishes_with_the_only_permitted_patch(self) -> None:
        result = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertEqual(result["status"], "published")
        patches = [call for call in self.transport.calls if call[0] == "PATCH"]
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0][2], b'{"draft":false}')

    def test_fresh_invocation_rejects_an_existing_published_release(self) -> None:
        self.transport.release.update(
            {
                "draft": False,
                "immutable": True,
                "published_at": "2026-07-26T12:00:00Z",
            }
        )

        with self.assertRaisesRegex(publisher.ReleaseMismatchError, "draft"):
            _ = self.coordinator.publish(self.plan, draft_run_id=55)
        self.assertFalse(any(call[0] == "PATCH" for call in self.transport.calls))

    def test_ambiguous_patch_reconciles_the_exact_published_release(self) -> None:
        self.transport.ambiguous_patch = True

        result = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertEqual(result["status"], "published")
        self.assertTrue(result["reconciled"])
        self.assertEqual(
            len([call for call in self.transport.calls if call[0] == "PATCH"]),
            1,
        )

    def test_ambiguous_patch_retries_read_only_reconciliation(self) -> None:
        self.transport.ambiguous_patch = True
        self.transport.stale_reconciliation_reads = 2

        with patch("scripts.publish_draft_release.time.sleep") as sleep:
            result = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertTrue(result["reconciled"])
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(
            len(
                [
                    call
                    for call in self.transport.calls
                    if call[0] == "GET" and call[1].endswith("/releases/9")
                ]
            ),
            3,
        )

    def test_ambiguous_patch_reconciliation_is_bounded(self) -> None:
        self.transport.ambiguous_patch = True
        self.transport.stale_reconciliation_reads = 4

        with (
            patch("scripts.publish_draft_release.time.sleep") as sleep,
            self.assertRaises(publisher.ReleaseMismatchError),
        ):
            _ = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(
            len(
                [
                    call
                    for call in self.transport.calls
                    if call[0] == "GET" and call[1].endswith("/releases/9")
                ]
            ),
            3,
        )

    def test_reconciliation_retries_malformed_release_json_without_repatching(
        self,
    ) -> None:
        self.transport.reconciliation_release_bodies = [b"{"]

        with patch("scripts.publish_draft_release.time.sleep") as sleep:
            result = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertEqual(result["status"], "published")
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(
            len([call for call in self.transport.calls if call[0] == "PATCH"]),
            1,
        )

    def test_reconciliation_retries_non_object_release_without_repatching(
        self,
    ) -> None:
        self.transport.reconciliation_release_bodies = [b"[]"]

        with patch("scripts.publish_draft_release.time.sleep") as sleep:
            result = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertEqual(result["status"], "published")
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(
            len([call for call in self.transport.calls if call[0] == "PATCH"]),
            1,
        )

    def test_reconciliation_retries_malformed_assets_without_repatching(
        self,
    ) -> None:
        self.transport.reconciliation_asset_bodies = [b"{"]

        with patch("scripts.publish_draft_release.time.sleep") as sleep:
            result = self.coordinator.publish(self.plan, draft_run_id=55)

        self.assertEqual(result["status"], "published")
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(
            len([call for call in self.transport.calls if call[0] == "PATCH"]),
            1,
        )

    def test_ambiguous_patch_rejects_changed_release_identity(self) -> None:
        self.transport.ambiguous_patch = True
        self.transport.change_after_patch = True

        with self.assertRaisesRegex(publisher.ReleaseMismatchError, "changed"):
            _ = self.coordinator.publish(self.plan, draft_run_id=55)

    def test_retry_class_patch_http_errors_are_ambiguous(self) -> None:
        transport = publisher.UrllibGitHubTransport(token="test-token")
        path = "/repos/context-engine-app/context-engine-mcp/releases/9"
        for status in (408, 409, 422, 429, 500, 599):
            with self.subTest(status=status):
                error = urllib_error.HTTPError(
                    url=f"https://api.github.com{path}",
                    code=status,
                    msg="test failure",
                    hdrs=Message(),
                    fp=io.BytesIO(b"{}"),
                )
                with (
                    patch(
                        "scripts.publish_draft_release.urllib_request.urlopen",
                        side_effect=error,
                    ),
                    self.assertRaises(publisher.TransportError) as caught,
                ):
                    _ = transport.request("PATCH", path, body=b'{"draft":false}')
                self.assertTrue(caught.exception.ambiguous)

    def test_patch_success_body_incomplete_is_ambiguous(self) -> None:
        transport = publisher.UrllibGitHubTransport(token="test-token")
        path = "/repos/context-engine-app/context-engine-mcp/releases/9"
        with (
            patch(
                "scripts.publish_draft_release.urllib_request.urlopen",
                return_value=IncompleteResponse(),
            ),
            self.assertRaises(publisher.TransportError) as caught,
        ):
            _ = transport.request("PATCH", path, body=b'{"draft":false}')

        self.assertTrue(caught.exception.ambiguous)

    def test_patch_error_body_incomplete_is_ambiguous(self) -> None:
        transport = publisher.UrllibGitHubTransport(token="test-token")
        path = "/repos/context-engine-app/context-engine-mcp/releases/9"
        error = urllib_error.HTTPError(
            url=f"https://api.github.com{path}",
            code=500,
            msg="test failure",
            hdrs=Message(),
            fp=IncompleteStream(),
        )
        with (
            patch(
                "scripts.publish_draft_release.urllib_request.urlopen",
                side_effect=error,
            ),
            self.assertRaises(publisher.TransportError) as caught,
        ):
            _ = transport.request("PATCH", path, body=b'{"draft":false}')

        self.assertTrue(caught.exception.ambiguous)

    def test_draft_run_mismatch_fails_before_network(self) -> None:
        with self.assertRaisesRegex(publisher.PlanError, "draft run"):
            _ = self.coordinator.publish(self.plan, draft_run_id=56)
        self.assertEqual(self.transport.calls, [])

    def test_endpoint_allowlist_rejects_other_mutations(self) -> None:
        for method, path in (
            ("DELETE", "/repos/context-engine-app/context-engine-mcp/releases/9"),
            ("POST", "/repos/context-engine-app/context-engine-mcp/releases"),
            ("PATCH", "/repos/context-engine-app/context-engine-mcp/releases/other"),
        ):
            with self.subTest(method=method, path=path):
                with self.assertRaises(publisher.EndpointError):
                    publisher.assert_allowed_endpoint(method, path)

    def test_publication_plan_rejects_partial_or_reordered_workflows(self) -> None:
        for mutate in ("missing", "reordered"):
            with self.subTest(mutate=mutate):
                raw = cast(
                    dict[str, object], json.loads(json.dumps(_publication_plan()))
                )
                workflows = cast(dict[str, object], raw["public_workflows"])
                if mutate == "missing":
                    del workflows["channels"]
                else:
                    stages = cast(list[object], raw["authorized_stages"])
                    stages[2], stages[3] = stages[3], stages[2]
                with self.assertRaises(publisher.PlanError):
                    _ = publisher.PublicationPlan.from_mapping(raw)


if __name__ == "__main__":
    _ = unittest.main()
