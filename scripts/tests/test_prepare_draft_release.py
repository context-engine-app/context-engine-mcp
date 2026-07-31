from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock

from typing_extensions import override

from scripts import prepare_draft_release as publisher


class FakeClient(publisher.GitHubClient):
    def __init__(self, mismatch: bool = False, omit_name: str | None = None) -> None:
        super().__init__(token="test")
        self.release: dict[str, object] | None = None
        self.asset_rows: dict[str, dict[str, object]] = {}
        self.mismatch: bool = mismatch
        self.omit_name: str | None = omit_name
        self.uploads: list[str] = []
        self.publications: int = 0

    @override
    def release_by_tag(self, tag: str) -> dict[str, object] | None:
        _ = tag
        return self.release

    @override
    def create_draft(self, plan: publisher.ValidatedPlan) -> dict[str, object]:
        self.release = {
            "id": 7,
            "tag_name": plan.tag,
            "name": plan.tag,
            "draft": True,
            "prerelease": False,
        }
        return self.release

    @override
    def assets(self, release_id: int) -> list[dict[str, object]]:
        _ = release_id
        rows = list(self.asset_rows.values())
        if self.mismatch and not rows:
            rows.append(
                {
                    "id": 1,
                    "name": "unexpected",
                    "size": 1,
                    "digest": "sha256:" + "0" * 64,
                    "state": "uploaded",
                }
            )
        return rows

    @override
    def upload(self, release_id: int, name: str, content: bytes) -> dict[str, object]:
        _ = release_id
        self.uploads.append(name)
        row: dict[str, object] = {
            "id": len(self.uploads),
            "name": name,
            "size": len(content),
            "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
            "state": "uploaded",
        }
        if name != self.omit_name:
            self.asset_rows[name] = row
        return row

    @override
    def publish(self, release_id: int, tag: str) -> dict[str, object]:
        _ = release_id
        self.publications += 1
        if self.release is None:
            raise AssertionError("release was not created")
        self.release.update(
            {
                "tag_name": tag,
                "draft": False,
                "immutable": True,
                "published_at": "2026-07-31T00:00:00Z",
            }
        )
        return self.release

    @override
    def release_by_id(self, release_id: int) -> dict[str, object]:
        _ = release_id
        if self.release is None:
            raise AssertionError("release is missing")
        return self.release


def _fixture() -> tuple[Path, dict[str, object]]:
    root = Path(tempfile.mkdtemp()) / "staged"
    root.mkdir()
    names = [
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "channel-candidates.json",
        "channel-candidates.tar.gz",
        "release-manifest.json",
        "release-provenance.json",
        "SHA256SUMS",
        "SHA256SUMS.sigstore.json",
    ]
    facts: list[dict[str, object]] = []
    for name in names:
        content = name.encode()
        _ = (root / name).write_bytes(content)
        facts.append(
            {
                "name": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    _ = (root / "staging-attestation.json").write_bytes(b"attestation")
    _ = (root / "staging-attestation.sigstore.json").write_bytes(b"signature")
    facts.sort(key=lambda row: str(row["name"]))
    canonical_facts = [
        {"filename": row["name"], "sha256": row["sha256"], "size": row["size"]}
        for row in facts
    ]
    asset_hash = hashlib.sha256(
        json.dumps(canonical_facts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    plan: dict[str, object] = {
        "profile": "desktop",
        "tag": "v0.1.0",
        "version": "0.1.0",
        "source_commit": "1" * 40,
        "distribution_commit": "2" * 40,
        "distribution_repository": publisher.PUBLIC_REPOSITORY,
        "distribution_tag_target": "2" * 40,
        "release_asset_set_sha256": asset_hash,
        "staging_attestation_sha256": hashlib.sha256(b"attestation").hexdigest(),
        "source_workflow": {
            "path": publisher.SOURCE_WORKFLOW,
            "commit": "1" * 40,
            "sha256": "3" * 64,
        },
        "public_workflow": {
            "path": publisher.PUBLIC_WORKFLOW,
            "commit": "2" * 40,
            "sha256": "4" * 64,
        },
        "source_run": {
            "id": 9,
            "attempt": 1,
            "url": "https://github.com/context-engine-app/context-engine/actions/runs/9",
        },
        "assets": facts,
    }
    return root, plan


class PublisherTests(unittest.TestCase):
    def test_create_draft_uses_the_prevalidated_existing_tag(self) -> None:
        root, raw_plan = _fixture()
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(raw_plan), encoding="utf-8")
        plan = publisher.ValidatedPlan.from_file(plan_path)
        client = publisher.GitHubClient(token="test")
        with mock.patch.object(
            client,
            "json",
            return_value=(201, {}, {"id": 7}),
        ) as request_json:
            _ = client.create_draft(plan)
        request_json.assert_called_once()
        body = cast(object, request_json.call_args.kwargs.get("body"))
        self.assertIsInstance(body, dict)
        self.assertNotIn("target_commitish", cast(dict[str, object], body))

    def test_publish_draft_uses_the_prevalidated_existing_tag(self) -> None:
        client = publisher.GitHubClient(token="test")
        with mock.patch.object(
            client,
            "json",
            return_value=(200, {}, {"id": 7, "draft": False}),
        ) as request_json:
            _ = client.publish(7, "v0.1.0")
        request_json.assert_called_once()
        body = cast(object, request_json.call_args.kwargs.get("body"))
        self.assertIsInstance(body, dict)
        self.assertNotIn("target_commitish", cast(dict[str, object], body))

    def test_publish_uses_the_prevalidated_tag_as_release_identity(self) -> None:
        root, raw_plan = _fixture()
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(raw_plan), encoding="utf-8")
        plan = publisher.ValidatedPlan.from_file(plan_path)
        client = FakeClient()
        client.release = {
            "id": 7,
            "tag_name": plan.tag,
            "name": plan.tag,
            "draft": True,
            "prerelease": False,
        }
        result = publisher.publish(plan, root, client)
        self.assertEqual(result["status"], "published")

    def test_plan_rejects_changed_asset_facts(self) -> None:
        root, plan = _fixture()
        assets = plan["assets"]
        self.assertIsInstance(assets, list)
        assets_list = cast(list[object], assets)
        plan["assets"] = assets_list[1:]
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(plan), encoding="utf-8")
        with self.assertRaises(publisher.PlanError):
            _ = publisher.ValidatedPlan.from_file(plan_path)

    def test_publish_uploads_once_and_publishes(self) -> None:
        root, raw_plan = _fixture()
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(raw_plan), encoding="utf-8")
        plan = publisher.ValidatedPlan.from_file(plan_path)
        client = FakeClient()
        result = publisher.publish(plan, root, client)
        self.assertEqual(result["status"], "published")
        self.assertEqual(len(client.uploads), len(plan.assets))
        self.assertEqual(client.publications, 1)

    def test_published_rerun_is_read_only(self) -> None:
        root, raw_plan = _fixture()
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(raw_plan), encoding="utf-8")
        plan = publisher.ValidatedPlan.from_file(plan_path)
        client = FakeClient()
        _ = publisher.publish(plan, root, client)
        client.uploads.clear()
        result = publisher.publish(plan, root, client)
        self.assertTrue(result["reused"])
        self.assertEqual(client.uploads, [])
        self.assertEqual(client.publications, 1)

    def test_mismatched_remote_asset_fails_closed(self) -> None:
        root, raw_plan = _fixture()
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(raw_plan), encoding="utf-8")
        plan = publisher.ValidatedPlan.from_file(plan_path)
        client = FakeClient(mismatch=True)
        with self.assertRaises(publisher.ReleaseMismatchError):
            _ = publisher.publish(plan, root, client)

    def test_missing_remote_asset_fails_closed(self) -> None:
        root, raw_plan = _fixture()
        plan_path = root.parent / "plan.json"
        _ = plan_path.write_text(json.dumps(raw_plan), encoding="utf-8")
        plan = publisher.ValidatedPlan.from_file(plan_path)
        client = FakeClient(omit_name=plan.assets[0].name)
        with self.assertRaises(publisher.ReleaseMismatchError):
            _ = publisher.publish(plan, root, client)


if __name__ == "__main__":
    _ = unittest.main()
