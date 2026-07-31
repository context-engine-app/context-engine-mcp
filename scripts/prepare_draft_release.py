#!/usr/bin/env python3
"""Publish one immutable GitHub release from a validated staging envelope.

The private release workflow supplies a portable plan and the exact release
assets.  This module validates those bytes, creates or resumes one draft,
checks GitHub's asset metadata, and performs the single draft-to-published
transition.  A rerun is read-only when the exact immutable release already
exists; any metadata mismatch fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast


PUBLIC_REPOSITORY = "context-engine-app/context-engine-mcp"
SOURCE_REPOSITORY = "context-engine-app/context-engine"
SOURCE_WORKFLOW = ".github/workflows/release.yml"
PUBLIC_WORKFLOW = ".github/workflows/prepare-draft-release.yml"
STAGING_ONLY = frozenset(
    {"staging-attestation.json", "staging-attestation.sigstore.json"}
)
REQUIRED_DOCUMENTS = frozenset({"release-manifest.json", "release-provenance.json"})
REQUIRED_CHECKSUMS = frozenset({"SHA256SUMS", "SHA256SUMS.sigstore.json"})
REQUIRED_CANDIDATES = frozenset(
    {"channel-candidates.json", "channel-candidates.tar.gz"}
)
TAG_RE = re.compile(
    r"^(repository-bootstrap-)?v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ASSET_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PLACEHOLDER_RE = re.compile(r"^untagged-[0-9a-f]{40}$")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_UPLOAD_RESPONSE_BYTES = 16 * 1024 * 1024


class PublishError(Exception):
    """A release cannot be safely published."""


class PlanError(PublishError):
    """The portable plan or staged bytes are invalid."""


class ReleaseMismatchError(PublishError):
    """GitHub contains a release that is not the requested release."""


class _UrlResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def read(self, amount: int = -1) -> bytes: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class AssetFact:
    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ValidatedPlan:
    profile: str
    tag: str
    version: str
    source_commit: str
    distribution_commit: str
    distribution_repository: str
    release_asset_set_sha256: str
    staging_attestation_sha256: str
    assets: tuple[AssetFact, ...]

    @classmethod
    def from_file(cls, path: Path) -> ValidatedPlan:
        try:
            raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as error:
            raise PlanError(f"cannot read validated plan: {error}") from error
        if not isinstance(raw, dict):
            raise PlanError("validated plan must be an object")
        raw = cast(dict[str, object], raw)
        profile = raw.get("profile")
        tag = raw.get("tag")
        version = raw.get("version")
        if not isinstance(profile, str) or profile not in {
            "desktop",
            "desktop-linux",
            "repository-bootstrap",
        }:
            raise PlanError("validated plan profile is unsupported")
        if not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None:
            raise PlanError("validated plan tag is not stable")
        match = TAG_RE.fullmatch(tag)
        if (
            match is None
            or not isinstance(version, str)
            or version != ".".join(match.groups()[1:])
        ):
            raise PlanError("validated plan version does not match tag")
        expected_tag = (
            f"repository-bootstrap-v{version}"
            if profile == "repository-bootstrap"
            else f"v{version}"
        )
        if tag != expected_tag:
            raise PlanError("validated plan tag does not match profile")
        source_commit = raw.get("source_commit")
        distribution_commit = raw.get("distribution_commit")
        distribution_repository = raw.get("distribution_repository")
        if (
            not isinstance(source_commit, str)
            or COMMIT_RE.fullmatch(source_commit) is None
        ):
            raise PlanError("source_commit is invalid")
        if (
            not isinstance(distribution_commit, str)
            or COMMIT_RE.fullmatch(distribution_commit) is None
        ):
            raise PlanError("distribution_commit is invalid")
        if (
            not isinstance(distribution_repository, str)
            or distribution_repository != PUBLIC_REPOSITORY
        ):
            raise PlanError("distribution_repository is not the public repository")
        if raw.get("distribution_tag_target") != distribution_commit:
            raise PlanError("distribution_tag_target must equal distribution_commit")
        source_workflow = raw.get("source_workflow")
        public_workflow = raw.get("public_workflow")
        if not isinstance(source_workflow, dict):
            raise PlanError("source_workflow.path is invalid")
        source_workflow = cast(dict[str, object], source_workflow)
        if source_workflow.get("path") != SOURCE_WORKFLOW:
            raise PlanError("source_workflow.path is invalid")
        if not isinstance(public_workflow, dict):
            raise PlanError("public_workflow.path is invalid")
        public_workflow = cast(dict[str, object], public_workflow)
        if public_workflow.get("path") != PUBLIC_WORKFLOW:
            raise PlanError("public_workflow.path is invalid")
        source_run = raw.get("source_run")
        if not isinstance(source_run, dict):
            raise PlanError("source_run is invalid")
        source_run = cast(dict[str, object], source_run)
        source_run_id = source_run.get("id")
        if not isinstance(source_run_id, int) or source_run_id < 1:
            raise PlanError("source_run is invalid")
        asset_rows = raw.get("assets")
        if not isinstance(asset_rows, list) or not asset_rows:
            raise PlanError("validated plan assets are missing")
        asset_rows = cast(list[object], asset_rows)
        assets: list[AssetFact] = []
        for index, row in enumerate(asset_rows):
            if not isinstance(row, dict):
                raise PlanError(f"assets[{index}] is not an object")
            row = cast(dict[str, object], row)
            name = row.get("name")
            sha256 = row.get("sha256")
            size = row.get("size")
            if not isinstance(name, str) or not _safe_asset_name(name):
                raise PlanError(f"assets[{index}].name is invalid")
            if not isinstance(sha256, str) or SHA_RE.fullmatch(sha256) is None:
                raise PlanError(f"assets[{index}].sha256 is invalid")
            if isinstance(size, bool) or not isinstance(size, int) or size < 1:
                raise PlanError(f"assets[{index}].size is invalid")
            assets.append(AssetFact(name, sha256, size))
        names = [asset.name for asset in assets]
        if names != sorted(names) or len(names) != len(set(names)):
            raise PlanError("validated plan assets must be unique and sorted")
        required = REQUIRED_DOCUMENTS | REQUIRED_CHECKSUMS
        if not required.issubset(names):
            raise PlanError("validated plan is missing release documents or checksums")
        if profile == "repository-bootstrap":
            if set(names) & REQUIRED_CANDIDATES:
                raise PlanError("repository-bootstrap plan must not contain candidates")
        elif not REQUIRED_CANDIDATES.issubset(names):
            raise PlanError("desktop plan must contain channel candidates")
        asset_hash = raw.get("release_asset_set_sha256")
        if not isinstance(asset_hash, str) or SHA_RE.fullmatch(asset_hash) is None:
            raise PlanError("release_asset_set_sha256 is invalid")
        canonical = [
            {"filename": a.name, "sha256": a.sha256, "size": a.size} for a in assets
        ]
        if (
            hashlib.sha256(
                json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            != asset_hash
        ):
            raise PlanError("release_asset_set_sha256 does not match asset facts")
        attestation_hash = raw.get("staging_attestation_sha256")
        if (
            not isinstance(attestation_hash, str)
            or SHA_RE.fullmatch(attestation_hash) is None
        ):
            raise PlanError("staging_attestation_sha256 is invalid")
        return cls(
            profile,
            tag,
            version,
            source_commit,
            distribution_commit,
            distribution_repository,
            asset_hash,
            attestation_hash,
            tuple(assets),
        )


def _safe_asset_name(name: str) -> bool:
    return (
        bool(name)
        and name not in {".", ".."}
        and "/" not in name
        and "\\" not in name
        and "\x00" not in name
    )


def _staged_assets(root: Path, plan: ValidatedPlan) -> dict[str, Path]:
    if root.is_symlink() or not root.is_dir():
        raise PlanError("staged assets directory must be a real directory")
    expected = {asset.name for asset in plan.assets}
    entries = list(root.iterdir())
    names = {entry.name for entry in entries}
    unexpected = sorted(names - expected - STAGING_ONLY)
    missing = sorted(expected - names)
    if unexpected:
        raise PlanError(f"staged assets contain unexpected entries: {unexpected}")
    if missing:
        raise PlanError(f"staged assets are missing: {missing}")
    for entry in entries:
        if entry.name in STAGING_ONLY:
            continue
        if entry.is_symlink() or not entry.is_file():
            raise PlanError(f"staged asset is not a regular file: {entry.name}")
    attestation = root / "staging-attestation.json"
    if attestation.is_symlink() or not attestation.is_file():
        raise PlanError("staging-attestation.json is missing")
    if (
        hashlib.sha256(attestation.read_bytes()).hexdigest()
        != plan.staging_attestation_sha256
    ):
        raise PlanError("staging attestation does not match the validated plan")
    result: dict[str, Path] = {}
    for asset in plan.assets:
        path = root / asset.name
        content = path.read_bytes()
        if (
            len(content) != asset.size
            or hashlib.sha256(content).hexdigest() != asset.sha256
        ):
            raise PlanError(f"staged asset bytes do not match the plan: {asset.name}")
        result[asset.name] = path
    return result


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()


class GitHubClient:
    """Small concrete GitHub REST client used by the one publish operation."""

    def __init__(
        self, token: str | None = None, repository: str = PUBLIC_REPOSITORY
    ) -> None:
        self.token: str = token or os.environ.get("GH_TOKEN", "")
        if not self.token:
            raise PublishError("GH_TOKEN must be set")
        if repository != PUBLIC_REPOSITORY:
            raise PublishError("repository is not the canonical public repository")
        self.repository: str = repository

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        body: bytes | None = None,
        content_type: str = "application/vnd.github+json",
    ) -> tuple[int, Mapping[str, str], bytes]:
        url = f"https://api.github.com{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "context-engine-release-publisher/1",
        }
        if body is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            url, data=body, headers=headers, method=method.upper()
        )
        try:
            response = cast(_UrlResponse, urllib.request.urlopen(request, timeout=30))
            try:
                return (
                    response.status,
                    dict(response.headers.items()),
                    response.read(MAX_UPLOAD_RESPONSE_BYTES),
                )
            finally:
                response.close()
        except urllib.error.HTTPError as error:
            return (
                error.code,
                dict(error.headers.items()),
                error.read(MAX_RESPONSE_BYTES),
            )
        except (OSError, urllib.error.URLError) as error:
            raise PublishError(f"GitHub request failed: {error}") from error

    def json(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        body: object | None = None,
    ) -> tuple[int, Mapping[str, str], object]:
        status, headers, response_body = self.request(
            method, path, query=query, body=None if body is None else _json_bytes(body)
        )
        if not response_body:
            return status, headers, None
        try:
            return status, headers, json.loads(response_body)
        except json.JSONDecodeError as error:
            raise PublishError(
                f"GitHub returned invalid JSON for {method} {path}"
            ) from error

    def _release_path(self, release_id: int) -> str:
        return f"/repos/{self.repository}/releases/{release_id}"

    def _assets_path(self, release_id: int) -> str:
        return f"{self._release_path(release_id)}/assets"

    def release_by_id(self, release_id: int) -> dict[str, object]:
        status, _, payload = self.json("GET", self._release_path(release_id))
        if status != 200 or not isinstance(payload, dict):
            raise PublishError("GitHub release lookup failed")
        return cast(dict[str, object], payload)

    def release_by_tag(self, tag: str) -> dict[str, object] | None:
        encoded = urllib.parse.quote(tag, safe="")
        status, _, payload = self.json(
            "GET", f"/repos/{self.repository}/releases/tags/{encoded}"
        )
        if status == 200:
            if not isinstance(payload, dict):
                raise PublishError("GitHub release response is not an object")
            return cast(dict[str, object], payload)
        if status != 404:
            raise PublishError(f"GitHub release lookup failed with HTTP {status}")
        matches: list[dict[str, object]] = []
        page = 1
        while True:
            status, _, page_payload = self.json(
                "GET",
                f"/repos/{self.repository}/releases",
                query={"per_page": "100", "page": str(page)},
            )
            if status != 200 or not isinstance(page_payload, list):
                raise PublishError("GitHub release list failed")
            rows = cast(list[object], page_payload)
            for value in rows:
                if not isinstance(value, dict):
                    continue
                value = cast(dict[str, object], value)
                if (
                    value.get("draft") is True
                    and value.get("name") == tag
                    and isinstance(value.get("tag_name"), str)
                    and PLACEHOLDER_RE.fullmatch(cast(str, value["tag_name"]))
                ):
                    matches.append(value)
            if len(rows) < 100:
                break
            page += 1
        if len(matches) > 1:
            raise ReleaseMismatchError(
                "more than one placeholder draft has the requested title"
            )
        return matches[0] if matches else None

    def assets(self, release_id: int) -> list[dict[str, object]]:
        status, _, payload = self.json(
            "GET", self._assets_path(release_id), query={"per_page": "100"}
        )
        if status != 200 or not isinstance(payload, list):
            raise PublishError("GitHub release assets lookup failed")
        return [
            cast(dict[str, object], value)
            for value in cast(list[object], payload)
            if isinstance(value, dict)
        ]

    def create_draft(self, plan: ValidatedPlan) -> dict[str, object]:
        body = {
            "tag_name": plan.tag,
            "target_commitish": plan.distribution_commit,
            "name": plan.tag,
            "body": "Release notes will be added manually before publication.",
            "draft": True,
            "prerelease": False,
        }
        status, _, payload = self.json(
            "POST", f"/repos/{self.repository}/releases", body=body
        )
        if status not in {200, 201} or not isinstance(payload, dict):
            raise PublishError(f"GitHub draft creation failed with HTTP {status}")
        return cast(dict[str, object], payload)

    def upload(self, release_id: int, name: str, content: bytes) -> dict[str, object]:
        path = f"/repos/{self.repository}/releases/{release_id}/assets"
        status, _, payload = self.request(
            "POST",
            path,
            query={"name": name},
            body=content,
            content_type="application/octet-stream",
        )
        if status not in {200, 201}:
            raise PublishError(f"GitHub asset upload failed with HTTP {status}")
        try:
            decoded: object = cast(object, json.loads(payload))
        except json.JSONDecodeError as error:
            raise PublishError("GitHub asset upload response is not JSON") from error
        if not isinstance(decoded, dict):
            raise PublishError("GitHub asset upload response is not an object")
        return cast(dict[str, object], decoded)

    def publish(self, release_id: int, tag: str, target: str) -> dict[str, object]:
        body = {"draft": False, "tag_name": tag, "target_commitish": target}
        status, _, payload = self.json(
            "PATCH", self._release_path(release_id), body=body
        )
        if status != 200 or not isinstance(payload, dict):
            raise PublishError(f"GitHub publication failed with HTTP {status}")
        return cast(dict[str, object], payload)


def _release_id(release: Mapping[str, object]) -> int:
    value = release.get("id")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReleaseMismatchError("release ID is invalid")
    return value


def _metadata(
    release_assets: Sequence[Mapping[str, object]],
) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for value in release_assets:
        name = value.get("name")
        size = value.get("size")
        digest = value.get("digest")
        if (
            not isinstance(name, str)
            or not _safe_asset_name(name)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 1
            or not isinstance(digest, str)
            or ASSET_DIGEST_RE.fullmatch(digest) is None
            or value.get("state") != "uploaded"
        ):
            raise ReleaseMismatchError("GitHub returned invalid release asset metadata")
        if name in result:
            raise ReleaseMismatchError(f"duplicate release asset: {name}")
        result[name] = (size, digest.removeprefix("sha256:"))
    return result


def _existing_metadata(
    release_assets: Sequence[Mapping[str, object]], plan: ValidatedPlan
) -> set[str]:
    actual = _metadata(release_assets)
    expected = {asset.name: (asset.size, asset.sha256) for asset in plan.assets}
    unexpected = sorted(set(actual) - set(expected))
    mismatched = sorted(
        name for name in set(actual) & set(expected) if actual[name] != expected[name]
    )
    if unexpected or mismatched:
        raise ReleaseMismatchError(
            f"release asset metadata differs (unexpected={unexpected}, mismatched={mismatched})"
        )
    return set(actual)


def _assert_metadata(
    release_assets: Sequence[Mapping[str, object]], plan: ValidatedPlan
) -> set[str]:
    actual = _existing_metadata(release_assets, plan)
    missing = sorted({asset.name for asset in plan.assets} - actual)
    if missing:
        raise ReleaseMismatchError(f"release is missing assets: {missing}")
    return actual


def publish(
    plan: ValidatedPlan, staged_assets: Path, client: GitHubClient
) -> dict[str, object]:
    release = client.release_by_tag(plan.tag)
    if release is None:
        release = client.create_draft(plan)
    release_id = _release_id(release)
    draft = release.get("draft")
    if draft is False:
        if (
            release.get("immutable") is not True
            or release.get("tag_name") != plan.tag
            or release.get("name") != plan.tag
            or release.get("target_commitish") != plan.distribution_commit
        ):
            raise ReleaseMismatchError(
                "existing published release identity differs from the plan"
            )
        _ = _assert_metadata(client.assets(release_id), plan)
        return {
            "status": "published",
            "tag": plan.tag,
            "release_id": release_id,
            "reused": True,
        }
    local = _staged_assets(staged_assets, plan)
    if (
        draft is not True
        or release.get("prerelease") is not False
        or release.get("name") != plan.tag
        or release.get("target_commitish") != plan.distribution_commit
        or (
            release.get("tag_name") != plan.tag
            and not (
                isinstance(release.get("tag_name"), str)
                and PLACEHOLDER_RE.fullmatch(cast(str, release["tag_name"]))
            )
        )
    ):
        raise ReleaseMismatchError("existing draft identity differs from the plan")
    existing = _existing_metadata(client.assets(release_id), plan)
    for name in sorted(set(local) - existing):
        uploaded = client.upload(release_id, name, local[name].read_bytes())
        if uploaded.get("name") != name or uploaded.get("state") != "uploaded":
            raise ReleaseMismatchError(
                f"GitHub returned unexpected upload metadata: {name}"
            )
    _ = _assert_metadata(client.assets(release_id), plan)
    published = client.publish(release_id, plan.tag, plan.distribution_commit)
    if published.get("draft") is not False:
        raise ReleaseMismatchError("GitHub did not publish the release")
    final = client.release_by_id(release_id)
    if (
        final.get("draft") is not False
        or final.get("immutable") is not True
        or final.get("published_at") is None
        or final.get("tag_name") != plan.tag
        or final.get("name") != plan.tag
        or final.get("target_commitish") != plan.distribution_commit
    ):
        raise ReleaseMismatchError("published release identity is not immutable")
    _ = _assert_metadata(client.assets(release_id), plan)
    return {
        "status": "published",
        "tag": plan.tag,
        "release_id": release_id,
        "reused": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--plan", type=Path, required=True)
    _ = parser.add_argument("--staged-assets", type=Path, required=True)
    _ = parser.add_argument("--tag", required=True)
    _ = parser.add_argument(
        "--repository", default=os.environ.get("GITHUB_REPOSITORY", PUBLIC_REPOSITORY)
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        plan = ValidatedPlan.from_file(cast(Path, args.plan))
        tag = cast(str, args.tag)
        if plan.tag != tag:
            raise PlanError("input tag does not match the validated plan")
        client = GitHubClient(repository=cast(str, args.repository))
        result = publish(plan, cast(Path, args.staged_assets), client)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (PublishError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
