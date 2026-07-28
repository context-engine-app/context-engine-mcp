"""Publish one fully verified draft release with a single immutable transition."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http import client as http_client
from pathlib import Path
from typing import Protocol, cast, final
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from scripts import prepare_draft_release as draft

REPOSITORY = "context-engine-app/context-engine-mcp"
AUTHORIZED_STAGES = (
    "source-release",
    "public-draft",
    "public-publish",
    "package-channels",
)
WORKFLOW_PATHS = {
    "draft": ".github/workflows/prepare-draft-release.yml",
    "publish": ".github/workflows/publish-draft-release.yml",
    "channels": ".github/workflows/prepare-package-channels.yml",
}
BASE_PLAN_KEYS = {
    "schema_version",
    "profile",
    "tag",
    "version",
    "source_repository",
    "source_commit",
    "distribution_repository",
    "distribution_commit",
    "distribution_tag_target",
    "release_asset_set_sha256",
    "staging_attestation_sha256",
    "source_workflow",
    "public_workflow",
    "source_run",
    "assets",
}
PUBLICATION_PLAN_KEYS = BASE_PLAN_KEYS | {
    "authorized_stages",
    "public_workflows",
    "draft_run",
}
RELEASE_PATH_RE = re.compile(
    r"^/repos/context-engine-app/context-engine-mcp/releases/[1-9][0-9]*$"
)
RELEASE_ASSETS_PATH_RE = re.compile(
    r"^/repos/context-engine-app/context-engine-mcp/releases/[1-9][0-9]*/assets$"
)
RELEASE_TAG_PATH_RE = re.compile(
    r"^/repos/context-engine-app/context-engine-mcp/releases/tags/(?:v|repository-bootstrap-v)(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RECONCILIATION_DELAYS_SECONDS = (0.0, 1.0, 2.0)


class PublisherError(Exception):
    """Base error for publication validation and transport failures."""


class PlanError(PublisherError):
    """The validated publication plan is malformed or inconsistent."""


class ReleaseMismatchError(PublisherError):
    """The remote release differs from the validated publication plan."""


class EndpointError(PublisherError):
    """The requested GitHub endpoint is outside the publisher allowlist."""


@final
class TransportError(PublisherError):
    """A GitHub API request failed before its outcome was known."""

    def __init__(self, message: str, *, ambiguous: bool) -> None:
        super().__init__(message)
        self.ambiguous: bool = ambiguous


class GitHubTransport(Protocol):
    """Transport contract used by the immutable publication coordinator."""

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> draft.Response: ...


class _UrlResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def read(self, amount: int = -1) -> bytes:
        """Read the response body."""

        ...

    def __enter__(self) -> _UrlResponse:
        """Enter the response context."""

        ...

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        """Close the response context."""

        ...


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PlanError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PlanError(f"{label} must be a positive integer")
    return value


def _workflow(value: object, label: str) -> dict[str, str]:
    raw = _mapping(value, label)
    if set(raw) != {"path", "commit", "sha256"}:
        raise PlanError(f"{label} keys are not exact")
    path = raw.get("path")
    commit = raw.get("commit")
    sha256 = raw.get("sha256")
    if not isinstance(path, str):
        raise PlanError(f"{label}.path must be text")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise PlanError(f"{label}.commit must be a lowercase commit")
    if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise PlanError(f"{label}.sha256 must be a lowercase SHA-256")
    return {"path": path, "commit": commit, "sha256": sha256}


@dataclass(frozen=True)
class PublicationPlan:
    """Validated inputs needed for the one-way draft publication transition."""

    release: draft.ValidatedPlan
    authorized_stages: tuple[str, ...]
    public_workflows: Mapping[str, Mapping[str, str]]
    draft_run_id: int
    draft_run_attempt: int

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> PublicationPlan:
        """Validate a portable public-publish plan."""

        if set(raw) != PUBLICATION_PLAN_KEYS:
            raise PlanError("publication plan keys are not exact")
        stages = raw.get("authorized_stages")
        if not isinstance(stages, list):
            raise PlanError("authorized stages must be complete and ordered")
        stage_values = cast(list[object], stages)
        if tuple(stage_values) != AUTHORIZED_STAGES:
            raise PlanError("authorized stages must be complete and ordered")
        core = {key: raw.get(key) for key in BASE_PLAN_KEYS}
        try:
            release = draft.ValidatedPlan.from_mapping(core)
        except draft.PlanError as error:
            raise PlanError(str(error)) from error

        raw_workflows = _mapping(raw.get("public_workflows"), "public_workflows")
        if set(raw_workflows) != set(WORKFLOW_PATHS):
            raise PlanError(
                "public workflows must contain draft, publish, and channels"
            )
        workflows: dict[str, Mapping[str, str]] = {}
        for name, expected_path in WORKFLOW_PATHS.items():
            workflow = _workflow(raw_workflows.get(name), f"public_workflows.{name}")
            if workflow["path"] != expected_path:
                raise PlanError(f"public_workflows.{name}.path is not canonical")
            if workflow["commit"] != release.distribution_commit:
                raise PlanError(
                    f"public_workflows.{name}.commit differs from distribution commit"
                )
            workflows[name] = workflow
        if workflows["draft"] != release.public_workflow:
            raise PlanError("draft workflow differs from the validated release plan")

        draft_run = _mapping(raw.get("draft_run"), "draft_run")
        if set(draft_run) != {"id", "attempt"}:
            raise PlanError("draft_run keys are not exact")
        return cls(
            release=release,
            authorized_stages=AUTHORIZED_STAGES,
            public_workflows=workflows,
            draft_run_id=_positive_integer(draft_run.get("id"), "draft_run.id"),
            draft_run_attempt=_positive_integer(
                draft_run.get("attempt"), "draft_run.attempt"
            ),
        )

    @classmethod
    def from_file(cls, path: Path) -> PublicationPlan:
        """Load and validate a publication plan from one regular JSON file."""

        try:
            if path.is_symlink() or not path.is_file():
                raise PlanError("publication plan must be a regular file")
            decoded = draft.parse_json(path.read_bytes(), "publication plan")
        except OSError as error:
            raise PlanError(f"cannot read publication plan: {error}") from error
        return cls.from_mapping(_mapping(decoded, "publication plan"))


@dataclass(frozen=True)
class _ReleaseSnapshot:
    release_id: int
    tag: str
    name: str
    target: str
    body: str
    assets: tuple[tuple[str, int, str], ...]


def assert_allowed_endpoint(method: str, path: str) -> None:
    """Reject every API route outside the publisher's read and publish closure."""

    allowed = (
        method == "GET"
        and (
            RELEASE_TAG_PATH_RE.fullmatch(path) is not None
            or RELEASE_PATH_RE.fullmatch(path) is not None
            or RELEASE_ASSETS_PATH_RE.fullmatch(path) is not None
        )
    ) or (method == "PATCH" and RELEASE_PATH_RE.fullmatch(path) is not None)
    if not allowed:
        raise EndpointError(f"endpoint is not allowed: {method} {path}")


@final
class UrllibGitHubTransport:
    """Bounded GitHub transport restricted by the publisher endpoint allowlist."""

    def __init__(
        self,
        *,
        token: str,
        api_base: str = "https://api.github.com",
        timeout: float = 30.0,
    ) -> None:
        if not token:
            raise TransportError("GitHub token is empty", ambiguous=False)
        self._token = token
        self._api_base = api_base.rstrip("/")
        self._timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> draft.Response:
        assert_allowed_endpoint(method, path)
        url = self._api_base + path
        if query:
            url += "?" + urllib_parse.urlencode(query)
        request_headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "context-engine-release-publisher",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if headers:
            request_headers.update(headers)
        request = urllib_request.Request(
            url=url,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with cast(
                _UrlResponse,
                cast(
                    object,
                    urllib_request.urlopen(request, timeout=self._timeout),
                ),
            ) as response:
                status = response.status
                response_headers = dict(response.headers.items())
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib_error.HTTPError as error:
            ambiguous = method == "PATCH" and (
                error.code in {408, 409, 422, 429} or error.code >= 500
            )
            try:
                response_body = error.read(MAX_RESPONSE_BYTES + 1)
            except (http_client.HTTPException, TimeoutError, OSError) as read_error:
                raise TransportError(
                    "GitHub error response could not be read",
                    ambiguous=ambiguous,
                ) from read_error
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise TransportError(
                    "GitHub response exceeds the size limit",
                    ambiguous=ambiguous,
                ) from error
            if ambiguous:
                raise TransportError(
                    f"GitHub publish request returned HTTP {error.code}",
                    ambiguous=True,
                ) from error
            return draft.Response(
                error.code, dict(error.headers.items()), response_body
            )
        except (
            http_client.HTTPException,
            urllib_error.URLError,
            TimeoutError,
            OSError,
        ) as error:
            raise TransportError(
                f"GitHub request failed: {error}",
                ambiguous=method == "PATCH",
            ) from error
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise TransportError(
                "GitHub response exceeds the size limit",
                ambiguous=method == "PATCH",
            )
        return draft.Response(status, response_headers, response_body)


@final
class Publisher:
    """Validate and publish exactly one complete draft release."""

    def __init__(self, transport: GitHubTransport, *, repository: str) -> None:
        if repository != REPOSITORY:
            raise PlanError("repository is not the canonical public repository")
        self._transport = transport
        self._repository = repository

    def publish(self, plan: PublicationPlan, *, draft_run_id: int) -> dict[str, object]:
        """Publish the verified draft or reconcile one ambiguous publish request."""

        if draft_run_id != plan.draft_run_id:
            raise PlanError("draft run ID differs from the publication plan")
        release = self._get_release_by_tag(plan.release.tag)
        snapshot = self._validate_draft(release, plan)
        path = self._release_path(snapshot.release_id)
        body = b'{"draft":false}'
        assert_allowed_endpoint("PATCH", path)
        try:
            response = self._transport.request(
                "PATCH",
                path,
                headers={"Content-Type": "application/json"},
                body=body,
            )
        except TransportError as error:
            if not error.ambiguous:
                raise
            self._reconcile_published(snapshot)
            return {
                "status": "published",
                "tag": snapshot.tag,
                "release_id": snapshot.release_id,
                "reconciled": True,
            }
        if response.status != 200:
            raise TransportError(
                f"GitHub publish request returned HTTP {response.status}",
                ambiguous=False,
            )
        self._reconcile_published(snapshot)
        return {
            "status": "published",
            "tag": snapshot.tag,
            "release_id": snapshot.release_id,
            "reconciled": False,
        }

    def _reconcile_published(self, snapshot: _ReleaseSnapshot) -> None:
        last_error: Exception | None = None
        for delay in RECONCILIATION_DELAYS_SECONDS:
            if delay > 0:
                time.sleep(delay)
            try:
                reconciled = self._get_release_by_id(snapshot.release_id)
                self._validate_published(reconciled, snapshot)
                return
            except (
                ReleaseMismatchError,
                TransportError,
                PlanError,
                draft.CoordinatorError,
            ) as error:
                last_error = error
        if last_error is not None:
            raise ReleaseMismatchError(
                "published release did not reconcile within the bounded retry window: "
                + str(last_error)
            ) from last_error
        raise ReleaseMismatchError(
            "publication reconciliation attempts are not configured"
        )

    def _validate_draft(
        self, release: Mapping[str, object], plan: PublicationPlan
    ) -> _ReleaseSnapshot:
        if release.get("draft") is not True:
            raise ReleaseMismatchError("release must be a draft before publication")
        if release.get("immutable") is not False:
            raise ReleaseMismatchError("draft release must not be immutable")
        if release.get("published_at") is not None:
            raise ReleaseMismatchError(
                "draft release already has a publication timestamp"
            )
        if release.get("prerelease") is not False:
            raise ReleaseMismatchError("release must not be a prerelease")
        release_id = self._release_id(release)
        tag = self._text(release.get("tag_name"), "release tag")
        name = self._text(release.get("name"), "release name")
        target = self._text(release.get("target_commitish"), "release target")
        body = self._text(release.get("body"), "release body")
        if (
            tag != plan.release.tag
            or name != plan.release.tag
            or target != plan.release.distribution_commit
        ):
            raise ReleaseMismatchError("draft release identity differs from the plan")
        marker = draft.parse_marker_body(body)
        expected_marker = {
            "tag": plan.release.tag,
            "release_version": plan.release.version,
            "profile": plan.release.profile,
            "source_commit": plan.release.source_commit,
            "distribution_commit": plan.release.distribution_commit,
            "release_asset_set_sha256": plan.release.release_asset_set_sha256,
            "staging_attestation_sha256": plan.release.staging_attestation_sha256,
            "source_run_id": plan.release.source_run["id"],
            "source_run_attempt": plan.release.source_run["attempt"],
            "source_workflow_sha256": plan.release.source_workflow["sha256"],
            "public_workflow_sha256": plan.release.public_workflow["sha256"],
            "state": "verified",
            "verified_run_id": plan.draft_run_id,
            "verified_run_attempt": plan.draft_run_attempt,
        }
        for key, expected in expected_marker.items():
            if marker.get(key) != expected:
                raise ReleaseMismatchError(f"draft marker differs for {key}")
        return _ReleaseSnapshot(
            release_id=release_id,
            tag=tag,
            name=name,
            target=target,
            body=body,
            assets=self._asset_snapshot(release_id, plan),
        )

    def _validate_published(
        self, release: Mapping[str, object], snapshot: _ReleaseSnapshot
    ) -> None:
        if release.get("draft") is not False:
            raise ReleaseMismatchError("published release still reports draft state")
        if release.get("immutable") is not True:
            raise ReleaseMismatchError("published release is not immutable")
        published_at = release.get("published_at")
        if not isinstance(published_at, str) or not published_at:
            raise ReleaseMismatchError("published release has no publication timestamp")
        if release.get("prerelease") is not False:
            raise ReleaseMismatchError("published release became a prerelease")
        observed = (
            self._release_id(release),
            self._text(release.get("tag_name"), "published tag"),
            self._text(release.get("name"), "published name"),
            self._text(release.get("target_commitish"), "published target"),
            self._text(release.get("body"), "published body"),
        )
        expected = (
            snapshot.release_id,
            snapshot.tag,
            snapshot.name,
            snapshot.target,
            snapshot.body,
        )
        if observed != expected:
            raise ReleaseMismatchError("published release identity changed")
        assets = self._asset_snapshot(snapshot.release_id, None)
        if assets != snapshot.assets:
            raise ReleaseMismatchError("published release asset metadata changed")

    def _asset_snapshot(
        self, release_id: int, plan: PublicationPlan | None
    ) -> tuple[tuple[str, int, str], ...]:
        response = self._request("GET", self._assets_path(release_id))
        if response.status != 200:
            raise TransportError(
                f"GitHub asset request returned HTTP {response.status}",
                ambiguous=False,
            )
        decoded = draft.parse_json(response.body, "release assets")
        if not isinstance(decoded, list):
            raise ReleaseMismatchError("release assets response is not an array")
        rows: list[tuple[str, int, str]] = []
        for index, value in enumerate(cast(list[object], decoded)):
            item = _mapping(value, f"release asset {index}")
            name = self._text(item.get("name"), f"release asset {index} name")
            size = item.get("size")
            digest = item.get("digest")
            state = item.get("state")
            if isinstance(size, bool) or not isinstance(size, int) or size < 1:
                raise ReleaseMismatchError(f"release asset {name} has invalid size")
            if state != "uploaded":
                raise ReleaseMismatchError(f"release asset {name} is not uploaded")
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            ):
                raise ReleaseMismatchError(f"release asset {name} has invalid digest")
            rows.append((name, size, digest))
        rows.sort()
        if len(rows) != len(set(rows)):
            raise ReleaseMismatchError("release contains duplicate asset metadata")
        if plan is not None:
            expected = tuple(
                sorted(
                    (fact.name, fact.size, f"sha256:{fact.sha256}")
                    for fact in plan.release.assets
                )
            )
            if tuple(rows) != expected:
                raise ReleaseMismatchError("draft release assets differ from the plan")
        return tuple(rows)

    def _get_release_by_tag(self, tag: str) -> Mapping[str, object]:
        encoded = urllib_parse.quote(tag, safe="")
        response = self._request("GET", f"{self._releases_path()}/tags/{encoded}")
        if response.status != 200:
            raise TransportError(
                f"GitHub release request returned HTTP {response.status}",
                ambiguous=False,
            )
        return self._response_object(response, "release response")

    def _get_release_by_id(self, release_id: int) -> Mapping[str, object]:
        response = self._request("GET", self._release_path(release_id))
        if response.status != 200:
            raise TransportError(
                f"GitHub release reconciliation returned HTTP {response.status}",
                ambiguous=False,
            )
        return self._response_object(response, "release reconciliation response")

    def _request(self, method: str, path: str) -> draft.Response:
        assert_allowed_endpoint(method, path)
        return self._transport.request(method, path, query={"per_page": "100"})

    @staticmethod
    def _response_object(response: draft.Response, label: str) -> Mapping[str, object]:
        decoded = draft.parse_json(response.body, label)
        return _mapping(decoded, label)

    @staticmethod
    def _release_id(release: Mapping[str, object]) -> int:
        value = release.get("id")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ReleaseMismatchError("release ID must be a positive integer")
        return value

    @staticmethod
    def _text(value: object, label: str) -> str:
        if not isinstance(value, str):
            raise ReleaseMismatchError(f"{label} must be text")
        return value

    def _releases_path(self) -> str:
        return f"/repos/{self._repository}/releases"

    def _release_path(self, release_id: int) -> str:
        return f"{self._releases_path()}/{release_id}"

    def _assets_path(self, release_id: int) -> str:
        return f"{self._release_path(release_id)}/assets"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--plan", type=Path, required=True)
    _ = parser.add_argument("--repository", default=REPOSITORY)
    _ = parser.add_argument("--draft-run-id", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the immutable draft publisher."""

    args = _parser().parse_args(argv)
    values = cast(Mapping[str, object], vars(args))
    plan_path = values.get("plan")
    repository = values.get("repository")
    draft_run_id = values.get("draft_run_id")
    token = os.environ.get("GH_TOKEN")
    if (
        not isinstance(plan_path, Path)
        or not isinstance(repository, str)
        or isinstance(draft_run_id, bool)
        or not isinstance(draft_run_id, int)
        or not token
    ):
        return 2
    try:
        plan = PublicationPlan.from_file(plan_path)
        result = Publisher(
            UrllibGitHubTransport(token=token),
            repository=repository,
        ).publish(plan, draft_run_id=draft_run_id)
    except (PublisherError, draft.CoordinatorError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
