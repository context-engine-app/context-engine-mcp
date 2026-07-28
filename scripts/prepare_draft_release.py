#!/usr/bin/env python3
"""Prepare and verify a public GitHub draft release.

The private release workflow produces a validated plan and a short-lived
staging envelope.  This module deliberately keeps the public-repository
operation small: it can create or resume one exact draft, upload only missing
assets, and verify the result.  It has no operation for publishing, deleting,
or replacing an asset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Protocol, cast


PUBLIC_RELEASE_REPOSITORY = "context-engine-app/context-engine-mcp"
SOURCE_RELEASE_REPOSITORY = "context-engine-app/context-engine"
SOURCE_WORKFLOW_PATH = ".github/workflows/release.yml"
PUBLIC_WORKFLOW_PATH = ".github/workflows/prepare-draft-release.yml"
STAGING_ONLY_NAMES = frozenset(
    {"staging-attestation.json", "staging-attestation.sigstore.json"}
)
RELEASE_DOCUMENT_NAMES = frozenset({"release-manifest.json", "release-provenance.json"})
CHECKSUM_NAMES = frozenset({"SHA256SUMS", "SHA256SUMS.sigstore.json"})
CANDIDATE_NAMES = frozenset({"channel-candidates.json", "channel-candidates.tar.gz"})
PROFILES = frozenset({"desktop", "desktop-linux", "repository-bootstrap"})
MARKER_KEYS = (
    "distribution_commit",
    "marker_version",
    "profile",
    "public_workflow_sha256",
    "release_asset_set_sha256",
    "release_version",
    "source_commit",
    "source_run_attempt",
    "source_run_id",
    "source_workflow_sha256",
    "staging_artifact_digest",
    "staging_artifact_expires_at",
    "staging_artifact_id",
    "staging_attestation_sha256",
    "state",
    "tag",
    "verified_run_attempt",
    "verified_run_id",
)
MARKER_VERSION = 1
MARKER_PREFIX = "<!-- context-engine-draft:v1\n"
MARKER_SUFFIX = "\n-->"
VISIBLE_RELEASE_LINE = "Release notes will be added manually before publication."
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(
    r"^(?:v|repository-bootstrap-v)((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$"
)
ARTIFACT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ASSET_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MIN_MUTATION_LEAD_SECONDS = 3600
MAX_JSON_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_WIRE_RESPONSE_BYTES = 256 * 1024 * 1024
JsonObject = dict[str, object]


def _is_safe_flat_asset_name(name: str) -> bool:
    return (
        bool(name)
        and name not in {".", ".."}
        and "/" not in name
        and "\\" not in name
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in name)
    )


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


def _read_bounded(response: _UrlResponse, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size <= limit:
        chunk = response.read(min(1024 * 1024, limit - size + 1))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise CoordinatorError("GitHub response exceeds the wire response limit")
    raise CoordinatorError("GitHub response exceeds the wire response limit")


class CoordinatorError(Exception):
    """Base class for safe coordinator failures."""


class DuplicateJsonKeyError(ValueError):
    """A JSON object contains the same key more than once."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(value: str | bytes, label: str) -> object:
    try:
        return cast(
            object, json.loads(value, object_pairs_hook=_reject_duplicate_json_keys)
        )
    except (DuplicateJsonKeyError, json.JSONDecodeError) as error:
        raise CoordinatorError(f"{label} is not valid JSON: {error}") from error


class PlanError(CoordinatorError):
    """The input plan is not a validated desktop release plan."""


class ReleaseMismatchError(CoordinatorError):
    """An existing release or asset does not match the validated plan."""


class PublishedReleaseError(ReleaseMismatchError):
    """The requested tag already identifies a published release."""


class ExpiredArtifactError(CoordinatorError):
    """The source staging artifact is no longer available for mutation."""


class TransportError(CoordinatorError):
    """A transport failure whose mutation outcome may be unknown."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        ambiguous: bool = True,
    ) -> None:
        super().__init__(message)
        self.status: int | None = status
        self.headers: dict[str, str] = dict(headers or {})
        self.body: bytes = body
        self.ambiguous: bool = ambiguous


class HttpError(TransportError):
    """An HTTP response outside the operation's expected status set."""

    def __init__(
        self,
        status: int,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        ambiguous: bool = False,
    ) -> None:
        super().__init__(
            f"GitHub REST request failed with HTTP {status}",
            status=status,
            headers=headers,
            body=body,
            ambiguous=ambiguous,
        )


@dataclass(frozen=True)
class Response:
    """A testable, decoded-independent REST response."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class GitHubTransport(Protocol):
    """Minimal transport used by the coordinator and its tests."""

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        """Issue one allow-listed REST request."""

        ...


def _path_allowed(method: str, path: str) -> bool:
    if not method or not path or "?" in path or not path.startswith("/"):
        return False
    method = method.upper()
    escaped_id = r"[0-9]+"
    route_patterns = (
        ("GET", r"^/repos/[^/]+/[^/]+/releases/tags/[^/]+$"),
        ("POST", r"^/repos/[^/]+/[^/]+/releases$"),
        ("GET", rf"^/repos/[^/]+/[^/]+/releases/{escaped_id}$"),
        ("PATCH", rf"^/repos/[^/]+/[^/]+/releases/{escaped_id}$"),
        ("GET", rf"^/repos/[^/]+/[^/]+/releases/{escaped_id}/assets$"),
        ("POST", rf"^/repos/[^/]+/[^/]+/releases/{escaped_id}/assets$"),
        ("GET", rf"^/repos/[^/]+/[^/]+/releases/assets/{escaped_id}$"),
    )
    return any(
        method == allowed_method and re.fullmatch(pattern, path) is not None
        for allowed_method, pattern in route_patterns
    )


def assert_allowed_endpoint(method: str, path: str) -> None:
    """Reject every REST operation outside the coordinator allow-list."""

    if not _path_allowed(method, path):
        raise CoordinatorError(f"endpoint is not allowed: {method.upper()} {path}")


class UrllibGitHubTransport:
    """GitHub REST transport using ``GH_TOKEN`` without exposing it in argv."""

    def __init__(
        self,
        *,
        token: str | None = None,
        api_base: str = "https://api.github.com",
        uploads_base: str = "https://uploads.github.com",
        timeout: float = 30.0,
    ) -> None:
        resolved_token = token if token is not None else os.environ.get("GH_TOKEN")
        if not resolved_token:
            raise CoordinatorError("GH_TOKEN must be provided through the environment")
        self._token: str = resolved_token
        self._api_base: str = api_base.rstrip("/")
        self._uploads_base: str = uploads_base.rstrip("/")
        self._timeout: float = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        method = method.upper()
        assert_allowed_endpoint(method, path)
        query_string = urllib.parse.urlencode(query or {})
        base = (
            self._uploads_base
            if method == "POST" and path.endswith("/assets")
            else self._api_base
        )
        url = f"{base}{path}"
        if query_string:
            url = f"{url}?{query_string}"
        request_headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "context-engine-draft-coordinator/1",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method=method
        )
        try:
            with cast(
                _UrlResponse,
                cast(object, urllib.request.urlopen(request, timeout=self._timeout)),
            ) as response:
                return Response(
                    response.status,
                    dict(response.headers.items()),
                    _read_bounded(response, MAX_WIRE_RESPONSE_BYTES),
                )
        except urllib.error.HTTPError as error:
            response_body = _read_bounded(
                cast(_UrlResponse, cast(object, error)), MAX_JSON_RESPONSE_BYTES
            )
            ambiguous = method in {"POST", "PATCH"} and (
                error.code in {408, 409, 422, 429} or error.code >= 500
            )
            raise HttpError(
                error.code,
                headers=dict(error.headers.items()),
                body=response_body,
                ambiguous=ambiguous,
            ) from error
        except (TimeoutError, urllib.error.URLError, OSError) as error:
            raise TransportError(
                f"GitHub REST transport failed: {error}", ambiguous=True
            ) from error


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _json_object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise CoordinatorError(f"{label} must be a JSON object with string keys")
    candidate = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in candidate):
        raise CoordinatorError(f"{label} must be a JSON object with string keys")
    return cast(JsonObject, value)


def _json_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PlanError(f"{label} must be an object with string keys")
    candidate = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in candidate):
        raise PlanError(f"{label} must be an object with string keys")
    return cast(Mapping[str, object], value)


def canonical_sha256(value: object) -> str:
    """Return the plan's canonical JSON SHA-256 digest."""

    return hashlib.sha256(_canonical_json(value)).hexdigest()


def parse_timestamp(value: str | datetime) -> datetime:
    """Parse an RFC3339 timestamp and normalize it to UTC."""

    if isinstance(value, datetime):
        result = value
    else:
        text = value.strip()
        if not text:
            raise PlanError("timestamp must not be empty")
        try:
            result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as error:
            raise PlanError(f"invalid RFC3339 timestamp: {value!r}") from error
    if result.tzinfo is None:
        raise PlanError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def _timestamp_text(value: str | datetime) -> str:
    result = parse_timestamp(value)
    text = result.isoformat()
    return text[:-6] + "Z" if text.endswith("+00:00") else text


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlanError(f"{label} must be a non-empty string")
    return value


def _require_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PlanError(f"{label} must be a positive integer")
    return value


def _require_sha(value: object, label: str) -> str:
    text = _require_string(value, label)
    if SHA256_RE.fullmatch(text) is None:
        raise PlanError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _require_commit(value: object, label: str) -> str:
    text = _require_string(value, label)
    if COMMIT_RE.fullmatch(text) is None:
        raise PlanError(f"{label} must be a lowercase 40-character commit")
    return text


def _require_exact_keys(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise PlanError(f"{label} keys differ (missing={missing}, extra={extra})")


@dataclass(frozen=True)
class AssetFact:
    """One validated public release asset."""

    name: str
    sha256: str
    size: int

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class ValidatedPlan:
    """Strict representation of the portable validator's output plan."""

    schema_version: int
    profile: str
    tag: str
    version: str
    source_repository: str
    source_commit: str
    distribution_repository: str
    distribution_commit: str
    distribution_tag_target: str
    release_asset_set_sha256: str
    staging_attestation_sha256: str
    source_workflow: Mapping[str, str]
    public_workflow: Mapping[str, str]
    source_run: Mapping[str, object]
    assets: tuple[AssetFact, ...]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> ValidatedPlan:
        expected = {
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
        _require_exact_keys(raw, expected, "validated plan")
        if raw["schema_version"] != 1:
            raise PlanError("validated plan schema_version must be 1")
        profile = _require_string(raw["profile"], "profile")
        if profile not in PROFILES:
            raise PlanError("validated plan profile is unsupported")
        tag = _require_string(raw["tag"], "tag")
        tag_match = TAG_RE.fullmatch(tag)
        if tag_match is None:
            raise PlanError(
                "tag must be vMAJOR.MINOR.PATCH or repository-bootstrap-vMAJOR.MINOR.PATCH"
            )
        version = _require_string(raw["version"], "version")
        if version != tag_match.group(1):
            raise PlanError("version does not match tag")
        expected_tag = (
            f"repository-bootstrap-v{version}"
            if profile == "repository-bootstrap"
            else f"v{version}"
        )
        if tag != expected_tag:
            raise PlanError("tag does not match profile")
        source_repository = _require_string(
            raw["source_repository"], "source_repository"
        )
        distribution_repository = _require_string(
            raw["distribution_repository"], "distribution_repository"
        )
        if source_repository != SOURCE_RELEASE_REPOSITORY:
            raise PlanError("source_repository is not the protected source repository")
        if distribution_repository != PUBLIC_RELEASE_REPOSITORY:
            raise PlanError(
                "distribution_repository is not the public release repository"
            )
        source_commit = _require_commit(raw["source_commit"], "source_commit")
        distribution_commit = _require_commit(
            raw["distribution_commit"], "distribution_commit"
        )
        if raw["distribution_tag_target"] != distribution_commit:
            raise PlanError("distribution_tag_target must equal distribution_commit")
        distribution_tag_target = _require_commit(
            raw["distribution_tag_target"], "distribution_tag_target"
        )
        release_asset_set_sha256 = _require_sha(
            raw["release_asset_set_sha256"], "release_asset_set_sha256"
        )
        staging_attestation_sha256 = _require_sha(
            raw["staging_attestation_sha256"], "staging_attestation_sha256"
        )

        source_workflow_raw = raw["source_workflow"]
        public_workflow_raw = raw["public_workflow"]
        source_run_raw = raw["source_run"]
        source_workflow_raw = _json_mapping(source_workflow_raw, "source_workflow")
        public_workflow_raw = _json_mapping(public_workflow_raw, "public_workflow")
        source_run_raw = _json_mapping(source_run_raw, "source_run")
        workflow_keys = {"path", "commit", "sha256"}
        _require_exact_keys(source_workflow_raw, workflow_keys, "source_workflow")
        _require_exact_keys(public_workflow_raw, workflow_keys, "public_workflow")
        _require_exact_keys(source_run_raw, {"id", "attempt", "url"}, "source_run")
        source_workflow = {
            "path": _require_string(
                source_workflow_raw["path"], "source_workflow.path"
            ),
            "commit": _require_commit(
                source_workflow_raw["commit"], "source_workflow.commit"
            ),
            "sha256": _require_sha(
                source_workflow_raw["sha256"], "source_workflow.sha256"
            ),
        }
        public_workflow = {
            "path": _require_string(
                public_workflow_raw["path"], "public_workflow.path"
            ),
            "commit": _require_commit(
                public_workflow_raw["commit"], "public_workflow.commit"
            ),
            "sha256": _require_sha(
                public_workflow_raw["sha256"], "public_workflow.sha256"
            ),
        }
        if source_workflow["path"] != SOURCE_WORKFLOW_PATH:
            raise PlanError(
                "source_workflow.path is not the protected release workflow"
            )
        if public_workflow["path"] != PUBLIC_WORKFLOW_PATH:
            raise PlanError("public_workflow.path is not the public draft workflow")
        source_run_id = _require_integer(source_run_raw["id"], "source_run.id")
        source_run_attempt = _require_integer(
            source_run_raw["attempt"], "source_run.attempt"
        )
        source_run_url = _require_string(source_run_raw["url"], "source_run.url")
        expected_source_run_url = f"https://github.com/{SOURCE_RELEASE_REPOSITORY}/actions/runs/{source_run_id}"
        if source_run_url != expected_source_run_url:
            raise PlanError("source_run.url is not the canonical source workflow URL")
        source_run = {
            "id": source_run_id,
            "attempt": source_run_attempt,
            "url": source_run_url,
        }

        raw_assets = raw["assets"]
        if not isinstance(raw_assets, list) or not cast(list[object], raw_assets):
            raise PlanError("assets must contain at least one entry")
        raw_asset_list = cast(list[object], raw_assets)
        assets: list[AssetFact] = []
        for index, raw_asset_value in enumerate(raw_asset_list):
            raw_asset = _json_mapping(raw_asset_value, f"assets[{index}]")
            _require_exact_keys(
                raw_asset, {"name", "sha256", "size"}, f"assets[{index}]"
            )
            name = _require_string(raw_asset["name"], f"assets[{index}].name")
            if not _is_safe_flat_asset_name(name):
                raise PlanError(f"assets[{index}].name is not an allowed public asset")
            assets.append(
                AssetFact(
                    name=name,
                    sha256=_require_sha(raw_asset["sha256"], f"assets[{index}].sha256"),
                    size=_require_integer(raw_asset["size"], f"assets[{index}].size"),
                )
            )
        names = [asset.name for asset in assets]
        if len(set(names)) != len(names):
            raise PlanError("assets must contain each validated asset exactly once")
        if names != sorted(names):
            raise PlanError("assets must be sorted by name")
        name_set = set(names)
        if not (RELEASE_DOCUMENT_NAMES | CHECKSUM_NAMES).issubset(name_set):
            raise PlanError(
                "validated plans must contain release documents and checksum assets"
            )
        if profile == "repository-bootstrap":
            if name_set & CANDIDATE_NAMES:
                raise PlanError(
                    "repository-bootstrap plans must not contain channel candidates"
                )
        elif not CANDIDATE_NAMES.issubset(name_set):
            raise PlanError(
                "CLI release plans must contain both channel candidate assets"
            )
        if (
            canonical_sha256([asset.as_dict() for asset in assets])
            != release_asset_set_sha256
        ):
            raise PlanError(
                "release_asset_set_sha256 does not match canonical asset facts"
            )
        return cls(
            schema_version=1,
            profile=profile,
            tag=tag,
            version=version,
            source_repository=source_repository,
            source_commit=source_commit,
            distribution_repository=distribution_repository,
            distribution_commit=distribution_commit,
            distribution_tag_target=distribution_tag_target,
            release_asset_set_sha256=release_asset_set_sha256,
            staging_attestation_sha256=staging_attestation_sha256,
            source_workflow=source_workflow,
            public_workflow=public_workflow,
            source_run=source_run,
            assets=tuple(assets),
        )

    @classmethod
    def from_file(cls, path: Path) -> ValidatedPlan:
        try:
            raw = parse_json(path.read_text(encoding="utf-8"), "validated plan")
        except (CoordinatorError, OSError) as error:
            raise PlanError(f"could not read validated plan {path}: {error}") from error
        return cls.from_mapping(_json_mapping(raw, "validated plan"))

    def asset_facts(self) -> dict[str, AssetFact]:
        return {asset.name: asset for asset in self.assets}

    def asset_names(self) -> frozenset[str]:
        """Return the exact release asset closure emitted by the validator."""

        return frozenset(asset.name for asset in self.assets)


def marker_metadata(
    plan: ValidatedPlan,
    *,
    artifact_id: int,
    artifact_digest: str,
    artifact_expires_at: str | datetime,
    state: str,
    verified_run_id: int | None = None,
    verified_run_attempt: int | None = None,
) -> dict[str, object]:
    """Build the exact marker object for one coordinator state."""

    if state not in {"preparing", "verified"}:
        raise PlanError("marker state must be preparing or verified")
    if state == "preparing" and (
        verified_run_id is not None or verified_run_attempt is not None
    ):
        raise PlanError("preparing marker cannot contain verified run facts")
    if state == "verified" and (
        verified_run_id is None or verified_run_attempt is None
    ):
        raise PlanError("verified marker requires verified run facts")
    if artifact_id < 1:
        raise PlanError("staging artifact id must be positive")
    if ARTIFACT_DIGEST_RE.fullmatch(artifact_digest) is None:
        raise PlanError("staging artifact digest must be sha256 hex")
    result: dict[str, object] = {
        "distribution_commit": plan.distribution_commit,
        "marker_version": MARKER_VERSION,
        "profile": plan.profile,
        "public_workflow_sha256": plan.public_workflow["sha256"],
        "release_asset_set_sha256": plan.release_asset_set_sha256,
        "release_version": plan.version,
        "source_commit": plan.source_commit,
        "source_run_attempt": plan.source_run["attempt"],
        "source_run_id": plan.source_run["id"],
        "source_workflow_sha256": plan.source_workflow["sha256"],
        "staging_artifact_digest": artifact_digest,
        "staging_artifact_expires_at": _timestamp_text(artifact_expires_at),
        "staging_artifact_id": artifact_id,
        "staging_attestation_sha256": plan.staging_attestation_sha256,
        "state": state,
        "tag": plan.tag,
        "verified_run_attempt": verified_run_attempt,
        "verified_run_id": verified_run_id,
    }
    if tuple(result) != MARKER_KEYS:
        raise AssertionError("marker key order drifted")
    return result


def render_body(
    marker: Mapping[str, object], *, visible_prefix: str = VISIBLE_RELEASE_LINE
) -> str:
    """Render a visible note and one final canonical marker."""

    if set(marker) != set(MARKER_KEYS):
        raise PlanError("marker has an unexpected key set")
    marker_json = _canonical_json(marker).decode("utf-8")
    return f"{visible_prefix}\n\n{MARKER_PREFIX}{marker_json}{MARKER_SUFFIX}"


def parse_marker_body(body: str) -> dict[str, object]:
    """Parse and validate the unique final canonical marker in a release body."""

    if body.count(MARKER_PREFIX) != 1:
        raise ReleaseMismatchError("release body must contain exactly one draft marker")
    marker_start = body.index(MARKER_PREFIX)
    marker_text = body[marker_start + len(MARKER_PREFIX) :]
    if not marker_text.endswith(MARKER_SUFFIX):
        raise ReleaseMismatchError("draft marker must be the final body content")
    marker_json = marker_text[: -len(MARKER_SUFFIX)]
    if "\n" in marker_json or "\r" in marker_json:
        raise ReleaseMismatchError("draft marker JSON must occupy one line")
    try:
        decoded = parse_json(marker_json, "draft marker")
    except CoordinatorError as error:
        raise ReleaseMismatchError("draft marker is not valid JSON") from error
    decoded_object = _json_object(decoded, "draft marker")
    if set(decoded_object) != set(MARKER_KEYS):
        raise ReleaseMismatchError("draft marker has an unexpected key set")
    if decoded_object.get("marker_version") != MARKER_VERSION:
        raise ReleaseMismatchError("draft marker version is unsupported")
    if _canonical_json(decoded_object).decode("utf-8") != marker_json:
        raise ReleaseMismatchError("draft marker JSON is not canonical")
    state = decoded_object.get("state")
    if state not in {"preparing", "verified"}:
        raise ReleaseMismatchError("draft marker state is unsupported")
    if state == "preparing" and (
        decoded_object.get("verified_run_id") is not None
        or decoded_object.get("verified_run_attempt") is not None
    ):
        raise ReleaseMismatchError(
            "preparing marker must not contain verified run facts"
        )
    if state == "verified":
        _ = _require_positive_marker_int(
            decoded_object.get("verified_run_id"), "verified_run_id"
        )
        _ = _require_positive_marker_int(
            decoded_object.get("verified_run_attempt"), "verified_run_attempt"
        )
    _ = _require_positive_marker_int(
        decoded_object.get("source_run_id"), "source_run_id"
    )
    _ = _require_positive_marker_int(
        decoded_object.get("source_run_attempt"), "source_run_attempt"
    )
    _ = _require_positive_marker_int(
        decoded_object.get("staging_artifact_id"), "staging_artifact_id"
    )
    return decoded_object


def _require_positive_marker_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ReleaseMismatchError(f"marker {label} must be a positive integer")
    return value


@dataclass(frozen=True)
class RemoteAsset:
    id: int
    name: str
    size: int
    digest: str | None


class DraftReleaseCoordinator:
    """Create/resume and verify one immutable public draft release."""

    def __init__(
        self,
        transport: GitHubTransport,
        *,
        repository: str,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 3,
        max_retry_delay: float = 10.0,
    ) -> None:
        if repository != PUBLIC_RELEASE_REPOSITORY:
            raise CoordinatorError(f"repository must be {PUBLIC_RELEASE_REPOSITORY}")
        if max_attempts < 1:
            raise CoordinatorError("max_attempts must be positive")
        self.transport: GitHubTransport = transport
        self.repository: str = repository
        self.now: Callable[[], datetime] = now
        self.sleep: Callable[[float], None] = sleep
        self.max_attempts: int = max_attempts
        self.max_retry_delay: float = max_retry_delay

    def prepare(
        self,
        plan: ValidatedPlan | Mapping[str, object],
        staged_assets: Path,
        *,
        artifact_id: int,
        artifact_digest: str,
        artifact_expires_at: str | datetime,
        public_run_id: int,
        public_run_attempt: int,
    ) -> dict[str, object]:
        """Prepare, upload, verify, and mark a release, without publishing it."""

        normalized_plan = (
            plan
            if isinstance(plan, ValidatedPlan)
            else ValidatedPlan.from_mapping(plan)
        )
        if normalized_plan.distribution_repository != self.repository:
            raise PlanError(
                "validated plan distribution_repository does not match repository"
            )
        if artifact_id < 1 or public_run_id < 1 or public_run_attempt < 1:
            raise PlanError("artifact and public run facts must be positive integers")
        if ARTIFACT_DIGEST_RE.fullmatch(artifact_digest) is None:
            raise PlanError("staging artifact digest must be sha256 hex")
        expiry_text = _timestamp_text(artifact_expires_at)
        expiry = parse_timestamp(expiry_text)
        local_assets = self._load_staged_assets(staged_assets, normalized_plan)
        preparing_marker = marker_metadata(
            normalized_plan,
            artifact_id=artifact_id,
            artifact_digest=artifact_digest,
            artifact_expires_at=expiry_text,
            state="preparing",
        )
        preparing_body = render_body(preparing_marker)
        release = self._get_release(normalized_plan.tag)
        if release is None:
            release = self._create_release(normalized_plan, preparing_body, expiry)
            read_only = False
        else:
            self._validate_release_identity(release, normalized_plan)
            marker = self._validate_existing_body(
                release, normalized_plan, preparing_marker
            )
            if marker["state"] == "verified":
                self._verify_assets(release, local_assets, normalized_plan)
                return self._result(
                    release,
                    state="verified",
                    read_only=True,
                    asset_count=len(local_assets),
                )
            read_only = False

        existing_assets = self._list_assets(release, normalized_plan)
        self._compare_existing_assets(existing_assets, local_assets, normalized_plan)
        for name in sorted(
            set(local_assets) - {asset.name for asset in existing_assets}
        ):
            self._upload_missing(
                release,
                name,
                local_assets[name].read_bytes(),
                expiry,
                local_assets,
                normalized_plan,
            )
        self._verify_assets(release, local_assets, normalized_plan)
        self._ensure_mutation_window(expiry)
        verified_marker = marker_metadata(
            normalized_plan,
            artifact_id=artifact_id,
            artifact_digest=artifact_digest,
            artifact_expires_at=expiry_text,
            state="verified",
            verified_run_id=public_run_id,
            verified_run_attempt=public_run_attempt,
        )
        verified_body = render_body(verified_marker)
        self._mark_verified(release, normalized_plan, verified_body, expiry)
        return self._result(
            release,
            state="verified",
            read_only=read_only,
            asset_count=len(local_assets),
        )

    def inspect(
        self,
        tag: str,
        *,
        expected_assets: Mapping[str, bytes] | None = None,
        output_dir: Path | None = None,
    ) -> dict[str, object]:
        """Inspect one draft read-only and optionally download every asset."""

        release = self._get_release(tag)
        if release is None:
            return {"tag": tag, "status": "missing", "read_only": True}
        if release.get("draft") is not True:
            raise PublishedReleaseError("release is already published")
        if release.get("immutable") is True:
            raise ReleaseMismatchError("release is immutable")
        if release.get("published_at") is not None:
            raise PublishedReleaseError("release has a publication timestamp")
        if release.get("prerelease") is not False:
            raise ReleaseMismatchError("release must not be a prerelease")
        if release.get("tag_name") != tag or release.get("name") != tag:
            raise ReleaseMismatchError(
                "release tag and title must equal the requested tag"
            )
        body = release.get("body")
        if not isinstance(body, str):
            raise ReleaseMismatchError("release body is not text")
        marker = parse_marker_body(body)
        if marker["tag"] != tag:
            raise ReleaseMismatchError(
                "release marker tag does not match the requested tag"
            )
        target_commit = release.get("target_commitish")
        if target_commit != marker["distribution_commit"]:
            raise ReleaseMismatchError(
                "release target does not match the marker distribution commit"
            )
        assets = self._list_assets(release)
        names = {asset.name for asset in assets}
        if len(assets) != len(names):
            raise ReleaseMismatchError("release contains duplicate asset names")
        manifest_asset = next(
            (asset for asset in assets if asset.name == "release-manifest.json"),
            None,
        )
        if manifest_asset is None:
            raise ReleaseMismatchError("release is missing release-manifest.json")
        manifest_raw = self._download_asset(manifest_asset)
        manifest_profile, expected_names = self._manifest_asset_names(manifest_raw, tag)
        if marker.get("profile") != manifest_profile:
            raise ReleaseMismatchError("release marker profile does not match manifest")
        if names != expected_names:
            raise ReleaseMismatchError(
                "release contains an asset set that differs from its manifest"
            )
        if expected_assets is not None and set(expected_assets) != expected_names:
            raise ReleaseMismatchError(
                "expected assets do not contain exact public asset set"
            )
        if output_dir is not None:
            self._prepare_output_dir(output_dir)
        for asset in assets:
            content = (
                manifest_raw
                if asset.name == "release-manifest.json"
                else self._download_asset(asset)
            )
            if expected_assets is not None and content != expected_assets.get(
                asset.name
            ):
                raise ReleaseMismatchError(f"asset bytes differ: {asset.name}")
            if output_dir is not None:
                output_dir.mkdir(parents=True, exist_ok=True)
                _ = (output_dir / asset.name).write_bytes(content)
        status = (
            "verified"
            if marker["state"] == "verified" and names == expected_names
            else "partial"
        )
        return {
            "tag": tag,
            "release_id": self._release_id(release),
            "status": status,
            "state": marker["state"],
            "marker": marker,
            "asset_count": len(assets),
            "read_only": True,
        }

    def _manifest_asset_names(self, raw: bytes, tag: str) -> tuple[str, set[str]]:
        try:
            decoded = parse_json(raw, "release manifest")
            manifest = _json_mapping(decoded, "release manifest")
        except CoordinatorError as error:
            raise ReleaseMismatchError("release manifest is not valid JSON") from error
        profile = manifest.get("profile")
        version = manifest.get("version")
        if not isinstance(profile, str) or profile not in PROFILES:
            raise ReleaseMismatchError("release manifest profile is unsupported")
        if not isinstance(version, str):
            raise ReleaseMismatchError("release manifest version is not text")
        tag_match = TAG_RE.fullmatch(tag)
        if tag_match is None or version != tag_match.group(1):
            raise ReleaseMismatchError("release tag is not a stable semantic version")
        manifest_tag = manifest.get("tag")
        if not isinstance(manifest_tag, str) or manifest_tag != tag:
            raise ReleaseMismatchError("release manifest tag differs from release tag")
        expected_tag = (
            f"repository-bootstrap-v{version}"
            if profile == "repository-bootstrap"
            else f"v{version}"
        )
        if tag != expected_tag:
            raise ReleaseMismatchError(
                "release manifest tag does not match release tag"
            )
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ReleaseMismatchError("release manifest artifacts are not an array")
        reserved_names = RELEASE_DOCUMENT_NAMES | CHECKSUM_NAMES | CANDIDATE_NAMES
        artifact_names: set[str] = set()
        for index, value in enumerate(cast(list[object], artifacts)):
            artifact = _json_mapping(value, f"release manifest artifact {index}")
            name = artifact.get("filename")
            if not isinstance(name, str) or not _is_safe_flat_asset_name(name):
                raise ReleaseMismatchError(
                    "release manifest contains an unsafe asset filename"
                )
            if name in reserved_names or name in artifact_names:
                raise ReleaseMismatchError(
                    "release manifest artifact filenames are not unique"
                )
            artifact_names.add(name)
        names: set[str] = set(RELEASE_DOCUMENT_NAMES | CHECKSUM_NAMES)
        names.update(artifact_names)
        if profile != "repository-bootstrap":
            names.update(CANDIDATE_NAMES)
        return profile, names

    def _prepare_output_dir(self, output_dir: Path) -> None:
        if output_dir.exists():
            if output_dir.is_symlink() or not output_dir.is_dir():
                raise CoordinatorError(
                    "inspect output directory must be a real directory"
                )
            if any(output_dir.iterdir()):
                raise CoordinatorError("inspect output directory must be empty")
            return
        output_dir.mkdir(parents=True)

    def _result(
        self,
        release: Mapping[str, object],
        *,
        state: str,
        read_only: bool,
        asset_count: int,
    ) -> dict[str, object]:
        return {
            "tag": release.get("tag_name"),
            "release_id": self._release_id(release),
            "state": state,
            "asset_count": asset_count,
            "read_only": read_only,
        }

    def _load_staged_assets(self, root: Path, plan: ValidatedPlan) -> dict[str, Path]:
        if not root.is_dir():
            raise PlanError(f"staged assets directory does not exist: {root}")
        entries = list(root.iterdir())
        expected_names = plan.asset_names()
        allowed = expected_names | STAGING_ONLY_NAMES
        unexpected = sorted(
            entry.name for entry in entries if entry.name not in allowed
        )
        if unexpected:
            raise PlanError(f"staged assets contain unexpected entries: {unexpected}")
        for entry in entries:
            if entry.is_symlink() or not entry.is_file():
                raise PlanError(
                    f"staged assets entry is not a regular file: {entry.name}"
                )
        missing = sorted(expected_names - {entry.name for entry in entries})
        if missing:
            raise PlanError(f"staged assets are missing: {missing}")
        attestation = root / "staging-attestation.json"
        sigstore = root / "staging-attestation.sigstore.json"
        if (
            attestation.is_symlink()
            or sigstore.is_symlink()
            or not attestation.is_file()
            or not sigstore.is_file()
        ):
            raise PlanError("staged assets must include both staging attestation files")
        attestation_bytes = attestation.read_bytes()
        if (
            hashlib.sha256(attestation_bytes).hexdigest()
            != plan.staging_attestation_sha256
        ):
            raise PlanError("staging attestation bytes do not match the validated plan")
        expected = plan.asset_facts()
        contents: dict[str, Path] = {}
        for name in sorted(expected_names):
            path = root / name
            content = path.read_bytes()
            fact = expected[name]
            if (
                len(content) != fact.size
                or hashlib.sha256(content).hexdigest() != fact.sha256
            ):
                raise PlanError(f"staged asset bytes do not match plan: {name}")
            contents[name] = path
        return contents

    def _ensure_mutation_window(self, expiry: datetime) -> None:
        remaining = (expiry - self.now().astimezone(timezone.utc)).total_seconds()
        if remaining < MIN_MUTATION_LEAD_SECONDS:
            raise ExpiredArtifactError(
                "staging artifact has less than the required mutation window"
            )

    def _get_release(self, tag: str) -> dict[str, object] | None:
        path = self._tag_path(tag)
        try:
            response = self._read_request("GET", path)
        except HttpError as error:
            if error.status == 404:
                return None
            raise
        if response.status == 404:
            return None
        if response.status != 200:
            raise HttpError(
                response.status, headers=response.headers, body=response.body
            )
        return self._object_response(response, "release")

    def _create_release(
        self, plan: ValidatedPlan, body: str, expiry: datetime
    ) -> dict[str, object]:
        payload = {
            "tag_name": plan.tag,
            "target_commitish": plan.distribution_commit,
            "name": plan.tag,
            "body": body,
            "draft": True,
            "prerelease": False,
            "generate_release_notes": False,
        }

        def reconcile() -> dict[str, object] | None:
            release = self._get_release(plan.tag)
            if release is None:
                return None
            self._validate_release_identity(release, plan)
            marker = self._validate_existing_body(
                release, plan, parse_marker_body(body)
            )
            if marker["state"] != "preparing":
                raise ReleaseMismatchError(
                    "ambiguous create reconciled to a non-preparing release"
                )
            return release

        self._ensure_mutation_window(expiry)
        response = self._mutating_request(
            "POST",
            self._releases_path(),
            body=_canonical_json(payload),
            headers={"Content-Type": "application/json"},
            reconcile=reconcile,
            expiry=expiry,
        )
        if isinstance(response, dict):
            return cast(JsonObject, response)
        if not isinstance(response, Response):
            raise CoordinatorError(
                "create mutation returned an unexpected reconciliation value"
            )
        release = self._object_response(response, "created release")
        self._validate_release_identity(release, plan)
        return release

    def _mark_verified(
        self,
        release: Mapping[str, object],
        plan: ValidatedPlan,
        body: str,
        expiry: datetime,
    ) -> None:
        release_id = self._release_id(release)
        payload = {
            "name": plan.tag,
            "target_commitish": plan.distribution_commit,
            "body": body,
            "draft": True,
        }

        def reconcile() -> dict[str, object] | None:
            current = self._get_release_by_id(release_id)
            if current is None:
                return None
            self._validate_release_identity(current, plan)
            marker = parse_marker_body(self._body(current))
            if marker["state"] == "verified":
                return current
            return None

        result = self._mutating_request(
            "PATCH",
            self._release_path(release_id),
            body=_canonical_json(payload),
            headers={"Content-Type": "application/json"},
            reconcile=reconcile,
            expiry=expiry,
        )
        if isinstance(result, dict):
            current = cast(dict[str, object], result)
        elif isinstance(result, Response):
            current = self._object_response(result, "verified release")
        else:
            raise CoordinatorError(
                "verify mutation returned an unexpected reconciliation value"
            )
        self._validate_release_identity(current, plan)
        marker = parse_marker_body(self._body(current))
        if marker["state"] != "verified":
            raise ReleaseMismatchError("GitHub did not return the verified marker")

    def _upload_missing(
        self,
        release: Mapping[str, object],
        name: str,
        content: bytes,
        expiry: datetime,
        local_assets: Mapping[str, Path],
        plan: ValidatedPlan,
    ) -> None:
        release_id = self._release_id(release)

        def reconcile() -> RemoteAsset | None:
            assets = self._list_assets(release, plan)
            self._compare_existing_assets(assets, local_assets, plan)
            for asset in assets:
                if asset.name == name:
                    return asset
            return None

        query = {"name": name}
        response = self._mutating_request(
            "POST",
            self._assets_path(release_id),
            query=query,
            body=content,
            headers={"Content-Type": "application/octet-stream"},
            reconcile=reconcile,
            expiry=expiry,
        )
        if isinstance(response, RemoteAsset):
            return
        if not isinstance(response, Response):
            raise CoordinatorError(
                "upload mutation returned an unexpected reconciliation value"
            )
        payload = self._object_response(response, f"uploaded asset {name}")
        response_name = payload.get("name")
        if response_name != name:
            raise ReleaseMismatchError(
                f"GitHub uploaded an unexpected asset: {response_name!r}"
            )

    def _verify_assets(
        self,
        release: Mapping[str, object],
        local_assets: Mapping[str, Path],
        plan: ValidatedPlan,
    ) -> None:
        assets = self._list_assets(release, plan)
        names = {asset.name for asset in assets}
        expected_names = set(plan.asset_names())
        if len(assets) != len(names) or names != expected_names:
            missing = sorted(expected_names - names)
            unexpected = sorted(names - expected_names)
            raise ReleaseMismatchError(
                f"final asset set differs (missing={missing}, unexpected={unexpected})"
            )
        self._compare_existing_assets(assets, local_assets, plan)

    def _compare_existing_assets(
        self,
        assets: Sequence[RemoteAsset],
        local_assets: Mapping[str, Path],
        plan: ValidatedPlan,
    ) -> None:
        del plan
        names = [asset.name for asset in assets]
        if len(names) != len(set(names)):
            raise ReleaseMismatchError("release contains duplicate asset names")
        unexpected = sorted(set(names) - set(local_assets))
        if unexpected:
            raise ReleaseMismatchError(
                f"release contains unexpected assets: {unexpected}"
            )
        for asset in assets:
            expected_path = local_assets.get(asset.name)
            if expected_path is None:
                raise ReleaseMismatchError(
                    f"no local bytes for existing asset: {asset.name}"
                )
            actual = self._download_asset(asset)
            expected = expected_path.read_bytes()
            if asset.size != len(expected):
                raise ReleaseMismatchError(f"asset size differs: {asset.name}")
            if (
                asset.digest is not None
                and asset.digest != f"sha256:{hashlib.sha256(expected).hexdigest()}"
            ):
                raise ReleaseMismatchError(f"asset digest differs: {asset.name}")
            if actual != expected:
                raise ReleaseMismatchError(f"asset bytes differ: {asset.name}")

    def _list_assets(
        self, release: Mapping[str, object], plan: ValidatedPlan | None = None
    ) -> list[RemoteAsset]:
        response = self._read_request(
            "GET",
            self._assets_path(self._release_id(release)),
            query={"per_page": "100"},
        )
        if response.status != 200:
            raise HttpError(
                response.status, headers=response.headers, body=response.body
            )
        try:
            decoded = parse_json(response.body, "GitHub assets response")
        except CoordinatorError as error:
            raise ReleaseMismatchError("GitHub assets response is not JSON") from error
        if not isinstance(decoded, list):
            raise ReleaseMismatchError("GitHub assets response is not an array")
        decoded_items = cast(list[object], decoded)
        result: list[RemoteAsset] = []
        ids: set[int] = set()
        for index, item_value in enumerate(decoded_items):
            if not isinstance(item_value, Mapping):
                raise ReleaseMismatchError(
                    f"asset response entry {index} is not an object"
                )
            item = _json_mapping(
                cast(Mapping[object, object], item_value),
                f"asset response entry {index}",
            )
            asset_id = item.get("id")
            name = item.get("name")
            size = item.get("size")
            state = item.get("state")
            digest = item.get("digest")
            if (
                isinstance(asset_id, bool)
                or not isinstance(asset_id, int)
                or asset_id < 1
            ):
                raise ReleaseMismatchError(
                    f"asset response entry {index} has invalid id"
                )
            if not isinstance(name, str) or not name:
                raise ReleaseMismatchError(
                    f"asset response entry {index} has invalid name"
                )
            if not isinstance(size, int) or isinstance(size, bool) or size < 1:
                raise ReleaseMismatchError(
                    f"asset response entry {index} has invalid size"
                )
            if state != "uploaded":
                raise ReleaseMismatchError(
                    f"asset response entry {index} is not uploaded"
                )
            if digest is not None and (
                not isinstance(digest, str) or ASSET_DIGEST_RE.fullmatch(digest) is None
            ):
                raise ReleaseMismatchError(
                    f"asset response entry {index} has invalid digest"
                )
            if asset_id in ids:
                raise ReleaseMismatchError("release contains duplicate asset IDs")
            ids.add(asset_id)
            if plan is not None:
                fact = plan.asset_facts().get(name)
                if fact is None:
                    raise ReleaseMismatchError(
                        f"asset is not in the validated plan: {name}"
                    )
                if size != fact.size or (
                    digest is not None and digest != f"sha256:{fact.sha256}"
                ):
                    raise ReleaseMismatchError(
                        f"asset metadata differs from the validated plan: {name}"
                    )
            result.append(
                RemoteAsset(
                    asset_id, name, size, digest if isinstance(digest, str) else None
                )
            )
        return result

    def _download_asset(self, asset: RemoteAsset) -> bytes:
        response = self._read_request(
            "GET",
            self._asset_path(asset.id),
            headers={"Accept": "application/octet-stream"},
            max_body_bytes=asset.size + 1,
        )
        if response.status != 200:
            raise HttpError(
                response.status, headers=response.headers, body=response.body
            )
        return response.body

    def _validate_release_identity(
        self, release: Mapping[str, object], plan: ValidatedPlan
    ) -> None:
        if release.get("draft") is not True:
            raise PublishedReleaseError("release is published or is not a draft")
        if release.get("immutable") is True:
            raise ReleaseMismatchError("release is immutable")
        if release.get("published_at") is not None:
            raise PublishedReleaseError("release has a publication timestamp")
        if release.get("prerelease") is not False:
            raise ReleaseMismatchError("release must not be a prerelease")
        if release.get("tag_name") != plan.tag:
            raise ReleaseMismatchError("release tag does not match validated plan")
        if release.get("name") != plan.tag:
            raise ReleaseMismatchError("release title does not equal the exact tag")
        if release.get("target_commitish") != plan.distribution_commit:
            raise ReleaseMismatchError(
                "release target does not match distribution commit"
            )

    def _validate_existing_body(
        self,
        release: Mapping[str, object],
        plan: ValidatedPlan,
        expected_preparing: Mapping[str, object],
    ) -> dict[str, object]:
        marker = parse_marker_body(self._body(release))
        common_keys = set(MARKER_KEYS) - {
            "state",
            "verified_run_attempt",
            "verified_run_id",
        }
        expected_common = {key: expected_preparing[key] for key in common_keys}
        if any(marker.get(key) != value for key, value in expected_common.items()):
            raise ReleaseMismatchError("release marker does not match validated plan")
        if marker["state"] == "preparing":
            if marker != dict(expected_preparing) or self._body(release) != render_body(
                expected_preparing
            ):
                raise ReleaseMismatchError(
                    "preparing release body must be exact and canonical"
                )
        elif marker["state"] == "verified":
            if (
                marker["verified_run_id"] is None
                or marker["verified_run_attempt"] is None
            ):
                raise ReleaseMismatchError(
                    "verified release marker is missing run facts"
                )
        else:
            raise ReleaseMismatchError("release marker state is unsupported")
        del plan
        return marker

    def _body(self, release: Mapping[str, object]) -> str:
        body = release.get("body")
        if not isinstance(body, str):
            raise ReleaseMismatchError("release body is not text")
        return body

    def _release_id(self, release: Mapping[str, object]) -> int:
        value = release.get("id")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ReleaseMismatchError("release response has no valid numeric id")
        return value

    def _get_release_by_id(self, release_id: int) -> dict[str, object] | None:
        try:
            response = self._read_request("GET", self._release_path(release_id))
        except HttpError as error:
            if error.status == 404:
                return None
            raise
        if response.status == 404:
            return None
        if response.status != 200:
            raise HttpError(
                response.status, headers=response.headers, body=response.body
            )
        return self._object_response(response, "release")

    def _read_request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        max_body_bytes: int = MAX_JSON_RESPONSE_BYTES,
    ) -> Response:
        assert_allowed_endpoint(method, path)
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self.transport.request(
                    method, path, query=query, headers=headers
                )
            except TransportError as error:
                if not self._retryable(error.status) or attempt >= self.max_attempts:
                    raise
                self.sleep(self._retry_delay(error.headers, attempt))
                continue
            if self._retryable(response.status):
                if attempt >= self.max_attempts:
                    raise HttpError(
                        response.status, headers=response.headers, body=response.body
                    )
                self.sleep(self._retry_delay(response.headers, attempt))
                continue
            if len(response.body) > max_body_bytes:
                raise CoordinatorError(
                    "GitHub response exceeds the bounded response limit"
                )
            return response
        raise CoordinatorError("retry budget exhausted")

    def _mutating_request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        reconcile: Callable[[], object | None],
        expiry: datetime,
    ) -> Response | object:
        assert_allowed_endpoint(method, path)
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            self._ensure_mutation_window(expiry)
            try:
                response = self.transport.request(
                    method, path, query=query, headers=headers, body=body
                )
                if len(response.body) > MAX_JSON_RESPONSE_BYTES:
                    raise CoordinatorError(
                        "GitHub mutation response exceeds the bounded JSON limit"
                    )
                if response.status in {200, 201}:
                    return response
                if response.status in {409, 422} or self._retryable(response.status):
                    raise HttpError(
                        response.status,
                        headers=response.headers,
                        body=response.body,
                        ambiguous=True,
                    )
                raise HttpError(
                    response.status,
                    headers=response.headers,
                    body=response.body,
                    ambiguous=False,
                )
            except TransportError as error:
                last_error = error
                if not error.ambiguous:
                    raise
                reconciled = reconcile()
                if reconciled is not None:
                    return reconciled
                if attempt >= self.max_attempts:
                    raise CoordinatorError(
                        f"mutation could not be reconciled: {error}"
                    ) from error
                self.sleep(self._retry_delay(error.headers, attempt))
        raise CoordinatorError(f"mutation failed: {last_error}")

    def _object_response(self, response: Response, label: str) -> dict[str, object]:
        try:
            decoded = parse_json(response.body, label)
        except CoordinatorError as error:
            raise CoordinatorError(f"{label} response is not JSON") from error
        return _json_object(decoded, label)

    def _retryable(self, status: int | None) -> bool:
        return status in {408, 429} or (status is not None and 500 <= status <= 599)

    def _retry_delay(self, headers: Mapping[str, str], attempt: int) -> float:
        raw = next(
            (value for key, value in headers.items() if key.lower() == "retry-after"),
            None,
        )
        delay = float(attempt)
        if raw is not None:
            try:
                delay = max(0.0, float(raw))
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(raw)
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=timezone.utc)
                    delay = max(
                        0.0, (retry_at - datetime.now(timezone.utc)).total_seconds()
                    )
                except (TypeError, ValueError, OverflowError):
                    delay = float(attempt)
        return min(delay, self.max_retry_delay)

    def _releases_path(self) -> str:
        return f"/repos/{self.repository}/releases"

    def _tag_path(self, tag: str) -> str:
        return f"{self._releases_path()}/tags/{urllib.parse.quote(tag, safe='')}"

    def _release_path(self, release_id: int) -> str:
        return f"{self._releases_path()}/{release_id}"

    def _assets_path(self, release_id: int) -> str:
        return f"{self._release_path(release_id)}/assets"

    def _asset_path(self, asset_id: int) -> str:
        return f"/repos/{self.repository}/releases/assets/{asset_id}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser(
        "inspect", help="inspect one draft read-only"
    )
    _ = inspect_parser.add_argument("--tag", required=True)
    _ = inspect_parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", PUBLIC_RELEASE_REPOSITORY),
    )
    _ = inspect_parser.add_argument("--output-dir", type=Path)
    prepare_parser = subparsers.add_parser(
        "prepare", help="create/resume and verify one draft"
    )
    _ = prepare_parser.add_argument("--plan", type=Path, required=True)
    _ = prepare_parser.add_argument("--staged-assets", type=Path, required=True)
    _ = prepare_parser.add_argument("--artifact-id", type=int, required=True)
    _ = prepare_parser.add_argument("--artifact-digest", required=True)
    _ = prepare_parser.add_argument("--artifact-expires-at", required=True)
    _ = prepare_parser.add_argument(
        "--public-run-id", type=int, default=_env_int("GITHUB_RUN_ID")
    )
    _ = prepare_parser.add_argument(
        "--public-run-attempt", type=int, default=_env_int("GITHUB_RUN_ATTEMPT", 1)
    )
    _ = prepare_parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", PUBLIC_RELEASE_REPOSITORY),
    )
    return parser


def _env_int(name: str, default: int | None = None) -> int | None:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise CoordinatorError(f"{name} must be an integer") from error


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        transport = UrllibGitHubTransport()
        command = cast(str, args.command)
        repository = cast(str, args.repository)
        coordinator = DraftReleaseCoordinator(transport, repository=repository)
        if command == "inspect":
            tag = cast(str, args.tag)
            output_dir = cast(Path | None, args.output_dir)
            result = coordinator.inspect(tag, output_dir=output_dir)
        else:
            public_run_id = cast(int | None, args.public_run_id)
            public_run_attempt = cast(int | None, args.public_run_attempt)
            if public_run_id is None or public_run_attempt is None:
                raise CoordinatorError(
                    "public run ID and attempt must be supplied or set in GITHUB_RUN_ID/GITHUB_RUN_ATTEMPT"
                )
            plan = ValidatedPlan.from_file(cast(Path, args.plan))
            result = coordinator.prepare(
                plan,
                cast(Path, args.staged_assets),
                artifact_id=cast(int, args.artifact_id),
                artifact_digest=cast(str, args.artifact_digest),
                artifact_expires_at=cast(str, args.artifact_expires_at),
                public_run_id=public_run_id,
                public_run_attempt=public_run_attempt,
            )
        print(
            json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
        return 0
    except (CoordinatorError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
