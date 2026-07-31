"""Prepare deterministic, data-only Homebrew and Scoop pull requests.

The coordinator validates both destination repositories before the first write.
A transport is injected for tests; the command-line entry point uses scoped
GitHub credentials for the two destination repositories.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
from http.client import HTTPResponse
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


REPOSITORY = "context-engine-app/context-engine-mcp"
DESTINATIONS = {
    "homebrew": "context-engine-app/homebrew-tap",
    "scoop": "context-engine-app/scoop-bucket",
}
EXPECTED_DEFAULT_BRANCH = "main"
BRANCH_PREFIX = "automation/context-engine-"
CANDIDATE_PATHS = {
    "homebrew": "Formula/context-engine.rb",
    "scoop": "bucket/context-engine.json",
}
TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ChannelError(ValueError):
    """Base class for deterministic channel preparation errors."""


class ChannelPlanError(ChannelError):
    """Inputs, candidate bytes, or release identity are invalid."""


class ChannelMutationError(ChannelError):
    """A destination repository cannot be reconciled without unsafe mutation."""


class TransportError(ChannelMutationError):
    """A GitHub request failed with a known mutation boundary."""


@dataclass(frozen=True)
class Response:
    """Small transport response used by the coordinator and fake transports."""

    status: int
    body: bytes


class GitHubTransport(Protocol):
    """Transport abstraction; tests inject an in-memory implementation."""

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response: ...


@dataclass(frozen=True)
class CandidateFile:
    """A candidate file with bytes and the immutable metadata it must satisfy."""

    path: str
    data: bytes
    sha256: str
    size: int
    mode: str
    source_manifest_sha256: str = ""
    source_candidate_sha256: str = ""


@dataclass(frozen=True)
class CandidateSet:
    """Validated baseline candidate bytes and release identity."""

    tag: str
    version: str
    profile: str
    source_manifest_sha256: str
    files: Mapping[str, CandidateFile]


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ChannelPlanError(f"{label} must be an object")
    mapping = cast(Mapping[object, object], value)
    return {str(key): item for key, item in mapping.items()}


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ChannelPlanError(f"{label} must be non-empty text")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ChannelPlanError(f"{label} must be a positive integer")
    return value


def _json_object(path: Path, label: str) -> dict[str, object]:
    try:
        if path.is_symlink() or not path.is_file():
            raise ChannelPlanError(f"{label} must be a regular file")
        decoded = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ChannelPlanError(f"cannot read {label}: {error}") from error
    return _mapping(decoded, label)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _decode_contents_api_content(encoded: str, label: str) -> bytes:
    """Decode GitHub Contents API base64 with only CR/LF wrapping allowed."""

    normalized = encoded.replace("\r", "").replace("\n", "")
    try:
        return base64.b64decode(normalized, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ChannelMutationError(f"{label} is not base64") from error


def _decode_contents_document(document: Mapping[str, object], label: str) -> bytes:
    """Require a regular base64 Contents API file and decode its bytes."""
    if document.get("type") != "file":
        raise ChannelMutationError(f"{label} is not a regular file")
    if document.get("encoding") != "base64":
        raise ChannelMutationError(f"{label} does not use base64 encoding")
    encoded = _text(document.get("content"), f"{label} content")
    return _decode_contents_api_content(encoded, f"{label} content")


def _safe_path(path: str, label: str) -> None:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ChannelPlanError(f"{label} is not a safe relative path")


def _read_archive(
    path: Path, records: Mapping[str, Mapping[str, object]]
) -> dict[str, bytes]:
    import tarfile

    if path.is_symlink() or not path.is_file():
        raise ChannelPlanError(f"candidate archive must be a regular file: {path}")
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)) or set(names) != set(records):
                raise ChannelPlanError(
                    "candidate archive members do not match metadata"
                )
            result: dict[str, bytes] = {}
            for member in members:
                _safe_path(member.name, "candidate archive member")
                if not member.isfile() or member.mode != 0o644:
                    raise ChannelPlanError(
                        f"candidate archive member is not a 0644 file: {member.name}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise ChannelPlanError(
                        f"candidate archive member has no bytes: {member.name}"
                    )
                data = stream.read()
                record = records[member.name]
                expected_size = record.get("size")
                expected_sha = record.get("sha256")
                if len(data) != expected_size or _sha256(data) != expected_sha:
                    raise ChannelPlanError(
                        f"candidate bytes do not match metadata: {member.name}"
                    )
                result[member.name] = data
            return result
    except (OSError, EOFError) as error:
        raise ChannelPlanError(f"cannot read candidate archive: {error}") from error


def _candidate_file(
    record: Mapping[str, object], data: bytes, label: str
) -> CandidateFile:
    path = _text(record.get("path"), f"{label}.path")
    _safe_path(path, f"{label}.path")
    sha = _text(record.get("sha256"), f"{label}.sha256")
    if SHA256_RE.fullmatch(sha) is None:
        raise ChannelPlanError(f"{label}.sha256 is not SHA-256")
    size = _positive_integer(record.get("size"), f"{label}.size")
    mode = _text(record.get("mode"), f"{label}.mode")
    if mode != "0644":
        raise ChannelPlanError(f"{label}.mode must be 0644")
    if len(data) != size or _sha256(data) != sha:
        raise ChannelPlanError(f"{label} bytes do not match digest or size")
    return CandidateFile(path, data, sha, size, mode)


def candidate_marker(tag: str, candidate: CandidateFile) -> str:
    """Return the canonical machine marker embedded in each channel PR."""

    value = {
        "tag": tag,
        "source_manifest_sha256": candidate.source_manifest_sha256,
        "candidate_sha256": candidate.sha256,
    }
    return (
        "<!-- context-engine-channel-marker: "
        + json.dumps(value, separators=(",", ":"), sort_keys=True)
        + " -->"
    )


def load_baseline_candidates(
    root: Path, *, expected_tag: str | None = None
) -> CandidateSet:
    """Load only public data candidates from a verified release asset directory."""

    if expected_tag is not None and TAG_RE.fullmatch(expected_tag) is None:
        raise ChannelPlanError("tag must be exactly vMAJOR.MINOR.PATCH")
    root = root.resolve()
    metadata = _json_object(root / "channel-candidates.json", "channel candidates")
    tag = _text(metadata.get("release_tag"), "channel candidates.release_tag")
    version = _text(metadata.get("version"), "channel candidates.version")
    profile = _text(metadata.get("profile"), "channel candidates.profile")
    source_manifest_sha = _text(
        metadata.get("source_manifest_sha256"),
        "channel candidates.source_manifest_sha256",
    )
    manifest_path = root / "release-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ChannelPlanError("release manifest must be a regular file")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise ChannelPlanError(f"cannot read release manifest: {error}") from error
    if _sha256(manifest_bytes) != source_manifest_sha:
        raise ChannelPlanError(
            "channel candidates do not bind the supplied release manifest"
        )
    if expected_tag is not None and tag != expected_tag:
        raise ChannelPlanError("candidate release tag differs from requested tag")
    if profile not in {"desktop", "desktop-linux"}:
        raise ChannelPlanError(
            "package channels require desktop or desktop-linux candidates"
        )
    raw_records = metadata.get("candidates")
    if not isinstance(raw_records, list):
        raise ChannelPlanError("channel candidates.candidates must be an array")
    records: dict[str, Mapping[str, object]] = {}
    for index, value in enumerate(cast(list[object], raw_records)):
        record = _mapping(value, f"channel candidates.candidates[{index}]")
        path = _text(record.get("path"), f"channel candidates.candidates[{index}].path")
        if path in records:
            raise ChannelPlanError("channel candidate paths must be unique")
        records[path] = record
    archive = root / "channel-candidates.tar.gz"
    try:
        archive_data = archive.read_bytes()
    except OSError as error:
        raise ChannelPlanError(f"cannot read candidate archive: {error}") from error
    archive_ref = _mapping(metadata.get("archive"), "channel candidates.archive")
    archive_sha = _text(archive_ref.get("sha256"), "channel candidates.archive.sha256")
    if not archive_data or _sha256(archive_data) != archive_sha:
        raise ChannelPlanError("candidate archive is missing or has the wrong digest")
    files = _read_archive(archive, records)
    candidates = {
        path: CandidateFile(
            path=candidate.path,
            data=candidate.data,
            sha256=candidate.sha256,
            size=candidate.size,
            mode=candidate.mode,
            source_manifest_sha256=source_manifest_sha,
            source_candidate_sha256=candidate.sha256,
        )
        for path, record in records.items()
        for candidate in (_candidate_file(record, files[path], f"candidate {path}"),)
    }
    required_paths = set(CANDIDATE_PATHS.values())
    if not required_paths <= set(candidates):
        missing = ", ".join(sorted(required_paths - set(candidates)))
        raise ChannelPlanError(
            f"candidate archive is missing required destination files: {missing}"
        )
    return CandidateSet(tag, version, profile, source_manifest_sha, candidates)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def assert_allowed_endpoint(repository: str, method: str, path: str) -> None:
    """Allow only the repository reads and deterministic Git data writes in scope."""

    if repository not in DESTINATIONS.values():
        raise ChannelMutationError("request is outside the destination repository")
    destination = next(
        (
            name
            for name, destination_repository in DESTINATIONS.items()
            if destination_repository == repository
        ),
        None,
    )
    if destination is None:
        raise ChannelMutationError("request has no canonical destination binding")
    base = f"/repos/{repository}"
    allowed = False
    if method == "GET":
        allowed = path in {
            base,
            f"{base}/git/ref/heads/{EXPECTED_DEFAULT_BRANCH}",
            f"{base}/contents/README.md",
            f"{base}/contents/.github/workflows/test.yml",
            f"{base}/contents/{CANDIDATE_PATHS[destination]}",
            f"{base}/pulls",
        }
        branch_prefix = f"{base}/git/ref/heads/{BRANCH_PREFIX}"
        if path.startswith(branch_prefix):
            allowed = TAG_RE.fullmatch(path.removeprefix(branch_prefix)) is not None
        pull_prefix = f"{base}/pulls/"
        if path.startswith(pull_prefix):
            allowed = (
                re.fullmatch(r"[1-9][0-9]*", path.removeprefix(pull_prefix)) is not None
            )
        commit_prefix = f"{base}/git/commits/"
        if path.startswith(commit_prefix):
            allowed = COMMIT_RE.fullmatch(path.removeprefix(commit_prefix)) is not None
        tree_prefix = f"{base}/git/trees/"
        if path.startswith(tree_prefix):
            allowed = COMMIT_RE.fullmatch(path.removeprefix(tree_prefix)) is not None
    elif method == "POST":
        allowed = path in {
            f"{base}/git/blobs",
            f"{base}/git/trees",
            f"{base}/git/commits",
            f"{base}/git/refs",
            f"{base}/pulls",
        }
    if not allowed:
        raise ChannelMutationError(
            f"channel preparation does not allow {method} {path}"
        )


def _validate_ref_creation_body(body: bytes | None) -> None:
    if body is None:
        raise ChannelMutationError("channel branch creation requires a JSON body")
    try:
        value = cast(object, json.loads(body))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ChannelMutationError(
            "channel branch creation body is invalid JSON"
        ) from error
    try:
        document = _mapping(value, "channel branch creation body")
    except ChannelPlanError as error:
        raise ChannelMutationError(
            "channel branch creation body must be a JSON object"
        ) from error
    if set(document) != {"ref", "sha"}:
        raise ChannelMutationError("channel branch creation body has unexpected fields")
    ref = document.get("ref")
    sha = document.get("sha")
    if not isinstance(ref, str) or not isinstance(sha, str):
        raise ChannelMutationError("channel branch creation body fields are invalid")
    branch_prefix = f"refs/heads/{BRANCH_PREFIX}"
    if (
        not ref.startswith(branch_prefix)
        or TAG_RE.fullmatch(ref.removeprefix(branch_prefix)) is None
    ):
        raise ChannelMutationError(
            "channel branch creation ref is not an automation branch"
        )
    if COMMIT_RE.fullmatch(sha) is None:
        raise ChannelMutationError("channel branch creation SHA is invalid")


class UrllibGitHubTransport:
    """Minimal GitHub REST transport used by the production workflow."""

    def __init__(
        self,
        token: str,
        *,
        api_base: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise ChannelPlanError("GH token is required for channel mutations")
        self._token: str = token
        self._api_base: str = api_base.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        url = self._api_base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            **dict(headers or {}),
        }
        if self._token:
            request_headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(
            url,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            response = cast(HTTPResponse, urllib.request.urlopen(request, timeout=30))
            try:
                return Response(response.status, response.read())
            finally:
                response.close()
        except urllib.error.HTTPError as error:
            return Response(error.code, error.read())
        except urllib.error.URLError as error:
            raise TransportError(f"GitHub request failed: {error}") from error


class ChannelCoordinator:
    """Validate both destinations, then create at most one inert PR each."""

    def __init__(
        self,
        transport: GitHubTransport | Mapping[str, GitHubTransport],
        *,
        repositories: Mapping[str, str] | None = None,
    ) -> None:
        self._transports: dict[str, GitHubTransport] = (
            dict(transport)
            if isinstance(transport, Mapping)
            else {name: transport for name in DESTINATIONS}
        )
        self._repositories: dict[str, str] = dict(repositories or DESTINATIONS)
        if set(self._repositories) != set(DESTINATIONS) or set(self._transports) != set(
            DESTINATIONS
        ):
            raise ChannelPlanError(
                "channel destinations must be exactly Homebrew and Scoop"
            )
        if self._repositories != DESTINATIONS:
            raise ChannelPlanError("channel destination repositories are not canonical")

    def _public_content(
        self, destination: str, path: str, ref: str
    ) -> dict[str, object]:
        response = self._request(
            destination,
            "GET",
            f"/repos/{self._repository(destination)}/contents/{urllib.parse.quote(path, safe='/')}",
            query={"ref": ref},
        )
        if response.status == 404:
            raise ChannelPlanError(f"{destination} bootstrap file is missing: {path}")
        return self._json_response(response, f"{destination} bootstrap file {path}")

    def prepare(
        self,
        *,
        tag: str,
        candidate_root: Path,
    ) -> dict[str, object]:
        """Validate both destinations, then prepare one pull request per channel."""

        if TAG_RE.fullmatch(tag) is None:
            raise ChannelPlanError("tag must be exactly vMAJOR.MINOR.PATCH")
        baseline = load_baseline_candidates(candidate_root, expected_tag=tag)
        desired = {
            destination: baseline.files[path]
            for destination, path in CANDIDATE_PATHS.items()
        }
        snapshots: dict[str, dict[str, object]] = {}
        for destination in DESTINATIONS:
            snapshots[destination] = self._preflight_destination(
                destination, desired[destination]
            )
        results: dict[str, object] = {}
        for destination in DESTINATIONS:
            results[destination] = self._prepare_destination(
                destination, tag, desired[destination], snapshots[destination]
            )
        return {
            "status": "prepared",
            "tag": tag,
            "branch": f"{BRANCH_PREFIX}{tag}",
            "destinations": results,
        }

    def _transport(self, destination: str) -> GitHubTransport:
        return self._transports[destination]

    def _repository(self, destination: str) -> str:
        return self._repositories[destination]

    def _request(
        self,
        destination: str,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        assert_allowed_endpoint(self._repository(destination), method, path)
        if method == "POST" and path.endswith("/git/refs"):
            _validate_ref_creation_body(body)
        try:
            return self._transport(destination).request(
                method,
                path,
                query=query,
                headers={"Content-Type": "application/json"} if body else None,
                body=body,
            )
        except ChannelMutationError:
            raise
        except Exception as error:
            raise TransportError(f"{method} {path} failed: {error}") from error

    def _json_response(self, response: Response, label: str) -> dict[str, object]:
        if response.status < 200 or response.status >= 300:
            raise TransportError(f"{label} returned HTTP {response.status}")
        try:
            value = cast(object, json.loads(response.body))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ChannelMutationError(f"{label} returned invalid JSON") from error
        return _mapping(value, label)

    def _preflight_destination(
        self, destination: str, desired: CandidateFile
    ) -> dict[str, object]:
        repo = self._repository(destination)
        base_path = f"/repos/{repo}"
        response = self._request(destination, "GET", base_path)
        if response.status == 404:
            raise ChannelPlanError(f"destination repository is missing: {repo}")
        repository = self._json_response(response, f"{destination} repository")
        if (
            repository.get("full_name") != repo
            or repository.get("private") is not False
            or repository.get("disabled") is not False
            or repository.get("archived") is not False
            or repository.get("default_branch") != EXPECTED_DEFAULT_BRANCH
        ):
            raise ChannelPlanError(
                f"{destination} repository is not an enabled public main repository"
            )
        ref_path = f"{base_path}/git/ref/heads/{EXPECTED_DEFAULT_BRANCH}"
        ref = self._request(destination, "GET", ref_path)
        head = self._json_response(ref, f"{destination} default branch")
        object_value = _mapping(
            head.get("object"), f"{destination} default branch.object"
        )
        sha = _text(object_value.get("sha"), f"{destination} default branch SHA")
        if COMMIT_RE.fullmatch(sha) is None:
            raise ChannelPlanError(f"{destination} default branch is not a commit")
        bootstrap: dict[str, str] = {}
        for path in ("README.md", ".github/workflows/test.yml"):
            document = self._public_content(destination, path, sha)
            if document.get("type") != "file":
                raise ChannelPlanError(
                    f"{destination} bootstrap path is not a regular file: {path}"
                )
            bootstrap[path] = _text(document.get("sha"), f"{destination} bootstrap SHA")
        content_path = (
            f"{base_path}/contents/{urllib.parse.quote(desired.path, safe='/')}"
        )
        content = self._request(
            destination,
            "GET",
            content_path,
            query={"ref": sha},
        )
        existing: bytes | None = None
        candidate_state = "absent"
        candidate_sha: str | None = None
        if content.status == 200:
            document = self._json_response(content, f"{destination} candidate content")
            existing = _decode_contents_document(document, f"{destination} candidate")
            candidate_sha = _text(document.get("sha"), f"{destination} candidate SHA")
            candidate_state = "present"
        elif content.status != 404:
            raise TransportError(
                f"{destination} candidate content returned HTTP {content.status}"
            )
        snapshot: dict[str, object] = {
            "repository": repo,
            "full_name": repository.get("full_name"),
            "private": repository.get("private"),
            "disabled": repository.get("disabled"),
            "archived": repository.get("archived"),
            "default_branch": repository.get("default_branch"),
            "default_sha": sha,
            "bootstrap": bootstrap,
            "candidate_path": desired.path,
            "candidate_state": candidate_state,
            "existing": existing,
        }
        if candidate_sha is not None:
            snapshot["candidate_sha"] = candidate_sha
        return snapshot

    def _open_pulls(self, destination: str, branch: str) -> list[dict[str, object]]:
        repo = self._repository(destination)
        response = self._request(
            destination,
            "GET",
            f"/repos/{repo}/pulls",
            query={
                "state": "all",
                "head": f"context-engine-app:{branch}",
                "base": EXPECTED_DEFAULT_BRANCH,
            },
        )
        if response.status != 200:
            raise TransportError(
                f"{destination} pull request lookup returned HTTP {response.status}"
            )
        try:
            decoded = cast(object, json.loads(response.body))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ChannelMutationError(
                f"{destination} pull request response is invalid"
            ) from error
        if not isinstance(decoded, list):
            raise ChannelMutationError(
                f"{destination} pull request response is not an array"
            )
        return [
            _mapping(value, f"{destination} pull request")
            for value in cast(list[object], decoded)
        ]

    def _prepare_destination(
        self,
        destination: str,
        tag: str,
        desired: CandidateFile,
        snapshot: Mapping[str, object],
    ) -> dict[str, object]:
        existing = snapshot.get("existing")
        if isinstance(existing, bytes) and existing == desired.data:
            return {"status": "up-to-date"}
        branch = f"{BRANCH_PREFIX}{tag}"
        pulls = self._open_pulls(destination, branch)
        for pull in pulls:
            head = _mapping(pull.get("head"), f"{destination} pull head")
            if head.get("ref") != branch:
                continue
            state = pull.get("state")
            if state == "open":
                branch_ref = self._request(
                    destination,
                    "GET",
                    f"/repos/{self._repository(destination)}/git/ref/heads/{branch}",
                )
                if branch_ref.status != 200:
                    raise ChannelMutationError(
                        f"{destination} open PR branch is missing"
                    )
                branch_document = self._json_response(
                    branch_ref, f"{destination} open PR branch"
                )
                branch_object = _mapping(
                    branch_document.get("object"),
                    f"{destination} open PR branch.object",
                )
                branch_sha = _text(
                    branch_object.get("sha"), f"{destination} open PR branch SHA"
                )
                default_sha = _text(snapshot.get("default_sha"), "default SHA")
                self._verify_branch_commit(
                    destination, branch_sha, default_sha, desired
                )
                head_sha = head.get("sha")
                if head_sha != branch_sha:
                    raise ChannelMutationError(
                        f"{destination} open PR head differs from its branch"
                    )
                marker = candidate_marker(tag, desired)
                if pull.get("title") != f"Context Engine {tag}" or marker not in str(
                    pull.get("body", "")
                ):
                    raise ChannelMutationError(
                        f"{destination} open PR marker differs from the deterministic candidate"
                    )
                return {"status": "open-pr", "number": pull.get("number")}
            if state == "closed":
                number = _positive_integer(
                    pull.get("number"), f"{destination} pull request number"
                )
                detail_response = self._request(
                    destination,
                    "GET",
                    f"/repos/{self._repository(destination)}/pulls/{number}",
                )
                if detail_response.status != 200:
                    raise TransportError(
                        f"{destination} pull request detail returned HTTP {detail_response.status}"
                    )
                detail = self._json_response(
                    detail_response, f"{destination} pull request detail"
                )
                if (
                    _positive_integer(
                        detail.get("number"),
                        f"{destination} pull request detail number",
                    )
                    != number
                    or detail.get("state") != "closed"
                ):
                    raise ChannelMutationError(
                        f"{destination} pull request detail does not match the closed PR"
                    )
                if (
                    detail.get("merged") is True
                    and isinstance(detail.get("merged_at"), str)
                    and detail.get("merged_at")
                ):
                    self._verify_default_bytes(destination, desired)
                    return {"status": "merged", "number": number}
                raise ChannelMutationError(
                    f"{destination} has a closed unmerged channel PR"
                )
        branch_ref_path = (
            f"/repos/{self._repository(destination)}/git/ref/heads/{branch}"
        )
        branch_ref = self._request(destination, "GET", branch_ref_path)
        branch_sha: str | None = None
        if branch_ref.status == 200:
            branch_document = self._json_response(
                branch_ref, f"{destination} channel branch"
            )
            branch_object = _mapping(
                branch_document.get("object"), f"{destination} channel branch.object"
            )
            branch_sha = _text(
                branch_object.get("sha"), f"{destination} channel branch SHA"
            )
            default_sha = _text(
                snapshot.get("default_sha"), f"{destination} default SHA"
            )
            if branch_sha == default_sha:
                raise ChannelMutationError(
                    f"{destination} deterministic branch unexpectedly points at the default head"
                )
            else:
                self._verify_branch_commit(
                    destination, branch_sha, default_sha, desired
                )
        elif branch_ref.status != 404:
            raise TransportError(
                f"{destination} channel branch returned HTTP {branch_ref.status}"
            )
        if branch_sha is None:
            branch_sha = self._create_commit(
                destination,
                branch,
                desired,
                _text(snapshot.get("default_sha"), "default SHA"),
            )
        pull = self._create_pull(destination, branch, tag, desired)
        return {"status": "created", "number": pull.get("number"), "commit": branch_sha}

    def _verify_default_bytes(self, destination: str, desired: CandidateFile) -> None:
        repo = self._repository(destination)
        path = f"/repos/{repo}/contents/{urllib.parse.quote(desired.path, safe='/')}"
        response = self._request(
            destination,
            "GET",
            path,
            query={"ref": EXPECTED_DEFAULT_BRANCH},
        )
        document = self._json_response(
            response, f"{destination} merged candidate content"
        )
        data = _decode_contents_document(
            document, f"{destination} merged candidate content"
        )
        if data != desired.data:
            raise ChannelMutationError(
                f"{destination} merged PR did not produce the expected candidate bytes"
            )

    def _verify_branch_commit(
        self,
        destination: str,
        branch_sha: str,
        default_sha: str,
        desired: CandidateFile,
    ) -> None:
        path = f"/repos/{self._repository(destination)}/git/commits/{branch_sha}"
        response = self._request(destination, "GET", path)
        document = self._json_response(response, f"{destination} channel branch commit")
        parents = document.get("parents")
        if not isinstance(parents, list) or not parents:
            raise ChannelMutationError(f"{destination} channel branch has no parent")
        parent = _mapping(
            cast(list[object], parents)[0],
            f"{destination} channel branch parent",
        )
        if parent.get("sha") != default_sha:
            raise ChannelMutationError(
                f"{destination} channel branch diverged from the verified default head"
            )
        tree = _mapping(document.get("tree"), f"{destination} channel branch tree")
        tree_sha = _text(tree.get("sha"), f"{destination} channel branch tree SHA")
        branch_entries = self._tree_entries(destination, tree_sha)
        parent_response = self._request(
            destination,
            "GET",
            f"/repos/{self._repository(destination)}/git/commits/{default_sha}",
        )
        parent_document = self._json_response(
            parent_response, f"{destination} default branch commit"
        )
        parent_tree = _mapping(
            parent_document.get("tree"), f"{destination} default branch tree"
        )
        parent_tree_sha = _text(
            parent_tree.get("sha"), f"{destination} default branch tree SHA"
        )
        parent_entries = self._tree_entries(destination, parent_tree_sha)
        changed_paths = {
            path
            for path in set(branch_entries) | set(parent_entries)
            if all(
                entry is None or entry[1] != "tree"
                for entry in (branch_entries.get(path), parent_entries.get(path))
            )
            and branch_entries.get(path) != parent_entries.get(path)
        }
        if changed_paths != {desired.path}:
            raise ChannelMutationError(
                f"{destination} channel branch changes paths outside the candidate allowlist"
            )
        expected_blob = _git_blob_sha(desired.data)
        observed = branch_entries.get(desired.path)
        if observed != ("100644", "blob", expected_blob):
            raise ChannelMutationError(
                f"{destination} channel branch contents diverged from candidate bytes"
            )

    def _tree_entries(
        self, destination: str, tree_sha: str
    ) -> dict[str, tuple[str, str, str]]:
        tree_response = self._request(
            destination,
            "GET",
            f"/repos/{self._repository(destination)}/git/trees/{tree_sha}",
            query={"recursive": "1"},
        )
        tree_document = self._json_response(tree_response, f"{destination} git tree")
        if tree_document.get("truncated") is True:
            raise ChannelMutationError(f"{destination} git tree response is truncated")
        entries = tree_document.get("tree")
        if not isinstance(entries, list):
            raise ChannelMutationError(f"{destination} git tree is not an array")
        result: dict[str, tuple[str, str, str]] = {}
        for value in cast(list[object], entries):
            entry = _mapping(value, f"{destination} git tree entry")
            path = _text(entry.get("path"), f"{destination} git tree entry path")
            mode = _text(entry.get("mode"), f"{destination} git tree entry mode")
            entry_type = _text(entry.get("type"), f"{destination} git tree entry type")
            sha = _text(entry.get("sha"), f"{destination} git tree entry SHA")
            _safe_path(path, f"{destination} git tree entry path")
            if re.fullmatch(r"[0-7]{6}", mode) is None:
                raise ChannelMutationError(
                    f"{destination} git tree entry mode is invalid"
                )
            if entry_type not in {"blob", "tree", "commit"}:
                raise ChannelMutationError(
                    f"{destination} git tree entry type is invalid"
                )
            if COMMIT_RE.fullmatch(sha) is None:
                raise ChannelMutationError(
                    f"{destination} git tree entry SHA is invalid"
                )
            if path in result:
                raise ChannelMutationError(
                    f"{destination} git tree contains duplicate paths"
                )
            result[path] = (mode, entry_type, sha)
        return result

    def _create_commit(
        self, destination: str, branch: str, desired: CandidateFile, default_sha: str
    ) -> str:
        repo = self._repository(destination)
        default_commit_response = self._request(
            destination,
            "GET",
            f"/repos/{repo}/git/commits/{default_sha}",
        )
        default_commit = self._json_response(
            default_commit_response, f"{destination} default branch commit"
        )
        default_tree = _mapping(
            default_commit.get("tree"), f"{destination} default branch tree"
        )
        default_tree_sha = _text(
            default_tree.get("sha"), f"{destination} default branch tree SHA"
        )
        blob_response = self._request(
            destination,
            "POST",
            f"/repos/{repo}/git/blobs",
            body=_json_bytes(
                {
                    "content": base64.b64encode(desired.data).decode(),
                    "encoding": "base64",
                }
            ),
        )
        blob = self._json_response(blob_response, f"{destination} candidate blob")
        blob_sha = _text(blob.get("sha"), f"{destination} candidate blob SHA")
        tree_response = self._request(
            destination,
            "POST",
            f"/repos/{repo}/git/trees",
            body=_json_bytes(
                {
                    "base_tree": default_tree_sha,
                    "tree": [
                        {
                            "path": desired.path,
                            "mode": "100644",
                            "type": "blob",
                            "sha": blob_sha,
                        }
                    ],
                }
            ),
        )
        tree = self._json_response(tree_response, f"{destination} candidate tree")
        tree_sha = _text(tree.get("sha"), f"{destination} candidate tree SHA")
        commit_response = self._request(
            destination,
            "POST",
            f"/repos/{repo}/git/commits",
            body=_json_bytes(
                {
                    "message": f"context-engine {branch.removeprefix(BRANCH_PREFIX)}",
                    "tree": tree_sha,
                    "parents": [default_sha],
                }
            ),
        )
        commit = self._json_response(commit_response, f"{destination} candidate commit")
        commit_sha = _text(commit.get("sha"), f"{destination} candidate commit SHA")
        ref_response = self._request(
            destination,
            "POST",
            f"/repos/{repo}/git/refs",
            body=_json_bytes({"ref": f"refs/heads/{branch}", "sha": commit_sha}),
        )
        _ = self._json_response(ref_response, f"{destination} candidate branch")
        return commit_sha

    def _create_pull(
        self, destination: str, branch: str, tag: str, desired: CandidateFile
    ) -> dict[str, object]:
        repo = self._repository(destination)
        response = self._request(
            destination,
            "POST",
            f"/repos/{repo}/pulls",
            body=_json_bytes(
                {
                    "title": f"Context Engine {tag}",
                    "head": f"context-engine-app:{branch}",
                    "base": EXPECTED_DEFAULT_BRANCH,
                    "body": "Generated from verified public channel candidate bytes; merge manually after review.\n"
                    + candidate_marker(tag, desired),
                }
            ),
        )
        return self._json_response(response, f"{destination} channel pull request")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "apply"):
        subparser = subparsers.add_parser(command)
        _ = subparser.add_argument("--tag", required=True)
        _ = subparser.add_argument("--candidate-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = cast(str, args.command)
    tag = cast(str, args.tag)
    candidate_root = cast(Path, args.candidate_root)
    try:
        if command == "validate":
            _ = load_baseline_candidates(candidate_root, expected_tag=tag)
            return 0
        transports: dict[str, GitHubTransport] = {}
        for destination in DESTINATIONS:
            variable = (
                "HOMEBREW_GH_TOKEN" if destination == "homebrew" else "SCOOP_GH_TOKEN"
            )
            token = os.environ.get(variable, "")
            if not token:
                raise ChannelPlanError(f"{variable} is required for channel mutations")
            transports[destination] = UrllibGitHubTransport(token)
        result = ChannelCoordinator(transports).prepare(
            tag=tag,
            candidate_root=candidate_root,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except ChannelError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
