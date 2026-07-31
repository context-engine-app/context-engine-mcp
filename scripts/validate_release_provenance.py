#!/usr/bin/env python3
"""Validate portable release envelopes and public release checkpoints.

This validator is deliberately independent from the private raw-evidence
validator.  It consumes only the public release documents and their files,
validates the byte-identical local schemas, and emits a deterministic
manifest-derived asset plan for the public coordinator.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib
import json
import re
import stat
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import NoReturn, Protocol, TypeAlias, cast

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_SCHEMA_SHA256 = (
    "2e398c70916e86ab58734cc77622bdf7e04e756c1ebdef73e9cc903ffb62baa8"
)
PROVENANCE_SCHEMA_SHA256 = (
    "c13bf530c6fe4befc00b398c2274b3ffeb7e6cbcfb78c38bc1a5da0b8bf4db60"
)
STAGING_SCHEMA_SHA256 = (
    "b8f1017ce278f762772e236eb08bf18a3c52b65f0e1e30c1d27cace51d305a6d"
)
WORKFLOW_REAUTH_SCHEMA_SHA256 = (
    "e3d0f0799be46b5ba74f863b7f65328c6659734cfe23f34fae08e0fc1d690809"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
REAUTH_REF_RE = re.compile(
    r"^refs/tags/release-reauthorization/((?:v|repository-bootstrap-v)(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))/(public-publish|package-channels)/([0-9a-fA-F]{40})$"
)
RUN_ID_RE = re.compile(r"^[0-9]+$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([^\x00\r\n\t /\\]+)$")
ARTIFACT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_REPOSITORY = "context-engine-app/context-engine"
DISTRIBUTION_REPOSITORY = "context-engine-app/context-engine-mcp"
SOURCE_WORKFLOW_PATH = ".github/workflows/release.yml"
PUBLIC_WORKFLOW_PATH = ".github/workflows/prepare-draft-release.yml"
PUBLISH_WORKFLOW_PATH = ".github/workflows/publish-draft-release.yml"
CHANNEL_WORKFLOW_PATH = ".github/workflows/prepare-package-channels.yml"
FOUNDATION_STAGES = ("source-release", "public-draft")
ORCHESTRATION_STAGES = FOUNDATION_STAGES + ("public-publish", "package-channels")
PUBLIC_WORKFLOW_PATHS = {
    "draft": PUBLIC_WORKFLOW_PATH,
    "publish": PUBLISH_WORKFLOW_PATH,
    "channels": CHANNEL_WORKFLOW_PATH,
}
CHECKSUM_ASSETS = {"SHA256SUMS", "SHA256SUMS.sigstore.json"}
RELEASE_DOCUMENTS = {
    "release-manifest.json",
    "release-provenance.json",
}
CANDIDATE_ASSETS = {
    "channel-candidates.json",
    "channel-candidates.tar.gz",
}
PROFILE_TARGETS: dict[str, frozenset[str]] = {
    "desktop": frozenset(
        {
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        }
    ),
    "desktop-linux": frozenset(
        {
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        }
    ),
    "repository-bootstrap": frozenset(),
}
TARGET_BUILD_SCRIPTS: dict[str, str] = {
    "x86_64-apple-darwin": "scripts/build_mac.sh",
    "aarch64-apple-darwin": "scripts/build_mac.sh",
    "x86_64-pc-windows-msvc": "scripts/build_win.sh",
    "x86_64-unknown-linux-gnu": "scripts/build_linux.sh",
}
TARGET_PAYLOAD_DETAILS: dict[str, dict[str, str]] = {
    "x86_64-apple-darwin": {
        "filename": "context-engine",
        "platform": "macos",
        "architecture": "x86_64",
        "archive_filename": "context-engine-x86_64-apple-darwin.tar.gz",
        "sbom_filename": "context-engine-x86_64-apple-darwin.cdx.json",
    },
    "aarch64-apple-darwin": {
        "filename": "context-engine",
        "platform": "macos",
        "architecture": "arm64",
        "archive_filename": "context-engine-aarch64-apple-darwin.tar.gz",
        "sbom_filename": "context-engine-aarch64-apple-darwin.cdx.json",
    },
    "x86_64-pc-windows-msvc": {
        "filename": "context-engine.exe",
        "platform": "windows",
        "architecture": "x86_64",
        "archive_filename": "context-engine-x86_64-pc-windows-msvc.zip",
        "sbom_filename": "context-engine-x86_64-pc-windows-msvc.cdx.json",
    },
    "x86_64-unknown-linux-gnu": {
        "filename": "context-engine",
        "platform": "linux",
        "architecture": "x86_64",
        "archive_filename": "context-engine-x86_64-unknown-linux-gnu.tar.gz",
        "sbom_filename": "context-engine-x86_64-unknown-linux-gnu.cdx.json",
    },
}
PROFILE_COMMON_FILENAMES: dict[str, frozenset[str]] = {
    "desktop": frozenset(
        {"LICENSE", "THIRD_PARTY_NOTICES.md", "context-engine-release.cdx.json"}
    ),
    "desktop-linux": frozenset(
        {"LICENSE", "THIRD_PARTY_NOTICES.md", "context-engine-release.cdx.json"}
    ),
    "repository-bootstrap": frozenset({"LICENSE", "THIRD_PARTY_NOTICES.md"}),
}
STAGING_ONLY_NAMES = {"staging-attestation.json", "staging-attestation.sigstore.json"}
MARKER_KEYS = {
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
}
PLAN_KEYS = {
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

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class ReleaseProvenanceValidationError(ValueError):
    """Raised when a staging envelope, draft, or trusted marker is invalid."""


class DependencyError(RuntimeError):
    """Raised when the pinned JSON Schema dependency is unavailable."""


class _SchemaError(Protocol):
    absolute_path: Iterable[object]
    message: str


class _SchemaValidator(Protocol):
    def __init__(self, schema: Mapping[str, object]) -> None: ...

    @classmethod
    def check_schema(cls, schema: Mapping[str, object]) -> None: ...

    def iter_errors(self, instance: Mapping[str, object]) -> Iterable[_SchemaError]: ...


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    value: JsonObject = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseProvenanceValidationError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> NoReturn:
    raise ReleaseProvenanceValidationError(
        f"non-standard JSON constant {value!r} is not allowed"
    )


def parse_json(text: str, source: str = "<document>") -> JsonValue:
    """Parse strict JSON without duplicate keys or non-standard constants."""
    try:
        return cast(
            JsonValue,
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            ),
        )
    except (ReleaseProvenanceValidationError, json.JSONDecodeError) as exc:
        raise ReleaseProvenanceValidationError(
            f"invalid JSON in {source}: {exc}"
        ) from exc


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReleaseProvenanceValidationError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ReleaseProvenanceValidationError(f"{label} must be a JSON array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ReleaseProvenanceValidationError(f"{label} must be a JSON string")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseProvenanceValidationError(f"{label} must be a JSON integer")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseProvenanceValidationError(message)


def _sha(value: object, label: str) -> str:
    text = _string(value, label)
    _require(
        bool(SHA256_RE.fullmatch(text)), f"{label} must be a lowercase SHA-256 digest"
    )
    return text


def _commit(value: object, label: str) -> str:
    text = _string(value, label)
    _require(bool(COMMIT_RE.fullmatch(text)), f"{label} must be a commit hash")
    return text


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _regular_file(path: Path, label: str) -> None:
    try:
        if path.is_symlink():
            raise ReleaseProvenanceValidationError(
                f"{label} must not be a symlink: {path}"
            )
        mode = path.stat().st_mode
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot inspect {label} {path}: {exc}"
        ) from exc
    if not stat.S_ISREG(mode):
        raise ReleaseProvenanceValidationError(
            f"{label} must be a regular file: {path}"
        )


def _read_bytes(path: Path, label: str) -> bytes:
    _regular_file(path, label)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot read {label} {path}: {exc}"
        ) from exc


def _read_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read_bytes(path, label)
    try:
        value = parse_json(raw.decode("utf-8"), str(path))
    except UnicodeDecodeError as exc:
        raise ReleaseProvenanceValidationError(
            f"{label} is not UTF-8 JSON: {path}"
        ) from exc
    return _object(value, label), raw


def _jsonschema() -> type[_SchemaValidator]:
    try:
        module = importlib.import_module("jsonschema")
    except ImportError as exc:
        raise DependencyError(
            "jsonschema is required; install scripts/release/requirements.txt"
        ) from exc
    try:
        namespace = cast(Mapping[str, object], vars(module))
        validator_type = namespace["Draft202012Validator"]
    except (AttributeError, KeyError) as exc:
        raise DependencyError(
            "jsonschema Draft 2020-12 support is required; install scripts/release/requirements.txt"
        ) from exc
    return cast(type[_SchemaValidator], validator_type)


def _reject_external_refs(value: object, label: str = "schema") -> None:
    if isinstance(value, dict):
        value = cast(dict[str, object], value)
        reference = value.get("$ref")
        if reference is not None:
            _require(
                isinstance(reference, str) and reference.startswith("#"),
                f"{label} contains an external JSON Schema reference",
            )
        for key, child in value.items():
            _reject_external_refs(child, f"{label}.{key}")
    elif isinstance(value, list):
        value = cast(list[object], value)
        for index, child in enumerate(value):
            _reject_external_refs(child, f"{label}[{index}]")


def _load_schema(
    schemas: Path, filename: str, expected_sha256: str
) -> dict[str, object]:
    path = schemas / filename
    raw = _read_bytes(path, f"schema {filename}")
    _require(
        _sha256_bytes(raw) == expected_sha256, f"schema digest mismatch for {filename}"
    )
    try:
        value = parse_json(raw.decode("utf-8"), str(path))
    except UnicodeDecodeError as exc:
        raise ReleaseProvenanceValidationError(
            f"schema is not UTF-8 JSON: {path}"
        ) from exc
    schema = _object(value, f"schema {filename}")
    _reject_external_refs(schema, f"schema {filename}")
    validator_type = _jsonschema()
    try:
        validator_type.check_schema(schema)
    except Exception as exc:  # jsonschema exposes implementation-specific errors
        raise ReleaseProvenanceValidationError(
            f"invalid Draft 2020-12 schema {filename}: {exc}"
        ) from exc
    return schema


def _validate_schema(
    document: Mapping[str, object], schema: dict[str, object], label: str
) -> None:
    validator_type = _jsonschema()
    validator = validator_type(schema)
    errors = list(validator.iter_errors(document))
    if errors:
        errors.sort(key=lambda item: tuple(str(part) for part in item.absolute_path))
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or label
        raise ReleaseProvenanceValidationError(
            f"{label} schema violation at {location}: {first.message}"
        )


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _workflow(value: object, label: str, expected_path: str) -> dict[str, str]:
    binding = _object(value, label)
    path = _string(binding.get("path"), f"{label}.path")
    _require(path == expected_path, f"{label}.path is not canonical")
    return {
        "path": path,
        "commit": _commit(binding.get("commit"), f"{label}.commit"),
        "sha256": _sha(binding.get("sha256"), f"{label}.sha256"),
    }


def validate_workflow_reauthorization(
    record: Mapping[str, object],
    *,
    expected_tag: str | None = None,
    expected_stage: str | None = None,
    original: Mapping[str, str] | None = None,
    replacement: Mapping[str, str] | None = None,
    runtime_commit: str | None = None,
) -> dict[str, object]:
    """Validate one protected replacement workflow execution record."""

    _require(
        set(record)
        == {
            "schema_version",
            "tag",
            "stage",
            "execution_ref",
            "original",
            "replacement",
            "reason",
            "approval_evidence",
        },
        "workflow reauthorization record keys are not exact",
    )
    _require(
        record.get("schema_version") == 1,
        "workflow reauthorization schema version is not 1",
    )
    tag = _string(record.get("tag"), "workflow reauthorization tag")
    _require(
        bool(
            re.fullmatch(
                r"(?:v|repository-bootstrap-v)(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
                tag,
            )
        ),
        "workflow reauthorization tag is invalid",
    )
    stage = _string(record.get("stage"), "workflow reauthorization stage")
    _require(
        stage in {"public-publish", "package-channels"},
        "workflow reauthorization stage is unsupported",
    )
    execution_ref = _string(
        record.get("execution_ref"), "workflow reauthorization execution ref"
    )
    ref_match = REAUTH_REF_RE.fullmatch(execution_ref)
    _require(
        ref_match is not None, "workflow reauthorization execution ref is not canonical"
    )
    if ref_match is not None:
        _require(
            ref_match.group(1) == tag and ref_match.group(2) == stage,
            "workflow reauthorization ref does not bind tag and stage",
        )
        replacement_commit = ref_match.group(3)
    else:
        replacement_commit = ""
    if expected_tag is not None:
        _require(
            tag == expected_tag,
            "workflow reauthorization tag differs from expected tag",
        )
    if expected_stage is not None:
        _require(
            stage == expected_stage,
            "workflow reauthorization stage differs from expected stage",
        )
    expected_path = (
        PUBLISH_WORKFLOW_PATH if stage == "public-publish" else CHANNEL_WORKFLOW_PATH
    )
    original_binding = _workflow(
        record.get("original"), "workflow reauthorization original", expected_path
    )
    replacement_binding = _workflow(
        record.get("replacement"), "workflow reauthorization replacement", expected_path
    )
    _require(
        replacement_binding["commit"].lower() == replacement_commit.lower(),
        "workflow reauthorization replacement commit differs from execution ref",
    )
    if runtime_commit is not None:
        _require(
            replacement_binding["commit"].lower() == runtime_commit.lower(),
            "workflow reauthorization replacement commit differs from runtime commit",
        )
    if original is not None:
        _require(
            original_binding == dict(original),
            "workflow reauthorization original differs from expected binding",
        )
    if replacement is not None:
        _require(
            replacement_binding == dict(replacement),
            "workflow reauthorization replacement differs from expected binding",
        )
    reason = _string(record.get("reason"), "workflow reauthorization reason")
    _require(bool(reason.strip()), "workflow reauthorization reason is empty")
    evidence = _object(
        record.get("approval_evidence"), "workflow reauthorization approval evidence"
    )
    _require(bool(evidence), "workflow reauthorization approval evidence is empty")
    return {
        "tag": tag,
        "stage": stage,
        "execution_ref": execution_ref,
        "original": original_binding,
        "replacement": replacement_binding,
        "reason": reason,
        "approval_evidence": evidence,
    }


def validate_reauthorization_execution(
    record: Mapping[str, object],
    *,
    expected_tag: str | None = None,
    expected_stage: str | None = None,
    original: Mapping[str, str] | None = None,
    replacement: Mapping[str, str] | None = None,
    runtime_commit: str | None = None,
) -> dict[str, object]:
    """Alias retained for workflow callers that name the execution boundary."""

    return validate_workflow_reauthorization(
        record,
        expected_tag=expected_tag,
        expected_stage=expected_stage,
        original=original,
        replacement=replacement,
        runtime_commit=runtime_commit,
    )


def validate_workflow_reauthorization_file(
    record_path: Path,
    schemas: Path,
    *,
    expected_tag: str | None = None,
    expected_stage: str | None = None,
    original: Mapping[str, str] | None = None,
    replacement: Mapping[str, str] | None = None,
    runtime_commit: str | None = None,
) -> dict[str, object]:
    """Load, schema-check, and bind one checked-in reauthorization record."""

    record, _ = _read_json(record_path, "workflow reauthorization record")
    schema = _load_schema(
        schemas,
        "workflow-reauthorization.schema.json",
        WORKFLOW_REAUTH_SCHEMA_SHA256,
    )
    _validate_schema(record, schema, "workflow reauthorization")
    return validate_workflow_reauthorization(
        record,
        expected_tag=expected_tag,
        expected_stage=expected_stage,
        original=original,
        replacement=replacement,
        runtime_commit=runtime_commit,
    )


def _public_workflows(
    manifest: Mapping[str, object], distribution_commit: str
) -> dict[str, dict[str, str]]:
    stages = _array(manifest.get("authorized_stages"), "manifest.authorized_stages")
    stage_names = tuple(_string(item, "manifest authorized stage") for item in stages)
    if stage_names == FOUNDATION_STAGES:
        expected_names = ("draft",)
    elif stage_names == ORCHESTRATION_STAGES:
        expected_names = ("draft", "publish", "channels")
    else:
        raise ReleaseProvenanceValidationError(
            "manifest authorized stages are incomplete or reordered"
        )
    bindings = _object(manifest.get("workflow_bindings"), "manifest.workflow_bindings")
    _require(
        set(bindings) == set(expected_names),
        "manifest workflow bindings do not match authorized stages",
    )
    workflows: dict[str, dict[str, str]] = {}
    for name in expected_names:
        workflow = _workflow(
            bindings.get(name),
            f"manifest public workflow {name}",
            PUBLIC_WORKFLOW_PATHS[name],
        )
        _require(
            workflow["commit"] == distribution_commit,
            f"manifest public workflow {name} commit differs from distribution commit",
        )
        workflows[name] = workflow
    return workflows


def _binding(value: object, label: str) -> dict[str, object]:
    item = _object(value, label)
    return item


def _package_coordinate(
    value: Mapping[str, object], label: str, *, artifact: bool, kind: str
) -> tuple[str, ...]:
    fields = (
        ("package_id", "id"),
        ("package_version", "version"),
        ("filename", "filename"),
        ("package_suite", "suite"),
        ("package_format", "package_format"),
    )
    coordinate = tuple(
        _string(
            value.get(artifact_field if artifact else binding_field),
            f"{label}.{artifact_field if artifact else binding_field}",
        )
        for artifact_field, binding_field in fields
    )
    architecture = _string(value.get("architecture"), f"{label}.architecture")
    if kind == "native-package":
        _require(
            architecture in {"amd64", "x86_64", "arm64"},
            f"{label}.architecture is not valid for native-package",
        )
    elif kind == "bootstrap-package":
        _require(
            architecture in {"all", "noarch"},
            f"{label}.architecture is not valid for bootstrap-package",
        )
    source_format = value.get("repository_source_format")
    return (
        *coordinate,
        architecture,
        "<missing>"
        if source_format is None
        else _string(source_format, f"{label}.repository_source_format"),
    )


def _validate_package_bindings(
    profile: str,
    version: str,
    artifacts: Iterable[Mapping[str, object]],
    package_binding: Mapping[str, object],
    bootstrap: Mapping[str, object],
) -> None:
    if profile == "desktop-linux":
        _require(
            _string(package_binding.get("mode"), "manifest.package_binding.mode")
            == "embedded",
            "desktop-linux package binding must be embedded",
        )
        packages = _array(
            package_binding.get("packages"), "manifest.package_binding.packages"
        )
        expected_architectures = {"deb": "amd64", "rpm": "x86_64"}
        for index, package in enumerate(packages):
            package_mapping = _object(
                package, f"manifest.package_binding.packages[{index}]"
            )
            package_format = _string(
                package_mapping.get("package_format"),
                f"manifest.package_binding.packages[{index}].package_format",
            )
            if package_format not in expected_architectures:
                raise ReleaseProvenanceValidationError(
                    "desktop-linux package binding format is unsupported"
                )
            _require(
                _string(
                    package_mapping.get("architecture"),
                    f"manifest.package_binding.packages[{index}].architecture",
                )
                == expected_architectures[package_format],
                "desktop-linux package binding architecture does not match its format",
            )
        actual_binding = [
            _package_coordinate(
                _object(package, f"manifest.package_binding.packages[{index}]"),
                f"manifest.package_binding.packages[{index}]",
                artifact=False,
                kind="native-package",
            )
            for index, package in enumerate(packages)
        ]
        expected_binding = {
            (
                "context-engine",
                version,
                f"context-engine_{version}-1_amd64.deb",
                "linux",
                "deb",
                "amd64",
                "<missing>",
            ),
            (
                "context-engine",
                version,
                f"context-engine-{version}-1.x86_64.rpm",
                "linux",
                "rpm",
                "x86_64",
                "<missing>",
            ),
        }
        _require(
            len(actual_binding) == len(expected_binding)
            and len(actual_binding) == len(set(actual_binding))
            and set(actual_binding) == expected_binding,
            "desktop-linux package binding must contain the canonical Debian and RPM pair",
        )

    actual: dict[str, list[tuple[str, ...]]] = {
        "native-package": [],
        "bootstrap-package": [],
    }
    for index, artifact in enumerate(artifacts):
        kind = artifact.get("kind")
        if isinstance(kind, str) and kind in actual:
            actual[kind].append(
                _package_coordinate(
                    artifact,
                    f"manifest.artifacts[{index}]",
                    artifact=True,
                    kind=kind,
                )
            )

    expected: dict[str, list[tuple[str, ...]]] = {
        "native-package": [],
        "bootstrap-package": [],
    }
    binding_specs = (
        (
            package_binding,
            "manifest.package_binding",
            {"embedded": "native-package"}
            if profile == "desktop-linux"
            else {"bootstrap": "bootstrap-package"}
            if profile == "repository-bootstrap"
            else {},
        ),
        (bootstrap, "manifest.bootstrap", {"embedded": "bootstrap-package"}),
    )
    for binding, label, local_kinds in binding_specs:
        mode = _string(binding.get("mode"), f"{label}.mode")
        kind = local_kinds.get(mode)
        if kind is None:
            continue
        packages = _array(binding.get("packages"), f"{label}.packages")
        expected[kind].extend(
            _package_coordinate(
                _object(package, f"{label}.packages[{index}]"),
                f"{label}.packages[{index}]",
                artifact=False,
                kind=kind,
            )
            for index, package in enumerate(packages)
        )

    for kind in actual:
        actual_coordinates = actual[kind]
        expected_coordinates = expected[kind]
        _require(
            len(actual_coordinates) == len(set(actual_coordinates)),
            f"manifest {kind} artifacts contain duplicate package coordinates",
        )
        _require(
            len(expected_coordinates) == len(set(expected_coordinates)),
            f"manifest binding for {kind} contains duplicate package coordinates",
        )
        _require(
            set(actual_coordinates) == set(expected_coordinates),
            f"manifest {kind} artifacts do not match their binding packages",
        )


def _validate_profile_payloads(
    profile: str, manifest: Mapping[str, object]
) -> dict[str, str]:
    expected_targets = PROFILE_TARGETS[profile]
    builds = [
        _object(item, f"manifest.builds[{index}]")
        for index, item in enumerate(_array(manifest.get("builds"), "manifest.builds"))
    ]
    payloads = [
        _object(item, f"manifest.payloads[{index}]")
        for index, item in enumerate(
            _array(manifest.get("payloads"), "manifest.payloads")
        )
    ]
    expected_payload_ids = {f"context-engine-{target}" for target in expected_targets}
    build_ids = [
        _string(item.get("payload_id"), "manifest build payload_id") for item in builds
    ]
    _require(
        set(build_ids) == expected_payload_ids
        and len(build_ids) == len(expected_payload_ids),
        "manifest builds do not match the profile payload set",
    )
    expected_scripts = {
        f"context-engine-{target}": TARGET_BUILD_SCRIPTS[target]
        for target in expected_targets
    }
    build_scripts = {
        _string(item.get("payload_id"), "manifest build payload_id"): _string(
            item.get("script"), "manifest build script"
        )
        for item in builds
    }
    _require(
        build_scripts == expected_scripts,
        "manifest build scripts do not match the profile payload set",
    )
    payload_ids = [_string(item.get("id"), "manifest payload id") for item in payloads]
    _require(
        set(payload_ids) == expected_payload_ids
        and len(payload_ids) == len(expected_payload_ids),
        "manifest payloads do not match the profile payload set",
    )
    payload_targets: dict[str, str] = {}
    for payload in payloads:
        payload_id = _string(payload.get("id"), "manifest payload id")
        target = _string(payload.get("target"), "manifest payload target")
        _require(
            payload_id == f"context-engine-{target}",
            "manifest payload id does not match its target",
        )
        details = TARGET_PAYLOAD_DETAILS.get(target)
        if details is None:
            raise ReleaseProvenanceValidationError(
                "manifest payload target is not supported by the profile payload contract"
            )
        for field in ("filename", "platform", "architecture"):
            _require(
                _string(payload.get(field), f"manifest payload {field}")
                == details[field],
                f"manifest payload {field} does not match target",
            )
        _require(
            _string(payload.get("executable_mode"), "manifest payload executable_mode")
            == "0755",
            "manifest payload executable_mode must be 0755",
        )
        _require(
            _string(payload.get("version_output"), "manifest payload version_output")
            == f"context-engine {_string(manifest.get('version'), 'manifest.version')}",
            "manifest payload version_output does not match manifest version",
        )
        payload_targets[payload_id] = target
    _require(
        frozenset(payload_targets.values()) == expected_targets
        and len(payload_targets) == len(expected_targets),
        "manifest payload targets do not match the profile target set",
    )
    return payload_targets


def _validate_profile_artifact_kinds(
    profile: str,
    artifacts: list[dict[str, object]],
    manifest: Mapping[str, object],
) -> None:
    allowed_kinds = {"archive", "sbom", "common"}
    if profile == "repository-bootstrap":
        allowed_kinds = {"bootstrap-package", "common"}
    elif profile == "desktop-linux":
        package_binding = _object(
            manifest.get("package_binding"), "manifest.package_binding"
        )
        if (
            _string(package_binding.get("mode"), "manifest.package_binding.mode")
            == "embedded"
        ):
            allowed_kinds.add("native-package")
        bootstrap = _object(manifest.get("bootstrap"), "manifest.bootstrap")
        if _string(bootstrap.get("mode"), "manifest.bootstrap.mode") == "embedded":
            allowed_kinds.add("bootstrap-package")
    for artifact in artifacts:
        _require(
            _string(artifact.get("kind"), "manifest artifact kind") in allowed_kinds,
            "manifest artifact kind is not authorized by the profile bindings",
        )


def _validate_profile_common_artifacts(
    profile: str, artifacts: Iterable[Mapping[str, object]]
) -> None:
    common_filenames = [
        _string(artifact.get("filename"), "manifest common artifact filename")
        for artifact in artifacts
        if artifact.get("kind") == "common"
    ]
    expected_filenames = set(PROFILE_COMMON_FILENAMES[profile])
    _require(
        len(common_filenames) == len(expected_filenames)
        and set(common_filenames) == expected_filenames,
        "manifest common artifacts do not match the profile contract",
    )


def _validate_cli_artifact_pairing(
    profile: str,
    artifacts: list[dict[str, object]],
    payload_targets: Mapping[str, str],
) -> None:
    if profile == "repository-bootstrap":
        return
    pairs: list[tuple[str, str]] = []
    for artifact in artifacts:
        kind = _string(artifact.get("kind"), "manifest artifact kind")
        if kind not in {"archive", "sbom"}:
            continue
        payload_id = _string(artifact.get("payload_id"), "manifest artifact payload_id")
        expected_target = payload_targets.get(payload_id)
        if expected_target is None:
            raise ReleaseProvenanceValidationError(
                "manifest artifact payload does not match the profile payload set"
            )
        _require(
            _string(artifact.get("target"), "manifest artifact target")
            == expected_target,
            "manifest artifact target does not match its payload",
        )
        details = TARGET_PAYLOAD_DETAILS[expected_target]
        _require(
            _string(artifact.get("platform"), "manifest artifact platform")
            == details["platform"],
            "manifest artifact platform does not match its payload target",
        )
        _require(
            _string(artifact.get("architecture"), "manifest artifact architecture")
            == details["architecture"],
            "manifest artifact architecture does not match its payload target",
        )
        expected_filename = details[
            "archive_filename" if kind == "archive" else "sbom_filename"
        ]
        _require(
            _string(artifact.get("filename"), "manifest artifact filename")
            == expected_filename,
            "manifest artifact filename does not match its payload target",
        )
        pairs.append((kind, payload_id))
    expected_pairs = {
        (kind, payload_id)
        for payload_id in payload_targets
        for kind in ("archive", "sbom")
    }
    _require(
        set(pairs) == expected_pairs and len(pairs) == len(expected_pairs),
        "manifest artifacts must contain one archive and one SBOM per payload",
    )


def _validate_manifest(
    manifest: Mapping[str, object], manifest_schema: dict[str, object]
) -> dict[str, object]:
    _validate_schema(manifest, manifest_schema, "release manifest")
    profile = _string(manifest.get("profile"), "manifest.profile")
    _require(
        profile in {"desktop", "desktop-linux", "repository-bootstrap"},
        "manifest profile is unsupported",
    )
    version = _string(manifest.get("version"), "manifest.version")
    _require(
        bool(VERSION_RE.fullmatch(version)),
        "manifest.version is not a stable semantic version",
    )
    tag = _string(manifest.get("tag"), "manifest.tag")
    expected_tag = (
        f"repository-bootstrap-v{version}"
        if profile == "repository-bootstrap"
        else f"v{version}"
    )
    _require(tag == expected_tag, "manifest tag/version mismatch")
    _require(
        _string(manifest.get("source_repository"), "manifest.source_repository")
        == SOURCE_REPOSITORY,
        "manifest source repository is not canonical",
    )
    _require(
        _string(
            manifest.get("distribution_repository"), "manifest.distribution_repository"
        )
        == DISTRIBUTION_REPOSITORY,
        "manifest distribution repository is not canonical",
    )
    source_commit = _commit(manifest.get("source_commit"), "manifest.source_commit")
    distribution_commit = _commit(
        manifest.get("distribution_commit"), "manifest.distribution_commit"
    )
    _require(
        _commit(
            manifest.get("distribution_tag_target"), "manifest.distribution_tag_target"
        )
        == distribution_commit,
        "manifest distribution tag target differs from distribution commit",
    )
    descriptor = _object(
        manifest.get("release_descriptor"), "manifest.release_descriptor"
    )
    _require(
        _string(descriptor.get("path"), "manifest.release_descriptor.path")
        == f"packaging/releases/{tag}.json",
        "manifest descriptor path does not match tag",
    )
    _ = _sha(descriptor.get("sha256"), "manifest.release_descriptor.sha256")
    _ = _sha(
        descriptor.get("package_binding_sha256"),
        "manifest.release_descriptor.package_binding_sha256",
    )
    schemas = _object(manifest.get("schemas"), "manifest.schemas")
    provenance_schema = _object(
        schemas.get("release_provenance"), "manifest.schemas.release_provenance"
    )
    _require(
        _string(provenance_schema.get("path"), "manifest provenance schema path")
        == "packaging/release-provenance.schema.json",
        "manifest provenance schema path is not canonical",
    )
    _require(
        _sha(provenance_schema.get("sha256"), "manifest provenance schema digest")
        == PROVENANCE_SCHEMA_SHA256,
        "manifest provenance schema digest is not pinned",
    )
    source_workflows = _object(
        manifest.get("source_workflows"), "manifest.source_workflows"
    )
    source_workflow = _workflow(
        source_workflows.get("release"),
        "manifest source workflow",
        SOURCE_WORKFLOW_PATH,
    )
    public_workflows = _public_workflows(manifest, distribution_commit)
    _require(
        source_workflow["commit"] == source_commit,
        "manifest source workflow commit differs from source commit",
    )
    artifacts = [
        _object(item, f"manifest.artifacts[{index}]")
        for index, item in enumerate(
            _array(manifest.get("artifacts"), "manifest.artifacts")
        )
    ]
    names = [
        _string(item.get("filename"), "manifest artifact filename")
        for item in artifacts
    ]
    _require(
        len(names) == len(set(names)), "manifest artifact filenames must be unique"
    )
    payload_targets = _validate_profile_payloads(profile, manifest)
    for index, artifact in enumerate(artifacts):
        filename = _string(
            artifact.get("filename"), f"manifest.artifacts[{index}].filename"
        )
        artifact_url = _string(artifact.get("url"), f"manifest.artifacts[{index}].url")
        expected_url = f"https://github.com/{DISTRIBUTION_REPOSITORY}/releases/download/{tag}/{filename}"
        _require(
            artifact_url == expected_url,
            f"manifest artifact URL is not immutable for {filename}",
        )
        _ = _sha(artifact.get("sha256"), f"manifest.artifacts[{index}].sha256")
        _require(
            _integer(artifact.get("size"), f"manifest.artifacts[{index}].size") >= 1,
            f"manifest artifact size is not positive: {filename}",
        )
    _validate_profile_artifact_kinds(profile, artifacts, manifest)
    _validate_profile_common_artifacts(profile, artifacts)
    _validate_cli_artifact_pairing(profile, artifacts, payload_targets)
    package_binding = _binding(
        manifest.get("package_binding"), "manifest.package_binding"
    )
    bootstrap = _binding(manifest.get("bootstrap"), "manifest.bootstrap")
    _validate_package_bindings(profile, version, artifacts, package_binding, bootstrap)
    _require(
        _canonical_sha({"package_binding": package_binding, "bootstrap": bootstrap})
        == _sha(
            descriptor.get("package_binding_sha256"), "manifest package binding digest"
        ),
        "manifest package binding digest is not canonical",
    )
    return {
        "profile": profile,
        "version": version,
        "tag": tag,
        "source_commit": source_commit,
        "distribution_commit": distribution_commit,
        "source_workflow": source_workflow,
        "public_workflow": public_workflows["draft"],
        "public_workflows": public_workflows,
        "descriptor": descriptor,
        "artifacts": artifacts,
        "package_binding_sha256": _sha(
            descriptor.get("package_binding_sha256"), "manifest package binding digest"
        ),
    }


def _validate_provenance(
    provenance: Mapping[str, object],
    provenance_schema: dict[str, object],
    manifest: Mapping[str, object],
    manifest_raw: bytes,
    expected: Mapping[str, object],
) -> dict[str, object]:
    _validate_schema(provenance, provenance_schema, "release provenance")
    for key in (
        "profile",
        "version",
        "tag",
        "source_commit",
        "distribution_commit",
        "distribution_tag_target",
    ):
        _require(
            provenance.get(key) == manifest.get(key),
            f"provenance {key} differs from manifest",
        )
    _require(
        _sha256_bytes(manifest_raw)
        == _sha(
            _object(provenance.get("manifest"), "provenance.manifest").get("sha256"),
            "provenance.manifest.sha256",
        ),
        "provenance manifest digest differs from supplied manifest",
    )
    manifest_ref = _object(provenance.get("manifest"), "provenance.manifest")
    _require(
        _string(manifest_ref.get("path"), "provenance.manifest.path")
        == "packaging/release-manifest.json",
        "provenance manifest path is not canonical",
    )
    descriptor = _object(
        provenance.get("release_descriptor"), "provenance.release_descriptor"
    )
    _require(
        descriptor == expected["descriptor"],
        "provenance descriptor binding differs from manifest",
    )
    workflows = _object(provenance.get("workflows"), "provenance.workflows")
    source = _object(workflows.get("source-release"), "provenance source workflow")
    _require(
        {key: source.get(key) for key in ("path", "commit", "sha256")}
        == expected["source_workflow"],
        "provenance source workflow differs from manifest",
    )
    public_workflows = cast(
        Mapping[str, Mapping[str, str]], expected["public_workflows"]
    )
    stage_names = {
        "draft": "public-draft",
        "publish": "public-publish",
        "channels": "package-channels",
    }
    _require(
        set(workflows)
        == {"source-release"} | {stage_names[name] for name in public_workflows},
        "provenance workflows do not match the manifest",
    )
    for name, expected_workflow in public_workflows.items():
        stage = stage_names[name]
        public = _object(workflows.get(stage), f"provenance {stage} workflow")
        _require(
            {key: public.get(key) for key in ("path", "commit", "sha256")}
            == expected_workflow,
            f"provenance {stage} workflow differs from manifest",
        )
    artifacts = [
        _object(item, "provenance artifact")
        for item in _array(provenance.get("artifacts"), "provenance.artifacts")
    ]
    expected_artifacts = [
        {key: item.get(key) for key in ("kind", "filename", "sha256", "size")}
        for item in cast(list[dict[str, object]], expected["artifacts"])
    ]
    actual_artifacts = [
        {key: item.get(key) for key in ("kind", "filename", "sha256", "size")}
        for item in artifacts
    ]
    _require(
        sorted(actual_artifacts, key=lambda item: cast(str, item["filename"]))
        == sorted(expected_artifacts, key=lambda item: cast(str, item["filename"])),
        "provenance artifact facts differ from manifest",
    )
    candidates = _object(provenance.get("candidates"), "provenance.candidates")
    if manifest.get("profile") == "repository-bootstrap":
        _require(
            candidates == {"status": "not-applicable"},
            "repository-bootstrap provenance candidates must be not-applicable",
        )
    else:
        _require(
            "status" not in candidates,
            "CLI release provenance candidates must be concrete",
        )
    return {"candidates": candidates, "expected": expected}


def _validate_manifest_and_provenance(
    root: Path, schemas: Path
) -> tuple[dict[str, object], bytes, dict[str, object], bytes, dict[str, object]]:
    manifest_schema = _load_schema(
        schemas, "release-manifest.schema.json", MANIFEST_SCHEMA_SHA256
    )
    provenance_schema = _load_schema(
        schemas, "release-provenance.schema.json", PROVENANCE_SCHEMA_SHA256
    )
    manifest, manifest_raw = _read_json(
        root / "release-manifest.json", "release manifest"
    )
    provenance, provenance_raw = _read_json(
        root / "release-provenance.json", "release provenance"
    )
    manifest_info = _validate_manifest(manifest, manifest_schema)
    provenance_info = _validate_provenance(
        provenance, provenance_schema, manifest, manifest_raw, manifest_info
    )
    return (
        manifest,
        manifest_raw,
        provenance,
        provenance_raw,
        {**manifest_info, **provenance_info},
    )


def _validate_candidates(
    root: Path,
    manifest: Mapping[str, object],
    manifest_raw: bytes,
    provenance: Mapping[str, object],
) -> dict[str, object]:
    candidates, candidates_raw = _read_json(
        root / "channel-candidates.json", "channel candidates"
    )
    archive_raw = _read_bytes(root / "channel-candidates.tar.gz", "candidate archive")
    candidate_provenance = _object(
        provenance.get("candidates"), "provenance.candidates"
    )
    document_ref = _object(
        candidate_provenance.get("document"), "provenance candidate document"
    )
    archive_ref = _object(
        candidate_provenance.get("archive"), "provenance candidate archive"
    )
    _require(
        document_ref
        == {"path": "channel-candidates.json", "sha256": _sha256_bytes(candidates_raw)},
        "provenance candidate document reference differs from supplied file",
    )
    _require(
        archive_ref
        == {"path": "channel-candidates.tar.gz", "sha256": _sha256_bytes(archive_raw)},
        "provenance candidate archive reference differs from supplied file",
    )
    _require(
        _string(
            candidates.get("source_manifest_sha256"), "candidate source manifest digest"
        )
        == _sha256_bytes(manifest_raw),
        "candidate source manifest digest differs from manifest",
    )
    _require(
        _string(candidates.get("profile"), "candidate profile")
        == _string(manifest.get("profile"), "manifest profile"),
        "candidate profile differs from manifest",
    )
    _require(
        _string(candidates.get("version"), "candidate version")
        == _string(manifest.get("version"), "manifest version"),
        "candidate version differs from manifest",
    )
    _require(
        _array(candidate_provenance.get("outputs"), "provenance candidate outputs")
        == _array(candidates.get("candidates"), "candidate outputs"),
        "provenance candidate outputs differ from candidate document",
    )
    _require(
        _object(candidate_provenance.get("generator"), "provenance candidate generator")
        == {
            **_object(candidates.get("generator"), "candidate generator"),
            "source_manifest_sha256": _sha256_bytes(manifest_raw),
        },
        "provenance candidate generator differs from candidate document",
    )
    return {"document": candidates, "raw": candidates_raw, "archive_raw": archive_raw}


def _expected_asset_names(manifest: Mapping[str, object]) -> set[str]:
    names = {
        _string(
            _object(item, "manifest artifact").get("filename"),
            "manifest artifact filename",
        )
        for item in _array(manifest.get("artifacts"), "manifest.artifacts")
    }
    names.update(RELEASE_DOCUMENTS)
    names.update(CHECKSUM_ASSETS)
    if manifest.get("profile") != "repository-bootstrap":
        names.update(CANDIDATE_ASSETS)
    return names


def _asset_facts(
    root: Path, names: Iterable[str]
) -> tuple[list[dict[str, object]], dict[str, tuple[str, int]]]:
    facts: list[dict[str, object]] = []
    by_name: dict[str, tuple[str, int]] = {}
    for name in sorted(names):
        _require(
            "/" not in name and "\\" not in name and name not in {"", ".", ".."},
            f"asset filename is unsafe: {name!r}",
        )
        path = root / name
        raw = _read_bytes(path, f"release asset {name}")
        digest, size = _sha256_bytes(raw), len(raw)
        facts.append({"filename": name, "sha256": digest, "size": size})
        by_name[name] = (digest, size)
    return facts, by_name


def _release_asset_set_sha(facts: list[dict[str, object]]) -> str:
    return _canonical_sha(facts)


def _validate_checksums(root: Path, asset_facts: Mapping[str, tuple[str, int]]) -> None:
    raw = _read_bytes(root / "SHA256SUMS", "SHA256SUMS")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseProvenanceValidationError("SHA256SUMS is not UTF-8 text") from exc
    lines = text.splitlines()
    expected_names = set(asset_facts) - CHECKSUM_ASSETS
    entries: list[tuple[str, str]] = []
    for line in lines:
        match = CHECKSUM_RE.fullmatch(line)
        _require(match is not None, f"invalid SHA256SUMS line: {line!r}")
        if match is None:
            continue
        entries.append((match.group(2), match.group(1)))
    _require(
        len(entries) == len(expected_names)
        and {name for name, _ in entries} == expected_names,
        "SHA256SUMS must contain exactly the non-checksum release assets",
    )
    names = [name for name, _ in entries]
    _require(
        names == sorted(names) and len(names) == len(set(names)),
        "SHA256SUMS names must be unique and sorted",
    )
    for name, digest in entries:
        _require(
            asset_facts[name][0] == digest, f"SHA256SUMS digest differs for {name}"
        )
    for bundle_name in ("SHA256SUMS.sigstore.json",):
        bundle, _ = _read_json(root / bundle_name, bundle_name)
        _require(bool(bundle), f"{bundle_name} must contain a JSON object")


def _validate_asset_facts(
    manifest: Mapping[str, object], asset_facts: Mapping[str, tuple[str, int]]
) -> None:
    for index, value in enumerate(
        _array(manifest.get("artifacts"), "manifest.artifacts")
    ):
        artifact = _object(value, f"manifest.artifacts[{index}]")
        filename = _string(
            artifact.get("filename"), f"manifest.artifacts[{index}].filename"
        )
        expected = (
            _sha(artifact.get("sha256"), f"manifest.artifacts[{index}].sha256"),
            _integer(artifact.get("size"), f"manifest.artifacts[{index}].size"),
        )
        _require(
            asset_facts.get(filename) == expected,
            f"release asset facts differ from manifest artifact: {filename}",
        )


def _validate_attestation(
    attestation: Mapping[str, object],
    staging_schema: dict[str, object],
    manifest: Mapping[str, object],
    manifest_raw: bytes,
    asset_set_sha: str,
) -> dict[str, object]:
    _validate_schema(attestation, staging_schema, "staging attestation")
    for key in (
        "release_tag",
        "version",
        "profile",
        "source_commit",
        "distribution_commit",
    ):
        manifest_key = "tag" if key == "release_tag" else key
        _require(
            attestation.get(key) == manifest.get(manifest_key),
            f"staging attestation {key} differs from manifest",
        )
    _require(
        _sha(
            attestation.get("release_asset_set_sha256"),
            "staging release asset set digest",
        )
        == asset_set_sha,
        "staging release asset set digest differs from supplied assets",
    )
    _require(
        _sha(attestation.get("release_manifest_sha256"), "staging manifest digest")
        == _sha256_bytes(manifest_raw),
        "staging manifest digest differs from supplied manifest",
    )
    descriptor = _object(
        manifest.get("release_descriptor"), "manifest.release_descriptor"
    )
    _require(
        _sha(attestation.get("release_descriptor_sha256"), "staging descriptor digest")
        == _sha(descriptor.get("sha256"), "manifest descriptor digest"),
        "staging descriptor digest differs from manifest",
    )
    _require(
        _sha(
            attestation.get("package_binding_sha256"), "staging package binding digest"
        )
        == _sha(
            descriptor.get("package_binding_sha256"), "manifest package binding digest"
        ),
        "staging package binding digest differs from manifest",
    )
    workflows = _object(manifest.get("source_workflows"), "manifest.source_workflows")
    public_bindings = _object(
        manifest.get("workflow_bindings"), "manifest.workflow_bindings"
    )
    attestation_workflows = _object(
        attestation.get("workflow_bindings"), "staging workflow bindings"
    )
    _require(
        _object(attestation_workflows.get("source-release"), "staging source workflow")
        == _object(workflows.get("release"), "manifest source workflow"),
        "staging source workflow differs from manifest",
    )
    stage_names = {
        "draft": "public-draft",
        "publish": "public-publish",
        "channels": "package-channels",
    }
    _require(
        set(attestation_workflows)
        == {"source-release"} | {stage_names[name] for name in public_bindings},
        "staging workflow bindings do not match the manifest",
    )
    for name, expected_binding in public_bindings.items():
        stage = stage_names.get(name)
        if stage is None:
            raise ReleaseProvenanceValidationError(
                f"manifest public workflow is unsupported: {name}"
            )
        _require(
            _object(attestation_workflows.get(stage), f"staging {stage} workflow")
            == _object(expected_binding, f"manifest {name} workflow"),
            f"staging {stage} workflow differs from manifest",
        )
    smoke = _object(attestation.get("license_smoke"), "staging license smoke")
    identity = _object(manifest.get("license_identity"), "manifest license identity")
    if manifest.get("profile") == "repository-bootstrap":
        _require(
            identity == {"mode": "not-applicable"}
            and smoke == {"status": "not-applicable"},
            "repository-bootstrap license smoke must be not-applicable",
        )
    else:
        _require(
            smoke.get("status") == "passed"
            and smoke.get("key_id") == identity.get("key_id")
            and smoke.get("public_key_sha256") == identity.get("public_key_sha256"),
            "staging license smoke does not match manifest identity",
        )
    record_ids = [
        _string(
            _object(item, "staging build record").get("payload_id"),
            "staging build record payload_id",
        )
        for item in _array(attestation.get("build_records"), "staging build records")
    ]
    verification_ids = [
        _string(
            _object(item, "staging payload verification").get("payload_id"),
            "staging payload verification payload_id",
        )
        for item in _array(
            attestation.get("payload_verifications"), "staging payload verifications"
        )
    ]
    payloads = [
        _object(item, "manifest payload")
        for item in _array(manifest.get("payloads"), "manifest.payloads")
    ]
    expected_ids = {
        _string(payload.get("id"), "manifest payload id") for payload in payloads
    }
    _require(
        set(record_ids) == expected_ids and len(record_ids) == len(expected_ids),
        "staging build records do not cover exact manifest payloads",
    )
    _require(
        set(verification_ids) == expected_ids
        and len(verification_ids) == len(expected_ids),
        "staging payload verifications do not cover exact manifest payloads",
    )
    run = _object(attestation.get("run"), "staging run")
    run_id = _string(run.get("id"), "staging run id")
    _require(bool(RUN_ID_RE.fullmatch(run_id)), "staging run id is not numeric")
    run_id_integer = int(run_id)
    _require(run_id_integer >= 1, "staging run id must be positive")
    run_url = _string(run.get("url"), "staging run URL")
    _require(
        run_url == f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{run_id}",
        "staging run URL is not canonical",
    )
    attempt = _integer(attestation.get("attempt"), "staging attempt")
    _require(attempt >= 1, "staging attempt must be positive")
    return {"id": run_id_integer, "attempt": attempt, "url": run_url}


def _validate_root_closure(root: Path, expected: set[str]) -> None:
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot inspect release root {root}: {exc}"
        ) from exc
    names = {entry.name for entry in entries}
    _require(
        names == expected,
        f"release root closure differs (missing={sorted(expected - names)}, extra={sorted(names - expected)})",
    )
    for entry in entries:
        _regular_file(entry, f"release asset {entry.name}")


def _validate_marker(
    marker: Mapping[str, object],
    manifest: Mapping[str, object],
    asset_set_sha: str,
    *,
    require_verified: bool = False,
) -> dict[str, object]:
    _require(set(marker) == MARKER_KEYS, "draft marker keys are not exact")
    _require(
        _integer(marker.get("marker_version"), "marker_version") == 1,
        "marker_version must be 1",
    )
    _require(
        _string(marker.get("profile"), "marker.profile")
        == _string(manifest.get("profile"), "manifest.profile"),
        "marker profile differs from manifest",
    )
    _require(
        _string(marker.get("tag"), "marker.tag")
        == _string(manifest.get("tag"), "manifest.tag"),
        "marker tag differs from manifest",
    )
    _require(
        _string(marker.get("release_version"), "marker.release_version")
        == _string(manifest.get("version"), "manifest.version"),
        "marker version differs from manifest",
    )
    _require(
        _commit(marker.get("source_commit"), "marker.source_commit")
        == _commit(manifest.get("source_commit"), "manifest.source_commit"),
        "marker source commit differs from manifest",
    )
    _require(
        _commit(marker.get("distribution_commit"), "marker.distribution_commit")
        == _commit(manifest.get("distribution_commit"), "manifest.distribution_commit"),
        "marker distribution commit differs from manifest",
    )
    public = _object(
        _object(manifest.get("workflow_bindings"), "manifest.workflow_bindings").get(
            "draft"
        ),
        "manifest public workflow",
    )
    source = _object(
        _object(manifest.get("source_workflows"), "manifest.source_workflows").get(
            "release"
        ),
        "manifest source workflow",
    )
    _require(
        _sha(marker.get("public_workflow_sha256"), "marker.public_workflow_sha256")
        == _sha(public.get("sha256"), "manifest public workflow digest"),
        "marker public workflow digest differs from manifest",
    )
    _require(
        _sha(marker.get("source_workflow_sha256"), "marker.source_workflow_sha256")
        == _sha(source.get("sha256"), "manifest source workflow digest"),
        "marker source workflow digest differs from manifest",
    )
    _require(
        _sha(marker.get("release_asset_set_sha256"), "marker.release_asset_set_sha256")
        == asset_set_sha,
        "marker release asset set digest differs from supplied assets",
    )
    staging_attestation_sha = _sha(
        marker.get("staging_attestation_sha256"), "marker.staging_attestation_sha256"
    )
    source_run_id = _integer(marker.get("source_run_id"), "marker.source_run_id")
    _require(source_run_id >= 1, "marker source_run_id must be positive")
    source_attempt = _integer(
        marker.get("source_run_attempt"), "marker.source_run_attempt"
    )
    _require(source_attempt >= 1, "marker source_run_attempt must be positive")
    staging_artifact_id = _integer(
        marker.get("staging_artifact_id"), "marker.staging_artifact_id"
    )
    _require(staging_artifact_id >= 1, "marker staging_artifact_id must be positive")
    staging_artifact_digest = _string(
        marker.get("staging_artifact_digest"), "marker.staging_artifact_digest"
    )
    _require(
        bool(ARTIFACT_DIGEST_RE.fullmatch(staging_artifact_digest)),
        "marker staging_artifact_digest must be sha256:<lowercase digest>",
    )
    staging_artifact_expires_at = _string(
        marker.get("staging_artifact_expires_at"),
        "marker.staging_artifact_expires_at",
    )
    try:
        parsed_expiry = datetime.strptime(
            staging_artifact_expires_at, "%Y-%m-%dT%H:%M:%SZ"
        )
    except ValueError as exc:
        raise ReleaseProvenanceValidationError(
            "marker staging_artifact_expires_at must be canonical UTC text"
        ) from exc
    _require(
        parsed_expiry.strftime("%Y-%m-%dT%H:%M:%SZ") == staging_artifact_expires_at,
        "marker staging_artifact_expires_at must be canonical UTC text",
    )
    state = _string(marker.get("state"), "marker.state")
    _require(state in {"preparing", "verified"}, "marker state is not supported")
    if require_verified:
        _require(state == "verified", "public draft marker must be verified")
    verified_id = marker.get("verified_run_id")
    verified_attempt = marker.get("verified_run_attempt")
    if state == "preparing":
        _require(
            verified_id is None and verified_attempt is None,
            "preparing marker must not contain verified run facts",
        )
    else:
        verified_integer = _integer(verified_id, "marker.verified_run_id")
        _require(verified_integer >= 1, "verified run ID must be positive")
        _require(
            _integer(verified_attempt, "marker.verified_run_attempt") >= 1,
            "verified run attempt must be positive",
        )
    return {
        "sha256": staging_attestation_sha,
        "state": state,
        "source_run": {
            "id": source_run_id,
            "attempt": source_attempt,
            "url": f"https://github.com/{SOURCE_REPOSITORY}/actions/runs/{source_run_id}",
        },
    }


def _plan(
    manifest: Mapping[str, object],
    asset_facts: Mapping[str, tuple[str, int]],
    asset_set_sha: str,
    staging_attestation_sha: str,
    source_run: Mapping[str, object],
    public_workflow_name: str = "draft",
) -> dict[str, object]:
    source = _object(
        _object(manifest.get("source_workflows"), "manifest.source_workflows").get(
            "release"
        ),
        "manifest source workflow",
    )
    public = _object(
        _object(manifest.get("workflow_bindings"), "manifest.workflow_bindings").get(
            public_workflow_name
        ),
        "manifest public workflow",
    )
    assets = [
        {"name": name, "sha256": digest, "size": size}
        for name, (digest, size) in sorted(asset_facts.items())
    ]
    plan: dict[str, object] = {
        "schema_version": 1,
        "profile": _string(manifest.get("profile"), "manifest.profile"),
        "tag": _string(manifest.get("tag"), "manifest.tag"),
        "version": _string(manifest.get("version"), "manifest.version"),
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": _commit(
            manifest.get("source_commit"), "manifest.source_commit"
        ),
        "distribution_repository": DISTRIBUTION_REPOSITORY,
        "distribution_commit": _commit(
            manifest.get("distribution_commit"), "manifest.distribution_commit"
        ),
        "distribution_tag_target": _commit(
            manifest.get("distribution_tag_target"), "manifest.distribution_tag_target"
        ),
        "release_asset_set_sha256": asset_set_sha,
        "staging_attestation_sha256": staging_attestation_sha,
        "source_workflow": {
            "path": _string(source.get("path"), "source workflow path"),
            "commit": _commit(source.get("commit"), "source workflow commit"),
            "sha256": _sha(source.get("sha256"), "source workflow digest"),
        },
        "public_workflow": {
            "path": _string(public.get("path"), "public workflow path"),
            "commit": _commit(public.get("commit"), "public workflow commit"),
            "sha256": _sha(public.get("sha256"), "public workflow digest"),
        },
        "source_run": dict(source_run),
        "assets": assets,
    }
    _require(set(plan) == PLAN_KEYS, "validated plan keys are not exact")
    return plan


def build_publication_plan(
    plan: Mapping[str, object],
    manifest: Mapping[str, object],
    marker_info: Mapping[str, object],
) -> dict[str, object]:
    """Bind the verified draft plan to the complete public orchestration."""

    stages = tuple(
        _string(item, "manifest authorized stage")
        for item in _array(
            manifest.get("authorized_stages"), "manifest.authorized_stages"
        )
    )
    _require(
        stages == ORCHESTRATION_STAGES,
        "public publication requires complete ordered orchestration stages",
    )
    distribution_commit = _commit(
        plan.get("distribution_commit"), "plan.distribution_commit"
    )
    workflows = _public_workflows(manifest, distribution_commit)
    _require(
        workflows.get("draft") == plan.get("public_workflow"),
        "publication draft workflow differs from the public plan",
    )
    run_id = _integer(marker_info.get("verified_run_id"), "marker.verified_run_id")
    run_attempt = _integer(
        marker_info.get("verified_run_attempt"), "marker.verified_run_attempt"
    )
    _require(
        run_id >= 1 and run_attempt >= 1,
        "verified draft run facts must be positive",
    )
    result = dict(plan)
    result["authorized_stages"] = list(stages)
    result["public_workflows"] = workflows
    result["draft_run"] = {"id": run_id, "attempt": run_attempt}
    return result


def _validate_common(
    root: Path, schemas: Path
) -> tuple[dict[str, object], bytes, dict[str, tuple[str, int]], str]:
    manifest, manifest_raw, provenance, _, _ = _validate_manifest_and_provenance(
        root, schemas
    )
    if manifest.get("profile") != "repository-bootstrap":
        _ = _validate_candidates(root, manifest, manifest_raw, provenance)
    expected_names = _expected_asset_names(manifest)
    facts, by_name = _asset_facts(root, expected_names)
    _validate_asset_facts(manifest, by_name)
    _validate_checksums(root, by_name)
    asset_set_sha = _release_asset_set_sha(facts)
    return manifest, manifest_raw, by_name, asset_set_sha


def validate_staging(root: Path, schemas: Path) -> dict[str, object]:
    """Validate the complete staging envelope and return a public plan."""
    try:
        root = root.resolve(strict=True)
        schemas = schemas.resolve(strict=True)
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot resolve staging paths: {exc}"
        ) from exc
    _require(root.is_dir() and schemas.is_dir(), "root and schemas must be directories")
    staging_schema = _load_schema(
        schemas, "staging-attestation.schema.json", STAGING_SCHEMA_SHA256
    )
    manifest, manifest_raw, by_name, asset_set_sha = _validate_common(root, schemas)
    _validate_root_closure(root, set(by_name) | STAGING_ONLY_NAMES)
    attestation, _ = _read_json(
        root / "staging-attestation.json", "staging attestation"
    )
    source_run = _validate_attestation(
        attestation,
        staging_schema,
        manifest,
        manifest_raw,
        asset_set_sha,
    )
    staging_sha = _sha256_bytes(
        _read_bytes(root / "staging-attestation.json", "staging attestation")
    )
    return _plan(manifest, by_name, asset_set_sha, staging_sha, source_run)


def validate_public_draft(root: Path, schemas: Path, marker: Path) -> dict[str, object]:
    """Validate the complete public draft and its trusted marker."""
    try:
        root = root.resolve(strict=True)
        schemas = schemas.resolve(strict=True)
        marker = marker.resolve(strict=True)
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot resolve public draft paths: {exc}"
        ) from exc
    _require(root.is_dir() and schemas.is_dir(), "root and schemas must be directories")
    manifest, _, by_name, asset_set_sha = _validate_common(root, schemas)
    _validate_root_closure(root, set(by_name))
    marker_document, _ = _read_json(marker, "draft marker")
    marker_info = _validate_marker(
        marker_document, manifest, asset_set_sha, require_verified=True
    )
    return _plan(
        manifest,
        by_name,
        asset_set_sha,
        _string(marker_info["sha256"], "marker staging attestation digest"),
        cast(Mapping[str, object], marker_info["source_run"]),
    )


def validate_package_channels(root: Path, schemas: Path) -> dict[str, object]:
    """Validate immutable public release inputs without a publication marker."""

    try:
        root = root.resolve(strict=True)
        schemas = schemas.resolve(strict=True)
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot resolve package-channel paths: {exc}"
        ) from exc
    _require(root.is_dir() and schemas.is_dir(), "root and schemas must be directories")
    manifest, _, by_name, asset_set_sha = _validate_common(root, schemas)
    _validate_root_closure(root, set(by_name))
    return _plan(
        manifest=manifest,
        asset_facts=by_name,
        asset_set_sha=asset_set_sha,
        staging_attestation_sha="",
        source_run={},
        public_workflow_name="channels",
    )


def validate_public_publish(
    root: Path, schemas: Path, marker: Path
) -> dict[str, object]:
    """Validate a draft and emit the atomic publication workflow plan."""

    plan = validate_public_draft(root, schemas, marker)
    resolved_root = root.resolve(strict=True)
    resolved_marker = marker.resolve(strict=True)
    manifest, _ = _read_json(
        resolved_root / "release-manifest.json", "release manifest"
    )
    marker_document, _ = _read_json(resolved_marker, "draft marker")
    return build_publication_plan(plan, manifest, marker_document)


def _write_plan(path: Path, plan: Mapping[str, object]) -> None:
    encoded = (
        json.dumps(plan, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if str(path) == "-":
        _ = sys.stdout.buffer.write(encoded)
        return
    if path.exists() and path.is_symlink():
        raise ReleaseProvenanceValidationError(
            f"output plan must not be a symlink: {path}"
        )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(encoded)
    except OSError as exc:
        raise ReleaseProvenanceValidationError(
            f"cannot write output plan {path}: {exc}"
        ) from exc


def parse_arguments(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    staging = subparsers.add_parser(
        "staging", help="validate the complete Stage A release envelope"
    )
    _ = staging.add_argument("--root", type=Path, required=True)
    _ = staging.add_argument("--schemas", type=Path, required=True)
    _ = staging.add_argument("--output-plan", type=Path, required=True)
    public = subparsers.add_parser(
        "public-draft", help="validate the complete public draft release"
    )
    _ = public.add_argument("--root", type=Path, required=True)
    _ = public.add_argument("--schemas", type=Path, required=True)
    _ = public.add_argument("--marker", type=Path, required=True)
    _ = public.add_argument("--output-plan", type=Path, required=True)
    package_channels = subparsers.add_parser(
        "package-channels",
        help="validate immutable release inputs for package-channel preparation",
    )
    _ = package_channels.add_argument("--root", type=Path, required=True)
    _ = package_channels.add_argument("--schemas", type=Path, required=True)
    _ = package_channels.add_argument("--output-plan", type=Path, required=True)
    reauthorization = subparsers.add_parser(
        "reauthorization",
        help="validate one checked-in release workflow reauthorization record",
    )
    _ = reauthorization.add_argument("--record", type=Path, required=True)
    _ = reauthorization.add_argument("--schemas", type=Path, required=True)
    _ = reauthorization.add_argument("--tag", required=True)
    _ = reauthorization.add_argument("--stage", required=True)
    _ = reauthorization.add_argument("--runtime-commit", required=True)
    for prefix in ("original", "replacement"):
        _ = reauthorization.add_argument(f"--{prefix}-path", required=True)
        _ = reauthorization.add_argument(f"--{prefix}-commit", required=True)
        _ = reauthorization.add_argument(f"--{prefix}-sha256", required=True)
    publication = subparsers.add_parser(
        "public-publish",
        help="validate the exact public draft and atomic publication bindings",
    )
    _ = publication.add_argument("--root", type=Path, required=True)
    _ = publication.add_argument("--schemas", type=Path, required=True)
    _ = publication.add_argument("--marker", type=Path, required=True)
    _ = publication.add_argument("--output-plan", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_arguments(argv)
    values = cast(Mapping[str, object], vars(args))
    mode = _string(values.get("mode"), "mode")
    if mode == "reauthorization":
        record = values.get("record")
        schemas = values.get("schemas")
        if not isinstance(record, Path) or not isinstance(schemas, Path):
            return 2
        original = {
            "path": _string(values.get("original_path"), "original path"),
            "commit": _string(values.get("original_commit"), "original commit"),
            "sha256": _string(values.get("original_sha256"), "original SHA-256"),
        }
        replacement = {
            "path": _string(values.get("replacement_path"), "replacement path"),
            "commit": _string(values.get("replacement_commit"), "replacement commit"),
            "sha256": _string(values.get("replacement_sha256"), "replacement SHA-256"),
        }
        try:
            _ = validate_workflow_reauthorization_file(
                record,
                schemas,
                expected_tag=_string(values.get("tag"), "tag"),
                expected_stage=_string(values.get("stage"), "stage"),
                original=original,
                replacement=replacement,
                runtime_commit=_string(values.get("runtime_commit"), "runtime commit"),
            )
        except (ReleaseProvenanceValidationError, DependencyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0
    root = values.get("root")
    schemas = values.get("schemas")
    marker = values.get("marker")
    output_plan = values.get("output_plan")
    if (
        not isinstance(root, Path)
        or not isinstance(schemas, Path)
        or not isinstance(output_plan, Path)
    ):
        return 2
    try:
        if mode == "staging":
            plan = validate_staging(root, schemas)
        elif mode == "package-channels":
            plan = validate_package_channels(root, schemas)
        else:
            if not isinstance(marker, Path):
                return 2
            if mode == "public-draft":
                plan = validate_public_draft(root, schemas, marker)
            else:
                plan = validate_public_publish(root, schemas, marker)
        _write_plan(output_plan, plan)
    except (
        ReleaseProvenanceValidationError,
        DependencyError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if str(output_plan) != "-":
        print(f"valid: {output_plan}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
