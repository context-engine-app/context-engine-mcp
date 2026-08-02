#!/usr/bin/env python3
"""Validate the public, data-only channel-candidate contract.

The validator intentionally has no dependency on the private release
contract validator. Desktop profiles consume ``release-manifest.json``,
``channel-candidates.json``, and ``channel-candidates.tar.gz``. Repository
bootstrap profiles require the candidate files to be absent. Archive members
are inspected from memory and are never extracted or executed.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib
import io
import json
import re
import stat
import sys
import tarfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import NoReturn, Protocol, TypeAlias, cast


ROOT = Path(__file__).resolve().parents[2]
CHANNEL_SCHEMA_SHA256 = (
    "15da9460985ad7ec7c48cfad343e4b0e6a706869b1714c5b8a40276952db3393"
)
LEGACY_CHANNEL_SCHEMA_SHA256 = (
    "7ce660193dc346c70fd0c8db57bd1d91d1743d3b6059959b96f76443d037d57a"
)
MANIFEST_SCHEMA_SHA256 = (
    "250c2d03ff52ca30be5e550ed011fa6b3bcb24f37fd86a25e5858aabd3ea4bbe"
)
CHANNEL_SCHEMA_NAME = "channel-candidates.schema.json"
MANIFEST_SCHEMA_NAME = "release-manifest.schema.json"
EXPECTED_TEMPLATES = {
    "packaging/homebrew/context-engine.rb.in",
    "packaging/scoop/context-engine.json.in",
}
EXPECTED_CANDIDATES = {
    ("homebrew", "formula"): "Formula/context-engine.rb",
    ("scoop", "manifest"): "bucket/context-engine.json",
}
LEGACY_EXPECTED_TEMPLATES = EXPECTED_TEMPLATES | {
    "packaging/winget/package.yaml.in",
    "packaging/winget/installer.yaml.in",
    "packaging/winget/locale.en-US.yaml.in",
}
LEGACY_EXPECTED_CANDIDATES = {
    **EXPECTED_CANDIDATES,
    (
        "winget",
        "version",
    ): "manifests/c/ContextEngine/ContextEngine/{version}/ContextEngine.ContextEngine.yaml",
    (
        "winget",
        "installer",
    ): "manifests/c/ContextEngine/ContextEngine/{version}/ContextEngine.ContextEngine.installer.yaml",
    (
        "winget",
        "locale",
    ): "manifests/c/ContextEngine/ContextEngine/{version}/ContextEngine.ContextEngine.locale.en-US.yaml",
}
EXPECTED_GENERATOR_SOURCES = {
    "packaging/channel-candidates.schema.json",
    "packaging/homebrew/context-engine.rb.in",
    "packaging/scoop/context-engine.json.in",
    "scripts/release/render_package_metadata.py",
    "scripts/release/validate_release_contract.py",
}
LEGACY_EXPECTED_GENERATOR_SOURCES = EXPECTED_GENERATOR_SOURCES | {
    "packaging/winget/package.yaml.in",
    "packaging/winget/installer.yaml.in",
    "packaging/winget/locale.en-US.yaml.in",
    "packaging/winget/schema/SOURCE.json",
    "packaging/winget/schema/manifest.defaultLocale.1.12.0.json",
    "packaging/winget/schema/manifest.installer.1.12.0.json",
    "packaging/winget/schema/manifest.version.1.12.0.json",
}
CLI_ARCHIVE_IDS: frozenset[str] = frozenset(
    {
        "context-engine-x86_64-apple-darwin",
        "context-engine-aarch64-apple-darwin",
        "context-engine-x86_64-pc-windows-msvc",
    }
)
PROFILE_ARCHIVE_IDS: dict[str, frozenset[str]] = {
    "desktop": CLI_ARCHIVE_IDS,
    "desktop-linux": CLI_ARCHIVE_IDS
    | frozenset(
        {
            "context-engine-x86_64-unknown-linux-gnu",
            "context-engine-aarch64-unknown-linux-gnu",
        }
    ),
}
LEGACY_DESKTOP_LINUX_ARCHIVE_IDS = PROFILE_ARCHIVE_IDS["desktop-linux"] - {
    "context-engine-aarch64-unknown-linux-gnu"
}


def _uses_legacy_channel_contract(profile: str, version: str) -> bool:
    return profile == "desktop-linux" and version == "0.1.0"


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
URL_RE: re.Pattern[str] = re.compile(r"https?://[^\s\"'<>]+")
MUTABLE_URL_RE: re.Pattern[str] = re.compile(
    r"/(?:latest|main|master|trunk|head)(?:/|$)|[?#]", re.IGNORECASE
)

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class CandidateValidationError(ValueError):
    """Raised when a public candidate document or archive is invalid."""


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
            raise CandidateValidationError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> NoReturn:
    raise CandidateValidationError(
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
    except (CandidateValidationError, json.JSONDecodeError) as exc:
        raise CandidateValidationError(f"invalid JSON in {source}: {exc}") from exc


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CandidateValidationError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise CandidateValidationError(f"{label} must be a JSON array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CandidateValidationError(f"{label} must be a JSON string")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CandidateValidationError(f"{label} must be a JSON integer")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateValidationError(message)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _regular_file(path: Path, label: str) -> None:
    try:
        if path.is_symlink():
            raise CandidateValidationError(f"{label} must not be a symlink: {path}")
        mode = path.stat().st_mode
    except OSError as exc:
        raise CandidateValidationError(f"cannot inspect {label} {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise CandidateValidationError(f"{label} must be a regular file: {path}")


def _read_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    _regular_file(path, label)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CandidateValidationError(f"cannot read {label} {path}: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateValidationError(f"{label} is not UTF-8 JSON: {path}") from exc
    value = parse_json(text, str(path))
    return _object(value, label), raw


def _safe_path(value: str, label: str) -> None:
    _require(bool(value), f"{label} must not be empty")
    _require("\\" not in value, f"{label} must not contain backslashes")
    _require("\x00" not in value, f"{label} must not contain NUL")
    _require(not value.startswith("/"), f"{label} must be relative")
    parts = value.split("/")
    _require(".." not in parts and "." not in parts, f"{label} contains traversal")


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


def _load_schema(schemas: Path, name: str, expected_sha256: str) -> dict[str, object]:
    path = schemas / name
    _regular_file(path, f"schema {name}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CandidateValidationError(f"cannot read schema {path}: {exc}") from exc
    actual = _sha256_bytes(raw)
    _require(actual == expected_sha256, f"schema digest mismatch for {name}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateValidationError(f"schema is not UTF-8 JSON: {path}") from exc
    value = parse_json(text, str(path))
    schema = _object(value, f"schema {name}")
    _reject_external_refs(schema, f"schema {name}")
    validator_type = _jsonschema()
    try:
        validator_type.check_schema(schema)
    except Exception as exc:  # jsonschema exposes implementation-specific errors
        raise CandidateValidationError(
            f"invalid Draft 2020-12 schema {name}: {exc}"
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
        raise CandidateValidationError(
            f"{label} schema violation at {location}: {first.message}"
        )


def _manifest_inputs(
    manifest: Mapping[str, object],
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, str]]:
    profile = _string(manifest.get("profile"), "manifest.profile")
    if profile not in PROFILE_ARCHIVE_IDS:
        raise CandidateValidationError(
            f"manifest profile does not define an archive set: {profile}"
        )
    version = _string(manifest.get("version"), "manifest.version")
    expected_archive_ids = (
        LEGACY_DESKTOP_LINUX_ARCHIVE_IDS
        if _uses_legacy_channel_contract(profile, version)
        else PROFILE_ARCHIVE_IDS[profile]
    )
    payloads: list[dict[str, str]] = []
    for index, value in enumerate(
        _array(manifest.get("payloads"), "manifest.payloads")
    ):
        payload = _object(value, f"manifest.payloads[{index}]")
        payloads.append(
            {
                "id": _string(payload.get("id"), f"manifest.payloads[{index}].id"),
                "filename": _string(
                    payload.get("filename"), f"manifest.payloads[{index}].filename"
                ),
                "sha256": _string(
                    payload.get("sha256"), f"manifest.payloads[{index}].sha256"
                ),
            }
        )
    payloads.sort(key=lambda item: item["id"])
    archives: list[dict[str, str]] = []
    archive_urls: dict[str, str] = {}
    for index, value in enumerate(
        _array(manifest.get("artifacts"), "manifest.artifacts")
    ):
        artifact = _object(value, f"manifest.artifacts[{index}]")
        if artifact.get("kind") != "archive":
            continue
        filename = _string(
            artifact.get("filename"), f"manifest.artifacts[{index}].filename"
        )
        artifact_url = _string(artifact.get("url"), f"manifest.artifacts[{index}].url")
        artifact_id = _string(
            artifact.get("payload_id"), f"manifest.artifacts[{index}].payload_id"
        )
        digest = _string(artifact.get("sha256"), f"manifest.artifacts[{index}].sha256")
        archives.append({"id": artifact_id, "filename": filename, "sha256": digest})
        archive_urls[filename] = artifact_url
    archives.sort(key=lambda item: item["id"])
    archive_count_message = (
        "manifest must contain exactly three archive records"
        if profile == "desktop"
        else f"manifest {profile} must contain exactly {len(expected_archive_ids)} archive records"
    )
    _require(
        len(archives) == len(expected_archive_ids),
        archive_count_message,
    )
    _require(
        len({item["id"] for item in archives}) == len(archives),
        "manifest archive payload IDs must be unique",
    )
    _require(
        len({item["filename"] for item in archives}) == len(archives),
        "manifest archive filenames must be unique",
    )
    _require(
        {item["id"] for item in archives} == set(expected_archive_ids),
        "manifest archive inputs are not the exact desktop set"
        if profile == "desktop"
        else f"manifest archive inputs are not the exact {profile} archive set",
    )
    return payloads, archives, archive_urls


def _candidate_paths(profile: str, version: str) -> dict[tuple[str, str], str]:
    candidates = (
        LEGACY_EXPECTED_CANDIDATES
        if _uses_legacy_channel_contract(profile, version)
        else EXPECTED_CANDIDATES
    )
    return {
        coordinate: path.format(version=version)
        for coordinate, path in candidates.items()
    }


def _validate_generator(
    generator: Mapping[str, object], source_commit: str, profile: str, version: str
) -> None:
    legacy = _uses_legacy_channel_contract(profile, version)
    expected_schema_sha256 = (
        LEGACY_CHANNEL_SCHEMA_SHA256 if legacy else CHANNEL_SCHEMA_SHA256
    )
    expected_templates = LEGACY_EXPECTED_TEMPLATES if legacy else EXPECTED_TEMPLATES
    expected_sources = (
        LEGACY_EXPECTED_GENERATOR_SOURCES if legacy else EXPECTED_GENERATOR_SOURCES
    )
    _require(
        _string(
            generator.get("release_source_commit"),
            "candidate generator release source commit",
        )
        == source_commit,
        "candidate generator release source commit differs from manifest",
    )
    _require(
        _string(generator.get("schema_path"), "candidate generator schema path")
        == "packaging/channel-candidates.schema.json",
        "candidate generator schema path is not canonical",
    )
    _require(
        _string(generator.get("schema_sha256"), "candidate generator schema digest")
        == expected_schema_sha256,
        "candidate generator schema digest is not the pinned public schema",
    )
    _require(
        _string(generator.get("generator_path"), "candidate generator path")
        == "scripts/release/render_package_metadata.py",
        "candidate generator path is not canonical",
    )
    templates = [
        _object(item, "candidate generator template")
        for item in _array(generator.get("templates"), "candidate generator templates")
    ]
    template_paths = [
        _string(item.get("path"), "candidate template path") for item in templates
    ]
    _require(
        set(template_paths) == expected_templates
        and len(template_paths) == len(expected_templates),
        "candidate generator templates are not the exact versioned template set",
    )
    sources = [
        _object(item, "candidate generator source")
        for item in _array(generator.get("sources"), "candidate generator sources")
    ]
    source_paths = [
        _string(item.get("path"), "candidate source path") for item in sources
    ]
    _require(
        len(source_paths) == len(set(source_paths)),
        "candidate generator source paths must be unique",
    )
    _require(
        set(source_paths) == expected_sources,
        "candidate generator sources are not the exact versioned source set",
    )
    for source_path in source_paths:
        _safe_path(source_path, "candidate generator source path")
    generator_commit = _string(
        generator.get("generator_commit"), "candidate generator commit"
    )
    _require(
        bool(COMMIT_RE.fullmatch(generator_commit)),
        "candidate generator commit is not a commit hash",
    )


def _validate_urls(
    data: bytes, archive_urls: Mapping[str, str], label: str
) -> set[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateValidationError(f"{label} is not UTF-8 data") from exc
    found_download_urls: set[str] = set()
    raw_urls = cast(list[str], URL_RE.findall(text))
    for raw_url in raw_urls:
        url = raw_url.rstrip(".,;:)]}>")
        _require(url.startswith("https://"), f"{label} contains a non-HTTPS URL")
        _require(
            not MUTABLE_URL_RE.search(url), f"{label} contains a mutable URL: {url}"
        )
        if "/releases/download/" in url:
            expected = set(archive_urls.values())
            _require(url in expected, f"{label} contains an unbound release URL: {url}")
            found_download_urls.add(url)
    return found_download_urls


def _require_ustar_headers(data: bytes) -> None:
    block_size = 512
    zero_block = bytes(block_size)
    _require(
        len(data) % block_size == 0,
        "candidate archive tar stream is not block-aligned",
    )
    offset = 0
    found_end = False
    while offset < len(data):
        header = data[offset : offset + block_size]
        if header == zero_block:
            _require(
                data[offset : offset + (2 * block_size)] == zero_block * 2,
                "candidate archive is missing the two-block end marker",
            )
            _require(
                not any(data[offset:]),
                "candidate archive contains data after its end marker",
            )
            found_end = True
            break
        _require(
            header[257:263] == b"ustar\0" and header[263:265] == b"00",
            "candidate archive must use USTAR headers",
        )
        _require(
            header[156:157] in (b"\0", tarfile.REGTYPE),
            "candidate archive contains a non-regular USTAR header",
        )
        size_field = header[124:136]
        _require(
            not size_field or size_field[0] & 0x80 == 0,
            "candidate archive uses a non-USTAR size encoding",
        )
        size_digits = size_field.strip(b"\0 ")
        _require(
            all(ord("0") <= digit <= ord("7") for digit in size_digits),
            "candidate archive contains an invalid USTAR size",
        )
        size = int(size_digits or b"0", 8)
        data_blocks = (size + block_size - 1) // block_size
        offset += block_size * (1 + data_blocks)
        _require(
            offset <= len(data),
            "candidate archive member extends beyond the tar stream",
        )
    _require(found_end, "candidate archive is missing its end marker")


def _read_candidate_archive(
    path: Path, records: Mapping[str, Mapping[str, object]], expected_digest: str
) -> dict[str, bytes]:
    _regular_file(path, "candidate archive")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        raw = path.read_bytes()
    except OSError as exc:
        raise CandidateValidationError(
            f"cannot read candidate archive {path}: {exc}"
        ) from exc
    _require(mode == 0o644, "candidate archive mode must be 0644")
    _require(
        _sha256_bytes(raw) == expected_digest,
        "candidate archive digest differs from channel-candidates.json",
    )
    _require(
        len(raw) >= 10 and raw[:2] == b"\x1f\x8b", "candidate archive is not gzip data"
    )
    _require(
        raw[3] == 0 and int.from_bytes(raw[4:8], "little") == 0,
        "candidate archive gzip header is not deterministic",
    )
    try:
        tar_bytes = gzip.decompress(raw)
        _require_ustar_headers(tar_bytes)
        archive = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:")
    except (EOFError, OSError, tarfile.TarError) as exc:
        raise CandidateValidationError(f"cannot open candidate archive: {exc}") from exc
    with archive:
        _require(
            not archive.pax_headers,
            "candidate archive must not contain global extended metadata",
        )
        try:
            members = archive.getmembers()
        except (EOFError, OSError, tarfile.TarError) as exc:
            raise CandidateValidationError(
                f"cannot inspect candidate archive: {exc}"
            ) from exc
        names = [member.name for member in members]
        _require(names == sorted(names), "candidate archive members are not sorted")
        _require(
            len(names) == len(set(names)), "candidate archive contains duplicate paths"
        )
        _require(
            set(names) == set(records),
            "candidate archive does not contain the exact candidate paths",
        )
        files: dict[str, bytes] = {}
        for member in members:
            _safe_path(member.name, "candidate archive member path")
            _require(
                member.type == tarfile.REGTYPE
                and member.isfile()
                and not member.linkname,
                f"candidate archive member is not a regular file: {member.name}",
            )
            _require(
                (
                    member.mode,
                    member.uid,
                    member.gid,
                    member.uname,
                    member.gname,
                    member.mtime,
                    member.devmajor,
                    member.devminor,
                )
                == (0o644, 0, 0, "", "", 0, 0, 0),
                f"candidate archive member metadata is not normalized: {member.name}",
            )
            _require(
                not member.pax_headers,
                f"candidate archive member has unexpected extended metadata: {member.name}",
            )
            try:
                stream = archive.extractfile(member)
                data = stream.read() if stream is not None else b""
            except (EOFError, OSError, tarfile.TarError) as exc:
                raise CandidateValidationError(
                    f"cannot read candidate archive member: {member.name}: {exc}"
                ) from exc
            _require(
                stream is not None,
                f"candidate archive member cannot be read: {member.name}",
            )
            record = records[member.name]
            _require(
                len(data)
                == _integer(record.get("size"), f"candidate {member.name} size"),
                f"candidate archive member size differs from channel-candidates.json: {member.name}",
            )
            _require(
                _sha256_bytes(data)
                == _string(record.get("sha256"), f"candidate {member.name} digest"),
                f"candidate archive member digest differs from channel-candidates.json: {member.name}",
            )
            files[member.name] = data
    return files


def validate_channel_candidates(root: Path, schemas: Path) -> None:
    """Validate fixed public candidate files under ``root``."""
    try:
        root = root.resolve(strict=True)
        schemas = schemas.resolve(strict=True)
    except OSError as exc:
        raise CandidateValidationError(
            f"cannot resolve candidate paths: {exc}"
        ) from exc
    if not root.is_dir() or not schemas.is_dir():
        raise CandidateValidationError("root and schemas must be directories")
    manifest, manifest_raw = _read_json(
        root / "release-manifest.json", "release manifest"
    )
    manifest_schema = _load_schema(
        schemas, MANIFEST_SCHEMA_NAME, MANIFEST_SCHEMA_SHA256
    )
    _validate_schema(manifest, manifest_schema, "release manifest")
    if manifest.get("profile") == "repository-bootstrap":
        for candidate_name in (
            "channel-candidates.json",
            "channel-candidates.tar.gz",
            "Formula/context-engine.rb",
            "bucket/context-engine.json",
        ):
            candidate_path = root / candidate_name
            if candidate_path.exists() or candidate_path.is_symlink():
                raise CandidateValidationError(
                    "repository-bootstrap release must not contain channel candidates"
                )
        return
    candidates, _ = _read_json(root / "channel-candidates.json", "channel candidates")
    channel_schema = _load_schema(schemas, CHANNEL_SCHEMA_NAME, CHANNEL_SCHEMA_SHA256)
    _validate_schema(candidates, channel_schema, "channel candidates")
    profile = _string(manifest.get("profile"), "manifest.profile")
    _require(
        profile in {"desktop", "desktop-linux"},
        "portable channel validation supports only CLI profiles",
    )
    version = _string(manifest.get("version"), "manifest.version")
    tag = _string(manifest.get("tag"), "manifest.tag")
    _require(
        _string(candidates.get("profile"), "candidates.profile") == profile,
        "channel candidates profile must match the manifest CLI profile",
    )
    _require(
        _string(candidates.get("version"), "candidates.version") == version
        and _string(candidates.get("release_tag"), "candidates.release_tag") == tag,
        "channel candidates release identity differs from manifest",
    )
    manifest_sha = _sha256_bytes(manifest_raw)
    _require(
        _string(
            candidates.get("source_manifest_sha256"),
            "candidates.source_manifest_sha256",
        )
        == manifest_sha,
        "channel candidates do not bind the supplied manifest",
    )
    payload_inputs, archive_inputs, archive_urls = _manifest_inputs(manifest)
    archive_by_id = {
        item["id"]: archive_urls[item["filename"]] for item in archive_inputs
    }
    inputs = _object(candidates.get("inputs"), "candidates.inputs")
    actual_payload_inputs = [
        _object(item, "candidate payload input")
        for item in _array(inputs.get("payloads"), "candidates.inputs.payloads")
    ]
    actual_archive_inputs = [
        _object(item, "candidate archive input")
        for item in _array(inputs.get("archives"), "candidates.inputs.archives")
    ]
    _require(
        actual_payload_inputs == payload_inputs,
        "candidate payload inputs differ from manifest",
    )
    _require(
        actual_archive_inputs == archive_inputs,
        "candidate archive inputs differ from manifest",
    )
    generator = _object(candidates.get("generator"), "candidates.generator")
    _validate_generator(
        generator,
        _string(manifest.get("source_commit"), "manifest.source_commit"),
        profile,
        version,
    )
    expected_paths = _candidate_paths(profile, version)
    records: dict[str, Mapping[str, object]] = {}
    coordinates_by_path: dict[str, tuple[str, str]] = {}
    coordinates: set[tuple[str, str]] = set()
    for index, value in enumerate(
        _array(candidates.get("candidates"), "candidates.candidates")
    ):
        candidate = _object(value, f"candidates.candidates[{index}]")
        kind = _string(candidate.get("kind"), f"candidate[{index}].kind")
        file_kind = _string(candidate.get("file_kind"), f"candidate[{index}].file_kind")
        coordinate = (kind, file_kind)
        _require(
            coordinate in expected_paths,
            f"unsupported candidate coordinate: {coordinate!r}",
        )
        path_value = _string(candidate.get("path"), f"candidate[{index}].path")
        _safe_path(path_value, f"candidate[{index}].path")
        _require(
            path_value == expected_paths[coordinate],
            f"candidate path is not canonical for {coordinate!r}",
        )
        _require(
            coordinate not in coordinates and path_value not in records,
            "candidate coordinates and paths must be unique",
        )
        _require(
            _string(candidate.get("mode"), f"candidate[{index}].mode") == "0644",
            f"candidate mode must be 0644: {path_value}",
        )
        _require(
            bool(
                SHA256_RE.fullmatch(
                    _string(candidate.get("sha256"), f"candidate[{index}].sha256")
                )
            ),
            f"candidate digest is not SHA-256: {path_value}",
        )
        _require(
            _integer(candidate.get("size"), f"candidate[{index}].size") >= 1,
            f"candidate size must be positive: {path_value}",
        )
        coordinates.add(coordinate)
        records[path_value] = candidate
        coordinates_by_path[path_value] = coordinate
    _require(
        coordinates == set(expected_paths),
        "channel candidates must contain the exact versioned coordinates",
    )
    archive_ref = _object(candidates.get("archive"), "candidates.archive")
    archive_path = root / "channel-candidates.tar.gz"
    _require(
        _string(archive_ref.get("path"), "candidates.archive.path")
        == "channel-candidates.tar.gz",
        "candidate archive path is not canonical",
    )
    archive_digest = _string(archive_ref.get("sha256"), "candidates.archive.sha256")
    files = _read_candidate_archive(archive_path, records, archive_digest)
    required_urls = {
        ("homebrew", "formula"): {
            archive_by_id["context-engine-x86_64-apple-darwin"],
            archive_by_id["context-engine-aarch64-apple-darwin"],
        },
        ("scoop", "manifest"): {archive_by_id["context-engine-x86_64-pc-windows-msvc"]},
    }
    if _uses_legacy_channel_contract(profile, version):
        required_urls[("winget", "installer")] = {
            archive_by_id["context-engine-x86_64-pc-windows-msvc"]
        }
    for name, data in files.items():
        found_urls = _validate_urls(data, archive_urls, name)
        required = required_urls.get(coordinates_by_path[name], set())
        _require(
            required <= found_urls,
            f"{name} does not contain all required release archive URLs",
        )


def parse_arguments(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="directory containing fixed candidate files",
    )
    _ = parser.add_argument(
        "--schemas",
        type=Path,
        required=True,
        help="directory containing pinned schemas",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        validate_channel_candidates(cast(Path, args.root), cast(Path, args.schemas))
    except (CandidateValidationError, DependencyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("valid: channel candidates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
