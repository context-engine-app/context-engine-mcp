"""Statically enforce the protected public draft-release workflow contract."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import cast

import yaml


CHECKOUT_USES = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
TOKEN_USES = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
DOWNLOAD_USES = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
SETUP_UV_USES = "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9"
COSIGN_USES = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
STABLE_TAG_TEXT = r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
READER_TOKEN = "steps.artifact-reader.outputs.token"
WRITER_TOKEN = "steps.release-writer.outputs.token"
INSTALLATION_TOKEN_REVOCATION = "DELETE /installation/token"
PREPARE_REPOSITORY = "context-engine-app/context-engine-mcp"
SOURCE_REPOSITORY = "context-engine-app/context-engine"
COSIGN_FLAGS = (
    "--certificate-identity",
    "--certificate-oidc-issuer",
    "--certificate-github-workflow-repository",
    "--certificate-github-workflow-ref",
    "--certificate-github-workflow-sha",
    "--certificate-github-workflow-name",
    "--certificate-github-workflow-trigger",
    "https://token.actions.githubusercontent.com",
)


class WorkflowError(ValueError):
    """A static workflow contract violation."""


Json = dict[str, object]
Predicate = Callable[[Json], bool]


def _mapping(value: object, label: str) -> Json:
    if not isinstance(value, Mapping):
        raise WorkflowError(f"{label} must be a mapping")
    result: Json = {}
    value_map = cast(Mapping[object, object], value)
    for raw_key, item in value_map.items():
        key: object = "on" if raw_key is True else raw_key
        if not isinstance(key, str):
            raise WorkflowError(f"{label} has a non-string key")
        result[key] = item
    return result


def _steps(job: Json) -> list[Json]:
    value = job.get("steps")
    if not isinstance(value, list):
        raise WorkflowError("release-draft.steps must be a list")
    raw_steps = cast(list[object], value)
    return [
        _mapping(item, f"release-draft.steps[{index}]")
        for index, item in enumerate(raw_steps)
    ]


def _run(step: Json) -> str:
    value = step.get("run")
    return value if isinstance(value, str) else ""


def _uses(step: Json) -> str:
    value = step.get("uses")
    return value if isinstance(value, str) else ""


def _env(step: Json) -> Json:
    value = step.get("env")
    return {} if value is None else _mapping(value, "step env")


def _if(step: Json) -> str:
    value = step.get("if")
    return value if isinstance(value, str) else ""


def _find_index(steps: Sequence[Json], predicate: Predicate) -> int | None:
    for index, step in enumerate(steps):
        if predicate(step):
            return index
    return None


def _workflow_trigger(workflow: Json) -> object:
    return workflow.get("on")


def _check_trigger(workflow: Json, errors: list[str]) -> None:
    trigger = _workflow_trigger(workflow)
    if not isinstance(trigger, Mapping):
        errors.append("workflow trigger must contain only workflow_dispatch")
        return
    trigger_map = cast(Mapping[object, object], trigger)
    if set(trigger_map) != {"workflow_dispatch"}:
        errors.append("workflow trigger must contain only workflow_dispatch")
        return
    dispatch = trigger_map.get("workflow_dispatch")
    if dispatch is None:
        dispatch_map: Mapping[object, object] = {}
    elif isinstance(dispatch, Mapping):
        dispatch_map = cast(Mapping[object, object], dispatch)
    else:
        errors.append("workflow_dispatch must be a mapping")
        return
    inputs = dispatch_map.get("inputs")
    if not isinstance(inputs, Mapping):
        errors.append("workflow_dispatch inputs must be exactly tag and source_run_id")
        return
    inputs_map = cast(Mapping[object, object], inputs)
    if set(inputs_map) != {"tag", "source_run_id"}:
        errors.append("workflow_dispatch inputs must be exactly tag and source_run_id")
        return
    for name in ("tag", "source_run_id"):
        value = inputs_map[name]
        if not isinstance(value, Mapping):
            errors.append(f"workflow_dispatch input {name} must be a mapping")
            continue
        input_map = cast(Mapping[object, object], value)
        if input_map.get("required") is not True or input_map.get("type") != "string":
            errors.append(f"workflow_dispatch input {name} must be required string")


def _check_permissions(workflow: Json, errors: list[str]) -> None:
    if workflow.get("permissions") != {"contents": "read", "actions": "read"}:
        errors.append("workflow permissions must be contents: read and actions: read")
    if "id-token" in str(workflow):
        errors.append("id-token permission is forbidden")


def _check_concurrency(workflow: Json, errors: list[str]) -> None:
    value = workflow.get("concurrency")
    if not isinstance(value, Mapping):
        errors.append("concurrency must disable cancellation")
        return
    concurrency = cast(Mapping[object, object], value)
    if concurrency.get("cancel-in-progress") is not False:
        errors.append("concurrency must set cancel-in-progress: false")
    group = concurrency.get("group")
    if not isinstance(group, str) or "inputs.tag" not in group:
        errors.append("concurrency group must bind inputs.tag")


def _with_map(step: Json) -> Mapping[object, object] | None:
    value = step.get("with")
    return cast(Mapping[object, object], value) if isinstance(value, Mapping) else None


def _check_actions(steps: Sequence[Json], errors: list[str]) -> None:
    checkout_steps: list[Json] = []
    token_steps: list[Json] = []
    download_steps: list[Json] = []
    setup_steps: list[Json] = []
    cosign_steps: list[Json] = []
    for step in steps:
        uses = _uses(step)
        if not uses:
            continue
        if uses.startswith("./"):
            errors.append(f"local action is not allowed: {uses}")
        elif uses == CHECKOUT_USES:
            checkout_steps.append(step)
        elif uses == TOKEN_USES:
            token_steps.append(step)
        elif uses == DOWNLOAD_USES:
            download_steps.append(step)
        elif uses == SETUP_UV_USES:
            setup_steps.append(step)
        elif uses == COSIGN_USES:
            cosign_steps.append(step)
            with_map = _with_map(step)
            if with_map is None or with_map.get("cosign-release") != "v3.0.6":
                errors.append("cosign installer must pin cosign-release v3.0.6")
        else:
            errors.append(f"remote action is not pinned or approved: {uses}")
    if len(checkout_steps) != 1:
        errors.append("workflow must use one pinned checkout action")
    elif checkout_steps[0].get("with") != {"persist-credentials": False}:
        errors.append("checkout must disable persisted credentials")
    if len(setup_steps) != 1:
        errors.append("workflow must use one pinned setup-uv action")
    elif setup_steps[0].get("with") != {
        "version": "0.11.32",
        "python-version": "3.11.13",
    }:
        errors.append("setup-uv must pin uv 0.11.32 and Python 3.11.13")
    if len(token_steps) != 2:
        errors.append("workflow must create exactly reader and writer App tokens")
    if len(download_steps) != 1:
        errors.append("workflow must download exactly one private artifact")
    if len(cosign_steps) != 1:
        errors.append("workflow must install Cosign exactly once")


def _check_token_action(
    step: Json, expected_id: str, writer: bool, errors: list[str]
) -> None:
    if step.get("id") != expected_id:
        errors.append(f"token action must have id {expected_id}")
    values = _with_map(step)
    if values is None:
        errors.append(f"{expected_id} token action requires a with mapping")
        return
    expected_keys = {
        "client-id",
        "private-key",
        "owner",
        "repositories",
        "permission-contents",
    }
    if not writer:
        expected_keys.add("permission-actions")
    if set(values) != expected_keys:
        errors.append(f"{expected_id} token action has an unexpected input set")
    if values.get("owner") != "context-engine-app":
        errors.append(f"{expected_id} token must be owned by context-engine-app")
    repository = "context-engine-mcp" if writer else "context-engine"
    if values.get("repositories") != repository:
        errors.append(f"{expected_id} token repository scope is incorrect")
    permission = "write" if writer else "read"
    if values.get("permission-contents") != permission:
        errors.append(f"{expected_id} token contents permission is incorrect")
    if not writer and values.get("permission-actions") != "read":
        errors.append("artifact-reader token must have actions: read")
    if "steps.preflight.outputs.skip_source" not in _if(step):
        errors.append(
            f"{expected_id} token must be skipped for a verified existing draft"
        )


def _check_download(step: Json, errors: list[str]) -> None:
    values = _with_map(step)
    expected_keys = {"artifact-ids", "path", "github-token", "repository", "run-id"}
    if values is None or set(values) != expected_keys:
        errors.append("artifact download must use the exact artifact ID and source run")
        return
    if values.get("artifact-ids") != "${{ steps.source-artifact.outputs.artifact_id }}":
        errors.append("artifact download must use source-artifact.outputs.artifact_id")
    if values.get("path") != "staged-release":
        errors.append("artifact download path must be staged-release")
    if values.get("github-token") != "${{ steps.artifact-reader.outputs.token }}":
        errors.append("artifact download must use the reader App token")
    if values.get("repository") != SOURCE_REPOSITORY:
        errors.append("artifact download repository scope is incorrect")
    if values.get("run-id") != "${{ inputs.source_run_id }}":
        errors.append("artifact download must bind inputs.source_run_id")
    if "steps.preflight.outputs.skip_source" not in _if(step):
        errors.append("artifact download must be skipped for a verified existing draft")


def _check_command_controls(command: str, errors: list[str]) -> None:
    lowered = command.lower()
    if "gh api" in lowered:
        api_calls = command.count("gh api")
        api_headers = lowered.count("x-github-api-version: 2026-03-10")
        if api_calls != api_headers:
            errors.append("every gh api call must pin X-GitHub-Api-Version: 2026-03-10")
    if "--clobber" in lowered:
        errors.append("artifact clobbering is forbidden")
    if re.search(r"\bgh\s+release\s+(?:publish|delete)\b", lowered):
        errors.append("release publication/deletion is forbidden")
    for match in re.finditer(
        r'gh\s+api\s+--method\s+([A-Za-z]+)(?:\s+(?:-H|--header)\s+"[^"]+")*\s+([^\s]+)',
        command,
    ):
        method = match.group(1).upper()
        endpoint = match.group(2)
        if method == "DELETE" and endpoint == "/installation/token":
            continue
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            errors.append(f"direct GitHub mutation is forbidden: {method} {endpoint}")


def _contains_all(command: str, values: Sequence[str]) -> bool:
    return all(value in command for value in values)


def _is_token_revocation(command: str) -> bool:
    return (
        re.search(
            r'gh\s+api\s+--method\s+DELETE(?:\s+(?:-H|--header)\s+"[^"]+")*\s+/installation/token',
            command,
        )
        is not None
    )


def _check_command_requirements(steps: Sequence[Json], errors: list[str]) -> None:
    commands = [_run(step) for step in steps]
    for command in commands:
        _check_command_controls(command, errors)
    runtime_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                STABLE_TAG_TEXT,
                "SOURCE_RUN_ID",
                "GITHUB_REPOSITORY",
                "GITHUB_REF",
                "GITHUB_SHA",
                "GITHUB_WORKFLOW_REF",
                "git rev-parse HEAD",
                ".github/workflows/prepare-draft-release.yml",
                "sha256sum",
                "GITHUB_OUTPUT",
            ),
        )
    ]
    if len(runtime_indices) != 1:
        errors.append(
            "runtime preflight must bind the protected tag, repository, ref, SHA, and workflow bytes"
        )
    runtime_index = runtime_indices[0] if runtime_indices else -1
    python_env_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "uv python install 3.11.13",
                "uv venv .venv --python 3.11.13",
                "uv pip install",
                "requirements.txt",
            ),
        )
    ]
    if len(python_env_indices) != 1:
        errors.append(
            "workflow must create the pinned uv Python environment before Python tools"
        )
    python_env_index = python_env_indices[0] if python_env_indices else -1
    preflight_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "scripts/prepare_draft_release.py inspect",
                "--tag",
                "--repository",
                "--output-dir",
                ".status",
                "missing",
                "partial",
                "verified",
                "skip_source",
                "verified)",
                "public-draft",
                "preflight-plan.json",
                "source_run.id",
                "public_workflow.path",
                "distribution_tag_target",
                "RUNTIME_WORKFLOW_SHA256",
                "GITHUB_SHA",
                "validate_channel_candidates.py",
                "cosign verify-blob",
                "SHA256SUMS",
                "certificate-github-workflow-sha",
            ),
        )
    ]
    if len(preflight_indices) != 1:
        errors.append(
            "workflow must inspect and validate an existing draft read-only before private access"
        )
    preflight_index = preflight_indices[0] if preflight_indices else -1
    reader_revoke_indices = [
        index
        for index, step in enumerate(steps)
        if _is_token_revocation(_run(step)) and READER_TOKEN in str(_env(step))
    ]
    writer_revoke_indices = [
        index
        for index, step in enumerate(steps)
        if _is_token_revocation(_run(step)) and WRITER_TOKEN in str(_env(step))
    ]
    if len(reader_revoke_indices) != 1 or len(writer_revoke_indices) != 1:
        errors.append("workflow must revoke reader and writer tokens exactly once")
    reader_revoke_index = reader_revoke_indices[0] if reader_revoke_indices else -1
    writer_revoke_index = writer_revoke_indices[0] if writer_revoke_indices else -1
    source_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "actions/runs",
                "SOURCE_RUN_ID",
                ".id",
                ".head_sha",
                ".head_branch",
                ".head_repository.full_name",
                ".head_repository.id",
                ".repository.full_name",
                ".repository.id",
                ".path",
                ".event",
                ".status",
                ".conclusion",
                "git/ref/tags",
                ".object.sha",
                "git/tags",
                "workflow_run.id",
                "workflow_run.head_sha",
                "workflow_run.head_branch",
                "workflow_run.repository_id",
                "workflow_run.head_repository_id",
                "size_in_bytes",
                "sha256:[0-9a-f]{64}",
                "GITHUB_OUTPUT",
                "3600",
            ),
        )
    ]
    # The digest regex is normally embedded in jq, so check it separately.
    if len(source_indices) != 1:
        source_indices = [
            index
            for index, command in enumerate(commands)
            if _contains_all(
                command,
                (
                    "actions/runs",
                    "SOURCE_RUN_ID",
                    ".head_sha",
                    ".head_branch",
                    ".head_repository.id",
                    ".repository.id",
                    "git/ref/tags",
                    ".object.sha",
                    "git/tags",
                    "workflow_run.id",
                    "workflow_run.head_sha",
                    "workflow_run.head_branch",
                    "workflow_run.repository_id",
                    "workflow_run.head_repository_id",
                    "size_in_bytes",
                    "GITHUB_OUTPUT",
                    "3600",
                ),
            )
            and "sha256:[0-9a-f]{64}" in command
        ]
    if len(source_indices) != 1:
        errors.append(
            "source verification must bind exact run IDs, SHA, tag, repositories, artifact, digest, and expiry"
        )
    source_index = source_indices[0] if source_indices else -1
    staging_validator_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "scripts/validate_release_provenance.py staging",
                "--root staged-release",
                "--schemas schemas",
                "--output-plan validated-plan.json",
            ),
        )
    ]
    candidate_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "scripts/validate_channel_candidates.py",
                "--root staged-release",
                "--schemas schemas",
            ),
        )
    ]
    if len(staging_validator_indices) != 1:
        errors.append(
            "workflow must run the portable staging provenance validator exactly once"
        )
    if len(candidate_indices) != 1:
        errors.append(
            "workflow must run the portable channel-candidate validator exactly once"
        )
    staging_validator_index = (
        staging_validator_indices[0] if staging_validator_indices else -1
    )
    candidate_index = candidate_indices[0] if candidate_indices else -1
    source_cosign_indices = [
        index
        for index, command in enumerate(commands)
        if "staged-release/SHA256SUMS.sigstore.json" in command
        and "staged-release/SHA256SUMS" in command
    ]
    source_cosign_count = sum(
        commands[index].count("cosign verify-blob") for index in source_cosign_indices
    )
    if (
        source_cosign_count != 2
        or len(source_cosign_indices) != 1
        or not _contains_all(
            commands[source_cosign_indices[0]],
            COSIGN_FLAGS
            + ("staging-attestation.sigstore.json", "staging-attestation.json"),
        )
    ):
        errors.append(
            "workflow must Cosign-verify both signed staging bundles with exact workflow identity"
        )
    source_cosign_index = source_cosign_indices[0] if source_cosign_indices else -1
    binding_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "validated-plan.json",
                "release-provenance.json",
                "staging-attestation.json",
                "source_workflow",
                "source_commit",
                "workflow_bindings.draft",
                "distribution_commit",
                "distribution_tag_target",
                "GITHUB_SHA",
                "RUNTIME_WORKFLOW_SHA256",
                "run.id",
                "attempt",
                "SOURCE_RUN_ID",
            ),
        )
    ]
    if len(binding_indices) != 1:
        errors.append(
            "workflow must bind plan, manifest, provenance, attestation, and runtime workflow identity"
        )
    binding_index = binding_indices[0] if binding_indices else -1
    expiry_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(command, ("ARTIFACT_EXPIRES_AT", "date -u -d", "3600"))
    ]
    if len(expiry_indices) != 1:
        errors.append(
            "workflow must recheck the artifact expiry window before mutation"
        )
    expiry_index = expiry_indices[0] if expiry_indices else -1
    prepare_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "scripts/prepare_draft_release.py prepare",
                "--plan",
                "--staged-assets",
                "--artifact-id",
                "--artifact-digest",
                "--artifact-expires-at",
                "--public-run-id",
                "--public-run-attempt",
                "--repository",
                "draft-prepare.json",
                'state == "verified"',
                "asset_count == 15",
            ),
        )
    ]
    inspect_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "scripts/prepare_draft_release.py inspect",
                "--tag",
                "--repository",
                "--output-dir",
                "draft-inspect.json",
                '.status == "verified"',
                "asset_count == 15",
            ),
        )
    ]
    if len(prepare_indices) != 1:
        errors.append(
            "workflow must invoke coordinator prepare with exact artifact and public-run bindings"
        )
    if len(inspect_indices) != 1:
        errors.append(
            "workflow must re-download and require a verified draft inspect result"
        )
    prepare_index = prepare_indices[0] if prepare_indices else -1
    inspect_index = inspect_indices[0] if inspect_indices else -1
    post_validator_indices = [
        index
        for index, command in enumerate(commands)
        if _contains_all(
            command,
            (
                "public-draft",
                "--root",
                "draft-assets",
                "--marker",
                "draft-marker.json",
                "draft-plan.json",
                "validate_channel_candidates.py",
                "cosign verify-blob",
                "draft-assets/SHA256SUMS",
            ),
        )
    ]
    if len(post_validator_indices) != 1:
        errors.append(
            "workflow must validate and Cosign-verify the exact re-downloaded public draft"
        )
    post_validator_index = post_validator_indices[0] if post_validator_indices else -1
    post_cosign_command = (
        commands[post_validator_index] if post_validator_index >= 0 else ""
    )
    if post_cosign_command and not _contains_all(post_cosign_command, COSIGN_FLAGS):
        errors.append(
            "re-downloaded draft checksum verification must use exact workflow identity"
        )
    if not reader_revoke_indices or not writer_revoke_indices:
        errors.append("token revocation endpoints must be present")
    for index, step in enumerate(steps):
        command = _run(step)
        environment = _env(step)
        condition = _if(step)
        token = environment.get("GH_TOKEN")
        if token == f"${{{{ {READER_TOKEN} }}}}" and index > reader_revoke_index:
            errors.append("reader App token is used after revocation")
        if token == f"${{{{ {READER_TOKEN} }}}}" and (
            "steps.preflight.outputs.skip_source" not in condition
        ):
            errors.append(
                "reader App token use must be skipped for a verified existing draft"
            )
        if token == f"${{{{ {WRITER_TOKEN} }}}}" and (
            index < 0 or index > writer_revoke_index
        ):
            errors.append("writer App token is used outside its scoped lifetime")
        if token == f"${{{{ {WRITER_TOKEN} }}}}" and (
            "steps.preflight.outputs.skip_source" not in condition
        ):
            errors.append(
                "writer App token use must be skipped for a verified existing draft"
            )
        if _is_token_revocation(command) and "always()" not in condition:
            errors.append("token revocation must run with always() cleanup")
    reader_index = _find_index(
        steps,
        lambda step: _uses(step) == TOKEN_USES and step.get("id") == "artifact-reader",
    )
    writer_index = _find_index(
        steps,
        lambda step: _uses(step) == TOKEN_USES and step.get("id") == "release-writer",
    )
    download_index = _find_index(steps, lambda step: _uses(step) == DOWNLOAD_USES)
    if (
        reader_index is None
        or preflight_index > reader_index
        or runtime_index < 0
        or runtime_index >= python_env_index
        or preflight_index < python_env_index
    ):
        errors.append(
            "runtime, uv setup, and read-only preflight must precede the reader token"
        )
    if reader_index is None or source_index < reader_index:
        errors.append("reader token must precede source verification")
    if download_index is None or source_index < 0 or source_index >= download_index:
        errors.append("exact artifact download must follow source verification")
    if (
        reader_revoke_index < 0
        or download_index is None
        or reader_revoke_index <= download_index
    ):
        errors.append("reader token must be revoked after exact download")
    if (
        staging_validator_index < 0
        or candidate_index < 0
        or reader_revoke_index >= staging_validator_index
        or candidate_index < reader_revoke_index
    ):
        errors.append("portable staging validation must follow reader revocation")
    if (
        source_cosign_index < 0
        or staging_validator_index < 0
        or source_cosign_index <= max(staging_validator_index, candidate_index)
    ):
        errors.append("staging Cosign verification must follow portable validation")
    if (
        binding_index < 0
        or source_cosign_index < 0
        or binding_index <= source_cosign_index
    ):
        errors.append(
            "runtime and release evidence binding must follow staging Cosign verification"
        )
    if expiry_index < 0 or binding_index < 0 or expiry_index <= binding_index:
        errors.append("expiry recheck must follow all validation and binding checks")
    if writer_index is None or expiry_index < 0 or writer_index <= expiry_index:
        errors.append("writer token must be created only after expiry recheck")
    if writer_index is None or prepare_index < 0 or prepare_index <= writer_index:
        errors.append("writer token must precede coordinator prepare")
    if (
        prepare_index < 0
        or inspect_index <= prepare_index
        or post_validator_index <= inspect_index
    ):
        errors.append(
            "draft prepare, inspect, and public validation must remain ordered"
        )
    if (
        writer_revoke_index < 0
        or post_validator_index < 0
        or writer_revoke_index <= post_validator_index
    ):
        errors.append(
            "writer token must remain available through post-draft validation"
        )


def check_workflow(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        value = cast(object, yaml.safe_load(path.read_text(encoding="utf-8")))
        workflow = _mapping(value, str(path))
        _check_trigger(workflow, errors)
        _check_permissions(workflow, errors)
        _check_concurrency(workflow, errors)
        if "env" in workflow:
            errors.append("workflow-level env is forbidden")
        jobs = _mapping(workflow.get("jobs"), "jobs")
        if set(jobs) != {"release-draft"}:
            errors.append("workflow must contain exactly one release-draft job")
        job = _mapping(jobs.get("release-draft"), "release-draft")
        if job.get("environment") != "release-draft":
            errors.append("release-draft must use the release-draft environment")
        if job.get("runs-on") != "ubuntu-24.04":
            errors.append("release-draft must run on ubuntu-24.04")
        if job.get("timeout-minutes") != 45:
            errors.append("release-draft must set timeout-minutes: 45")
        if "env" in job or "permissions" in job:
            errors.append("release-draft must not override workflow env or permissions")
        steps = _steps(job)
        _check_actions(steps, errors)
        token_steps = [step for step in steps if _uses(step) == TOKEN_USES]
        if len(token_steps) == 2:
            _check_token_action(token_steps[0], "artifact-reader", False, errors)
            _check_token_action(token_steps[1], "release-writer", True, errors)
        download_steps = [step for step in steps if _uses(step) == DOWNLOAD_USES]
        if len(download_steps) == 1:
            _check_download(download_steps[0], errors)
        _check_command_requirements(steps, errors)
    except (OSError, UnicodeError, yaml.YAMLError, WorkflowError) as exc:
        errors.append(f"cannot inspect workflow: {exc}")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "workflow",
        type=Path,
        nargs="?",
        default=Path(".github/workflows/prepare-draft-release.yml"),
    )
    arguments = parser.parse_args(argv)
    errors = check_workflow(cast(Path, getattr(arguments, "workflow")))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 2
    print("valid: prepare-draft-release workflow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
