"""Statically verify the protected immutable-release publication workflow."""

from __future__ import annotations

import argparse
import importlib
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

REMOTE_ACTION_RE = re.compile(r"^[^./][^@]*@[0-9a-f]{40}$")
EXPECTED_INPUTS = {"tag", "draft_run_id"}
EXPECTED_PERMISSIONS = {
    "contents": "read",
    "actions": "read",
    "attestations": "read",
}
EXPECTED_CONCURRENCY_GROUP = "release-draft-${{ inputs.tag }}"
EXPECTED_PREFLIGHT_STEPS = (
    "Check out public workflow tools",
    "Validate inputs and runtime binding",
    "Set up pinned uv and Python",
    "Create pinned Python environment",
    "Install pinned Cosign",
    "Re-download and validate verified draft",
)
EXPECTED_PUBLISH_STEPS = (
    "Check out public workflow tools",
    "Revalidate protected runtime binding",
    "Set up pinned uv and Python",
    "Create pinned Python environment",
    "Install pinned Cosign",
    "Repeat complete draft and workflow validation",
    "Create private artifact-reader App token",
    "Independently verify private source run and workflow",
    "Revoke private artifact-reader token",
    "Create final publisher App token",
    "Require immutable releases",
    "Verify live tag target before publication",
    "Publish exact verified draft",
    "Verify immutable release and every asset",
    "Revoke final publisher token",
)
CANONICAL_PUBLISH_COMMAND = """set -euo pipefail
.venv/bin/python -m scripts.publish_draft_release \\
  --plan "$RUNNER_TEMP/publication-plan.json" \\
  --repository "$GITHUB_REPOSITORY" \\
  --draft-run-id "$DRAFT_RUN_ID" \\
  | tee "$RUNNER_TEMP/publication-result.json"
jq -e '.status == "published"' "$RUNNER_TEMP/publication-result.json" > /dev/null"""
CANONICAL_REVOKE_COMMAND = (
    'gh api --method DELETE -H "X-GitHub-Api-Version: 2026-03-10" '
    + "/installation/token"
)
GH_API_MUTATION_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-X|--method|-f|--raw-field|-F|--field|--input)(?:\s|=)"
)


class _YamlModule(Protocol):
    YAMLError: type[Exception]

    def safe_load(self, stream: str) -> object: ...


class WorkflowError(ValueError):
    """The publication workflow cannot be parsed safely."""


def _yaml() -> _YamlModule:
    try:
        return cast(_YamlModule, cast(object, importlib.import_module("yaml")))
    except ImportError as error:
        raise WorkflowError("PyYAML is required") from error


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WorkflowError(f"{label} must be a mapping")
    return cast(Mapping[str, object], value)


def _steps(job: Mapping[str, object], label: str) -> list[Mapping[str, object]]:
    value = job.get("steps")
    if not isinstance(value, list):
        raise WorkflowError(f"{label}.steps must be a list")
    return [
        _mapping(item, f"{label}.steps[{index}]")
        for index, item in enumerate(cast(list[object], value))
    ]


def _step_names(
    steps: Sequence[Mapping[str, object]], label: str, errors: list[str]
) -> tuple[str, ...]:
    names: list[str] = []
    for index, step in enumerate(steps):
        name = step.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{label}.steps[{index}] must have a non-empty name")
            continue
        names.append(name)
    if len(names) != len(set(names)):
        errors.append(f"{label} step names must be unique")
    return tuple(names)


def _trigger(workflow: Mapping[str, object]) -> object:
    generic = cast(Mapping[object, object], workflow)
    return generic.get("on", generic.get(True))


def _step_index(steps: Sequence[Mapping[str, object]], name: str) -> int | None:
    for index, step in enumerate(steps):
        if step.get("name") == name:
            return index
    return None


def _step_run(step: Mapping[str, object]) -> str:
    value = step.get("run", "")
    return value if isinstance(value, str) else ""


def _check_trigger(workflow: Mapping[str, object], errors: list[str]) -> None:
    trigger = _mapping(_trigger(workflow), "on")
    if set(trigger) != {"workflow_dispatch"}:
        errors.append("workflow trigger must be only workflow_dispatch")
        return
    dispatch = _mapping(trigger.get("workflow_dispatch"), "workflow_dispatch")
    inputs = _mapping(dispatch.get("inputs"), "workflow_dispatch.inputs")
    if set(inputs) != EXPECTED_INPUTS:
        errors.append("workflow dispatch inputs must be exactly tag and draft_run_id")
    for name in EXPECTED_INPUTS:
        item = _mapping(inputs.get(name), f"input {name}")
        if item.get("required") is not True or item.get("type") != "string":
            errors.append(f"input {name} must be a required string")


def _check_concurrency(workflow: Mapping[str, object], errors: list[str]) -> None:
    concurrency = _mapping(workflow.get("concurrency"), "concurrency")
    if concurrency != {
        "group": EXPECTED_CONCURRENCY_GROUP,
        "cancel-in-progress": False,
    }:
        errors.append(
            "concurrency must serialize draft preparation and publication "
            + "with release-draft-${{ inputs.tag }} and disable cancellation"
        )


def _check_reauthorization_refs(
    commands: str, stage: str, workflow: str, errors: list[str]
) -> None:
    ref_marker = (
        f'test "$GITHUB_REF" = '
        f'"refs/tags/release-reauthorization/$TAG_NAME/{stage}/$runtime_commit"'
    )
    workflow_marker = (
        f'test "$GITHUB_WORKFLOW_REF" = '
        f'"$GITHUB_REPOSITORY/.github/workflows/{workflow}@$GITHUB_REF"'
    )
    for marker in (ref_marker, workflow_marker):
        if commands.count(marker) < 1:
            errors.append(f"{stage} reauthorization binding is not exact: {marker}")


def _check_remote_actions(jobs: Mapping[str, object], errors: list[str]) -> None:
    for job_name, raw_job in jobs.items():
        job = _mapping(raw_job, f"jobs.{job_name}")
        for step in _steps(job, f"jobs.{job_name}"):
            uses = step.get("uses")
            if not isinstance(uses, str) or uses.startswith("./"):
                continue
            if REMOTE_ACTION_RE.fullmatch(uses) is None:
                errors.append(f"remote action is not pinned to a full commit: {uses}")
            if uses.startswith("actions/checkout@"):
                values = _mapping(step.get("with"), "checkout.with")
                if values.get("persist-credentials") is not False:
                    errors.append("checkout must disable persisted credentials")


def _check_preflight(job: Mapping[str, object], errors: list[str]) -> None:
    if "environment" in job:
        errors.append("preflight job must not use an environment")
    if "secrets." in str(job):
        errors.append("preflight job must not use secrets")
    steps = _steps(job, "jobs.preflight")
    if _step_names(steps, "jobs.preflight", errors) != EXPECTED_PREFLIGHT_STEPS:
        errors.append("preflight steps must match the exact approved sequence")
    commands = "\n".join(_step_run(step) for step in steps)
    _check_reauthorization_refs(
        commands, "public-publish", "publish-draft-release.yml", errors
    )
    for marker in (
        "validate_release_provenance.py public-publish",
        "validate_channel_candidates.py",
        "actions/runs/$DRAFT_RUN_ID",
        "cosign verify-blob",
        "publish-draft-release.yml@refs/tags/$TAG_NAME",
        "release-reauthorization",
        "workflow-reauthorization.schema.json",
    ):
        if marker not in commands:
            errors.append(f"preflight is missing required validation: {marker}")


def _check_token_step(
    step: Mapping[str, object],
    *,
    client_id: str,
    private_key: str,
    repository: str,
    permissions: Mapping[str, str],
    errors: list[str],
) -> None:
    if (
        step.get("uses")
        != "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
    ):
        errors.append("App token action is not pinned to the approved commit")
        return
    values = _mapping(step.get("with"), "App token inputs")
    expected = {
        "client-id": client_id,
        "private-key": private_key,
        "owner": "context-engine-app",
        "repositories": repository,
    }
    expected.update(permissions)
    if values != expected:
        errors.append("App token inputs are not exact")


def _check_credential_scope(
    steps: Sequence[Mapping[str, object]], errors: list[str]
) -> None:
    scopes = (
        (
            "ARTIFACT_READER_APP_CLIENT_ID",
            {"Create private artifact-reader App token"},
            "artifact-reader credential",
        ),
        (
            "ARTIFACT_READER_APP_PRIVATE_KEY",
            {"Create private artifact-reader App token"},
            "artifact-reader credential",
        ),
        (
            "steps.artifact-reader.outputs.token",
            {
                "Independently verify private source run and workflow",
                "Revoke private artifact-reader token",
            },
            "artifact-reader token",
        ),
        (
            "IMMUTABLE_RELEASE_PUBLISHER_APP_CLIENT_ID",
            {"Create final publisher App token"},
            "publisher credential",
        ),
        (
            "IMMUTABLE_RELEASE_PUBLISHER_APP_PRIVATE_KEY",
            {"Create final publisher App token"},
            "publisher credential",
        ),
        (
            "steps.final-publisher.outputs.token",
            {
                "Require immutable releases",
                "Publish exact verified draft",
                "Revoke final publisher token",
            },
            "publisher token",
        ),
    )
    for step in steps:
        name = step.get("name")
        if not isinstance(name, str):
            continue
        rendered = str(step)
        for marker, allowed_steps, label in scopes:
            if marker in rendered and name not in allowed_steps:
                errors.append(f"{label} is referenced outside its approved steps")


def _check_direct_mutations(
    steps: Sequence[Mapping[str, object]], errors: list[str]
) -> None:
    for step in steps:
        run = _step_run(step).strip()
        if not run:
            continue
        name = step.get("name")
        if (
            name
            in {
                "Revoke private artifact-reader token",
                "Revoke final publisher token",
            }
            and run == CANONICAL_REVOKE_COMMAND
        ):
            continue
        if ("gh api" in run and GH_API_MUTATION_FLAG_RE.search(run) is not None) or any(
            marker in run
            for marker in (
                "gh release create",
                "gh release delete",
                "gh release edit",
                "gh release upload",
                "gh run rerun",
                "gh workflow run",
                "git push",
                "curl ",
                "wget ",
            )
        ):
            errors.append("workflow contains a direct mutation outside the publisher")


def _check_publish(job: Mapping[str, object], errors: list[str]) -> None:
    if job.get("environment") != "release-publish":
        errors.append("publish job must use the release-publish environment")
    steps = _steps(job, "jobs.publish")
    if _step_names(steps, "jobs.publish", errors) != EXPECTED_PUBLISH_STEPS:
        errors.append("publish steps must match the exact approved sequence")

    reader_index = _step_index(steps, "Create private artifact-reader App token")
    if reader_index is not None:
        _check_token_step(
            steps[reader_index],
            client_id="${{ vars.ARTIFACT_READER_APP_CLIENT_ID }}",
            private_key="${{ secrets.ARTIFACT_READER_APP_PRIVATE_KEY }}",
            repository="context-engine",
            permissions={
                "permission-actions": "read",
                "permission-contents": "read",
            },
            errors=errors,
        )
    publisher_index = _step_index(steps, "Create final publisher App token")
    if publisher_index is not None:
        _check_token_step(
            steps[publisher_index],
            client_id="${{ vars.IMMUTABLE_RELEASE_PUBLISHER_APP_CLIENT_ID }}",
            private_key="${{ secrets.IMMUTABLE_RELEASE_PUBLISHER_APP_PRIVATE_KEY }}",
            repository="context-engine-mcp",
            permissions={
                "permission-administration": "read",
                "permission-contents": "write",
            },
            errors=errors,
        )

    immutable_index = _step_index(steps, "Require immutable releases")
    if immutable_index is not None:
        immutable_env = _mapping(
            steps[immutable_index].get("env"), "immutable release preflight env"
        )
        if immutable_env != {"GH_TOKEN": "${{ steps.final-publisher.outputs.token }}"}:
            errors.append(
                "immutable release preflight must use the final publisher token"
            )

    tag_index = _step_index(steps, "Verify live tag target before publication")
    if tag_index is not None:
        tag_env = _mapping(
            steps[tag_index].get("env"), "live tag target verification env"
        )
        if tag_env != {
            "GH_TOKEN": "${{ github.token }}",
            "TAG_NAME": "${{ inputs.tag }}",
        }:
            errors.append("live tag target verification must use the read-only token")

    publish_index = _step_index(steps, "Publish exact verified draft")
    if publish_index is not None:
        publish_step = steps[publish_index]
        publish_env = _mapping(publish_step.get("env"), "publisher mutation env")
        if publish_env != {
            "GH_TOKEN": "${{ steps.final-publisher.outputs.token }}",
            "DRAFT_RUN_ID": "${{ inputs.draft_run_id }}",
        }:
            errors.append("publisher mutation environment is not exact")
        if _step_run(publish_step).strip() != CANONICAL_PUBLISH_COMMAND:
            errors.append("publisher mutation command is not canonical")

    verify_index = _step_index(steps, "Verify immutable release and every asset")
    if verify_index is not None:
        verify_env = _mapping(
            steps[verify_index].get("env"), "post-publication verification env"
        )
        if verify_env != {
            "GH_TOKEN": "${{ github.token }}",
            "TAG_NAME": "${{ inputs.tag }}",
        }:
            errors.append("post-publication verification must use the read-only token")

    _check_credential_scope(steps, errors)
    _check_direct_mutations(steps, errors)
    commands = "\n".join(_step_run(step) for step in steps)
    _check_reauthorization_refs(
        commands, "public-publish", "publish-draft-release.yml", errors
    )
    if commands.count("-m scripts.publish_draft_release") != 1:
        errors.append("workflow must invoke exactly one release publication mutation")
    for marker in (
        "immutable-releases",
        'gh release verify "$TAG_NAME"',
        "gh release verify-asset",
        "validate_release_provenance.py public-publish",
        "validate_channel_candidates.py",
        "cosign verify-blob",
    ):
        if marker not in commands:
            label = (
                "immutable release verification"
                if marker.startswith("gh release verify")
                else marker
            )
            errors.append(f"publish job is missing {label}")
    candidate_commands = [
        _step_run(step)
        for step in steps
        if "validate_channel_candidates.py" in _step_run(step)
    ]
    if any(
        "profile" not in command
        or "repository-bootstrap" not in command
        or ('if [[ "$profile"' not in command and 'case "$profile"' not in command)
        for command in candidate_commands
    ):
        errors.append(
            "channel-candidate validation must be conditional on the release profile"
        )
    if (
        commands.count(".assets | length") < 1
        or commands.count("asset_count == $expected_asset_count") < 1
    ):
        errors.append(
            "workflow must derive every inspected asset count from the validated plan"
        )
    for marker, count in (
        ('"repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG_NAME"', 2),
        ('"repos/$GITHUB_REPOSITORY/git/tags/$tag_object_sha"', 2),
        ('test "$live_tag_target" = "$expected_tag_target"', 1),
        ('test "$frozen_tag_target" = "$expected_tag_target"', 1),
    ):
        if commands.count(marker) < count:
            errors.append(
                "publish job must verify the exact live tag target before and after publication"
            )

    for name, token_id in (
        ("Revoke private artifact-reader token", "artifact-reader"),
        ("Revoke final publisher token", "final-publisher"),
    ):
        index = _step_index(steps, name)
        if index is None:
            continue
        step = steps[index]
        condition = step.get("if")
        if not isinstance(condition, str) or "always()" not in condition:
            errors.append(f"{name} must run unconditionally after token creation")
        if "/installation/token" not in _step_run(step):
            errors.append(f"{name} must revoke the installation token")
        if token_id not in str(step):
            errors.append(f"{name} does not reference the correct token")


def check_workflow(path: Path) -> list[str]:
    """Return all static contract violations for one publication workflow."""

    try:
        yaml = _yaml()
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            return [f"invalid YAML: {error}"]
        workflow = _mapping(document, "workflow")
        jobs = _mapping(workflow.get("jobs"), "jobs")
        if set(jobs) != {"preflight", "publish"}:
            return ["workflow jobs must be exactly preflight and publish"]
        errors: list[str] = []
        _check_trigger(workflow, errors)
        _check_concurrency(workflow, errors)
        if "env" in workflow:
            errors.append("workflow must not define environment-wide variables")
        permissions = _mapping(workflow.get("permissions"), "permissions")
        if permissions != EXPECTED_PERMISSIONS:
            errors.append(
                "workflow permissions must be contents:read, actions:read, and attestations:read"
            )
        preflight = _mapping(jobs.get("preflight"), "jobs.preflight")
        publish = _mapping(jobs.get("publish"), "jobs.publish")
        for label, job in (("preflight", preflight), ("publish", publish)):
            if "permissions" in job:
                errors.append(f"{label} job must not override workflow permissions")
            if "env" in job:
                errors.append(f"{label} job must not define job-wide variables")
        if publish.get("needs") != "preflight":
            errors.append("publish job must depend on preflight")
        _check_remote_actions(jobs, errors)
        _check_preflight(preflight, errors)
        _check_publish(publish, errors)
        return errors
    except (OSError, WorkflowError) as error:
        return [str(error)]


def main(argv: Sequence[str] | None = None) -> int:
    """Check one publication workflow from the command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("workflow", type=Path)
    args = parser.parse_args(argv)
    workflow = cast(Path, args.workflow)
    errors = check_workflow(workflow)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
