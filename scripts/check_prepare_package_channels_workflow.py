"""Validate the protected package-channel publication workflow."""

from __future__ import annotations

import argparse
import importlib
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast


EXPECTED_STEPS = (
    "Check out public package tools",
    "Set up pinned uv and Python",
    "Create isolated Python environment",
    "Validate immutable release and channel candidates",
    "Create Homebrew installation token",
    "Create Scoop installation token",
    "Create channel pull requests",
    "Revoke Homebrew installation token",
    "Revoke Scoop installation token",
)
TOKEN_ACTION = (
    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
)
REMOTE_ACTION_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
FORBIDDEN_TEXT = (
    "repair",
    "reauthorization",
    "anonymous",
    "artifact-reader",
    "preflight-plan",
)


class _YamlModule(Protocol):
    def safe_load(self, stream: str) -> object: ...


class WorkflowError(ValueError):
    """The workflow cannot be parsed or does not satisfy the publication contract."""


def _yaml() -> _YamlModule:
    try:
        return cast(_YamlModule, cast(object, importlib.import_module("yaml")))
    except ImportError as error:
        raise WorkflowError("PyYAML is required") from error


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WorkflowError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _steps(job: Mapping[str, object]) -> list[Mapping[str, object]]:
    value = job.get("steps")
    if not isinstance(value, list):
        raise WorkflowError("publish.steps must be an array")
    return [_mapping(item, "publish step") for item in cast(list[object], value)]


def _run(step: Mapping[str, object]) -> str:
    value = step.get("run")
    return value if isinstance(value, str) else ""


def _named_step(
    steps: Sequence[Mapping[str, object]], name: str
) -> Mapping[str, object]:
    matches = [step for step in steps if step.get("name") == name]
    if len(matches) != 1:
        raise WorkflowError(f"workflow must contain exactly one {name!r} step")
    return matches[0]


def _check_token(
    steps: Sequence[Mapping[str, object]], name: str, repository: str
) -> None:
    step = _named_step(steps, name)
    if step.get("uses") != TOKEN_ACTION:
        raise WorkflowError(f"{name} must use the pinned App-token action")
    inputs = _mapping(step.get("with"), f"{name}.with")
    if inputs.get("repositories") != repository:
        raise WorkflowError(f"{name} must target only {repository}")
    if inputs.get("permission-contents") != "write":
        raise WorkflowError(f"{name} must have contents write permission")
    if inputs.get("permission-pull-requests") != "write":
        raise WorkflowError(f"{name} must have pull-requests write permission")


def check_workflow(path: Path) -> list[str]:
    """Return every contract violation in the package-channel workflow."""

    try:
        source = path.read_text(encoding="utf-8")
        workflow = _mapping(_yaml().safe_load(source), "workflow")
        yaml_workflow = cast(Mapping[object, object], workflow)
        trigger_value = yaml_workflow.get("on", yaml_workflow.get(True))
        trigger = _mapping(trigger_value, "workflow.on")
        dispatch = _mapping(trigger.get("workflow_dispatch"), "workflow_dispatch")
        inputs = _mapping(dispatch.get("inputs"), "workflow_dispatch.inputs")
        permissions = _mapping(workflow.get("permissions"), "workflow.permissions")
        jobs = _mapping(workflow.get("jobs"), "workflow.jobs")
        if set(inputs) != {"tag"}:
            raise WorkflowError("workflow_dispatch must expose only the tag input")
        if dict(permissions) != {"contents": "read"}:
            raise WorkflowError("workflow permissions must be exactly contents: read")
        if set(jobs) != {"publish"}:
            raise WorkflowError("workflow must contain only the publish job")
        job = _mapping(jobs.get("publish"), "jobs.publish")
        if job.get("environment") != "release-channel":
            raise WorkflowError("publish must use the release-channel environment")
        steps = _steps(job)
        names = tuple(step.get("name") for step in steps)
        if names != EXPECTED_STEPS:
            raise WorkflowError("publish steps are not the minimal canonical sequence")
        lowered = source.lower()
        for forbidden in FORBIDDEN_TEXT:
            if forbidden in lowered:
                raise WorkflowError(
                    f"workflow contains obsolete mechanism: {forbidden}"
                )
        for step in steps:
            uses = step.get("uses")
            if isinstance(uses, str) and REMOTE_ACTION_RE.fullmatch(uses) is None:
                raise WorkflowError(f"remote action is not pinned by full SHA: {uses}")
        validation = _run(_named_step(steps, EXPECTED_STEPS[3]))
        if 'test "$GITHUB_REF" = "refs/heads/main"' not in validation:
            raise WorkflowError("channel publication must run from protected main")
        for asset in (
            "release-manifest.json",
            "channel-candidates.json",
            "channel-candidates.tar.gz",
        ):
            if asset not in validation:
                raise WorkflowError(f"validation does not download {asset}")
        if "validate_channel_candidates.py" not in validation:
            raise WorkflowError("validation must check channel candidate bytes")
        if (
            ".isDraft == false" not in validation
            or ".isImmutable == true" not in validation
        ):
            raise WorkflowError("validation must require a published immutable release")
        _check_token(steps, EXPECTED_STEPS[4], "homebrew-tap")
        _check_token(steps, EXPECTED_STEPS[5], "scoop-bucket")
        mutation = _named_step(steps, EXPECTED_STEPS[6])
        mutation_env = _mapping(mutation.get("env"), "channel mutation env")
        if set(mutation_env) != {"HOMEBREW_GH_TOKEN", "SCOOP_GH_TOKEN", "TAG_NAME"}:
            raise WorkflowError("channel mutation environment is not minimal")
        mutation_run = _run(mutation)
        if "prepare_package_channels.py apply" not in mutation_run:
            raise WorkflowError("channel mutation must call the channel coordinator")
        if '--tag "$TAG_NAME"' not in mutation_run:
            raise WorkflowError("channel coordinator must receive the selected tag")
        if '--candidate-root "$RUNNER_TEMP/release"' not in mutation_run:
            raise WorkflowError("channel coordinator must receive validated candidates")
        for name in EXPECTED_STEPS[7:]:
            if "/installation/token" not in _run(_named_step(steps, name)):
                raise WorkflowError(f"{name} must revoke its installation token")
        return []
    except (OSError, WorkflowError) as error:
        return [str(error)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("workflow", type=Path)
    args = parser.parse_args(argv)
    workflow_path = cast(Path, args.workflow)
    errors = check_workflow(workflow_path)
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print(f"valid: {workflow_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
