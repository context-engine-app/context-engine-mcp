"""Statically verify the protected package-channel workflow."""

from __future__ import annotations

import argparse
import importlib
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

REMOTE_ACTION_RE = re.compile(r"^[^./][^@]*@[0-9a-f]{40}$")
EXPECTED_INPUTS = {
    "tag",
    "homebrew_repair_run_id",
    "homebrew_repair_attempt",
    "scoop_repair_run_id",
    "scoop_repair_attempt",
}
EXPECTED_PERMISSIONS = {"contents": "read", "actions": "read", "attestations": "read"}
EXPECTED_PREFLIGHT_STEPS = (
    "Check out public workflow tools",
    "Set up pinned uv and Python",
    "Create pinned Python environment",
    "Validate immutable release and workflow binding",
    "Validate optional repair provenance",
    "Validate repository-bootstrap inputs",
    "Anonymous destination preflight and plan",
)
EXPECTED_PUBLISH_STEPS = (
    "Check out public workflow tools",
    "Set up pinned uv and Python",
    "Create pinned Python environment",
    "Revalidate protected runtime binding",
    "Download verified release assets",
    "Restore anonymous preflight plan",
    "Create private artifact-reader App token",
    "Retrieve optional repair candidate bytes",
    "Validate repair candidate bytes",
    "Revoke private artifact-reader token",
    "Create separate Homebrew installation token",
    "Create separate Scoop installation token",
    "Create channel pull requests",
    "Revoke Homebrew installation token",
    "Revoke Scoop installation token",
)
TOKEN_ACTION = (
    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
)
COORDINATOR_ENV = {
    "GH_TOKEN": "${{ github.token }}",
    "HOMEBREW_GH_TOKEN": "${{ steps.homebrew.outputs.token }}",
    "SCOOP_GH_TOKEN": "${{ steps.scoop.outputs.token }}",
    "TAG_NAME": "${{ inputs.tag }}",
    "HOMEBREW_REPAIR_RUN_ID": "${{ inputs.homebrew_repair_run_id }}",
    "HOMEBREW_REPAIR_ATTEMPT": "${{ inputs.homebrew_repair_attempt }}",
    "SCOOP_REPAIR_RUN_ID": "${{ inputs.scoop_repair_run_id }}",
    "SCOOP_REPAIR_ATTEMPT": "${{ inputs.scoop_repair_attempt }}",
}
COORDINATOR_RUN = """set -euo pipefail
.venv/bin/python scripts/prepare_package_channels.py apply \\
  --tag "$TAG_NAME" --candidate-root "$RUNNER_TEMP/release" --schemas schemas \\
  --preflight-plan "$RUNNER_TEMP/channel-preflight.json" \\
  --homebrew-repair-root "$RUNNER_TEMP/repairs/homebrew" --scoop-repair-root "$RUNNER_TEMP/repairs/scoop" \\
  --homebrew-repair-run-id "$HOMEBREW_REPAIR_RUN_ID" --homebrew-repair-attempt "$HOMEBREW_REPAIR_ATTEMPT" \\
  --scoop-repair-run-id "$SCOOP_REPAIR_RUN_ID" --scoop-repair-attempt "$SCOOP_REPAIR_ATTEMPT" \\
  --homebrew-generator-commit "$(cat "$RUNNER_TEMP/repairs/homebrew/generator-commit" 2>/dev/null || true)" \\
  --scoop-generator-commit "$(cat "$RUNNER_TEMP/repairs/scoop/generator-commit" 2>/dev/null || true)"
test "automation/context-engine-$TAG_NAME" != ""
# No force push, no auto merge, no release mutation, or branch deletion is permitted."""
REVOCATION_RUN = (
    'gh api --method DELETE -H "X-GitHub-Api-Version: 2026-03-10" /installation/token'
)
MUTATION_RE = re.compile(
    r"(?:git\s+push\s+--force|gh\s+pr\s+merge|gh\s+release\s+(?:create|delete|edit|upload)|gh\s+run\s+rerun|gh\s+workflow\s+run|git\s+push\s+:\s|curl\s+|wget\s+)"
)
CLI_PROFILE_STEP_GUARD = (
    "${{ steps.release-plan.outputs.profile == 'desktop' || "
    "steps.release-plan.outputs.profile == 'desktop-linux' }}"
)
BOOTSTRAP_PROFILE_STEP_GUARD = (
    "${{ steps.release-plan.outputs.profile == 'repository-bootstrap' }}"
)
CLI_PROFILE_JOB_GUARD = (
    "${{ needs.preflight.outputs.profile == 'desktop' || "
    "needs.preflight.outputs.profile == 'desktop-linux' }}"
)


class _YamlModule(Protocol):
    YAMLError: type[Exception]

    def safe_load(self, stream: str) -> object: ...


class WorkflowError(ValueError):
    """The package-channel workflow cannot be parsed safely."""


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


def _names(
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


def _run(step: Mapping[str, object]) -> str:
    value = step.get("run", "")
    return value if isinstance(value, str) else ""


def _check_release_verification(commands: str, label: str, errors: list[str]) -> None:
    markers = (
        'gh release verify "$TAG_NAME" --repo "$GITHUB_REPOSITORY"',
        "gh release verify-asset",
        ".isDraft == false and .isImmutable == true",
        "while IFS= read -r -d '' asset",
    )
    for marker in markers:
        if marker not in commands:
            errors.append(f"{label} is missing release verification: {marker}")
    verify_index = commands.find('gh release verify "$TAG_NAME"')
    candidate_index = commands.find("validate_release_provenance.py package-channels")
    if verify_index < 0 or candidate_index < 0 or verify_index > candidate_index:
        errors.append(f"{label} release verification must precede candidate validation")


def _check_reauthorization_refs(commands: str, errors: list[str]) -> None:
    markers = (
        'test "$GITHUB_REF" = '
        + '"refs/tags/release-reauthorization/$TAG_NAME/package-channels/$runtime_commit"',
        'test "$GITHUB_WORKFLOW_REF" = '
        + '"$GITHUB_REPOSITORY/.github/workflows/prepare-package-channels.yml@$GITHUB_REF"',
    )
    for marker in markers:
        if marker not in commands:
            errors.append(f"reauthorization binding is not exact: {marker}")


def _check_repair_api_version(commands: str, errors: list[str]) -> None:
    header = "X-GitHub-Api-Version: 2026-03-10"
    targets = (
        "actions/runs/$run_id",
        "actions/runs/$run_id/artifacts",
        "actions/artifacts/$artifact_id/zip",
    )
    for target in targets:
        target_offset = 0
        call_segment: str | None = None
        while True:
            target_offset = commands.find(target, target_offset)
            if target_offset < 0:
                break
            api_offset = commands.rfind("gh api", 0, target_offset)
            if api_offset >= 0:
                call_segment = commands[api_offset:target_offset]
                break
            target_offset += len(target)
        if call_segment is None or header not in call_segment:
            errors.append(f"repair API call is missing pinned version: {target}")


def _check_profile_guard(
    value: object, expected: str, label: str, errors: list[str]
) -> None:
    if value != expected:
        errors.append(
            f"{label} profile guard must name exactly desktop and desktop-linux"
            if expected == CLI_PROFILE_STEP_GUARD
            else f"{label} profile guard is not exact"
        )


def _check_profile_case(
    commands: str, label: str, errors: list[str], *, require_bootstrap: bool
) -> None:
    case_index = commands.find('case "$profile" in')
    cli_index = commands.find("desktop|desktop-linux)", case_index + 1)
    if case_index < 0 or cli_index < 0:
        errors.append(f"{label} must branch explicitly on the two CLI profiles")
        return
    cli_end = commands.find(";;", cli_index)
    candidate_index = commands.find("validate_channel_candidates.py", case_index + 1)
    if cli_end < 0 or not cli_index < candidate_index < cli_end:
        errors.append(
            f"{label} candidate validation must be inside the CLI profile branch"
        )
    if require_bootstrap:
        bootstrap_index = commands.find("repository-bootstrap)", cli_end + 1)
        if bootstrap_index < 0:
            errors.append(f"{label} must handle repository-bootstrap explicitly")
            return
        bootstrap_end = commands.find(";;", bootstrap_index)
        if bootstrap_end < 0:
            errors.append(f"{label} repository-bootstrap branch is incomplete")
            return
        bootstrap_commands = commands[bootstrap_index:bootstrap_end]
        if "validate_channel_candidates.py" in bootstrap_commands:
            errors.append(f"{label} bootstrap branch must not validate candidate files")
        if "prepare_package_channels.py preflight" in bootstrap_commands:
            errors.append(f"{label} bootstrap branch must not read destination state")
    default_index = commands.find("*)", cli_end + 1)
    default_end = commands.find(";;", default_index) if default_index >= 0 else -1
    if (
        default_index < 0
        or default_end < 0
        or "exit 1" not in commands[default_index:default_end]
    ):
        errors.append(f"{label} must reject unsupported release profiles")


def _check_trigger(workflow: Mapping[str, object], errors: list[str]) -> None:
    generic = cast(Mapping[object, object], workflow)
    trigger = generic.get("on", generic.get(True))
    dispatch = _mapping(
        _mapping(trigger, "on").get("workflow_dispatch"), "workflow_dispatch"
    )
    inputs = _mapping(dispatch.get("inputs"), "workflow_dispatch.inputs")
    if set(inputs) != EXPECTED_INPUTS:
        errors.append(
            "workflow dispatch inputs must be exactly tag and four optional repair fields"
        )
    for name in EXPECTED_INPUTS:
        item = _mapping(inputs.get(name), f"input {name}")
        if item.get("type") != "string":
            errors.append(f"input {name} must be a string")
        required = item.get("required")
        if name == "tag" and required is not True:
            errors.append("tag input must be required")
        if name != "tag" and required is not False:
            errors.append(f"{name} input must be optional")


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
    if "environment" in job or "env" in job or "secrets." in str(job):
        errors.append("preflight must be credential-free and environment-free")
    steps = _steps(job, "jobs.preflight")
    if any(
        isinstance(step.get("uses"), str)
        and "create-github-app-token" in cast(str, step.get("uses"))
        for step in steps
    ):
        errors.append("preflight must not create an installation token")
    if _names(steps, "jobs.preflight", errors) != EXPECTED_PREFLIGHT_STEPS:
        errors.append("preflight steps must match the exact approved sequence")
    commands = "\n".join(_run(step) for step in steps)
    outputs = _mapping(job.get("outputs"), "jobs.preflight.outputs")
    if dict(outputs) != {
        "profile": "${{ steps.release-plan.outputs.profile }}",
        "preflight_plan_b64": "${{ steps.anonymous-preflight.outputs.plan_b64 }}",
    }:
        errors.append("preflight outputs must expose the validated profile and plan")
    release_plan = next(
        (
            step
            for step in steps
            if step.get("name") == "Validate immutable release and workflow binding"
        ),
        None,
    )
    if release_plan is None or release_plan.get("id") != "release-plan":
        errors.append("immutable release step must publish the validated profile")
    else:
        release_commands = _run(release_plan)
        for marker in (
            '[[ "$TAG_NAME" =~ ^(v|repository-bootstrap-v)(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]',
            "profile=$(jq -er '.profile' \"$RUNNER_TEMP/package-plan.json\")",
            "desktop|desktop-linux)",
            "repository-bootstrap)",
            'test ! -e "$RUNNER_TEMP/release/channel-candidates.json"',
            'test ! -e "$RUNNER_TEMP/release/channel-candidates.tar.gz"',
            'test ! -e "$RUNNER_TEMP/release/Formula/context-engine.rb"',
            'test ! -e "$RUNNER_TEMP/release/bucket/context-engine.json"',
            'echo "profile=$profile" >> "$GITHUB_OUTPUT"',
        ):
            if marker not in release_commands:
                errors.append(
                    f"immutable release step is missing profile guard: {marker}"
                )
        _check_profile_case(
            release_commands,
            "immutable release profile",
            errors,
            require_bootstrap=True,
        )
    repair = next(
        (
            step
            for step in steps
            if step.get("name") == "Validate optional repair provenance"
        ),
        None,
    )
    if repair is None:
        errors.append("optional repair validation step is missing")
    else:
        _check_profile_guard(
            repair.get("if"), CLI_PROFILE_STEP_GUARD, "repair validation", errors
        )
    bootstrap = next(
        (
            step
            for step in steps
            if step.get("name") == "Validate repository-bootstrap inputs"
        ),
        None,
    )
    if bootstrap is None:
        errors.append("repository-bootstrap input validation step is missing")
    else:
        _check_profile_guard(
            bootstrap.get("if"),
            BOOTSTRAP_PROFILE_STEP_GUARD,
            "repository-bootstrap validation",
            errors,
        )
        bootstrap_commands = _run(bootstrap)
        for selector in (
            "HOMEBREW_REPAIR_RUN_ID",
            "HOMEBREW_REPAIR_ATTEMPT",
            "SCOOP_REPAIR_RUN_ID",
            "SCOOP_REPAIR_ATTEMPT",
        ):
            if f'test -z "${selector}"' not in bootstrap_commands:
                errors.append(
                    f"repository-bootstrap validation must require an empty {selector}"
                )
        for forbidden in (
            "gh ",
            "GH_TOKEN",
            "create-github-app-token",
            "prepare_package_channels.py",
            "context-engine-app/homebrew-tap",
            "context-engine-app/scoop-bucket",
        ):
            if forbidden in bootstrap_commands:
                errors.append(
                    f"repository-bootstrap validation must not reach {forbidden.strip()}"
                )
        if TOKEN_ACTION in str(bootstrap) or "GH_TOKEN" in str(bootstrap):
            errors.append(
                "repository-bootstrap validation must not create or expose a token"
            )
    anonymous = next(
        (
            step
            for step in steps
            if step.get("name") == "Anonymous destination preflight and plan"
        ),
        None,
    )
    if anonymous is None:
        errors.append("anonymous destination preflight step is missing")
    else:
        _check_profile_guard(
            anonymous.get("if"), CLI_PROFILE_STEP_GUARD, "destination preflight", errors
        )
    for step in steps:
        if step is anonymous:
            continue
        run = _run(step)
        if "prepare_package_channels.py preflight" in run:
            errors.append(
                "destination preflight must be isolated behind its CLI profile guard"
            )
        if any(
            destination in run
            for destination in (
                "context-engine-app/homebrew-tap",
                "context-engine-app/scoop-bucket",
            )
        ):
            errors.append(
                "preflight must not read destination state outside its guarded step"
            )
    _check_release_verification(commands, "preflight", errors)
    _check_reauthorization_refs(commands, errors)
    for marker in (
        "validate_release_provenance.py package-channels",
        "validate_channel_candidates.py",
        "workflow binding",
        "context-engine-app/homebrew-tap",
        "context-engine-app/scoop-bucket",
        "prepare_package_channels.py preflight",
    ):
        if (
            marker not in commands
            or marker
            in {"context-engine-app/homebrew-tap", "context-engine-app/scoop-bucket"}
            and commands.count(marker) < 2
        ):
            label = (
                "destination repository"
                if marker
                in {
                    "context-engine-app/homebrew-tap",
                    "context-engine-app/scoop-bucket",
                }
                else marker
            )
            errors.append(f"preflight is missing required validation: {label}")
    if (
        "GH_TOKEN" in commands
        or "GITHUB_TOKEN" in commands
        or "create-github-app-token" in commands
    ):
        errors.append("preflight must not use credentials or installation tokens")


def _check_token(
    step: Mapping[str, object], *, expected_repository: str, errors: list[str]
) -> None:
    if step.get("uses") != TOKEN_ACTION:
        errors.append("package App token action is not pinned to the approved commit")
        return
    values = _mapping(step.get("with"), "package App token inputs")
    if values.get("client-id") != "${{ vars.PACKAGE_METADATA_APP_CLIENT_ID }}":
        errors.append("package App token must use the one package-metadata identity")
    if values.get("private-key") != "${{ secrets.PACKAGE_METADATA_APP_PRIVATE_KEY }}":
        errors.append("package App token must use the package-metadata private key")
    if values.get("owner") != "context-engine-app":
        errors.append("package App token owner is not canonical")
    if values.get("repositories") != expected_repository:
        errors.append(
            "each installation token must be scoped to exactly one destination repo"
        )
    if (
        values.get("permission-contents") != "write"
        or values.get("permission-pull-requests") != "write"
    ):
        errors.append(
            "destination token permissions must be contents/write and pull-requests/write"
        )
    if set(values) != {
        "client-id",
        "private-key",
        "owner",
        "repositories",
        "permission-contents",
        "permission-pull-requests",
    }:
        errors.append("destination App token inputs are not exact")


def _check_publish(job: Mapping[str, object], errors: list[str]) -> None:
    _check_profile_guard(job.get("if"), CLI_PROFILE_JOB_GUARD, "publish job", errors)
    if job.get("environment") != "release-channel":
        errors.append("publish job must use release-channel environment")
    if "env" in job:
        errors.append("publish job must not define job-level env")
    steps = _steps(job, "jobs.publish")
    if _names(steps, "jobs.publish", errors) != EXPECTED_PUBLISH_STEPS:
        errors.append("publish steps must match the exact approved sequence")
    reader = next(
        (
            step
            for step in steps
            if step.get("name") == "Create private artifact-reader App token"
        ),
        None,
    )
    if reader is None:
        errors.append("private artifact-reader token step is missing")
    else:
        if "inputs.homebrew_repair_run_id" not in str(
            reader.get("if", "")
        ) or "inputs.scoop_repair_run_id" not in str(reader.get("if", "")):
            errors.append(
                "artifact-reader token must be conditional on a complete repair pair"
            )
        if reader.get("uses") != TOKEN_ACTION:
            errors.append("artifact-reader App token action is not pinned")
        values = _mapping(reader.get("with"), "artifact-reader App token inputs")
        if (
            values.get("owner") != "context-engine-app"
            or values.get("repositories") != "context-engine"
        ):
            errors.append(
                "artifact-reader token must be scoped to private context-engine only"
            )
        if (
            values.get("permission-actions") != "read"
            or values.get("permission-contents") != "read"
        ):
            errors.append("artifact-reader token must be read-only")
    for name, repository in (
        ("Create separate Homebrew installation token", "homebrew-tap"),
        ("Create separate Scoop installation token", "scoop-bucket"),
    ):
        step = next((value for value in steps if value.get("name") == name), None)
        if step is None:
            errors.append(f"{name} is missing")
        else:
            _check_token(step, expected_repository=repository, errors=errors)
    homebrew = next(
        (
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Create separate Homebrew installation token"
        ),
        None,
    )
    scoop = next(
        (
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Create separate Scoop installation token"
        ),
        None,
    )
    reader_index = next(
        (
            index
            for index, step in enumerate(steps)
            if step.get("name") == "Revoke private artifact-reader token"
        ),
        None,
    )
    if (
        reader_index is None
        or homebrew is None
        or scoop is None
        or reader_index > min(homebrew, scoop)
    ):
        errors.append(
            "private artifact-reader token must be revoked before destination writes"
        )
    commands = "\n".join(_run(step) for step in steps)
    _check_profile_case(commands, "publish profile", errors, require_bootstrap=False)
    retrieval = next(
        (
            step
            for step in steps
            if step.get("name") == "Retrieve optional repair candidate bytes"
        ),
        None,
    )
    if (
        retrieval is None
        or "inputs.homebrew_repair_run_id" not in str(retrieval.get("if", ""))
        or "inputs.scoop_repair_run_id" not in str(retrieval.get("if", ""))
    ):
        errors.append("repair retrieval must be conditional on a complete repair pair")
    for marker in (
        "actions/runs",
        "context-engine-channel-repair",
        "extract-repair",
        "validate-repair",
        "--preflight-plan",
        "verify-preflight",
        "prepare-channel-repair.yml@",
        "desktop|desktop-linux)",
        'test "$profile" = "$EXPECTED_PROFILE"',
        "package-channel publish requires a CLI release profile",
    ):
        if marker not in commands:
            errors.append(f"publish job is missing repair/preflight marker: {marker}")
    if ".head_branch == $tag" in commands:
        errors.append("publish job must not bind repair runs to the release branch")
    _check_release_verification(commands, "publish", errors)
    _check_reauthorization_refs(commands, errors)
    _check_repair_api_version(commands, errors)
    for marker in ("context-engine-", "no force", "no auto", "no release"):
        if marker not in commands.lower():
            errors.append(f"publish job is missing safety marker: {marker}")
    coordinator = next(
        (step for step in steps if step.get("name") == "Create channel pull requests"),
        None,
    )
    if coordinator is None:
        errors.append("package-channel coordinator step is missing")
    else:
        coordinator_run = _run(coordinator).strip()
        if coordinator_run != COORDINATOR_RUN:
            errors.append("package-channel coordinator command is not canonical")
        if dict(_mapping(coordinator.get("env"), "coordinator environment")) != (
            COORDINATOR_ENV
        ):
            errors.append("package-channel coordinator environment is not canonical")
        if re.search(
            r"\bgh\s+api\s+--method\s+(?:POST|PATCH|DELETE)\b", coordinator_run
        ):
            errors.append("package-channel coordinator contains a forbidden mutation")
    token_outputs = (
        "steps.homebrew.outputs.token",
        "steps.scoop.outputs.token",
    )
    token_consumers = {
        "Create channel pull requests",
        "Revoke Homebrew installation token",
        "Revoke Scoop installation token",
    }
    for step in steps:
        if step.get("name") not in token_consumers and any(
            output in str(step) for output in token_outputs
        ):
            errors.append("installation token output is reused outside approved steps")
    if MUTATION_RE.search(commands) or MUTATION_RE.search(
        "\n".join(str(step) for step in steps)
    ):
        errors.append("workflow contains a forbidden direct mutation")
    for step in steps:
        name = step.get("name")
        if isinstance(name, str) and "Revoke" in name:
            if (
                "always()" not in str(step.get("if", ""))
                or _run(step).strip() != REVOCATION_RUN
            ):
                errors.append(f"{name} must use the canonical revoke command")


def check_workflow(path: Path) -> list[str]:
    """Return all static contract violations for one package-channel workflow."""
    try:
        yaml = _yaml()
        source = path.read_text(encoding="utf-8")
        try:
            document = yaml.safe_load(source)
        except yaml.YAMLError as error:
            return [f"invalid YAML: {error}"]
        workflow = _mapping(document, "workflow")
        if re.search(r"profile\s*!=\s*['\"]repository-bootstrap['\"]", source):
            return ["profile guard must name exactly desktop and desktop-linux"]
        jobs = _mapping(workflow.get("jobs"), "jobs")
        if set(jobs) != {"preflight", "publish"}:
            return ["workflow jobs must be exactly preflight and publish"]
        errors: list[str] = []
        _check_trigger(workflow, errors)
        permissions = _mapping(workflow.get("permissions"), "permissions")
        if permissions != EXPECTED_PERMISSIONS:
            errors.append(
                "workflow permissions must be contents/actions/attestations read-only"
            )
        concurrency = _mapping(workflow.get("concurrency"), "concurrency")
        if concurrency != {
            "group": "package-channels-${{ inputs.tag }}",
            "cancel-in-progress": False,
        }:
            errors.append("concurrency must serialize package channels by tag")
        preflight = _mapping(jobs.get("preflight"), "jobs.preflight")
        publish = _mapping(jobs.get("publish"), "jobs.publish")
        if publish.get("needs") != "preflight":
            errors.append("publish job must depend on credential-free preflight")
        for label, job in (("preflight", preflight), ("publish", publish)):
            if "permissions" in job:
                errors.append(f"{label} must not override workflow permissions")
        _check_remote_actions(jobs, errors)
        _check_preflight(preflight, errors)
        _check_publish(publish, errors)
        if MUTATION_RE.search(source):
            errors.append("workflow contains a forbidden direct mutation")
        return errors
    except (OSError, WorkflowError) as error:
        return [str(error)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("workflow", type=Path)
    args = parser.parse_args(argv)
    errors = check_workflow(cast(Path, args.workflow))
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
