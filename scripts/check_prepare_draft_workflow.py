#!/usr/bin/env python3
"""Check the single protected release publication workflow."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from collections.abc import Mapping
from typing import cast

import yaml


CHECKOUT_USES = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
TOKEN_USES = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
DOWNLOAD_USES = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
SETUP_UV_USES = "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9"
COSIGN_USES = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
READER_TOKEN = "steps.artifact-reader.outputs.token"
PUBLISHER_TOKEN = "steps.publisher.outputs.token"
REVOCATION = "installation/token"
PUBLISH_RE = re.compile(r"python -m scripts\.prepare_draft_release --plan")


class WorkflowError(ValueError):
    """The workflow does not implement the release publication contract."""


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkflowError(f"{label} must be a mapping")
    return cast(dict[str, object], value)


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    raw = job.get("steps")
    if not isinstance(raw, list):
        raise WorkflowError("release-publish.steps must be a list")
    return [
        _mapping(value, f"step {index}")
        for index, value in enumerate(cast(list[object], raw))
    ]


def _on(workflow: dict[str, object]) -> dict[str, object]:
    value = workflow.get("on")
    if value is None:
        value = cast(Mapping[object, object], workflow).get(True)
    trigger = _mapping(value, "on")
    dispatch = _mapping(trigger.get("workflow_dispatch"), "on.workflow_dispatch")
    inputs = _mapping(dispatch.get("inputs"), "workflow_dispatch.inputs")
    if set(inputs) != {"tag", "source_run_id"}:
        raise WorkflowError(
            "workflow_dispatch must expose exactly tag and source_run_id"
        )
    for name, item in inputs.items():
        config = _mapping(item, f"input {name}")
        if config.get("required") is not True or config.get("type") != "string":
            raise WorkflowError(f"input {name} must be a required string")
    return trigger


def check_workflow(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        workflow = _mapping(
            cast(object, yaml.safe_load(path.read_text(encoding="utf-8"))),
            "workflow",
        )
        _ = _on(workflow)
        if workflow.get("permissions") != {
            "contents": "read",
            "actions": "read",
            "attestations": "read",
        }:
            raise WorkflowError("workflow permissions must be read-only")
        concurrency = _mapping(workflow.get("concurrency"), "concurrency")
        if (
            concurrency.get("group") != "release-publish-${{ inputs.tag }}"
            or concurrency.get("cancel-in-progress") is not False
        ):
            raise WorkflowError("publication concurrency must serialize the tag")
        jobs = _mapping(workflow.get("jobs"), "jobs")
        if set(jobs) != {"release-publish"}:
            raise WorkflowError("workflow must contain only the release-publish job")
        job = _mapping(jobs["release-publish"], "release-publish")
        if job.get("environment") != "release-publish":
            raise WorkflowError(
                "publication job must use the release-publish environment"
            )
        steps = _steps(job)
        names = [step.get("name") for step in steps]
        expected = [
            "Check out public workflow tools",
            "Validate protected inputs",
            "Set up pinned uv and Python",
            "Create pinned Python environment",
            "Install pinned Cosign",
            "Create private reader App token",
            "Verify source run and staging artifact",
            "Download exact private staging artifact",
            "Revoke private reader token",
            "Validate staging and candidate assets",
            "Verify signed staging checksums",
            "Create public publisher App token",
            "Publish exact immutable release",
            "Revoke public publisher token",
        ]
        if names != expected:
            raise WorkflowError(f"workflow steps must be exactly {expected}")
        uses = [str(step.get("uses", "")) for step in steps]
        for expected_use in (CHECKOUT_USES, SETUP_UV_USES, COSIGN_USES):
            if uses.count(expected_use) != 1:
                raise WorkflowError(
                    f"workflow must pin exactly one {expected_use} action"
                )
        if uses.count(TOKEN_USES) != 2 or uses.count(DOWNLOAD_USES) != 1:
            raise WorkflowError(
                "workflow must create two scoped tokens and download one artifact"
            )
        commands = "\n".join(str(step.get("run", "")) for step in steps)
        if 'test "$GITHUB_REF" = "refs/heads/main"' not in commands:
            raise WorkflowError("publication must run from protected main")
        if len(PUBLISH_RE.findall(commands)) != 1:
            raise WorkflowError(
                "workflow must invoke the canonical publisher exactly once"
            )
        if (
            "prepare_draft_release.py inspect" in commands
            or "publish_draft_release.py" in commands
        ):
            raise WorkflowError(
                "workflow must not use draft inspection or the obsolete publisher"
            )
        if "release-reauthorization" in commands or "marker" in commands:
            raise WorkflowError(
                "workflow must not use reauthorization or release markers"
            )
        publisher_index = names.index("Create public publisher App token")
        publish_index = names.index("Publish exact immutable release")
        revoke_index = names.index("Revoke public publisher token")
        if not publisher_index < publish_index < revoke_index:
            raise WorkflowError("publisher token must surround the one mutation")
        publisher_inputs = _mapping(
            steps[publisher_index].get("with"), "publisher token inputs"
        )
        if publisher_inputs != {
            "client-id": "${{ vars.IMMUTABLE_RELEASE_PUBLISHER_APP_CLIENT_ID }}",
            "private-key": "${{ secrets.IMMUTABLE_RELEASE_PUBLISHER_APP_PRIVATE_KEY }}",
            "owner": "context-engine-app",
            "repositories": "context-engine-mcp",
            "permission-contents": "write",
        }:
            raise WorkflowError(
                "publisher credentials and scope must match release-publish"
            )
        publish_step = steps[publish_index]
        publish_env = _mapping(publish_step.get("env"), "publisher environment")
        if publish_env.get("GH_TOKEN") != "${{ steps.publisher.outputs.token }}":
            raise WorkflowError("publisher command must use the publisher token")
        for name in ("Revoke private reader token", "Revoke public publisher token"):
            step = steps[names.index(name)]
            if (
                "always()" not in str(step.get("if", ""))
                or "--method DELETE" not in str(step.get("run", ""))
                or REVOCATION not in str(step.get("run", ""))
            ):
                raise WorkflowError(f"{name} must always revoke its token")
    except (OSError, yaml.YAMLError, WorkflowError) as error:
        errors.append(str(error))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "workflow",
        type=Path,
        nargs="?",
        default=Path(".github/workflows/prepare-draft-release.yml"),
    )
    args = parser.parse_args(argv)
    workflow = cast(Path, args.workflow)
    errors = check_workflow(workflow)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"valid: {workflow}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
