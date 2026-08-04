from __future__ import annotations

import json
import io
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from typing_extensions import override


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "release-manifest-canonical.json"
# macOS exposes /var and /tmp as symlinked compatibility aliases.  Keep test
# fixtures on the physical temp volume so the installer can reject every
# symlinked ancestor without weakening its production path checks.
if os.name != "nt" and Path("/private/tmp").is_dir():
    os.environ["TMPDIR"] = "/private/tmp"
TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
)


class InstallerContractTests(unittest.TestCase):
    def run_shell(
        self,
        body: str,
        *args: str | os.PathLike[str],
        environment_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CONTEXT_ENGINE_INSTALLER_TEST_ONLY"] = "1"
        if environment_overrides:
            environment.update(environment_overrides)
        command_args = [str(argument) for argument in args]
        requested_shell = environment.get("CONTEXT_ENGINE_TEST_SHELL")
        shell = shutil.which(requested_shell) if requested_shell else None
        shell = shell or shutil.which("sh") or shutil.which("bash")
        if shell is None:
            self.skipTest("POSIX shell is not installed on this host")
        return subprocess.run(
            [shell, "-c", ". ./install.sh; " + body, "installer-test", *command_args],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def start_shell(
        self,
        body: str,
        *,
        environment_overrides: dict[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        environment = os.environ.copy()
        environment["CONTEXT_ENGINE_INSTALLER_TEST_ONLY"] = "1"
        if environment_overrides:
            environment.update(environment_overrides)
        requested_shell = environment.get("CONTEXT_ENGINE_TEST_SHELL")
        shell = shutil.which(requested_shell) if requested_shell else None
        shell = shell or shutil.which("sh") or shutil.which("bash")
        if shell is None:
            self.skipTest("POSIX shell is not installed on this host")
        return subprocess.Popen(
            [shell, "-c", ". ./install.sh; " + body, "installer-test"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def run_pwsh(self, command: str) -> subprocess.CompletedProcess[str]:
        requested_shell = os.environ.get("CONTEXT_ENGINE_TEST_POWERSHELL")
        shell = shutil.which(requested_shell) if requested_shell else None
        shell = shell or shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("PowerShell is not installed on this host")
        return subprocess.run(
            [shell, "-NoProfile", "-Command", command],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        _ = path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def write_tar(path: Path, members: Sequence[tuple[str, bytes, str | None]]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for name, payload, linkname in members:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                if linkname is not None:
                    info.type = tarfile.SYMTYPE
                    info.linkname = linkname
                    archive.addfile(info)
                else:
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))

    @staticmethod
    def write_directory_reparse(link: Path, target: Path) -> None:
        if os.name != "nt":
            link.symlink_to(target, target_is_directory=True)
            return
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if shell is None:
            raise OSError("Windows PowerShell is required to create a junction")
        link_literal = "'" + str(link).replace("'", "''") + "'"
        target_literal = "'" + str(target).replace("'", "''") + "'"
        result = subprocess.run(
            [
                shell,
                "-NoProfile",
                "-Command",
                f"$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path {link_literal} -Target {target_literal} | Out-Null",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or "junction creation failed")

    @staticmethod
    def write_zip(path: Path, name: str, payload: bytes) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _ = archive.writestr(name, payload)

    @staticmethod
    def write_zip_entries(path: Path, entries: Sequence[tuple[str, bytes]]) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in entries:
                _ = archive.writestr(name, payload)

    @staticmethod
    def write_zip_symlink(path: Path, name: str, target: str) -> None:
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (0o120777 << 16) | 0xA0000000
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(info, target.encode())

    @staticmethod
    def ps_literal(path: Path) -> str:
        return "'" + str(path).replace("'", "''") + "'"

    @staticmethod
    def fake_curl(path: Path) -> None:
        InstallerContractTests.write_executable(
            path,
            """#!/bin/sh
head=0
headers=
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --head) head=1 ;;
    --dump-header) shift; headers=$1 ;;
    --output) shift; output=$1 ;;
    --write-out) shift ;;
  esac
  shift
done
if [ "$head" -eq 1 ]; then
  case "${FAKE_CURL_MODE:-valid}" in
    missing) printf 'HTTP/1.1 200 OK\\r\\n\\r\\n' > "$headers" ;;
    duplicate) printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %s\\r\\nContent-Length: %s\\r\\n\\r\\n' "$FAKE_LENGTH" "$FAKE_LENGTH" > "$headers" ;;
    mismatch) printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %s\\r\\n\\r\\n' "$((FAKE_LENGTH + 1))" > "$headers" ;;
    *) printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %s\\r\\n\\r\\n' "$FAKE_LENGTH" > "$headers" ;;
  esac
  printf '%s' "$FAKE_URL"
else
  if [ "$output" = - ]; then
    cat "$FAKE_PAYLOAD"
    if [ "${FAKE_CURL_MODE:-valid}" = overflow ]; then printf x; fi
  else
    cat "$FAKE_PAYLOAD" > "$output"
    if [ "${FAKE_CURL_MODE:-valid}" = overflow ]; then printf x >> "$output"; fi
  fi
fi
""",
        )

    def test_fixture_is_bom_free_and_schema_shaped(self) -> None:
        self.assertFalse(FIXTURE.read_bytes().startswith(b"\xef\xbb\xbf"))
        manifest = cast(
            dict[str, object], json.loads(FIXTURE.read_text(encoding="utf-8"))
        )
        self.assertEqual(
            manifest["distribution_repository"], "context-engine-app/context-engine-mcp"
        )
        self.assertEqual(manifest["tag"], "v0.2.0")
        self.assertEqual(manifest["version"], "0.2.0")
        self.assertEqual(
            {
                str(record["target"])
                for record in cast(list[dict[str, object]], manifest["artifacts"])
            },
            set(TARGETS),
        )
        self.assertEqual(
            {
                str(record["target"])
                for record in cast(list[dict[str, object]], manifest["payloads"])
            },
            set(TARGETS),
        )

    def test_shell_manifest_parser_selects_every_target(self) -> None:
        for target in TARGETS:
            result = self.run_shell(
                'parse_manifest "$1" "$2"',
                str(FIXTURE),
                target,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            fields = result.stdout.rstrip("\n").split("\t")
            self.assertEqual(fields[0:2], ["v0.2.0", "0.2.0"])
            self.assertEqual(fields[3], target)
            self.assertEqual(fields[7], f"context-engine-{target}")

    def test_shell_manifest_parser_accepts_singleton_sections_and_rejects_empty_sections(
        self,
    ) -> None:
        pristine = cast(
            dict[str, object],
            json.loads(FIXTURE.read_text(encoding="utf-8")),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = "x86_64-unknown-linux-gnu"
            singleton = cast(dict[str, object], json.loads(json.dumps(pristine)))
            singleton["artifacts"] = [
                record
                for record in cast(list[dict[str, object]], singleton["artifacts"])
                if record["target"] == target
            ]
            singleton["payloads"] = [
                record
                for record in cast(list[dict[str, object]], singleton["payloads"])
                if record["target"] == target
            ]
            singleton_path = root / "singleton.json"
            _ = singleton_path.write_text(json.dumps(singleton, indent=2) + "\n")
            result = self.run_shell('parse_manifest "$1" "$2"', singleton_path, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            empty = cast(dict[str, object], json.loads(json.dumps(pristine)))
            empty["artifacts"] = []
            empty["payloads"] = []
            empty_path = root / "empty.json"
            _ = empty_path.write_text(json.dumps(empty, indent=2) + "\n")
            result = self.run_shell('! parse_manifest "$1" "$2"', empty_path, target)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_valid_manifest_handoff_reaches_fresh_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = base / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            body = (
                'parsed=$(parse_manifest "$1" "$2") || exit 1\n'
                "tab=$(printf '\\t')\n"
                'IFS="$tab" read -r tag version archive_filename archive_target archive_url archive_sha archive_size payload_id payload_filename payload_sha payload_size payload_mode payload_version <<EOF\n'
                "$parsed\n"
                "EOF\n"
                '[ "$archive_target" = "$2" ] && [ "$payload_filename" = context-engine ] || exit 1\n'
                'install_fresh "$archive_target" "$tag" "$version" "$archive_filename" "$archive_sha" "$archive_size" "$payload_filename" "$payload_sha" "$payload_size" "$payload_mode" "$payload_version" "$3" "$4" "$5"\n'
            )
            result = self.run_shell(
                body,
                str(FIXTURE),
                "x86_64-unknown-linux-gnu",
                working,
                root,
                entrypoint,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "context-engine").is_file())
            self.assertTrue(entrypoint.is_symlink())
            self.assertFalse(working.exists())

    def test_shell_main_uses_distinct_archive_extraction_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive_name = "context-engine-x86_64-unknown-linux-gnu.tar.gz"
            payload = b"#!/bin/sh\nprintf '%s\\n' 'context-engine 0.2.0'\n"
            archive = base / archive_name
            self.write_tar(archive, [("context-engine", payload, None)])
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            payload_sha = hashlib.sha256(payload).hexdigest()
            manifest = {
                "distribution_repository": "context-engine-app/context-engine-mcp",
                "tag": "v0.2.0",
                "version": "0.2.0",
                "artifacts": [
                    {
                        "architecture": "x86_64",
                        "filename": archive_name,
                        "kind": "archive",
                        "payload_id": "context-engine-x86_64-unknown-linux-gnu",
                        "platform": "linux",
                        "sha256": archive_sha,
                        "size": str(archive.stat().st_size),
                        "target": "x86_64-unknown-linux-gnu",
                        "url": f"https://github.com/context-engine-app/context-engine-mcp/releases/download/v0.2.0/{archive_name}",
                    }
                ],
                "payloads": [
                    {
                        "architecture": "x86_64",
                        "executable_mode": "0755",
                        "filename": "context-engine",
                        "id": "context-engine-x86_64-unknown-linux-gnu",
                        "license_mode": "enforced",
                        "platform": "linux",
                        "sha256": payload_sha,
                        "size": str(len(payload)),
                        "target": "x86_64-unknown-linux-gnu",
                        "version_output": "context-engine 0.2.0",
                    }
                ],
            }
            manifest_path = base / "release-manifest.json"
            _ = manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            checksums_path = base / "SHA256SUMS"
            _ = checksums_path.write_text(f"{archive_sha}  {archive_name}\n")
            observed = base / "observed"
            home = base / "home"
            home.mkdir()
            command = (
                "target_for_host() { printf '%s\\n' x86_64-unknown-linux-gnu; }; "
                "id() { printf '%s\\n' 999999; }; "
                "classify_entrypoint() { printf '%s\\n' fresh; }; "
                "discover_tag() { printf '%s\\n' v0.2.0; }; "
                f'curl_get() {{ case "$1" in *release-manifest.json) cp {self.ps_literal(manifest_path)} "$2" ;; *SHA256SUMS) cp {self.ps_literal(checksums_path)} "$2" ;; esac; }}; '
                f'download_archive() {{ cp {self.ps_literal(archive)} "$3"; }}; '
                f'install_fresh() {{ test -f "${{12}}/context-engine" && cp "${{12}}/context-engine" {self.ps_literal(observed)}; }}; '
                "main"
            )
            result = self.run_shell(
                command,
                environment_overrides={"HOME": str(home)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(observed.read_bytes(), payload)

    def test_shell_minimum_release_rejects_before_working_or_network_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            temp_root = base / "temp"
            home.mkdir()
            temp_root.mkdir()
            result = self.run_shell(
                "id() { printf '%s\\n' 999999; }; "
                + "target_for_host() { printf '%s\\n' x86_64-unknown-linux-gnu; }; "
                + "classify_entrypoint() { printf '%s\\n' fresh; }; "
                + "discover_tag() { printf '%s\\n' v0.1.1; }; "
                + 'curl_get() { : > "$HOME/network"; }; '
                + 'install_fresh() { : > "$HOME/install"; }; '
                + "main",
                environment_overrides={
                    "HOME": str(home),
                    "TMPDIR": str(temp_root),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("older than 0.2.0", result.stderr)
            self.assertFalse((home / "network").exists())
            self.assertFalse((home / "install").exists())
            self.assertFalse((home / ".local" / "lib" / "context-engine").exists())
            self.assertEqual(
                sorted(path.name for path in home.iterdir()),
                [".context-engine-installer.lock"],
            )
            lock_path = home / ".context-engine-installer.lock"
            self.assertTrue(lock_path.is_file())
            self.assertEqual(lock_path.read_bytes(), b"")
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(temp_root.iterdir()), [])

    def test_shell_install_stage_is_sibling_of_physical_root_when_entrypoint_parent_differs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = base / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            promotion_log = base / "promotions.log"
            command = (
                f"promotion_log={self.ps_literal(promotion_log)}; "
                'mv() { printf \'%s\\n\' "$*" >> "$promotion_log"; command mv "$@"; }; '
                "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3" fresh'
            )
            result = self.run_shell(command, working, root, entrypoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "context-engine").is_file())
            self.assertTrue(entrypoint.is_symlink())
            self.assertFalse(working.exists())
            promotions = promotion_log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(
                any(line.split()[-1] == str(root) for line in promotions),
                promotions,
            )

    def test_shell_entrypoint_conflict_is_classified_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            network_log = base / "network.log"
            self.write_executable(
                fake_bin / "curl",
                f"#!/bin/sh\nprintf '%s\\n' called >> '{network_log}'\nexit 1\n",
            )
            home = base / "home"
            home.mkdir()
            unsafe_parent = home / "bin"
            _ = unsafe_parent.write_text("not a directory", encoding="utf-8")
            result = self.run_shell(
                '! classify_entrypoint x86_64-unknown-linux-gnu "$1/context-engine"; test ! -e "$2"',
                unsafe_parent,
                network_log,
                environment_overrides={
                    "HOME": str(home),
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(network_log.exists())

    def test_shell_working_cleanup_failure_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            working = Path(directory) / "working"
            working.mkdir()
            result = self.run_shell(
                'rm() { return 1; }; working="$1"; cleanup_working',
                working,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cleanup failed", result.stderr)

    def test_shell_installer_lock_is_persistent_empty_private_and_reusable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            environment = {"HOME": str(home)}
            result = self.run_shell(
                'acquire_installer_lock; test -f "$HOME/.context-engine-installer.lock"; '
                + 'test "$(wc -c < "$HOME/.context-engine-installer.lock" | tr -d "[:space:]")" = 0; '
                + "release_installer_lock",
                environment_overrides=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lock_path = home / ".context-engine-installer.lock"
            self.assertTrue(lock_path.is_file())
            self.assertEqual(lock_path.read_bytes(), b"")
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            result = self.run_shell(
                "acquire_installer_lock; release_installer_lock",
                environment_overrides=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_shell_installer_lock_rejects_unsafe_types_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            home.mkdir()
            lock_path = home / ".context-engine-installer.lock"
            cases: list[tuple[str, object]] = []
            target = base / "target"
            _ = target.write_text("", encoding="utf-8")
            lock_path.symlink_to(target)
            cases.append(("symlink", None))
            lock_path.unlink()
            lock_path.mkdir()
            cases.append(("directory", None))
            lock_path.rmdir()
            _ = lock_path.write_text("", encoding="utf-8")
            lock_path.chmod(0o644)
            cases.append(("mode", None))
            lock_path.unlink()
            _ = lock_path.write_text("not empty", encoding="utf-8")
            lock_path.chmod(0o600)
            cases.append(("nonempty", None))
            for name, _unused in cases:
                if name == "symlink":
                    lock_path.unlink(missing_ok=True)
                    lock_path.symlink_to(target)
                elif name == "directory":
                    if lock_path.is_symlink() or lock_path.is_file():
                        lock_path.unlink()
                    lock_path.mkdir(exist_ok=True)
                elif name == "mode":
                    if lock_path.is_dir():
                        lock_path.rmdir()
                    _ = lock_path.write_text("", encoding="utf-8")
                    lock_path.chmod(0o644)
                else:
                    if lock_path.is_dir():
                        lock_path.rmdir()
                    elif lock_path.is_symlink() or lock_path.is_file():
                        lock_path.unlink()
                    _ = lock_path.write_text("not empty", encoding="utf-8")
                    lock_path.chmod(0o600)
                result = self.run_shell(
                    "acquire_installer_lock", environment_overrides={"HOME": str(home)}
                )
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("installer lock", result.stderr, name)
            stat_bin = base / "stat-bin"
            stat_bin.mkdir()
            self.write_executable(stat_bin / "stat", "#!/bin/sh\nprintf '999999\\n'\n")
            lock_path.unlink()
            _ = lock_path.write_text("", encoding="utf-8")
            lock_path.chmod(0o600)
            result = self.run_shell(
                "acquire_installer_lock",
                environment_overrides={
                    "HOME": str(home),
                    "PATH": f"{stat_bin}{os.pathsep}{os.environ['PATH']}",
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("owned by the current user", result.stderr)

    def test_shell_installer_lock_fails_before_creation_for_missing_utility_and_bad_home(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "uname", "#!/bin/sh\nprintf Linux\n")
            self.write_executable(fake_bin / "command", "#!/bin/sh\nexit 1\n")
            result = self.run_shell(
                "acquire_installer_lock",
                environment_overrides={
                    "HOME": str(home),
                    "PATH": str(fake_bin),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((home / ".context-engine-installer.lock").exists())
            result = self.run_shell(
                "main", environment_overrides={"HOME": "relative-home"}
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("home directory must be absolute", result.stderr)
            result = self.run_shell("main", environment_overrides={"HOME": ""})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("home directory is not set", result.stderr)

    def test_shell_installer_lock_contention_and_handled_cleanup_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            environment = {"HOME": str(home)}
            holder = self.start_shell(
                "trap cleanup_working EXIT; trap cleanup_signal HUP INT TERM; "
                + 'acquire_installer_lock; : > "$HOME/ready"; sleep 2',
                environment_overrides=environment,
            )
            for _attempt in range(40):
                if (home / "ready").exists():
                    break
                time.sleep(0.05)
            self.assertTrue((home / "ready").exists())
            contender = self.run_shell(
                "acquire_installer_lock", environment_overrides=environment
            )
            self.assertNotEqual(contender.returncode, 0)
            self.assertIn("another installer is already running", contender.stderr)
            _, holder_stderr = holder.communicate(timeout=5)
            self.assertEqual(holder.returncode, 0, holder_stderr)
            failed = self.start_shell(
                "trap cleanup_working EXIT; trap cleanup_signal HUP INT TERM; "
                + "acquire_installer_lock; fail expected",
                environment_overrides=environment,
            )
            _ = failed.communicate(timeout=5)
            self.assertNotEqual(failed.returncode, 0)
            reusable = self.run_shell(
                "acquire_installer_lock; release_installer_lock",
                environment_overrides=environment,
            )
            self.assertEqual(reusable.returncode, 0, reusable.stderr)
            signaled = self.start_shell(
                "trap cleanup_working EXIT; trap cleanup_signal HUP INT TERM; "
                + "acquire_installer_lock; kill -TERM $$",
                environment_overrides=environment,
            )
            _ = signaled.communicate(timeout=5)
            self.assertNotEqual(signaled.returncode, 0)
            reusable = self.run_shell(
                "acquire_installer_lock; release_installer_lock",
                environment_overrides=environment,
            )
            self.assertEqual(reusable.returncode, 0, reusable.stderr)

    def test_shell_installer_lock_contention_blocks_fresh_legacy_and_marked_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for transition in ("fresh", "legacy", "marked"):
                home = base / transition / "home"
                home.mkdir(parents=True)
                root = home / ".local" / "lib" / "context-engine"
                if transition == "marked":
                    root.mkdir(parents=True)
                holder = self.start_shell(
                    "trap cleanup_working EXIT; trap cleanup_signal HUP INT TERM; "
                    + 'acquire_installer_lock; : > "$HOME/ready"; sleep 2',
                    environment_overrides={"HOME": str(home)},
                )
                for _attempt in range(40):
                    if (home / "ready").exists():
                        break
                    time.sleep(0.05)
                self.assertTrue((home / "ready").exists(), transition)
                contender_body = (
                    "id() { printf '%s\\n' 999999; }; "
                    "target_for_host() { printf '%s\\n' x86_64-unknown-linux-gnu; }; "
                    f'classify_entrypoint() {{ printf "%s\\n" {transition if transition != "marked" else "fresh"}; }}; '
                    'discover_tag() { : > "$HOME/network"; printf "%s\\n" v0.2.0; }; '
                    'install_fresh() { : > "$HOME/install"; }; '
                    "marked_installation_valid() { return 0; }; "
                    'marked_reinstall() { : > "$HOME/updated"; return 0; }; '
                    "main"
                )
                result = self.run_shell(
                    contender_body, environment_overrides={"HOME": str(home)}
                )
                self.assertNotEqual(result.returncode, 0, transition)
                self.assertIn(
                    "another installer is already running", result.stderr, transition
                )
                self.assertFalse((home / "network").exists(), transition)
                self.assertFalse((home / "install").exists(), transition)
                self.assertFalse((home / "updated").exists(), transition)
                if transition == "marked":
                    self.assertEqual(list(root.iterdir()), [], transition)
                _, holder_stderr = holder.communicate(timeout=5)
                self.assertEqual(holder.returncode, 0, holder_stderr)

    def test_shell_size_validation_keeps_signed_64_bit_decimal_strings(self) -> None:
        body = (
            "validate_size 9007199254740993 && "
            "validate_size 9223372036854775807 && "
            "! validate_size 9223372036854775808 && "
            "! validate_size 01 && ! validate_size 0 && ! validate_size -1 && "
            "decimal_gt 10000000 4194304 && ! decimal_gt 4194304 10000000"
        )
        result = self.run_shell(body)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_curl_enforces_https_and_inactivity_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log = root / "curl-args"
            self.write_executable(
                fake_bin / "curl",
                f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{log}'\n",
            )
            result = self.run_shell(
                'ce_curl "https://example.test/release"',
                environment_overrides={
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = log.read_text(encoding="utf-8").splitlines()
            self.assertIn("--proto", arguments)
            self.assertIn("=https", arguments)
            self.assertIn("--speed-time", arguments)
            self.assertIn("30", arguments)
            self.assertIn("--speed-limit", arguments)
            self.assertIn("1", arguments)
            rejection = self.run_shell(
                '! ce_curl "http://127.0.0.1:9/installer-test"',
                environment_overrides={"PATH": os.environ["PATH"]},
            )
            self.assertEqual(rejection.returncode, 0, rejection.stderr)

    def test_shell_semver_rejects_leading_zero_components(self) -> None:
        result = self.run_shell(
            "test \"$(version_parts 1.2.3)\" = '1 2 3' && "
            + 'test -z "$(version_parts 01.2.3)" && '
            + 'test -z "$(version_parts 1.02.3)" && '
            + 'test -z "$(version_parts 1.2.03)"'
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_semver_rejects_leading_zero_components(self) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            "Add-Type -AssemblyName System.Net.Http; "
            "$response = New-Object System.Net.Http.HttpResponseMessage; "
            "function global:Invoke-HttpGet { return @{ Response = $response; Url = 'https://github.com/context-engine-app/context-engine-mcp/releases/tag/v01.2.3' } }; "
            "try { Get-LatestTag -Client $null -Url 'https://github.com/context-engine-app/context-engine-mcp/releases/latest'; exit 1 } catch { exit 0 }"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_http_redirects_honor_https_limit_and_cumulative_deadline(
        self,
    ) -> None:
        command = r"""
$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1
Add-Type -AssemblyName System.Net.Http
$references = @([System.Net.Http.HttpClient].Assembly.Location, [System.Net.TransportContext].Assembly.Location) | Select-Object -Unique
$source = @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public sealed class InstallerRedirectHandler : HttpMessageHandler {
    private readonly int mode;
    private int calls;
    public InstallerRedirectHandler(int selectedMode) { mode = selectedMode; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
        calls++;
        if (mode == 0) {
            await Task.Delay(800, cancellationToken);
            var redirect = new HttpResponseMessage(HttpStatusCode.Redirect);
            redirect.Headers.Location = new Uri("https://example.test/next");
            return redirect;
        }
        if (mode == 1) {
            var redirect = new HttpResponseMessage(HttpStatusCode.Redirect);
            redirect.Headers.Location = new Uri("http://example.test/insecure");
            return redirect;
        }
        var loop = new HttpResponseMessage(HttpStatusCode.Redirect);
        loop.Headers.Location = new Uri("https://example.test/loop");
        return loop;
    }
}
'@
Add-Type -TypeDefinition $source -ReferencedAssemblies $references
$handler = New-Object InstallerRedirectHandler(0); $client = New-Object System.Net.Http.HttpClient($handler)
try { Invoke-HttpGet -Client $client -Url 'https://example.test/start' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(1)); exit 1 } catch { }
$client.Dispose(); $handler = New-Object InstallerRedirectHandler(1); $client = New-Object System.Net.Http.HttpClient($handler)
try { Invoke-HttpGet -Client $client -Url 'https://example.test/start' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)); exit 1 } catch { }
$client.Dispose(); $handler = New-Object InstallerRedirectHandler(2); $client = New-Object System.Net.Http.HttpClient($handler)
try { Invoke-HttpGet -Client $client -Url 'https://example.test/start' -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)); exit 1 } catch { exit 0 }
"""
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_loopback_streaming_rejects_overflow_and_stall(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            protocol_version: str = "HTTP/1.1"

            def do_GET(self) -> None:
                if self.path == "/overflow":
                    body = b"x" * 5
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    _ = self.wfile.write(body)
                    return
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                _ = self.wfile.write(b"x")
                _ = self.wfile.flush()
                time.sleep(2)
                _ = self.wfile.write(b"xxx")

            @override
            def log_message(self, format: str, *args: object) -> None:
                del format, args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory() as directory:
                overflow_destination = Path(directory) / "overflow"
                stall_destination = Path(directory) / "stall"
                command = (
                    "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                    "Add-Type -AssemblyName System.Net.Http; $client = Get-HttpClient; "
                    f"$response = $client.GetAsync('{base_url}/overflow', [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult(); "
                    f"$http = @{{ Response = $response }}; $caught=$false; try {{ Read-ResponseFile -Http $http -Destination {self.ps_literal(overflow_destination)} -ExpectedSize 4 -MaximumSize 4 -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(5)); }} catch {{ if ($_.Exception.Message -notlike '*manifest size*' -and $_.Exception.Message -notlike '*exceeds*') {{ exit 1 }}; $caught=$true }}; if (-not $caught) {{ exit 1 }}; "
                    f"$response = $client.GetAsync('{base_url}/stall', [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult(); $http = @{{ Response = $response }}; $started=[DateTimeOffset]::UtcNow; $caught=$false; try {{ Read-ResponseFile -Http $http -Destination {self.ps_literal(stall_destination)} -ExpectedSize 4 -MaximumSize 4 -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(1)); }} catch {{ if ($_.Exception.Message -notlike '*response read deadline exceeded*') {{ exit 1 }}; $caught=$true }}; if (-not $caught -or ([DateTimeOffset]::UtcNow - $started).TotalSeconds -gt 4) {{ exit 1 }}; $client.Dispose()"
                )
                result = self.run_pwsh(command)
                self.assertEqual(
                    result.returncode,
                    0,
                    f"stdout={result.stdout!r} stderr={result.stderr!r}",
                )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_power_shell_stream_acquisition_honors_absolute_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = self.ps_literal(Path(directory) / "delayed-payload")
            command = r"""
$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1
Add-Type -AssemblyName System.Net.Http
$references = @([System.Net.Http.HttpClient].Assembly.Location, [System.Net.TransportContext].Assembly.Location) | Select-Object -Unique
$source = @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
public sealed class DelayedInstallerContent : HttpContent {
    private readonly int delayMilliseconds;
    public DelayedInstallerContent(int delay) { delayMilliseconds = delay; }
    protected override async Task<Stream> CreateContentReadStreamAsync() {
        await Task.Delay(delayMilliseconds);
        return new MemoryStream(new byte[] { 1, 2, 3, 4 });
    }
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext context) {
        return stream.WriteAsync(new byte[] { 1, 2, 3, 4 }, 0, 4);
    }
    protected override bool TryComputeLength(out long length) { length = 4; return true; }
}
'@
Add-Type -TypeDefinition $source -ReferencedAssemblies $references
$response = New-Object System.Net.Http.HttpResponseMessage
$response.Content = New-Object DelayedInstallerContent(3000)
$started = [DateTimeOffset]::UtcNow; $caught = $false
try {
    Read-ResponseFile -Http @{ Response = $response } -Destination __DESTINATION__ -ExpectedSize 4 -MaximumSize 4 -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(1))
} catch {
    if ($_.Exception.Message -notlike '*stream acquisition*') { exit 1 }
    $caught = $true
}
if (-not $caught -or ([DateTimeOffset]::UtcNow - $started).TotalSeconds -gt 2.5) { exit 1 }
""".replace("__DESTINATION__", destination)
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((Path(directory) / "delayed-payload").exists())

    def test_fixture_sizes_are_canonical_strings_and_payloads_are_production_mode(
        self,
    ) -> None:
        manifest = cast(
            dict[str, object], json.loads(FIXTURE.read_text(encoding="utf-8"))
        )
        for section in ("artifacts", "payloads"):
            records = cast(list[dict[str, object]], manifest[section])
            for record in records:
                self.assertIsInstance(record["size"], str)
                self.assertRegex(cast(str, record["size"]), r"^[1-9][0-9]*$")
        for payload in cast(list[dict[str, object]], manifest["payloads"]):
            self.assertEqual(payload["executable_mode"], "0755")
            self.assertEqual(payload["version_output"], "context-engine 0.2.0")

    def test_shell_download_rejects_missing_duplicate_mismatched_head_and_get_overflow(
        self,
    ) -> None:
        payload = b"payload-bytes"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload_path = root / "payload"
            _ = payload_path.write_bytes(payload)
            fake_curl = root / "curl"
            self.fake_curl(fake_curl)
            for mode in ("missing", "duplicate", "mismatch", "overflow"):
                output = root / f"{mode}.archive"
                headers = root / f"{mode}.headers"
                result = self.run_shell(
                    'download_archive "$1" "$2" "$3" "$4"',
                    "https://github.com/context-engine-app/context-engine-mcp/releases/download/v0.2.0/context-engine-x86_64-unknown-linux-gnu.tar.gz",
                    str(len(payload)),
                    output,
                    headers,
                    environment_overrides={
                        "PATH": f"{root}{os.pathsep}{os.environ['PATH']}",
                        "FAKE_CURL_MODE": mode,
                        "FAKE_LENGTH": str(len(payload)),
                        "FAKE_PAYLOAD": str(payload_path),
                        "FAKE_URL": "https://github.com/context-engine-app/context-engine-mcp/releases/download/v0.2.0/context-engine-x86_64-unknown-linux-gnu.tar.gz",
                    },
                )
                self.assertNotEqual(result.returncode, 0, mode)
            output = root / "valid.archive"
            headers = root / "valid.headers"
            result = self.run_shell(
                'download_archive "$1" "$2" "$3" "$4"',
                "https://github.com/context-engine-app/context-engine-mcp/releases/download/v0.2.0/context-engine-x86_64-unknown-linux-gnu.tar.gz",
                str(len(payload)),
                output,
                headers,
                environment_overrides={
                    "PATH": f"{root}{os.pathsep}{os.environ['PATH']}",
                    "FAKE_CURL_MODE": "valid",
                    "FAKE_LENGTH": str(len(payload)),
                    "FAKE_PAYLOAD": str(payload_path),
                    "FAKE_URL": "https://github.com/context-engine-app/context-engine-mcp/releases/download/v0.2.0/context-engine-x86_64-unknown-linux-gnu.tar.gz",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), payload)

    def test_shell_loopback_rejects_chunked_overflow_and_read_stall(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            protocol_version: str = "HTTP/1.1"
            _expected_client_abort: bool = False

            @override
            def handle(self) -> None:
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError):
                    if not getattr(self, "_expected_client_abort", False):
                        raise

            def do_HEAD(self) -> None:
                if (
                    self.path == "/valid"
                    or self.path == "/mismatch"
                    or self.path == "/changed"
                ):
                    self.send_response(200)
                    self.send_header("Content-Length", "5")
                elif self.path == "/duplicate":
                    self.send_response(200)
                    self.send_header("Content-Length", "5")
                    self.send_header("Content-Length", "5")
                else:
                    self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:
                if self.path == "/valid" or self.path == "/mismatch":
                    body = b"valid"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    _ = self.wfile.write(body)
                    return
                if self.path == "/changed":
                    body = b"change"
                    self.send_response(200)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    _ = self.wfile.write(f"{len(body):X}\r\n".encode())
                    _ = self.wfile.write(body)
                    _ = self.wfile.write(b"\r\n0\r\n\r\n")
                    return
                if self.path == "/chunked":
                    self._expected_client_abort = True
                    body = b"x" * (4 * 1024 * 1024 + 1)
                    self.send_response(200)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    _ = self.wfile.write(f"{len(body):X}\r\n".encode())
                    _ = self.wfile.write(body)
                    _ = self.wfile.write(b"\r\n0\r\n\r\n")
                    return
                if self.path == "/exact":
                    body = b"x" * (4 * 1024 * 1024)
                    self.send_response(200)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    _ = self.wfile.write(f"{len(body):X}\r\n".encode())
                    _ = self.wfile.write(body)
                    _ = self.wfile.write(b"\r\n0\r\n\r\n")
                    return
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                _ = self.wfile.write(b"x")
                _ = self.wfile.flush()
                time.sleep(2)
                _ = self.wfile.write(b"xxx")

            @override
            def log_message(self, format: str, *args: object) -> None:
                del format, args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for mode, expected_size, should_succeed in (
                    ("valid", 5, True),
                    ("missing", 5, False),
                    ("duplicate", 5, False),
                    ("mismatch", 4, False),
                    ("changed", 5, False),
                ):
                    output = root / f"{mode}.archive"
                    headers = root / f"{mode}.headers"
                    result = self.run_shell(
                        'ce_curl() { curl --fail --silent --show-error --location --max-redirs 10 --connect-timeout 10 --max-time 60 --speed-time 30 --speed-limit 1 "$@"; }; canonical_release_request() { return 0; }; acceptable_redirect() { return 0; }; download_archive "$1" "$2" "$3" "$4"',
                        f"{base_url}/{mode}",
                        str(expected_size),
                        output,
                        headers,
                    )
                    if should_succeed:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(output.read_bytes(), b"valid")
                    else:
                        self.assertNotEqual(
                            result.returncode,
                            0,
                            f"{mode}: stdout={result.stdout!r} stderr={result.stderr!r}",
                        )
                        if output.exists():
                            self.assertLessEqual(
                                output.stat().st_size, 4 * 1024 * 1024, mode
                            )
                chunked = root / "chunked"
                result = self.run_shell(
                    'ce_curl() { curl --fail --silent --show-error --location --max-redirs 10 --connect-timeout 10 --max-time 60 --speed-time 30 --speed-limit 1 "$@"; }; canonical_release_request() { return 0; }; acceptable_redirect() { return 0; }; curl_get "$1" "$2"',
                    f"{base_url}/chunked",
                    chunked,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
                if chunked.exists():
                    self.assertLessEqual(chunked.stat().st_size, 4 * 1024 * 1024)
                exact = root / "exact"
                result = self.run_shell(
                    'ce_curl() { curl --fail --silent --show-error --location --max-redirs 10 --connect-timeout 10 --max-time 60 --speed-time 30 --speed-limit 1 "$@"; }; canonical_release_request() { return 0; }; acceptable_redirect() { return 0; }; curl_get "$1" "$2"',
                    f"{base_url}/exact",
                    exact,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(exact.stat().st_size, 4 * 1024 * 1024)
                stalled = root / "stalled"
                result = self.run_shell(
                    'ce_curl() { curl --fail --silent --show-error --location --max-redirs 10 --connect-timeout 10 --max-time 60 --speed-time 30 --speed-limit 1 "$@"; }; ce_curl --speed-time 1 --speed-limit 1 --max-time 5 --output "$2" "$1"',
                    f"{base_url}/stall",
                    stalled,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_shell_archive_extraction_accepts_safe_docs_and_rejects_unsafe_members(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "safe.tar.gz"
            working = root / "safe-working"
            working.mkdir()
            output = root / "safe.payload"
            self.write_tar(
                archive,
                [
                    ("context-engine", b"ok", None),
                    ("README.md", b"readme", None),
                    ("LICENSE", b"license", None),
                    ("docs/usage.txt", b"docs", None),
                ],
            )
            result = self.run_shell(
                'extract_archive "$1" context-engine "$2" "$3"',
                archive,
                output,
                working,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), b"ok")
            self.assertFalse((working / "README.md").exists())
            self.assertFalse((working / "LICENSE").exists())
            self.assertFalse((working / "docs").exists())

            cases = {
                "traversal": [("../context-engine", b"bad", None)],
                "dot": [(".", b"bad", None)],
                "dot-dot": [("..", b"bad", None)],
                "terminal-dot": [("foo/.", b"bad", None)],
                "terminal-dot-dot": [("foo/..", b"bad", None)],
                "symlink": [("context-engine", b"", "outside")],
            }
            for name, members in cases.items():
                unsafe_archive = root / f"{name}.tar.gz"
                unsafe_working = root / f"{name}-working"
                unsafe_working.mkdir()
                unsafe_output = root / f"{name}.payload"
                self.write_tar(unsafe_archive, members)
                result = self.run_shell(
                    '! extract_archive "$1" context-engine "$2" "$3"',
                    unsafe_archive,
                    unsafe_output,
                    unsafe_working,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(unsafe_output.exists())

            directory_archive = root / "directory.tar.gz"
            directory_working = root / "directory-working"
            directory_working.mkdir()
            directory_output = root / "directory.payload"
            with tarfile.open(directory_archive, "w:gz") as archive_handle:
                info = tarfile.TarInfo("docs")
                info.type = tarfile.DIRTYPE
                archive_handle.addfile(info)
                payload_info = tarfile.TarInfo("context-engine")
                payload_info.size = 2
                archive_handle.addfile(payload_info, io.BytesIO(b"ok"))
            result = self.run_shell(
                '! extract_archive "$1" context-engine "$2" "$3"',
                directory_archive,
                directory_output,
                directory_working,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(directory_output.exists())

    def test_shell_archive_rejects_payload_mode_and_duplicate_member_types(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mode_archive = root / "mode.tar.gz"
            mode_working = root / "mode-working"
            mode_working.mkdir()
            mode_output = root / "mode.payload"
            with tarfile.open(mode_archive, "w:gz") as archive_handle:
                info = tarfile.TarInfo("context-engine")
                info.mode = 0o644
                info.size = 2
                archive_handle.addfile(info, io.BytesIO(b"ok"))
            result = self.run_shell(
                '! extract_archive "$1" context-engine "$2" "$3" 0755',
                mode_archive,
                mode_output,
                mode_working,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(mode_output.exists())

            duplicate_archive = root / "duplicate.tar.gz"
            duplicate_working = root / "duplicate-working"
            duplicate_working.mkdir()
            duplicate_output = root / "duplicate.payload"
            with tarfile.open(duplicate_archive, "w:gz") as archive_handle:
                safe = tarfile.TarInfo("README.md")
                safe.mode = 0o644
                safe.size = 4
                archive_handle.addfile(safe, io.BytesIO(b"safe"))
                unsafe = tarfile.TarInfo("README.md")
                unsafe.mode = 0o777
                unsafe.type = tarfile.SYMTYPE
                unsafe.linkname = "outside"
                archive_handle.addfile(unsafe)
                unsafe_hardlink = tarfile.TarInfo("README.md")
                unsafe_hardlink.mode = 0o777
                unsafe_hardlink.type = tarfile.LNKTYPE
                unsafe_hardlink.linkname = "README.md"
                archive_handle.addfile(unsafe_hardlink)
                payload = tarfile.TarInfo("context-engine")
                payload.mode = 0o755
                payload.size = 2
                archive_handle.addfile(payload, io.BytesIO(b"ok"))
            result = self.run_shell(
                '! extract_archive "$1" context-engine "$2" "$3" 0755',
                duplicate_archive,
                duplicate_output,
                duplicate_working,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(duplicate_output.exists())

    def test_shell_extracted_payload_size_mismatch_fails_before_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "payload.tar.gz"
            working = root / "working"
            working.mkdir()
            output = root / "payload"
            self.write_tar(archive, [("context-engine", b"ok", None)])
            result = self.run_shell(
                'extract_archive "$1" context-engine "$2" "$3" && [ "$(wc -c < "$2" | tr -d "[:space:]")" = 99 ]',
                archive,
                output,
                working,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(output.exists())

    def test_shell_fresh_install_rejects_empty_destination_and_rolls_back_staging_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "install"
            root.mkdir()
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                'install_fresh "x86_64-unknown-linux-gnu" v0.2.0 0.2.0 archive.tar.gz sha 1 context-engine sha 1 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                base,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(root.iterdir()), [])

            root.rmdir()
            working = base / "working"
            working.mkdir()
            result = self.run_shell(
                'install_fresh "x86_64-unknown-linux-gnu" v0.2.0 0.2.0 archive.tar.gz sha 1 context-engine sha 1 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(root.exists())
            self.assertEqual(list(base.glob(".context-engine-install.*")), [])
            self.assertFalse(working.exists())

    def test_shell_fresh_mutation_failures_roll_back_before_and_after_promotion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for failure in ("copy", "chmod", "marker", "promotion", "entrypoint"):
                case = base / failure
                case.mkdir()
                root = case / "install"
                entrypoint = case / "bin" / "context-engine"
                working = case / "working"
                working.mkdir()
                entrypoint.parent.mkdir()
                _ = (working / "context-engine").write_bytes(b"payload")
                body = (
                    'case "$1" in\n'
                    "  copy) cp() { return 1; } ;;\n"
                    "  chmod) chmod() { return 1; } ;;\n"
                    "  marker) write_marker() { return 1; } ;;\n"
                    "  promotion) mv() { return 1; } ;;\n"
                    "  entrypoint) repair_entrypoint() { return 1; } ;;\n"
                    "esac\n"
                    "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                    'context-engine sha 7 0755 "context-engine 0.2.0" "$2" "$3" "$4"\n'
                )
                result = self.run_shell(
                    body,
                    failure,
                    working,
                    root,
                    entrypoint,
                )
                self.assertNotEqual(result.returncode, 0, failure)
                self.assertFalse(root.exists(), failure)
                self.assertEqual(
                    list(case.glob(".context-engine-install.*")), [], failure
                )
                self.assertFalse(working.exists(), failure)

    def test_shell_fresh_failure_removes_all_created_installation_ancestors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = base / "one" / "two" / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                "cp() { return 1; }; "
                + "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(root.parent.exists())
            self.assertFalse((base / "one").exists())
            self.assertFalse(working.exists())

    def test_shell_literal_glob_components_are_not_expanded_in_validation_or_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            validation = base / "validation"
            (validation / "literal*" / "literal?" / "literal[bracket]").mkdir(
                parents=True
            )
            _ = (validation / "literal!decoy").write_text("file")
            _ = (validation / "literal-star-decoy").write_text("file")
            _ = (validation / "literalQ").write_text("file")
            _ = (validation / "literalb").write_text("file")
            result = self.run_shell(
                "cd \"$1\" && safe_directory_ancestors 'literal*/literal?/literal[bracket]'",
                validation,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            cleanup = base / "cleanup"
            decoy = cleanup / "literal-star-decoy" / "literalQ" / "literalb"
            decoy.mkdir(parents=True)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = cleanup / "literal*" / "literal?" / "literal[bracket]" / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                "cp() { return 1; }; "
                + "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(root.exists())
            self.assertFalse((cleanup / "literal*").exists())
            self.assertTrue(decoy.exists())
            self.assertFalse(working.exists())

    def test_shell_fresh_failure_removes_created_entrypoint_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "sudo", '#!/bin/sh\nexec "$@"\n')
            root = base / "install"
            entrypoint = base / "created-bin" / "context-engine"
            result = self.run_shell(
                "cp() { return 1; }; "
                + "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
                environment_overrides={
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                },
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(entrypoint.parent.exists())
            self.assertFalse(working.exists())

    def test_shell_install_cleanup_failure_is_reported_after_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = base / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                "blocked_working=$1; "
                + 'rm() { case "$*" in *"$blocked_working") return 1 ;; esac; command rm "$@"; }; '
                + "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recovery failed", result.stderr)
            self.assertIn("remove working directory", result.stderr)
            self.assertTrue(root.exists())
            self.assertTrue(working.exists())

    def test_shell_install_rejects_mv_nested_stage_without_removing_race_winner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = base / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                'mv() { race_root=$3; race_stage=$2; mkdir -p "$race_root"; '
                + 'command mv "$race_stage" "$race_root/$(basename "$race_stage")"; }; '
                + "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3" fresh',
                working,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("installation directory appeared", result.stderr)
            self.assertTrue(root.is_dir())
            self.assertEqual(list(root.iterdir()), [])
            self.assertFalse(working.exists())

    def test_shell_fresh_rejects_symlinked_installation_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            real = base / "real"
            real.mkdir()
            linked = base / "linked"
            try:
                linked.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink test unavailable: {error}")
            (real / "install").mkdir()
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine").write_bytes(b"payload")
            root = linked / "install" / "context-engine"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                'install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((real / "install").exists())

    def test_shell_entrypoint_repair_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            physical = root / "install" / "context-engine"
            physical.parent.mkdir()
            _ = physical.write_text("binary", encoding="utf-8")
            entrypoint = root / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            result = self.run_shell(
                'repair_entrypoint "$1" "$2" && repair_entrypoint "$1" "$2" && [ "$(readlink "$2")" = "$1" ]',
                physical,
                entrypoint,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_entrypoint_parent_safety_and_usr_local_bin_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            parent_file = base / "parent-file"
            _ = parent_file.write_text("not-a-directory", encoding="utf-8")
            result = self.run_shell(
                '! entrypoint_parent "$1"',
                parent_file / "context-engine",
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            real_parent = base / "real-parent"
            real_parent.mkdir()
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            (real_parent / "bin").mkdir()
            result = self.run_shell(
                '! entrypoint_parent "$1"',
                linked_parent / "bin" / "context-engine",
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        system_parent = Path("/usr/local/bin")
        if not system_parent.is_dir() or system_parent.is_symlink():
            self.skipTest("/usr/local/bin is not an existing real directory")
        before = system_parent.stat()
        result = self.run_shell(
            'entrypoint_parent "$1"', system_parent / "context-engine"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        after = system_parent.stat()
        self.assertEqual((after.st_uid, after.st_mode), (before.st_uid, before.st_mode))

    def test_shell_staged_version_check_kills_and_reaps_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "slow"
            working = root / "working"
            working.mkdir()
            self.write_executable(
                binary,
                "#!/bin/sh\ntrap '' TERM INT\nwhile :; do :; done\n",
            )
            result = self.run_shell(
                '! run_version "$1" "context-engine 0.2.0" "$2"',
                binary,
                working,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_staged_version_check_rejects_extra_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "extra-output"
            working = root / "working"
            working.mkdir()
            self.write_executable(
                binary,
                "#!/bin/sh\nprintf '%s\\n\\n' 'context-engine 0.2.0'\n",
            )
            result = self.run_shell(
                '! run_version "$1" "context-engine 0.2.0" "$2"',
                binary,
                working,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_legacy_target_hashes_and_unsupported_targets_are_explicit(
        self,
    ) -> None:
        result = self.run_shell(
            'test "$(legacy_hash aarch64-apple-darwin)" = e271e9e8c14dfa759729978513148d05f11f9050e63a365338a63222c1faa144 && '
            + 'test "$(legacy_hash aarch64-unknown-linux-gnu)" = 41fc962f14a34fad23585152c2b5acd52db9569ce0474337f34d0261bf3cf84b && '
            + "! legacy_hash x86_64-unknown-linux-gnu"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_legacy_migration_rejects_wrong_hash_and_spoofed_version(
        self,
    ) -> None:
        expected_hash = (
            "e271e9e8c14dfa759729978513148d05f11f9050e63a365338a63222c1faa144"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for failure, hash_value, version, extra_line in (
                ("wrong-hash", "0" * 64, "context-engine 0.1.1", False),
                ("spoofed-version", expected_hash, "context-engine 0.2.0", False),
                ("extra-version-line", expected_hash, "context-engine 0.1.1", True),
            ):
                case = base / failure
                case.mkdir()
                root = case / "install"
                entrypoint = case / "bin" / "context-engine"
                entrypoint.parent.mkdir()
                version_script = f"#!/bin/sh\nprintf '%s\\n' '{version}'\n"
                if extra_line:
                    version_script += "printf '\\n'\n"
                self.write_executable(entrypoint, version_script)
                fake_bin = case / "fake-bin"
                fake_bin.mkdir()
                self.write_executable(
                    fake_bin / "sha256sum",
                    f"#!/bin/sh\nprintf '%s  %s\\n' '{hash_value}' \"$2\"\n",
                )
                before = entrypoint.read_bytes()
                result = self.run_shell(
                    'install_fresh aarch64-apple-darwin v0.2.0 0.2.0 archive sha 1 context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                    case / "working",
                    root,
                    entrypoint,
                    environment_overrides={
                        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    },
                )
                self.assertNotEqual(result.returncode, 0, failure)
                self.assertEqual(entrypoint.read_bytes(), before, failure)
                self.assertFalse(root.exists(), failure)
                self.assertFalse(
                    list(entrypoint.parent.glob(".context-engine-legacy-backup.*"))
                )

    def test_shell_legacy_migration_commits_and_restores_on_entrypoint_failure(
        self,
    ) -> None:
        expected_hash = (
            "e271e9e8c14dfa759729978513148d05f11f9050e63a365338a63222c1faa144"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(
                fake_bin / "sha256sum",
                f"#!/bin/sh\nprintf '%s  %s\\n' '{expected_hash}' \"$2\"\n",
            )
            for failure in (False, True):
                case = base / ("rollback" if failure else "success")
                case.mkdir()
                root = case / "install"
                entrypoint = case / "bin" / "context-engine"
                entrypoint.parent.mkdir()
                self.write_executable(
                    entrypoint,
                    "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.1.1'\n",
                )
                before = entrypoint.read_bytes()
                working = case / "working"
                working.mkdir()
                self.write_executable(
                    working / "context-engine",
                    "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.2.0'\n",
                )
                hook = "repair_entrypoint() { return 1; }; " if failure else ""
                result = self.run_shell(
                    hook
                    + "install_fresh aarch64-apple-darwin v0.2.0 0.2.0 archive sha 1 "
                    + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                    working,
                    root,
                    entrypoint,
                    environment_overrides={
                        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    },
                )
                if failure:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(entrypoint.read_bytes(), before)
                    self.assertFalse(root.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(root.is_dir())
                    self.assertTrue(entrypoint.is_symlink())
                    self.assertEqual(
                        entrypoint.resolve(), (root / "context-engine").resolve()
                    )
                self.assertFalse(
                    list(entrypoint.parent.glob(".context-engine-legacy-backup.*"))
                )

    def test_shell_legacy_post_commit_container_cleanup_failure_preserves_installation(
        self,
    ) -> None:
        expected_hash = (
            "e271e9e8c14dfa759729978513148d05f11f9050e63a365338a63222c1faa144"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(
                fake_bin / "sha256sum",
                f"#!/bin/sh\nprintf '%s  %s\\n' '{expected_hash}' \"$2\"\n",
            )
            root = base / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            self.write_executable(
                entrypoint,
                "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.1.1'\n",
            )
            working = base / "working"
            working.mkdir()
            self.write_executable(
                working / "context-engine",
                "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.2.0'\n",
            )
            result = self.run_shell(
                "remove_legacy_backup_container() { return 1; }; "
                + "install_fresh aarch64-apple-darwin v0.2.0 0.2.0 archive sha 1 "
                + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                working,
                root,
                entrypoint,
                environment_overrides={
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "post-commit cleanup failed: remove legacy backup container",
                result.stderr,
            )
            self.assertTrue((root / "context-engine").is_file())
            self.assertTrue((root / ".context-engine-installation.json").is_file())
            self.assertTrue(entrypoint.is_symlink())
            self.assertEqual(entrypoint.resolve(), (root / "context-engine").resolve())
            self.assertFalse(working.exists())
            backup_containers = list(
                entrypoint.parent.glob(".context-engine-legacy-backup.*")
            )
            self.assertEqual(len(backup_containers), 1)
            self.assertEqual(list(backup_containers[0].iterdir()), [])

    def test_shell_install_fresh_handled_signals_roll_back_before_and_after_promotion(
        self,
    ) -> None:
        for signal_name in ("HUP", "INT", "TERM"):
            for phase in ("before", "after"):
                with tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    working = base / "working"
                    working.mkdir()
                    self.write_executable(
                        working / "context-engine",
                        "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.2.0'\n",
                    )
                    root = base / "install"
                    entrypoint = base / "bin" / "context-engine"
                    entrypoint.parent.mkdir()
                    home = base / "home"
                    home.mkdir()
                    if phase == "before":
                        hook = f"cp() {{ kill -{signal_name} $$; }}; "
                    else:
                        hook = f"repair_entrypoint() {{ kill -{signal_name} $$; }}; "
                    result = self.run_shell(
                        "acquire_installer_lock; "
                        + hook
                        + "install_fresh x86_64-unknown-linux-gnu v0.2.0 0.2.0 archive sha 1 "
                        + 'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"',
                        working,
                        root,
                        entrypoint,
                        environment_overrides={"HOME": str(home)},
                    )
                    self.assertNotEqual(result.returncode, 0, f"{signal_name} {phase}")
                    self.assertFalse(root.exists(), f"{signal_name} {phase}")
                    self.assertFalse(entrypoint.exists(), f"{signal_name} {phase}")
                    self.assertFalse(working.exists(), f"{signal_name} {phase}")
                    reusable = self.run_shell(
                        "acquire_installer_lock; release_installer_lock",
                        environment_overrides={"HOME": str(home)},
                    )
                    self.assertEqual(reusable.returncode, 0, reusable.stderr)

    def test_shell_legacy_restore_failure_is_reported_and_backup_preserved(
        self,
    ) -> None:
        expected_hash = (
            "e271e9e8c14dfa759729978513148d05f11f9050e63a365338a63222c1faa144"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(
                fake_bin / "sha256sum",
                f"#!/bin/sh\nprintf '%s  %s\\n' '{expected_hash}' \"$2\"\n",
            )
            root = base / "install"
            entrypoint = base / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            self.write_executable(
                entrypoint,
                "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.1.1'\n",
            )
            working = base / "working"
            working.mkdir()
            self.write_executable(
                working / "context-engine",
                "#!/bin/sh\nprintf '%s\\n' 'context-engine 0.2.0'\n",
            )
            body = (
                "mv_count=0; "
                'mv() { mv_count=$((mv_count + 1)); if [ "$mv_count" -eq 3 ]; then return 1; fi; command mv "$@"; }; '
                "repair_entrypoint() { return 1; }; "
                "install_fresh aarch64-apple-darwin v0.2.0 0.2.0 archive sha 1 "
                'context-engine sha 7 0755 "context-engine 0.2.0" "$1" "$2" "$3"'
            )
            result = self.run_shell(
                body,
                working,
                root,
                entrypoint,
                environment_overrides={
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recovery failed", result.stderr)
            self.assertTrue(
                list(entrypoint.parent.glob(".context-engine-legacy-backup.*"))
            )

    def test_shell_marked_updater_failure_does_not_mutate_marker_or_binary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".context-engine-installation.json"
            binary = root / "context-engine"
            _ = marker.write_text(
                '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
                + '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n',
                encoding="utf-8",
            )
            self.write_executable(binary, "#!/bin/sh\nexit 7\n")
            entrypoint = root / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            entrypoint.symlink_to(binary)
            marker_before = marker.read_bytes()
            binary_before = binary.read_bytes()
            result = self.run_shell('marked_reinstall "$1" "$2"', root, entrypoint)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_bytes(), marker_before)
            self.assertEqual(binary.read_bytes(), binary_before)
            self.assertTrue(entrypoint.is_symlink())
            self.assertEqual(entrypoint.readlink(), binary)

    def test_shell_marked_reinstall_accepts_numeric_schema_and_invokes_updater_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".context-engine-installation.json"
            binary = root / "context-engine"
            log = root / "updates.log"
            _ = marker.write_text(
                '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
                + '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n',
                encoding="utf-8",
            )
            self.write_executable(
                binary,
                f"#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{log}'\n",
            )
            entrypoint = root / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            entrypoint.symlink_to(binary)
            result = self.run_shell('marked_reinstall "$1" "$2"', root, entrypoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8"), "update\n")

    def test_shell_marked_reinstall_preflights_entrypoint_parent_before_updater(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".context-engine-installation.json"
            binary = root / "context-engine"
            log = root / "updates.log"
            _ = marker.write_text(
                '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
                + '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n',
                encoding="utf-8",
            )
            self.write_executable(
                binary,
                f"#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{log}'\n",
            )
            _ = (root / "missing-bin").write_text("not a directory", encoding="utf-8")
            entrypoint = root / "missing-bin" / "context-engine"
            result = self.run_shell('! marked_reinstall "$1" "$2"', root, entrypoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(log.exists())

    def test_shell_manifest_executable_mode_mismatch_is_rejected(self) -> None:
        result = self.run_shell(
            "validate_payload_mode 0755 && ! validate_payload_mode 0644"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_exact_size_parser_rejects_noncanonical_values(self) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            "$ok = Get-ExactInt64 -Value '9007199254740993' -Name size; "
            "if ($ok -ne 9007199254740993) { exit 1 }; "
            "try { Get-ExactInt64 -Value '9223372036854775808' -Name size; exit 1 } "
            "catch { exit 0 }"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_manifest_binds_production_mode_and_version(self) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; "
            "$selected = Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; "
            "if ($selected.ArchiveSize -ne 12348 -or $selected.PayloadSize -ne 10004) { exit 1 }; "
            "$manifest.artifacts = @($manifest.artifacts | Where-Object { $_.target -eq 'x86_64-pc-windows-msvc' }); "
            "$manifest.payloads = @($manifest.payloads | Where-Object { $_.target -eq 'x86_64-pc-windows-msvc' }); "
            "$selected = Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; "
            "if ($selected.ArchiveSize -ne 12348 -or $selected.PayloadSize -ne 10004) { exit 1 }"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_manifest_rejects_non_string_identity_and_selected_fields(
        self,
    ) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; "
            "$manifest.distribution_repository = 42; "
            "try { Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 } catch { }; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; "
            "$archive = @($manifest.artifacts | Where-Object { $_.target -eq 'x86_64-pc-windows-msvc' })[0]; $archive.filename = 42; "
            "try { Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 } catch { }; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; "
            "$payload = @($manifest.payloads | Where-Object { $_.target -eq 'x86_64-pc-windows-msvc' })[0]; $payload.size = 10004; "
            "try { Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 } catch { }"
            f"; $manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; $windowsArchive = @($manifest.artifacts | Where-Object {{ $_.target -eq 'x86_64-pc-windows-msvc' }})[0]; $windowsPayload = @($manifest.payloads | Where-Object {{ $_.target -eq 'x86_64-pc-windows-msvc' }})[0]; $manifest.artifacts = @($windowsArchive); $manifest.payloads = @($windowsPayload); "
            "$selected = Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; if ($selected.ArchiveSize -ne 12348 -or $selected.PayloadSize -ne 10004) { exit 1 }; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; $windowsArchive = @($manifest.artifacts | Where-Object {{ $_.target -eq 'x86_64-pc-windows-msvc' }})[0]; $manifest.artifacts = $windowsArchive; try {{ Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 }} catch {{ }}; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; $windowsPayload = @($manifest.payloads | Where-Object {{ $_.target -eq 'x86_64-pc-windows-msvc' }})[0]; $manifest.payloads = $windowsPayload; try {{ Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 }} catch {{ }}; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; $manifest.artifacts = @(); try {{ Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 }} catch {{ }}; "
            f"$manifest = Get-Content -LiteralPath '{FIXTURE}' -Raw | ConvertFrom-Json; $manifest.payloads = @(); try {{ Get-SelectedManifest -Manifest $manifest -Target 'x86_64-pc-windows-msvc' -Tag 'v0.2.0' -Version '0.2.0'; exit 1 }} catch {{ exit 0 }}"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_checksum_parser_rejects_malformed_duplicate_records(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SHA256SUMS"
            filename = "context-engine-x86_64-pc-windows-msvc.zip"
            _ = path.write_text(
                "a" * 64 + f"  {filename}\nnot-a-sha  {filename}\n",
                encoding="utf-8",
            )
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; $caught=$false; "
                f"try {{ Get-Checksum -Path {self.ps_literal(path)} -Filename '{filename}'; exit 1 }} catch {{ $caught=$true }}; if (-not $caught) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)
            _ = path.write_text("a" * 64 + f"  {filename} extra\n", encoding="utf-8")
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; $caught=$false; "
                f"try {{ Get-Checksum -Path {self.ps_literal(path)} -Filename '{filename}'; exit 1 }} catch {{ $caught=$true }}; if (-not $caught) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_archive_overflow_and_payload_mismatch_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "payload.zip"
            destination = root / "payload.exe"
            download = root / "download.zip"
            unsafe_archive = root / "unsafe.zip"
            reparse_archive = root / "reparse.zip"
            drive_archive = root / "drive.zip"
            self.write_zip_entries(
                archive,
                [
                    ("context-engine.exe", b"payload"),
                    ("README.md", b"readme"),
                    ("LICENSE", b"license"),
                    ("docs/usage.txt", b"docs"),
                ],
            )
            self.write_zip_symlink(unsafe_archive, "evil", "target")
            reparse_info = zipfile.ZipInfo("README.md")
            reparse_info.external_attr = 0x400
            with zipfile.ZipFile(reparse_archive, "w") as archive_handle:
                archive_handle.writestr(reparse_info, b"reparse")
            self.write_zip_entries(
                drive_archive,
                [
                    ("context-engine.exe", b"payload"),
                    ("C:/escape", b"escape"),
                    ("C:escape", b"drive-relative"),
                ],
            )
            archive_literal = self.ps_literal(archive)
            destination_literal = self.ps_literal(destination)
            download_literal = self.ps_literal(download)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "Add-Type -AssemblyName System.Net.Http; "
                "$response = New-Object System.Net.Http.HttpResponseMessage; "
                "$response.Content = [System.Net.Http.ByteArrayContent]::new([byte[]](1,2,3,4)); "
                "$http = @{ Response = $response }; "
                f"try {{ Read-ResponseFile -Http $http -Destination {download_literal} -ExpectedSize 4 -MaximumSize 3; exit 1 }} catch {{ }}; "
                f"try {{ Read-ZipPayload -ArchivePath {archive_literal} -PayloadName 'context-engine.exe' -Destination {destination_literal} -ExpectedSize 8; exit 1 }} catch {{ }}; "
                f"try {{ Read-ZipPayload -ArchivePath {self.ps_literal(unsafe_archive)} -PayloadName 'context-engine.exe' -Destination {self.ps_literal(root / 'unsafe.exe')} -ExpectedSize 7; exit 1 }} catch {{ }}"
                f"; try {{ Read-ZipPayload -ArchivePath {self.ps_literal(reparse_archive)} -PayloadName 'context-engine.exe' -Destination {self.ps_literal(root / 'reparse.exe')} -ExpectedSize 7; exit 1 }} catch {{ }}"
                f"; try {{ Read-ZipPayload -ArchivePath {self.ps_literal(drive_archive)} -PayloadName 'context-engine.exe' -Destination {self.ps_literal(root / 'drive.exe')} -ExpectedSize 7; exit 1 }} catch {{ exit 0 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_minimum_release_rejects_before_working_or_path_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "install-root"
            temp_root = base / "temp"
            temp_root.mkdir()
            path_marker = base / "path-mutated"
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                f"$env:TEMP={self.ps_literal(temp_root)}; $env:TMP={self.ps_literal(temp_root)}; "
                ". ./install.ps1; "
                f"function global:Get-InstallRoot {{ return {self.ps_literal(root)} }}; "
                "function global:Get-HttpClient { return $null }; "
                "function global:Get-LatestTag { return 'v0.1.1' }; "
                "function global:Get-UpdatedUserPath { param($Directory, $PreviousPath); return $PreviousPath }; "
                f"function global:Set-UserEnvironmentPath {{ Set-Content -LiteralPath {self.ps_literal(path_marker)} -Value mutated }}; "
                "try { Invoke-Installer; exit 1 } catch { if ($_.Exception.Message -notlike '*older than*') { exit 1 } }; "
                f"if (Test-Path -LiteralPath {self.ps_literal(root)}) {{ exit 1 }}; "
                f"if (Test-Path -LiteralPath {self.ps_literal(path_marker)}) {{ exit 1 }}; "
                f"if (@(Get-ChildItem -LiteralPath {self.ps_literal(temp_root)} -Force).Count -ne 0) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_zip_payload_mode_requires_production_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad_mode_archive = root / "bad-mode.zip"
            good_mode_archive = root / "good-mode.zip"
            for path, mode in (
                (bad_mode_archive, 0o100644),
                (good_mode_archive, 0o100755),
            ):
                info = zipfile.ZipInfo("context-engine.exe")
                info.create_system = 3
                info.external_attr = mode << 16
                with zipfile.ZipFile(path, "w") as archive_handle:
                    archive_handle.writestr(info, b"payload")
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "$caught=$false; "
                f"try {{ Read-ZipPayload -ArchivePath {self.ps_literal(bad_mode_archive)} -PayloadName 'context-engine.exe' -Destination {self.ps_literal(root / 'bad.exe')} -ExpectedSize 7 }} catch {{ $caught=$true }}; "
                "if (-not $caught) { exit 1 }; "
                f"Read-ZipPayload -ArchivePath {self.ps_literal(good_mode_archive)} -PayloadName 'context-engine.exe' -Destination {self.ps_literal(root / 'good.exe')} -ExpectedSize 7; "
                f"if (-not (Test-Path -LiteralPath {self.ps_literal(root / 'good.exe')})) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_staged_version_timeout_kills_and_reaps_process(self) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            "$script:Killed = $false; $script:Reaped = $false; $script:Disposed = $false; "
            "$output = [pscustomobject]@{}; $output | Add-Member ScriptMethod ReadToEndAsync { return [Threading.Tasks.Task[string]]::FromResult('') }; "
            "$fake = [pscustomobject]@{ StartInfo = $null; ExitCode = 0; StandardOutput = $output; StandardError = $output }; "
            "$fake | Add-Member ScriptMethod Start { return $true }; "
            "$fake | Add-Member ScriptMethod WaitForExit { param($Milliseconds); if ($null -ne $Milliseconds) { return $false }; $script:Reaped = $true; return $true }; "
            "$fake | Add-Member ScriptMethod Kill { $script:Killed = $true }; "
            "$fake | Add-Member ScriptMethod Dispose { $script:Disposed = $true }; "
            "function global:New-Object { param([string]$TypeName); if ($TypeName -eq 'System.Diagnostics.Process') { return $fake }; return Microsoft.PowerShell.Utility\\New-Object -TypeName $TypeName }; "
            "try { Invoke-VersionCheck -Binary 'ignored' -Expected 'context-engine 0.2.0'; exit 1 } catch { if (-not $script:Killed -or -not $script:Reaped -or -not $script:Disposed) { exit 1 } }; exit 0"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_staged_version_check_rejects_extra_output(self) -> None:
        command = r"""
$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1
$script:Output = ''; $output = [pscustomobject]@{}
$output | Add-Member ScriptMethod ReadToEndAsync { return [Threading.Tasks.Task[string]]::FromResult($script:Output) }
$fake = [pscustomobject]@{ StartInfo = $null; ExitCode = 0; StandardOutput = $output; StandardError = $output }
$fake | Add-Member ScriptMethod Start { return $true }
$fake | Add-Member ScriptMethod WaitForExit { param($Milliseconds); return $true }
function global:New-Object { param([string]$TypeName); if ($TypeName -eq 'System.Diagnostics.Process') { return $fake }; return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName }
foreach ($value in @("context-engine 0.2.0`n`n", " context-engine 0.2.0`n", "context-engine 0.2.0`t`n")) {
    $script:Output = $value; $caught = $false
    try { Invoke-VersionCheck -Binary 'ignored' -Expected 'context-engine 0.2.0' } catch { $caught = $true }
    if (-not $caught) { exit 1 }
}
exit 0
"""
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_fresh_install_rejects_empty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Context Engine"
            root.mkdir()
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                ". ./install.ps1; "
                f"try {{ Invoke-FreshInstall -Selected @{{}} -Version '0.2.0' -Working '.' -Root {root_literal}; exit 1 }} "
                f"catch {{ if (-not (Test-Path -LiteralPath {root_literal})) {{ exit 1 }} }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_fresh_transaction_rolls_back_before_and_after_promotion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine.exe").write_bytes(b"payload")
            for failure in ("before", "after"):
                root = base / failure / "Context Engine"
                root.parent.mkdir()
                root_literal = self.ps_literal(root)
                working_literal = self.ps_literal(working)
                if failure == "before":
                    hook = "function global:Copy-Item { throw 'before promotion' }; "
                    post_assertion = ""
                else:
                    hook = (
                        "$script:setPathCalls=0; $script:setPathValues=@(); "
                        "function global:Set-UserEnvironmentPath { param($Value); $script:setPathCalls++; $script:setPathValues += [string]$Value; "
                        "if ($script:setPathCalls -eq 1) { throw 'after promotion' }; "
                        "[Environment]::SetEnvironmentVariable('PATH', $Value, 'User') }; "
                    )
                    post_assertion = "if ($script:setPathCalls -ne 2 -or -not [string]::Equals($script:setPathValues[1], [string]$before, [StringComparison]::Ordinal)) { exit 1 }; "
                command = (
                    "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                    ". ./install.ps1; "
                    "$runningOnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT; "
                    "$before = [Environment]::GetEnvironmentVariable('PATH', 'User'); "
                    "try { if ($runningOnWindows) { [Environment]::SetEnvironmentVariable('PATH', 'context-engine-test-path', 'User') }; "
                    f"{hook}"
                    "try { Invoke-FreshInstall -Selected @{} -Version '0.2.0' -Working "
                    f"{working_literal} -Root {root_literal}; exit 1 }} catch {{ }}; "
                    f"if (Test-Path -LiteralPath {root_literal}) {{ throw 'installation root survived rollback' }}; "
                    f"{post_assertion}"
                    "if ($runningOnWindows -and [Environment]::GetEnvironmentVariable('PATH', 'User') -ne 'context-engine-test-path') { throw 'user PATH was not restored' }; "
                    "} finally { if ($runningOnWindows) { [Environment]::SetEnvironmentVariable('PATH', $before, 'User') } }"
                )
                result = self.run_pwsh(command)
                self.assertEqual(
                    result.returncode,
                    0,
                    f"{failure}: stdout={result.stdout!r} stderr={result.stderr!r}",
                )

    def test_power_shell_fresh_install_preflights_user_path_before_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine.exe").write_bytes(b"payload")
            root = base / "missing-parent" / "Context Engine"
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "function global:Get-UpdatedUserPath { param($Directory, $PreviousPath); return ($PreviousPath + ';' + $Directory) }; "
                "function global:Test-UserEnvironmentWritable { return $false }; "
                f"try {{ Invoke-FreshInstall -Selected @{{}} -Version '0.2.0' -Working {self.ps_literal(working)} -Root {root_literal}; exit 1 }} catch {{ if ($_.Exception.Message -notlike '*not writable*') {{ exit 1 }} }}; "
                f"if (Test-Path -LiteralPath {root_literal}) {{ exit 1 }}; if (Test-Path -LiteralPath {self.ps_literal(root.parent)}) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_fresh_transaction_removes_created_parent_and_surfaces_recovery_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            working = base / "working"
            working.mkdir()
            _ = (working / "context-engine.exe").write_bytes(b"payload")
            root = base / "created-one" / "created-two" / "Context Engine"
            root_literal = self.ps_literal(root)
            working_literal = self.ps_literal(working)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "function global:Copy-Item { throw 'primary failure' }; "
                f"try {{ Invoke-FreshInstall -Selected @{{}} -Version '0.2.0' -Working {working_literal} -Root {root_literal}; exit 1 }} "
                "catch { if ($_.Exception.Message -notlike '*primary failure*') { exit 1 } }; "
                f"if (Test-Path -LiteralPath {self.ps_literal(root.parent)}) {{ exit 1 }}; "
                f"if (Test-Path -LiteralPath {self.ps_literal(root.parent.parent)}) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

            root = base / "cleanup-failure" / "Context Engine"
            root.parent.mkdir()
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "function global:Copy-Item { throw 'primary failure' }; "
                "function global:Remove-Item { throw 'cleanup failure' }; "
                f"try {{ Invoke-FreshInstall -Selected @{{}} -Version '0.2.0' -Working {working_literal} -Root {root_literal}; exit 1 }} "
                "catch { $message = $_.Exception.Message; if ($message -notlike '*recovery failed*') { exit 1 } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_fresh_install_rejects_reparse_final_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            root = base / "Context Engine"
            try:
                self.write_directory_reparse(root, target)
            except (OSError, NotImplementedError) as error:
                if os.name == "nt":
                    self.fail(f"Windows reparse fixture unavailable: {error}")
                self.skipTest(f"symlink test unavailable: {error}")
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                f"try {{ Invoke-FreshInstall -Selected @{{}} -Version '0.2.0' -Working '.' -Root {self.ps_literal(root)}; exit 1 }} "
                "catch { $message = $_.Exception.Message; if ($message -notlike '*reparse*') { exit 1 } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_fresh_install_rejects_reparse_above_existing_descendant(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            (target / "existing").mkdir(parents=True)
            linked = base / "linked"
            try:
                self.write_directory_reparse(linked, target)
            except (OSError, NotImplementedError) as error:
                if os.name == "nt":
                    self.fail(f"Windows reparse fixture unavailable: {error}")
                self.skipTest(f"symlink test unavailable: {error}")
            root = linked / "existing" / "missing" / "Context Engine"
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                f"try {{ Invoke-FreshInstall -Selected @{{}} -Version '0.2.0' -Working '.' -Root {self.ps_literal(root)}; exit 1 }} "
                "catch { $message = $_.Exception.Message; if ($message -notlike '*unsafe*') { exit 1 } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_installer_classifies_existing_destination_before_network(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for kind in ("file", "reparse"):
                local_app_data = base / kind
                local_app_data.mkdir()
                root = local_app_data / "Context Engine"
                if kind == "file":
                    _ = root.write_text("conflict", encoding="utf-8")
                else:
                    try:
                        target = local_app_data / "reparse-target"
                        target.mkdir()
                        self.write_directory_reparse(root, target)
                    except (OSError, NotImplementedError) as error:
                        if os.name == "nt":
                            self.fail(f"Windows reparse fixture unavailable: {error}")
                        self.skipTest(f"symlink test unavailable: {error}")
                command = (
                    "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                    f"$env:LOCALAPPDATA = {self.ps_literal(local_app_data)}; "
                    ". ./install.ps1; "
                    "function global:Get-HttpClient { throw 'network must not run' }; "
                    "try { Invoke-Installer; exit 1 } catch { $message = $_.Exception.Message; if ($message -notlike '*unsafe*') { exit 1 } }"
                )
                result = self.run_pwsh(command)
                self.assertEqual(result.returncode, 0, f"{kind}: {result.stderr}")

    def test_power_shell_installer_rejects_unsafe_missing_root_ancestor_before_network(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            local_app_data = base / "local"
            local_app_data.mkdir()
            unsafe_parent = local_app_data / "unsafe-parent"
            _ = unsafe_parent.write_text("not a directory", encoding="utf-8")
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                f"$env:LOCALAPPDATA = {self.ps_literal(local_app_data)}; "
                ". ./install.ps1; "
                f"function global:Get-InstallRoot {{ return {self.ps_literal(unsafe_parent / 'Context Engine')} }}; "
                "function global:Get-HttpClient { throw 'network must not run' }; "
                "try { Invoke-Installer; exit 1 } catch { $message = $_.Exception.Message; if ($message -notlike '*unsafe*') { exit 1 } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_installer_reports_working_cleanup_failure_with_primary_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            local_app_data = Path(directory) / "local"
            local_app_data.mkdir()
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                f"$env:LOCALAPPDATA = {self.ps_literal(local_app_data)}; . ./install.ps1; "
                "function global:Get-HttpClient { return $null }; "
                "function global:Get-LatestTag { return 'v0.2.0' }; "
                "function global:Save-RemoteFile { throw 'primary network failure' }; "
                "function global:Remove-Item { throw 'working cleanup failure' }; "
                "try { Invoke-Installer; exit 1 } catch { $message = $_.Exception.Message; if ($message -notlike '*primary network failure*' -or $message -notlike '*cleanup failed*') { exit 1 } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marked_lock_failure_preserves_state_and_user_path(
        self,
    ) -> None:
        marker_text = (
            '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
            '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".context-engine-installation.json"
            binary = root / "context-engine.exe"
            _ = marker.write_text(marker_text, encoding="utf-8")
            self.write_executable(binary, "not-a-real-binary")
            marker_before = marker.read_bytes()
            binary_before = binary.read_bytes()
            marker_hash = hashlib.sha256(marker_before).hexdigest()
            binary_hash = hashlib.sha256(binary_before).hexdigest()
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "$runningOnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT; "
                "$before = [Environment]::GetEnvironmentVariable('PATH', 'User'); "
                "try { if ($runningOnWindows) { [Environment]::SetEnvironmentVariable('PATH', 'context-engine-lock-path', 'User') }; "
                "function global:Start-Process { return [pscustomobject]@{ ExitCode = 7 } }; "
                f"try {{ Invoke-MarkedReinstall -Root {root_literal}; exit 1 }} catch {{ }}; "
                f"if ((Get-Sha256 -Path {self.ps_literal(marker)}) -ne '{marker_hash}') {{ exit 1 }}; "
                f"if ((Get-Sha256 -Path {self.ps_literal(binary)}) -ne '{binary_hash}') {{ exit 1 }}; "
                "if ($runningOnWindows -and [Environment]::GetEnvironmentVariable('PATH', 'User') -ne 'context-engine-lock-path') { exit 1 }; "
                "} finally { if ($runningOnWindows) { [Environment]::SetEnvironmentVariable('PATH', $before, 'User') } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marked_backup_delegation_and_conflicts(self) -> None:
        marker_text = (
            '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
            '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "backup-install"
            root.mkdir()
            _ = (root / ".context-engine-installation.json").write_text(
                marker_text, encoding="utf-8"
            )
            backup = root / ".context-engine.previous.exe"
            self.write_executable(backup, "not-a-real-binary")
            log = base / "delegation.log"
            root_literal = self.ps_literal(root)
            log_literal = self.ps_literal(log)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "function global:Start-Process { param([string]$FilePath,[object]$ArgumentList,[switch]$Wait,[switch]$PassThru,[switch]$NoNewWindow); "
                f"[IO.File]::WriteAllText({log_literal}, $FilePath + '|' + $ArgumentList); "
                "return [pscustomobject]@{ ExitCode = 0 } }; "
                f"$result = Invoke-MarkedReinstall -Root {root_literal}; "
                f"if (-not $result -or (Get-Content -LiteralPath {log_literal} -Raw) -notlike '*previous.exe|update*') {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

            unsafe_root = base / "unsafe-canonical"
            unsafe_root.mkdir()
            _ = (unsafe_root / ".context-engine-installation.json").write_text(
                marker_text, encoding="utf-8"
            )
            (unsafe_root / "context-engine.exe").mkdir()
            self.write_executable(
                unsafe_root / ".context-engine.previous.exe", "backup"
            )
            unsafe_literal = self.ps_literal(unsafe_root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                f"if (Invoke-MarkedReinstall -Root {unsafe_literal}) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

            for name, backup_kind in (
                ("missing-backup", "missing"),
                ("unsafe-backup", "directory"),
            ):
                conflict_root = base / name
                conflict_root.mkdir()
                _ = (conflict_root / ".context-engine-installation.json").write_text(
                    marker_text, encoding="utf-8"
                )
                if backup_kind == "directory":
                    (conflict_root / ".context-engine.previous.exe").mkdir()
                conflict_literal = self.ps_literal(conflict_root)
                command = (
                    "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                    f"if (Invoke-MarkedReinstall -Root {conflict_literal}) {{ exit 1 }}"
                )
                result = self.run_pwsh(command)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marked_reinstall_rejects_canonical_reparse(
        self,
    ) -> None:
        marker_text = (
            '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
            '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "canonical-reparse"
            root.mkdir()
            _ = (root / ".context-engine-installation.json").write_text(
                marker_text, encoding="utf-8"
            )
            self.write_executable(root / ".context-engine.previous.exe", "backup")
            try:
                target = root.parent / "canonical-target"
                target.mkdir()
                self.write_directory_reparse(root / "context-engine.exe", target)
            except (OSError, NotImplementedError) as error:
                if os.name == "nt":
                    self.fail(f"Windows reparse fixture unavailable: {error}")
                self.skipTest(f"symlink test unavailable: {error}")
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                f"if (Invoke-MarkedReinstall -Root {root_literal}) {{ exit 1 }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marked_reinstall_rejects_reparse_ancestor_before_updater(
        self,
    ) -> None:
        marker_text = (
            '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
            '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            (target / "existing").mkdir(parents=True)
            linked = base / "linked"
            try:
                self.write_directory_reparse(linked, target)
            except (OSError, NotImplementedError) as error:
                if os.name == "nt":
                    self.fail(f"Windows reparse fixture unavailable: {error}")
                self.skipTest(f"symlink test unavailable: {error}")
            root = linked / "existing" / "Context Engine"
            root.mkdir()
            _ = (root / ".context-engine-installation.json").write_text(
                marker_text, encoding="utf-8"
            )
            self.write_executable(root / "context-engine.exe", "updater")
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; "
                ". ./install.ps1; "
                f"function global:Get-InstallRoot {{ return {root_literal} }}; "
                "function global:Get-HttpClient { throw 'network must not run' }; "
                "function global:Start-Process { throw 'updater must not run' }; "
                "try { Invoke-Installer; exit 1 } catch { $message = $_.Exception.Message; if ($message -notlike '*unsafe*') { exit 1 } }"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_workflow_locks_both_shells_and_manual_dispatch(self) -> None:
        workflow = (ROOT / ".github/workflows/release-contract.yml").read_text(
            encoding="utf-8"
        )
        for required in (
            "workflow_dispatch:",
            "unix-installers:",
            "windows-installers:",
            "os: [ubuntu-24.04, macos-15]",
            "shellcheck-v0.11.0.darwin.aarch64.tar.xz",
            "shell: powershell",
            "shell: pwsh",
            "PowerShell-7.6.4-win-x64.zip",
            "80832551C52809301E6071C8BAC977BEB5A2F1EC953EB4DB9F94DEB953333793",
            "uv pip install --python .venv/bin/python --requirement scripts/requirements-dev.txt",
            "uv pip install --python ./.venv/Scripts/python.exe --requirement scripts/requirements-dev.txt",
            '"$env:GITHUB_PATH"',
            "Get-Command pwsh",
            "CONTEXT_ENGINE_TEST_POWERSHELL: powershell.exe",
            "CONTEXT_ENGINE_TEST_POWERSHELL: pwsh.exe",
            "CONTEXT_ENGINE_TEST_SHELL: sh.exe",
            "finally {",
            "Run installer fixtures with inbox Windows PowerShell 5.1",
            "Run installer fixtures with pinned PowerShell 7.6.4",
            "-m unittest scripts.tests.test_installers -k power_shell -v",
            "go install mvdan.cc/sh/v3/cmd/shfmt@v3.8.0",
            "shellcheck install.sh",
        ):
            self.assertIn(required, workflow)
        self.assertEqual(
            workflow.count(
                "-m unittest scripts.tests.test_installers -k power_shell -v"
            ),
            2,
        )
        self.assertNotIn("macos-14", workflow)
        self.assertNotIn("shellcheck --severity=warning", workflow)

    def test_shell_parser_rejects_duplicate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            malformed = Path(directory) / "manifest.json"
            fixture_text = FIXTURE.read_text(encoding="utf-8")
            duplicate_text = fixture_text.replace(
                '  "version": "0.2.0"\n',
                '  "version": "0.2.0",\n  "version": "0.2.0"\n',
                1,
            )
            _ = malformed.write_text(duplicate_text, encoding="utf-8")
            result = self.run_shell(
                '! parse_manifest "$1" x86_64-unknown-linux-gnu',
                str(malformed),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            reordered = Path(directory) / "reordered.json"
            reordered_text = fixture_text.replace('  "tag": "v0.2.0",\n', "", 1)
            reordered_text = reordered_text.replace(
                '  "distribution_repository": "context-engine-app/context-engine-mcp",\n',
                '  "tag": "v0.2.0",\n  "distribution_repository": "context-engine-app/context-engine-mcp",\n',
                1,
            )
            _ = reordered.write_text(reordered_text, encoding="utf-8")
            result = self.run_shell(
                '! parse_manifest "$1" x86_64-unknown-linux-gnu',
                str(reordered),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            empty_duplicate = Path(directory) / "empty-duplicate.json"
            empty_duplicate_text = fixture_text.replace(
                '  "distribution_repository": "context-engine-app/context-engine-mcp",\n',
                '  "distribution_repository": "",\n  "distribution_repository": "context-engine-app/context-engine-mcp",\n',
                1,
            )
            _ = empty_duplicate.write_text(empty_duplicate_text, encoding="utf-8")
            result = self.run_shell(
                '! parse_manifest "$1" x86_64-unknown-linux-gnu',
                str(empty_duplicate),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            reordered_object = Path(directory) / "reordered-object.json"
            reordered_object_text = fixture_text.replace(
                '      "filename": "context-engine-x86_64-unknown-linux-gnu.tar.gz",\n      "kind": "archive",',
                '      "kind": "archive",\n      "filename": "context-engine-x86_64-unknown-linux-gnu.tar.gz",',
                1,
            )
            _ = reordered_object.write_text(reordered_object_text, encoding="utf-8")
            result = self.run_shell(
                '! parse_manifest "$1" x86_64-unknown-linux-gnu',
                str(reordered_object),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_manifest_parser_rejects_unquoted_scalars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for needle, replacement in (
                ('  "size": "12345"', '  "size": 12345'),
                (
                    '  "target": "aarch64-apple-darwin"',
                    '  "target": aarch64-apple-darwin',
                ),
            ):
                malformed = Path(directory) / "manifest.json"
                text = FIXTURE.read_text(encoding="utf-8").replace(
                    needle, replacement, 1
                )
                _ = malformed.write_text(text, encoding="utf-8")
                result = self.run_shell(
                    '! parse_manifest "$1" aarch64-apple-darwin', malformed
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_checksum_parser_rejects_duplicate_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checksums = Path(directory) / "SHA256SUMS"
            _ = checksums.write_text(
                "a" * 64
                + "  context-engine-x86_64-unknown-linux-gnu.tar.gz\n"
                + "a" * 64
                + "  context-engine-x86_64-unknown-linux-gnu.tar.gz\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                '! parse_checksum "$1" context-engine-x86_64-unknown-linux-gnu.tar.gz',
                str(checksums),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            _ = checksums.write_text(
                "a" * 64
                + "  context-engine-x86_64-unknown-linux-gnu.tar.gz\n"
                + "not-a-sha  context-engine-x86_64-unknown-linux-gnu.tar.gz\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                '! parse_checksum "$1" context-engine-x86_64-unknown-linux-gnu.tar.gz',
                str(checksums),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            _ = checksums.write_text(
                "a" * 64 + "  context-engine-x86_64-unknown-linux-gnu.tar.gz extra\n",
                encoding="utf-8",
            )
            result = self.run_shell(
                '! parse_checksum "$1" context-engine-x86_64-unknown-linux-gnu.tar.gz',
                str(checksums),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_marker_is_exact_and_unknown_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker.json"
            result = self.run_shell(
                'write_marker "$1"; marked_reinstall "$2" "$3"',
                marker,
                directory,
                marker,
            )
            self.assertNotEqual(result.returncode, 0)
            _ = marker.write_text(
                '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
                + '  "distribution_repository": "context-engine-app/context-engine-mcp",\n'
                + '  "extra": true\n}\n',
                encoding="utf-8",
            )
            result = self.run_shell('! marked_reinstall "$1" "$2"', directory, marker)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_marker_rejects_junk_and_noncanonical_field_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / ".context-engine-installation.json"
            binary = root / "context-engine"
            self.write_executable(binary, "#!/bin/sh\nexit 0\n")
            entrypoint = root / "bin" / "context-engine"
            entrypoint.parent.mkdir()
            entrypoint.symlink_to(binary)
            invalid_markers = (
                b'junk\n{\n  "schema_version": 1,\n  "installation_method": "direct",\n  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n',
                b'{\n  "installation_method": "direct",\n  "schema_version": 1,\n  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n',
                b'{\n  "schema_version": "1",\n  "installation_method": "direct",\n  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n',
            )
            for invalid in invalid_markers:
                _ = marker.write_bytes(invalid)
                result = self.run_shell(
                    '! marked_reinstall "$1" "$2"', root, entrypoint
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marker_rejects_string_and_float_schema_versions(self) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            "$path = [IO.Path]::GetTempFileName(); "
            "try { "
            '[IO.File]::WriteAllText($path, \'{"schema_version":"1","installation_method":"direct","distribution_repository":"context-engine-app/context-engine-mcp"}\'); '
            "if (Test-Marker $path) { exit 1 }; "
            '[IO.File]::WriteAllText($path, \'{"schema_version":1.0,"installation_method":"direct","distribution_repository":"context-engine-app/context-engine-mcp"}\'); '
            "if (Test-Marker $path) { exit 1 }; "
            '[IO.File]::WriteAllText($path, \'{"schema_version":1,"Schema_Version":1,"installation_method":"direct","distribution_repository":"context-engine-app/context-engine-mcp"}\'); '
            "if (Test-Marker $path) { exit 1 } "
            "} finally { Remove-Item -LiteralPath $path -Force }"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marker_writer_is_bom_free_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "marker.json"
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                f"Write-Marker {self.ps_literal(path)}; "
                f"if (-not (Test-Marker {self.ps_literal(path)})) {{ exit 1 }}; "
                f"$canonical = [IO.File]::ReadAllBytes({self.ps_literal(path)}); "
                f"$bom = [byte[]](0xEF,0xBB,0xBF) + [IO.File]::ReadAllBytes({self.ps_literal(path)}); "
                f"[IO.File]::WriteAllBytes({self.ps_literal(path)}, $bom); "
                f"if (Test-Marker {self.ps_literal(path)}) {{ exit 1 }}; "
                f'[IO.File]::WriteAllText({self.ps_literal(path)}, \'{{"schema_version":1,"schema_version":1,"installation_method":"direct","distribution_repository":"context-engine-app/context-engine-mcp"}}\'); '
                f"if (Test-Marker {self.ps_literal(path)}) {{ exit 1 }}; "
                f'[IO.File]::WriteAllText({self.ps_literal(path)}, \'{{"schema_version":1,"installation_method":"direct","distribution_repository":"context-engine-app/context-engine-mcp","schema_version":1}}\'); '
                f"if (Test-Marker {self.ps_literal(path)}) {{ exit 1 }}; "
                f"[IO.File]::WriteAllBytes({self.ps_literal(path)}, $canonical)"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)
            newline = "\r\n" if os.name == "nt" else "\n"
            expected = (
                "{\n"
                '  "schema_version": 1,\n'
                '  "installation_method": "direct",\n'
                '  "distribution_repository": "context-engine-app/context-engine-mcp"\n'
                "}\n"
            ).replace("\n", newline)
            self.assertEqual(path.read_bytes(), expected.encode("utf-8"))

    def test_power_shell_user_path_idempotence_normalizes_trailing_separator_and_case(
        self,
    ) -> None:
        command = (
            "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
            "$directory='C:\\Users\\Example\\Context Engine'; "
            "$previous='C:\\Windows\\System32;C:\\USERS\\EXAMPLE\\Context Engine\\'; "
            "$result=Get-UpdatedUserPath -Directory $directory -PreviousPath $previous; "
            "if (-not [string]::Equals($result, $previous, [StringComparison]::Ordinal)) { exit 1 }; "
            "$added=Get-UpdatedUserPath -Directory $directory -PreviousPath 'C:\\Windows\\System32'; "
            "if (-not [string]::Equals($added, ($previous.Split(';')[0] + ';' + $directory), [StringComparison]::Ordinal)) { exit 1 }"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_marked_reinstall_preflights_path_repair_before_updater(
        self,
    ) -> None:
        marker_text = (
            '{\n  "schema_version": 1,\n  "installation_method": "direct",\n'
            '  "distribution_repository": "context-engine-app/context-engine-mcp"\n}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _ = (root / ".context-engine-installation.json").write_text(
                marker_text, encoding="utf-8"
            )
            self.write_executable(root / "context-engine.exe", "updater")
            root_literal = self.ps_literal(root)
            command = (
                "$env:CONTEXT_ENGINE_INSTALLER_TEST_ONLY='1'; . ./install.ps1; "
                "function global:Get-UpdatedUserPath { throw 'path preflight' }; "
                "function global:Start-Process { throw 'updater must not run' }; "
                f"try {{ Invoke-MarkedReinstall -Root {root_literal}; exit 1 }} catch {{ $message = $_.Exception.Message; if ($message -notlike '*path preflight*') {{ exit 1 }} }}"
            )
            result = self.run_pwsh(command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_power_shell_parser_accepts_script(self) -> None:
        command = (
            "$tokens=$null; $errors=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            "'install.ps1',[ref]$tokens,[ref]$errors) | Out-Null; "
            "if ($errors.Count -ne 0) { exit 1 }"
        )
        result = self.run_pwsh(command)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    _ = unittest.main()
