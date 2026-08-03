# context-engine-mcp

Official Context Engine releases, verification artifacts, and canonical direct installers.

## Install

Use the website command for your platform:

```sh
curl -fsSL https://context-engine.app/install.sh | sh
```

```powershell
irm https://context-engine.app/install.ps1 | iex
```

If the website is unavailable, the emergency fallback sources are
`https://raw.githubusercontent.com/context-engine-app/context-engine-mcp/main/install.sh` and
`https://raw.githubusercontent.com/context-engine-app/context-engine-mcp/main/install.ps1`.

Direct installations are user-owned at `$HOME/.local/lib/context-engine/context-engine` on macOS/Linux, with a
`/usr/local/bin/context-engine` symlink, and at `%LOCALAPPDATA%\Context Engine\context-engine.exe` on Windows, with
that directory added once to the user's `PATH`. Set `CONTEXT_ENGINE_API_KEY` before first use.

Homebrew, Scoop, APT, DNF, and exact release archives are available from the [download page](https://context-engine.app/download).
Package installations own an adjacent immutable `.context-engine-installation.json` marker and do not use direct-update
state or lock files.

Run `context-engine update` to update a direct installation or delegate to Homebrew, Scoop, APT, or DNF as applicable.
Existing direct `v0.1.1` ARM64 installations are migrated once by the installer; other unmarked or conflicting
installations must be resolved before reinstalling.
