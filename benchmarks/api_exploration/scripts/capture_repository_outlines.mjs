import { basename, dirname, resolve } from "node:path";
import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { McpClient } from "../launch-artifacts/tools/mcp-client.mjs";
import {
  CAPTURE_SCHEMA_VERSION,
  adjacentParentBatches,
  assertNoTruncation,
  canonicalRepositoryRoot,
  captureToolingIdentities,
  gitRevisionForScript,
  isTruncatedResponse,
  loadOrCreateManifest,
  parseBoolean,
  parseOptions,
  readJson,
  renderMcpResponse,
  requireOption,
  resolvePinnedRevision,
  sha256Text,
  splitBatchRange,
  stableJson,
  verifyWorkingTree,
  writeCanonicalManifest,
  writeStableJson,
} from "./repository_outline_common.mjs";

const HELP = `Usage: scripts/capture_repository_outlines.mjs [options]

Capture complete outline responses for a pinned checkout. This command is the
only Work Package 1 entry point that initializes Context Engine; measurement
consumes its preserved artifacts without starting a server.

Required:
  --repo-root PATH             checkout to capture
  --revision REV               revision; checkout HEAD must resolve to it
  --outline-artifacts DIR      empty output directory for index and responses
  --server-config PATH         JSON {command,args,env} for the MCP server
  --extension EXT              primary extension (repeat or comma-separate)
  --manifest PATH              existing sorted manifest (alternative to --extension)

Optional:
  --manifest-out PATH          where an extension-derived manifest is written
  --name NAME                  repository display name (default: basename)
  --language LABEL             language label
  --batch-size N               maximum files per outline response, 1..8 (default: 8)
  --timeout-ms N               MCP request timeout (default: 300000)
  --language-server NAME       language-server identity
  --language-server-version V  language-server version
  --ce-version V               override captured CE version
  --ce-binary-sha256 HEX       SHA-256 of the exact CE binary used for capture
  --cache-enabled BOOL         whether CE outline caching was enabled
  --captured-at ISO            supplied capture timestamp (default: now)
  --help                       show this help
`;

function textFromContent(result) {
  const response = result?.response ?? result;
  return (response?.content ?? []).filter((block) => block?.type === "text").map((block) => block.text ?? "").join("\n");
}

function responseIsError(result) {
  const response = result?.response ?? result;
  return response?.isError === true;
}

function positiveInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`--${name} must be a positive integer`);
  return parsed;
}

function ensureCaptureDirectory(directory) {
  mkdirSync(directory, { recursive: true });
  const existing = readdirSync(directory);
  if (existing.length > 0) {
    throw new Error(`outline artifact directory must be empty: ${directory}`);
  }
}

function parseServerConfig(path) {
  const config = readJson(path);
  if (!config || typeof config !== "object" || typeof config.command !== "string" || config.command.length === 0) {
    throw new Error(`server config must contain a non-empty command: ${path}`);
  }
  if (config.args !== undefined && !Array.isArray(config.args)) throw new Error("server config args must be an array");
  if (config.env !== undefined && (!config.env || typeof config.env !== "object" || Array.isArray(config.env))) {
    throw new Error("server config env must be an object");
  }
  return { command: config.command, args: config.args ?? [], env: config.env ?? {} };
}

function buildCaptureIndex({ repositoryRoot, revision, manifest, options, batchSize, scriptRevision, capturedAt, tooling, ce }) {
  const displayName = options.name ?? basename(repositoryRoot);
  return {
    schema_version: CAPTURE_SCHEMA_VERSION,
    repository: {
      display_name: displayName,
      language: options.language ?? null,
      requested_revision: revision.requested,
      revision: revision.resolved,
    },
    manifest: {
      path: manifest.path,
      hash: manifest.hash,
      file_count: manifest.paths.length,
      files: manifest.paths,
    },
    capture: {
      status: "running",
      captured_at: capturedAt,
      workspace_root: repositoryRoot,
      script_revision: scriptRevision,
      script_sha256: tooling.capture_script.sha256,
      tooling_identities: tooling,
      ce: ce ?? {},
      language_server: {
        identity: options["language-server"] ?? null,
        version: options["language-server-version"] ?? null,
      },
      cache_enabled: options["cache-enabled"] === undefined ? null : parseBoolean(options["cache-enabled"], "cache-enabled"),
      warnings: [],
      partial_failures: [],
      truncation_rejected: true,
      rendering: {
        source: "sum UTF-8 bytes and tokenizer counts per manifest file without separators",
        outline: "sum content[].text joined with LF within each final accepted MCP response without separators between responses",
        include_service_guidance: true,
        include_saved_receipts: true,
        exclude_host_wrapper_text: true,
      },
      acceptance: {
        invariant: "final accepted batches cover every manifest file exactly once and in manifest order",
        recursive_split_only_on_verified_truncation: true,
      },
    },
    batch_policy: {
      size: batchSize,
      strategy: "adjacent_parent_directory_then_maximum_size",
      split_events: [],
      batches: [],
    },
    files: [],
  };
}

async function main() {
  const { options, positional } = parseOptions(process.argv.slice(2), new Set(["extension"]));
  if (options.help !== undefined || positional.length > 0) {
    if (positional.length > 0) throw new Error(`unexpected positional argument: ${positional[0]}`);
    console.log(HELP);
    return;
  }
  const repositoryRoot = canonicalRepositoryRoot(requireOption(options, "repo-root"));
  const revision = resolvePinnedRevision(repositoryRoot, requireOption(options, "revision"));
  const outlineArtifacts = resolve(requireOption(options, "outline-artifacts"));
  ensureCaptureDirectory(outlineArtifacts);
  const serverConfig = parseServerConfig(resolve(requireOption(options, "server-config")));
  const batchSize = positiveInteger(options["batch-size"] ?? 8, "batch-size");
  if (batchSize > 8) throw new Error("--batch-size must be between 1 and 8");
  const timeoutMs = positiveInteger(options["timeout-ms"] ?? 300_000, "timeout-ms");
  const capturedAt = options["captured-at"] ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(capturedAt))) throw new Error(`--captured-at is not a valid timestamp: ${capturedAt}`);
  const manifestPath = options.manifest ? resolve(options.manifest) : undefined;
  const manifestOut = options["manifest-out"] ? resolve(options["manifest-out"]) : resolve(dirname(outlineArtifacts), "manifest.txt");
  const manifest = loadOrCreateManifest({
    repositoryRoot,
    revision: revision.resolved,
    extensions: options.extension,
    manifestPath,
    defaultManifestPath: manifestOut,
  });
  if (manifest.paths.length === 0) throw new Error("the pinned manifest contains no source files");
  writeCanonicalManifest(manifest, resolve(dirname(outlineArtifacts), "manifest.txt"));
  verifyWorkingTree(repositoryRoot, revision.resolved, manifest.paths);

  const scriptRevision = gitRevisionForScript(new URL(import.meta.url).pathname);
  const tooling = captureToolingIdentities();
  const ceBinarySha256 = options["ce-binary-sha256"];
  if (!ceBinarySha256 || !/^[0-9a-f]{64}$/i.test(ceBinarySha256)) {
    throw new Error("--ce-binary-sha256 must be a 64-character hexadecimal SHA-256 digest");
  }
  const indexPath = resolve(outlineArtifacts, "index.json");
  let client;
  let index;
  try {
    index = buildCaptureIndex({
      repositoryRoot,
      revision,
      manifest,
      options,
      batchSize,
      scriptRevision,
      capturedAt,
      tooling,
      ce: { binary_sha256: ceBinarySha256.toLowerCase() },
    });
    writeStableJson(indexPath, index);

    client = await McpClient.spawn({ ...serverConfig, cwd: repositoryRoot });
    const initializeResult = await client.initialize();
    index.capture.ce = {
      binary_sha256: ceBinarySha256.toLowerCase(),
      protocol_version: initializeResult?.protocolVersion ?? null,
      server_info: initializeResult?.serverInfo ?? null,
      version: options["ce-version"] ?? initializeResult?.serverInfo?.version ?? null,
    };
    try {
      const workspaceResult = await client.callTool(
        "initialize_workspace",
        { workspace_root: repositoryRoot },
        { timeoutMs },
      );
      if (workspaceResult?.isError === true) {
        const details = textFromContent(workspaceResult);
        if (!/already initialized/i.test(details)) throw new Error(`initialize_workspace failed: ${details}`);
      }
    } catch (error) {
      if (!/already initialized/i.test(String(error))) throw error;
      index.capture.warnings.push("server initialized the workspace during startup");
    }

    const captureBatch = async (range) => {
      const request = {
        tool: "outline",
        args: { files: range.files, workspace_root: repositoryRoot },
      };
      let response;
      try {
        response = await client.callTool("outline", request.args, { timeoutMs });
      } catch (error) {
        throw new Error(`outline request for manifest range ${range.start_index}:${range.end_index} failed: ${error.message ?? error}`);
      }
      const responseText = textFromContent(response);
      if (isTruncatedResponse(response, responseText)) {
        if (range.files.length === 1) {
          throw new Error(`single-file outline response is truncated: ${range.files[0]}`);
        }
        const [left, right] = splitBatchRange(range);
        index.batch_policy.split_events.push({
          start_index: range.start_index,
          end_index: range.end_index,
          files: range.files,
          left,
          right,
          reason: "verified_truncation",
        });
        writeStableJson(indexPath, index);
        await captureBatch(left);
        await captureBatch(right);
        return;
      }
      if (responseIsError(response)) {
        throw new Error(`outline request returned an MCP error: ${responseText || "no error text"}`);
      }
      let rendered;
      try {
        rendered = renderMcpResponse(response);
        assertNoTruncation(response, rendered.text);
      } catch (error) {
        throw new Error(`outline response for manifest range ${range.start_index}:${range.end_index} rejected: ${error.message ?? error}`);
      }
      const batchNumber = index.batch_policy.batches.length + 1;
      const batchId = `batch-${String(batchNumber).padStart(4, "0")}`;
      const responsePath = resolve(outlineArtifacts, `${batchId}.response.json`);
      writeStableJson(responsePath, { request, response });
      const responseBytes = stableJson({ request, response });
      const batch = {
        id: batchId,
        start_index: range.start_index,
        end_index: range.end_index,
        files: range.files,
        request,
        response_file: `${batchId}.response.json`,
        response_sha256: sha256Text(responseBytes),
        rendered_bytes: Buffer.byteLength(rendered.text, "utf8"),
        rendered_text_sha256: sha256Text(rendered.text),
        content_block_types: rendered.blockTypes,
        ignored_content_block_types: rendered.ignoredBlockTypes,
        status: "accepted",
      };
      index.batch_policy.batches.push(batch);
      for (const [position, file] of range.files.entries()) {
        index.files.push({
          path: file,
          batch_id: batchId,
          batch_position: position,
          response_file: batch.response_file,
          status: "accepted",
        });
      }
      writeStableJson(indexPath, index);
      console.error(`captured ${range.end_index}/${manifest.paths.length}`);
    };

    for (const range of adjacentParentBatches(manifest.paths, batchSize)) {
      await captureBatch(range);
    }
    verifyWorkingTree(repositoryRoot, revision.resolved, manifest.paths);
    const capturedFiles = index.batch_policy.batches.flatMap((batch) => batch.files);
    if (stableJson(capturedFiles) !== stableJson(manifest.paths)) {
      throw new Error("final accepted batches do not cover the manifest exactly in order");
    }
    if (stableJson(index.files.map((entry) => entry.path)) !== stableJson(manifest.paths)) {
      throw new Error("per-file coverage index does not cover the manifest exactly in order");
    }
    index.capture.status = "accepted";
    index.batch_policy.count = index.batch_policy.batches.length;
    writeStableJson(indexPath, index);
    console.log(JSON.stringify({ index: indexPath, files: manifest.paths.length, batches: index.batch_policy.count }));
  } catch (error) {
    if (index) {
      index.capture.status = "failed";
      index.capture.error = String(error.message ?? error);
      writeStableJson(indexPath, index);
    }
    throw error;
  } finally {
    if (client) await client.close();
  }
}

if (process.argv.includes("--help")) {
  console.log(HELP);
} else {
  main().catch((error) => {
    console.error(`capture_repository_outlines: ${error.message ?? error}`);
    process.exitCode = 1;
  });
}
