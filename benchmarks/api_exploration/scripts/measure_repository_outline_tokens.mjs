import { basename, dirname, resolve } from "node:path";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  RESULT_SCHEMA_VERSION,
  SUPPORTED_ENCODINGS,
  adjacentParentBatches,
  assertNoTruncation,
  canonicalRepositoryRoot,
  captureToolingIdentities,
  gitRevisionForScript,
  hashDirectory,
  loadOrCreateManifest,
  measurementToolingIdentities,
  parseEncodings,
  parseOptions,
  readJson,
  renderMcpResponse,
  requireOption,
  resolvePinnedRevision,
  resolveSafePath,
  sha256Bytes,
  sortStrings,
  stableJson,
  splitBatchRange,
  writeCanonicalManifest,
  verifyWorkingTree,
  validateRelativePath,
  writeStableJson,
} from "./repository_outline_common.mjs";

const TOKENIZER_PACKAGE = "tiktoken";
const scriptsRoot = dirname(fileURLToPath(import.meta.url));
const tokenizerPackageAnchor = resolve(scriptsRoot, "../launch-artifacts/tools/package.json");
const tokenizerRequire = createRequire(tokenizerPackageAnchor);
const tokenizerEntry = tokenizerRequire.resolve(TOKENIZER_PACKAGE);
const { get_encoding: getEncoding } = tokenizerRequire(TOKENIZER_PACKAGE);
const tokenizerPackageMetadata = JSON.parse(readFileSync(resolve(dirname(tokenizerEntry), "package.json"), "utf8"));
const TOKENIZER_VERSION = tokenizerPackageMetadata.version;
const encoders = new Map();

const EXPECTED_RENDERING = {
  source: "sum UTF-8 bytes and tokenizer counts per manifest file without separators",
  outline: "sum content[].text joined with LF within each final accepted MCP response without separators between responses",
  include_service_guidance: true,
  include_saved_receipts: true,
  exclude_host_wrapper_text: true,
};

const TOKENIZER_FIXTURES = [
  { text: "", counts: { cl100k_base: 0, o200k_base: 0 } },
  { text: "hello world", counts: { cl100k_base: 2, o200k_base: 2 } },
  {
    text: "def f(x: int | None) -> str:\n    return str(x)\n",
    counts: { cl100k_base: 16, o200k_base: 16 },
  },
  { text: "こんにちは世界", counts: { cl100k_base: 4, o200k_base: 2 } },
];

const HELP = `Usage: scripts/measure_repository_outline_tokens.mjs [options]

Measure raw source and complete rendered outline artifacts for exactly one
pinned Git-tree manifest. This command never initializes Context Engine.

Required:
  --repo-root PATH             checkout whose source is measured
  --revision REV               revision; checkout HEAD must resolve to it
  --outline-artifacts DIR      capture directory containing index.json
  --output-json PATH           deterministic result destination
  --extension EXT              primary extension (repeat or comma-separate)
  --manifest PATH              existing sorted manifest (alternative to --extension)

Optional:
  --name NAME                  repository display name
  --language LABEL             language label
  --encoding NAME              cl100k_base or o200k_base (repeat/comma; default: both)
  --script-revision REV        override script revision metadata
  --help                       show this help
`;

function encoderFor(encoding) {
  if (!SUPPORTED_ENCODINGS.includes(encoding)) {
    throw new Error(`unsupported tokenizer encoding ${encoding}; choose ${SUPPORTED_ENCODINGS.join(" or ")}`);
  }
  if (!encoders.has(encoding)) encoders.set(encoding, getEncoding(encoding));
  return encoders.get(encoding);
}

function countTokens(text, encoding) {
  if (text.length === 0) return 0;
  return encoderFor(encoding).encode(text).length;
}

function verifyTokenizerFixtures() {
  if (typeof TOKENIZER_VERSION !== "string" || TOKENIZER_VERSION.length === 0) {
    throw new Error("unable to discover the installed tiktoken package version");
  }
  for (const fixture of TOKENIZER_FIXTURES) {
    for (const encoding of SUPPORTED_ENCODINGS) {
      const actual = countTokens(fixture.text, encoding);
      const expected = fixture.counts[encoding];
      if (actual !== expected) {
        throw new Error(`tiktoken fixture mismatch for ${encoding}: expected ${expected}, received ${actual}`);
      }
    }
  }
}

function textFromUtf8(bytes, path) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`source is not valid UTF-8: ${path}: ${error.message}`);
  }
}

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function assertArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
}

function assertObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
}

function assertExactKeys(value, expected, label) {
  const actual = sortStrings(Object.keys(value));
  const wanted = sortStrings(expected);
  if (!sameArray(actual, wanted)) throw new Error(`${label} contains unexpected or missing fields`);
}

function sameRange(left, right) {
  return left?.start_index === right.start_index && left?.end_index === right.end_index && sameArray(left?.files ?? [], right.files);
}

function artifactResponseFiles(index) {
  assertArray(index.batch_policy?.batches, "index.batch_policy.batches");
  return index.batch_policy.batches.map((batch, position) => {
    assertObject(batch, `batch ${position + 1}`);
    if (typeof batch.id !== "string" || !/^batch-[0-9]{4}$/.test(batch.id)) {
      throw new Error(`batch ${position + 1} has an invalid id`);
    }
    const expected = `${batch.id}.response.json`;
    if (batch.response_file !== expected) throw new Error(`${batch.id} response_file must be ${expected}`);
    validateRelativePath(batch.response_file, `${batch.id} response_file`);
    assertArray(batch.files, `${batch.id}.files`);
    if (!sameArray(batch.files, sortStrings(batch.files))) throw new Error(`${batch.id}.files must be sorted`);
    if (batch.status !== "accepted") throw new Error(`${batch.id} is not accepted`);
    return { ...batch, response_file: expected };
  });
}

function assertManifestMetadata(index, manifest, revision, repositoryRoot) {
  assertObject(index, "outline artifact index");
  if (index.schema_version !== 2) throw new Error(`unsupported outline capture schema: ${index.schema_version}`);
  assertObject(index.repository, "index.repository");
  if (index.repository.revision !== revision.resolved) {
    throw new Error(`outline capture revision ${index.repository.revision} does not match ${revision.resolved}`);
  }
  assertObject(index.manifest, "index.manifest");
  if (index.manifest.hash !== manifest.hash) throw new Error("outline artifact manifest hash does not match source manifest");
  if (index.manifest.file_count !== manifest.paths.length) throw new Error("outline artifact manifest count does not match source manifest");
  assertArray(index.manifest.files, "index.manifest.files");
  if (!sameArray(index.manifest.files, manifest.paths)) throw new Error("outline artifact manifest files do not match source manifest");
  assertObject(index.capture, "index.capture");
  if (index.capture.status !== "accepted") throw new Error(`outline capture status is not accepted: ${index.capture.status}`);
  if (index.capture.workspace_root !== repositoryRoot) throw new Error("outline capture workspace root does not match the measured checkout");
  if (typeof index.capture.captured_at !== "string" || !Number.isFinite(Date.parse(index.capture.captured_at))) {
    throw new Error("outline capture is missing a valid captured_at timestamp");
  }
  if (index.capture.partial_failures?.length) throw new Error("outline capture contains partial failures");
  if ((index.capture.warnings ?? []).some((warning) => /truncat/i.test(String(warning)))) {
    throw new Error("outline capture warnings include truncation");
  }
  if (index.capture.truncation_rejected !== true) throw new Error("outline capture did not enforce truncation rejection");
  if (stableJson(index.capture.rendering) !== stableJson(EXPECTED_RENDERING)) throw new Error("outline capture rendering contract is invalid");
  assertObject(index.capture.acceptance, "index.capture.acceptance");
  if (index.capture.acceptance.invariant !== "final accepted batches cover every manifest file exactly once and in manifest order") {
    throw new Error("outline capture acceptance invariant is invalid");
  }
  if (index.capture.acceptance.recursive_split_only_on_verified_truncation !== true) {
    throw new Error("outline capture does not require verified truncation before recursive splitting");
  }
  if (index.capture.ce?.binary_sha256 === undefined || !/^[0-9a-f]{64}$/i.test(index.capture.ce.binary_sha256)) {
    throw new Error("outline capture is missing the CE binary SHA-256 identity");
  }
  assertObject(index.capture.tooling_identities, "index.capture.tooling_identities");
  assertObject(index.batch_policy, "index.batch_policy");
  assertArray(index.batch_policy.split_events, "index.batch_policy.split_events");
}

function assertFileMetadata(index, manifest, batches) {
  assertArray(index.files, "index.files");
  if (index.files.length !== manifest.paths.length) throw new Error("outline file metadata count does not match manifest");
  const paths = index.files.map((entry) => entry?.path);
  if (paths.some((path) => typeof path !== "string")) throw new Error("outline file metadata contains an invalid path");
  if (!sameArray(paths, sortStrings(paths))) throw new Error("outline file metadata must be sorted");
  if (!sameArray(paths, manifest.paths)) throw new Error("outline file metadata paths do not match manifest");
  const batchById = new Map(batches.map((batch) => [batch.id, batch]));
  const seen = new Set();
  for (const entry of index.files) {
    assertObject(entry, `outline file metadata for ${entry?.path ?? "unknown path"}`);
    assertExactKeys(entry, ["path", "batch_id", "batch_position", "response_file", "status"], `outline file metadata for ${entry.path ?? "unknown path"}`);
    validateRelativePath(entry.path, "outline file metadata path");
    if (seen.has(entry.path)) throw new Error(`duplicate outline file metadata: ${entry.path}`);
    seen.add(entry.path);
    if (entry.status !== "accepted") throw new Error(`outline file is not accepted: ${entry.path}`);
    const batch = batchById.get(entry.batch_id);
    if (!batch || !batch.files.includes(entry.path)) throw new Error(`outline file has no matching batch: ${entry.path}`);
    if (entry.response_file !== batch.response_file) throw new Error(`outline file response mismatch: ${entry.path}`);
    if (entry.batch_position !== batch.files.indexOf(entry.path)) throw new Error(`outline file batch position mismatch: ${entry.path}`);
  }
  for (const batch of batches) {
    const batchFiles = index.files.filter((entry) => entry.batch_id === batch.id).map((entry) => entry.path);
    if (!sameArray(batchFiles, batch.files)) throw new Error(`${batch.id} file metadata does not match its batch`);
  }
}

function assertBatchOrdering(batches, index, manifest) {
  if (index.batch_policy.count !== batches.length) throw new Error("outline batch count does not match metadata");
  if (!Number.isInteger(index.batch_policy.size) || index.batch_policy.size < 1 || index.batch_policy.size > 8) {
    throw new Error("outline batch size must be an integer from 1 through 8");
  }
  if (index.batch_policy.strategy !== "adjacent_parent_directory_then_maximum_size") {
    throw new Error("outline batch strategy is invalid");
  }
  const ids = batches.map((batch) => batch.id);
  const expectedIds = batches.map((_, index) => `batch-${String(index + 1).padStart(4, "0")}`);
  if (!sameArray(ids, expectedIds)) throw new Error("outline batches must be contiguous and ordered");
  for (const batch of batches) {
    if (batch.files.length > index.batch_policy.size) throw new Error(`${batch.id} exceeds the declared batch size`);
    if (batch.files.length === 0) throw new Error(`${batch.id} has no files`);
    if (batch.end_index !== batch.start_index + batch.files.length) {
      throw new Error(`${batch.id} boundaries do not match its ordered manifest slice`);
    }
    if (!sameArray(batch.files, manifest.paths.slice(batch.start_index, batch.end_index))) {
      throw new Error(`${batch.id} files do not match its ordered manifest slice`);
    }
    const expectedRequest = { tool: "outline", args: { files: batch.files, workspace_root: index.capture.workspace_root } };
    if (stableJson(batch.request) !== stableJson(expectedRequest)) throw new Error(`${batch.id} request metadata is invalid`);
  }

  const splitEvents = index.batch_policy.split_events;
  for (const [position, event] of splitEvents.entries()) {
    assertObject(event, `split event ${position + 1}`);
    assertExactKeys(event, ["start_index", "end_index", "files", "left", "right", "reason"], `split event ${position + 1}`);
    if (event.reason !== "verified_truncation") throw new Error(`split event ${position + 1} has an invalid reason`);
    assertArray(event.files, `split event ${position + 1}.files`);
    if (event.files.length < 2) throw new Error(`split event ${position + 1} cannot split fewer than two files`);
    if (!sameArray(event.files, manifest.paths.slice(event.start_index, event.end_index))) {
      throw new Error(`split event ${position + 1} files do not match its manifest slice`);
    }
    assertObject(event.left, `split event ${position + 1}.left`);
    assertObject(event.right, `split event ${position + 1}.right`);
    assertExactKeys(event.left, ["start_index", "end_index", "files"], `split event ${position + 1}.left`);
    assertExactKeys(event.right, ["start_index", "end_index", "files"], `split event ${position + 1}.right`);
    assertArray(event.left.files, `split event ${position + 1}.left.files`);
    assertArray(event.right.files, `split event ${position + 1}.right.files`);
    const [expectedLeft, expectedRight] = splitBatchRange(event);
    if (!sameRange(event.left, expectedLeft) || !sameRange(event.right, expectedRight)) {
      throw new Error(`split event ${position + 1} is not an ordered recursive halving`);
    }
  }

  let splitPosition = 0;
  let batchPosition = 0;
  const visit = (range) => {
    const split = splitEvents[splitPosition];
    if (split && sameRange(split, range)) {
      splitPosition += 1;
      visit(split.left);
      visit(split.right);
      return;
    }
    const batch = batches[batchPosition];
    if (!batch || !sameRange(batch, range)) throw new Error("accepted batch topology does not match deterministic batching and split events");
    batchPosition += 1;
  };
  for (const range of adjacentParentBatches(manifest.paths, index.batch_policy.size)) visit(range);
  if (splitPosition !== splitEvents.length || batchPosition !== batches.length) {
    throw new Error("capture contains unused split events or accepted batches");
  }
}

function responsePayload(responsePath) {
  const payload = readJson(responsePath);
  if (!payload || typeof payload !== "object" || !payload.response) throw new Error(`outline artifact is missing response: ${responsePath}`);
  if (!payload.request || payload.request.tool !== "outline") throw new Error(`outline artifact is missing outline request: ${responsePath}`);
  assertExactKeys(payload, ["request", "response"], `outline artifact ${responsePath}`);
  return payload;
}

function metricsFor(rawBytes, outlineBytes, rawTokens, outlineTokens) {
  const ratio = rawTokens === 0 ? null : outlineTokens / rawTokens;
  const reduction = ratio === null ? null : 1 - ratio;
  const multiplier = outlineTokens === 0 ? null : rawTokens / outlineTokens;
  return {
    raw_bytes: rawBytes,
    outline_bytes: outlineBytes,
    raw_tokens: rawTokens,
    outline_tokens: outlineTokens,
    ratio,
    reduction,
    reduction_percent: reduction === null ? null : reduction * 100,
    multiplier,
  };
}

async function main() {
  const { options, positional } = parseOptions(process.argv.slice(2), new Set(["extension", "encoding"]));
  if (options.help !== undefined || positional.length > 0) {
    if (positional.length > 0) throw new Error(`unexpected positional argument: ${positional[0]}`);
    console.log(HELP);
    return;
  }
  const encodings = parseEncodings(options.encoding);
  verifyTokenizerFixtures();
  const repositoryRoot = canonicalRepositoryRoot(requireOption(options, "repo-root"));
  const revision = resolvePinnedRevision(repositoryRoot, requireOption(options, "revision"));
  const outlineArtifacts = resolve(requireOption(options, "outline-artifacts"));
  if (!existsSync(outlineArtifacts) || !lstatSync(outlineArtifacts).isDirectory()) {
    throw new Error(`outline artifact directory does not exist: ${outlineArtifacts}`);
  }
  const outputJson = resolve(requireOption(options, "output-json"));
  const manifestPath = options.manifest ? resolve(options.manifest) : undefined;
  const manifestOut = manifestPath ?? resolve(dirname(outputJson), "manifest.txt");
  const manifest = loadOrCreateManifest({
    repositoryRoot,
    revision: revision.resolved,
    extensions: options.extension,
    manifestPath,
    defaultManifestPath: manifestOut,
  });
  if (manifest.paths.length === 0) throw new Error("the pinned manifest contains no source files");
  writeCanonicalManifest(manifest, resolve(dirname(outputJson), "manifest.txt"));
  verifyWorkingTree(repositoryRoot, revision.resolved, manifest.paths);
  const indexPath = resolve(outlineArtifacts, "index.json");
  if (!existsSync(indexPath)) throw new Error(`outline artifact index is missing: ${indexPath}`);
  const index = readJson(indexPath);
  assertManifestMetadata(index, manifest, revision, repositoryRoot);
  const currentCaptureTooling = captureToolingIdentities();
  if (stableJson(currentCaptureTooling) !== stableJson(index.capture.tooling_identities)) {
    throw new Error("capture tooling sources changed after outline capture; regenerate the capture");
  }
  const currentMeasurementTooling = measurementToolingIdentities();
  const batches = artifactResponseFiles(index);
  assertBatchOrdering(batches, index, manifest);
  assertFileMetadata(index, manifest, batches);

  const artifactDirectory = hashDirectory(outlineArtifacts);
  const expectedArtifactFiles = sortStrings(["index.json", ...batches.map((batch) => batch.response_file)]);
  if (!sameArray(artifactDirectory.files, expectedArtifactFiles)) {
    const extra = artifactDirectory.files.filter((path) => !expectedArtifactFiles.includes(path));
    const missing = expectedArtifactFiles.filter((path) => !artifactDirectory.files.includes(path));
    throw new Error(`outline artifact files disagree with index (extra=${extra.join(",")}, missing=${missing.join(",")})`);
  }

  const rawByEncoding = Object.fromEntries(encodings.map((encoding) => [encoding, 0]));
  let rawBytes = 0;
  for (const path of manifest.paths) {
    const sourcePath = resolveSafePath(repositoryRoot, path);
    const bytes = readFileSync(sourcePath);
    const source = textFromUtf8(bytes, path);
    rawBytes += bytes.length;
    for (const encoding of encodings) rawByEncoding[encoding] += countTokens(source, encoding);
  }

  const outlineByEncoding = Object.fromEntries(encodings.map((encoding) => [encoding, 0]));
  let outlineBytes = 0;
  const measuredBatches = [];
  for (const batch of batches) {
    const responsePath = resolve(outlineArtifacts, ...batch.response_file.split("/"));
    const payload = responsePayload(responsePath);
    const expectedRequest = { tool: "outline", args: { files: batch.files, workspace_root: index.capture.workspace_root } };
    if (stableJson(payload.request) !== stableJson(expectedRequest)) throw new Error(`${batch.id} request does not match index`);
    const rendered = renderMcpResponse(payload);
    assertNoTruncation(payload, rendered.text);
    const renderedBytes = Buffer.byteLength(rendered.text, "utf8");
    if (renderedBytes !== batch.rendered_bytes) throw new Error(`${batch.id} rendered byte count changed`);
    if (sha256Bytes(Buffer.from(rendered.text, "utf8")) !== batch.rendered_text_sha256) throw new Error(`${batch.id} rendered text hash changed`);
    const responseBytes = readFileSync(responsePath);
    if (responseBytes.toString("utf8") !== stableJson(payload)) throw new Error(`${batch.id} response artifact is not canonical stable JSON`);
    if (sha256Bytes(responseBytes) !== batch.response_sha256) throw new Error(`${batch.id} response hash changed`);
    if (!sameArray(rendered.blockTypes, batch.content_block_types)) throw new Error(`${batch.id} content block types changed`);
    if (!sameArray(rendered.ignoredBlockTypes, batch.ignored_content_block_types)) throw new Error(`${batch.id} ignored content block types changed`);
    outlineBytes += renderedBytes;
    for (const encoding of encodings) outlineByEncoding[encoding] += countTokens(rendered.text, encoding);
    measuredBatches.push({
      id: batch.id,
      start_index: batch.start_index,
      end_index: batch.end_index,
      file_count: batch.files.length,
      rendered_bytes: renderedBytes,
    });
  }

  const tokenizers = {};
  for (const encoding of encodings) {
    tokenizers[encoding] = {
      id: `tiktoken/${encoding}`,
      package: TOKENIZER_PACKAGE,
      version: TOKENIZER_VERSION,
      ...metricsFor(rawBytes, outlineBytes, rawByEncoding[encoding], outlineByEncoding[encoding]),
    };
  }
  const result = {
    schema_version: RESULT_SCHEMA_VERSION,
    repository: {
      display_name: options.name ?? index.repository.display_name ?? basename(repositoryRoot),
      language: options.language ?? index.repository.language ?? null,
      requested_revision: revision.requested,
      revision: revision.resolved,
    },
    manifest: {
      file: "manifest.txt",
      hash: manifest.hash,
      file_count: manifest.paths.length,
    },
    outline_artifacts: {
      directory: "outline-artifacts",
      index_sha256: sha256Bytes(readFileSync(indexPath)),
      artifact_hash: artifactDirectory.hash,
    },
    capture: {
      captured_at: index.capture.captured_at,
      workspace_root: index.capture.workspace_root,
      ce: index.capture.ce ?? {},
      language_server: index.capture.language_server ?? {},
      cache_enabled: index.capture.cache_enabled ?? null,
      acceptance: index.capture.acceptance,
      tooling_identities: index.capture.tooling_identities,
    },
    script_revision: options["script-revision"] ?? gitRevisionForScript(new URL(import.meta.url).pathname),
    script_sha256: currentMeasurementTooling.measurement_script.sha256,
    tooling_identities: currentMeasurementTooling,
    batch_policy: {
      size: index.batch_policy.size,
      count: batches.length,
      split_events: index.batch_policy.split_events,
      batches: measuredBatches,
    },
    rendering: index.capture.rendering,
    exclusions: {
      primary_extensions: manifest.extensions ?? [],
      excluded_paths: manifest.excluded,
      policy: "tracked primary-language files are included unless an explicit manifest excludes them",
    },
    tokenizers,
  };
  writeStableJson(outputJson, result);
  process.stdout.write(stableJson(result));
}

if (process.argv.includes("--help")) {
  console.log(HELP);
} else {
  main().catch((error) => {
    console.error(`measure_repository_outline_tokens: ${error.message ?? error}`);
    process.exitCode = 1;
  });
}
