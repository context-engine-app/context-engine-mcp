import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const MANIFEST_SCHEMA_VERSION = 1;
export const CAPTURE_SCHEMA_VERSION = 2;
export const RESULT_SCHEMA_VERSION = 1;
export const SUPPORTED_ENCODINGS = ["cl100k_base", "o200k_base"];

function utf8Compare(left, right) {
  return Buffer.from(left, "utf8").compare(Buffer.from(right, "utf8"));
}

export function sortStrings(values) {
  return [...values].sort(utf8Compare);
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort(utf8Compare)
        .map((key) => [key, sortValue(value[key])]),
    );
  }
  return value;
}

export function stableJson(value) {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`;
}

export function writeStableJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, stableJson(value), "utf8");
}

export function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256Text(text) {
  return sha256Bytes(Buffer.from(text, "utf8"));
}

function hashToolingSources(sources) {
  const scriptsRoot = dirname(fileURLToPath(import.meta.url));
  const repositoryRoot = resolve(scriptsRoot, "..");
  return Object.fromEntries(
    Object.entries(sources).map(([name, path]) => [
      name,
      {
        path: relative(repositoryRoot, path).split(sep).join("/"),
        sha256: sha256Bytes(readFileSync(path)),
      },
    ]),
  );
}

export function captureToolingIdentities() {
  const scriptsRoot = dirname(fileURLToPath(import.meta.url));
  return hashToolingSources({
    capture_script: resolve(scriptsRoot, "capture_repository_outlines.mjs"),
    shared_script: resolve(scriptsRoot, "repository_outline_common.mjs"),
  });
}

export function measurementToolingIdentities() {
  const scriptsRoot = dirname(fileURLToPath(import.meta.url));
  return hashToolingSources({
    measurement_script: resolve(scriptsRoot, "measure_repository_outline_tokens.mjs"),
    measurement_launcher: resolve(scriptsRoot, "measure_repository_outline_tokens.sh"),
    shared_script: resolve(scriptsRoot, "repository_outline_common.mjs"),
  });
}

export function adjacentParentBatches(paths, maximumSize) {
  if (!Number.isInteger(maximumSize) || maximumSize < 1 || maximumSize > 8) {
    throw new Error("batch size must be an integer from 1 through 8");
  }
  const batches = [];
  let groupStart = 0;
  while (groupStart < paths.length) {
    const parent = posix.dirname(paths[groupStart]);
    let groupEnd = groupStart + 1;
    while (groupEnd < paths.length && posix.dirname(paths[groupEnd]) === parent) groupEnd += 1;
    for (let start = groupStart; start < groupEnd; start += maximumSize) {
      const end = Math.min(start + maximumSize, groupEnd);
      batches.push({ start_index: start, end_index: end, files: paths.slice(start, end) });
    }
    groupStart = groupEnd;
  }
  return batches;
}

export function splitBatchRange(batch) {
  if (!batch || !Array.isArray(batch.files) || batch.files.length < 2) {
    throw new Error("only a batch containing at least two files can be split");
  }
  const leftSize = Math.ceil(batch.files.length / 2);
  const middle = batch.start_index + leftSize;
  return [
    {
      start_index: batch.start_index,
      end_index: middle,
      files: batch.files.slice(0, leftSize),
    },
    {
      start_index: middle,
      end_index: batch.end_index,
      files: batch.files.slice(leftSize),
    },
  ];
}

export function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`unable to read JSON ${path}: ${error.message}`);
  }
}

function gitOutput(repoRoot, args) {
  try {
    return execFileSync("git", args, {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const details = String(error.stderr ?? error.message ?? error).trim();
    throw new Error(`git ${args.join(" ")} failed${details ? `: ${details}` : ""}`);
  }
}

function gitBytes(repoRoot, args) {
  try {
    return execFileSync("git", args, {
      cwd: repoRoot,
      maxBuffer: 256 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const details = String(error.stderr ?? error.message ?? error).trim();
    throw new Error(`git ${args.join(" ")} failed${details ? `: ${details}` : ""}`);
  }
}

export function gitRevisionForScript(scriptPath) {
  const scriptDirectory = dirname(resolve(scriptPath));
  try {
    return gitOutput(scriptDirectory, ["rev-parse", "HEAD"]).trim();
  } catch {
    return "unknown";
  }
}

export function canonicalRepositoryRoot(repositoryRoot) {
  const root = resolve(repositoryRoot);
  if (!existsSync(root)) throw new Error(`repository root does not exist: ${root}`);
  let stats;
  try {
    stats = lstatSync(root);
  } catch (error) {
    throw new Error(`cannot inspect repository root ${root}: ${error.message}`);
  }
  if (!stats.isDirectory()) throw new Error(`repository root is not a directory: ${root}`);
  return realpathSync(root);
}

export function resolvePinnedRevision(repositoryRoot, declaredRevision) {
  if (!declaredRevision) throw new Error("a pinned revision is required");
  const revision = gitOutput(repositoryRoot, ["rev-parse", "--verify", `${declaredRevision}^{commit}`]).trim();
  const head = gitOutput(repositoryRoot, ["rev-parse", "--verify", "HEAD"]).trim();
  if (head !== revision) {
    throw new Error(`repository HEAD ${head} does not match declared revision ${revision}`);
  }
  return { requested: declaredRevision, resolved: revision, head };
}

function pathHasUnsafeCharacters(path) {
  for (const character of path) {
    const code = character.codePointAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

export function validateRelativePath(path, label = "path") {
  if (typeof path !== "string" || path.length === 0) throw new Error(`${label} must be a non-empty string`);
  if (
    path.includes("\0") ||
    path.includes("\n") ||
    path.includes("\r") ||
    path.includes("\\") ||
    path.startsWith("/") ||
    path.includes("//") ||
    pathHasUnsafeCharacters(path)
  ) {
    throw new Error(`${label} contains an unsafe or unrepresentable path: ${JSON.stringify(path)}`);
  }
  const parts = path.split("/");
  if (parts.some((part) => part.length === 0 || part === "." || part === "..")) {
    throw new Error(`${label} contains an escaping path: ${JSON.stringify(path)}`);
  }
  return path;
}

function treeEntries(repositoryRoot, revision) {
  const outputBytes = gitBytes(repositoryRoot, ["ls-tree", "-r", "-z", "--full-tree", revision]);
  let output;
  try {
    output = new TextDecoder("utf-8", { fatal: true }).decode(outputBytes);
  } catch (error) {
    throw new Error(`git tree contains invalid UTF-8 path data: ${error.message}`);
  }
  const entries = new Map();
  for (const record of output.split("\0")) {
    if (!record) continue;
    const separator = record.indexOf("\t");
    if (separator < 0) throw new Error(`malformed git tree record: ${JSON.stringify(record)}`);
    const header = record.slice(0, separator).split(" ");
    const path = record.slice(separator + 1);
    validateRelativePath(path, "git tree path");
    if (header.length !== 3) throw new Error(`malformed git tree header for ${path}`);
    const [mode, type, object] = header;
    if (entries.has(path)) throw new Error(`duplicate git tree path: ${path}`);
    entries.set(path, { mode, type, object });
  }
  return entries;
}

function extensionMatches(path, extensions) {
  return extensions.some((extension) => path.endsWith(extension));
}

export function normalizeExtensions(extensions) {
  const values = (extensions ?? [])
    .flatMap((value) => String(value).split(","))
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => (value.startsWith(".") ? value : `.${value}`));
  const unique = [...new Set(values)];
  if (unique.length === 0) throw new Error("a primary extension is required when no manifest is supplied");
  return sortStrings(unique);
}

function regularBlob(entry, path) {
  if (!entry) throw new Error(`path is not tracked at the pinned revision: ${path}`);
  if (entry.type !== "blob" || !["100644", "100755"].includes(entry.mode)) {
    throw new Error(`path is not a tracked regular source blob: ${path} (${entry.mode} ${entry.type})`);
  }
}

export function readManifestFile(manifestPath) {
  if (!existsSync(manifestPath)) throw new Error(`manifest does not exist: ${manifestPath}`);
  const bytes = readFileSync(manifestPath);
  if (bytes.length === 0) throw new Error(`manifest is empty: ${manifestPath}`);
  const text = bytes.toString("utf8");
  if (text.includes("\r")) throw new Error(`manifest must use LF line endings: ${manifestPath}`);
  if (!text.endsWith("\n")) throw new Error(`manifest must end with an LF newline: ${manifestPath}`);
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.some((line) => line.length === 0)) throw new Error(`manifest contains a blank line: ${manifestPath}`);
  const seen = new Set();
  for (const line of lines) {
    validateRelativePath(line, "manifest path");
    if (seen.has(line)) throw new Error(`manifest contains a duplicate path: ${line}`);
    seen.add(line);
  }
  const sorted = sortStrings(lines);
  if (sorted.some((value, index) => value !== lines[index])) {
    throw new Error(`manifest paths must be sorted by UTF-8 byte order: ${manifestPath}`);
  }
  return { paths: lines, bytes: Buffer.from(`${lines.join("\n")}\n`, "utf8"), sourceBytes: bytes };
}

export function loadOrCreateManifest({ repositoryRoot, revision, extensions, manifestPath, defaultManifestPath }) {
  const tree = treeEntries(repositoryRoot, revision);
  const primaryExtensions = extensions?.length ? normalizeExtensions(extensions) : null;
  const trackedPrimary = [];
  if (primaryExtensions) {
    for (const [path, entry] of tree.entries()) {
      if (!extensionMatches(path, primaryExtensions)) continue;
      regularBlob(entry, path);
      trackedPrimary.push(path);
    }
  }
  trackedPrimary.splice(0, trackedPrimary.length, ...sortStrings(trackedPrimary));
  const selectedPath = manifestPath ? resolve(manifestPath) : resolve(defaultManifestPath);
  let selected;
  if (manifestPath && !existsSync(selectedPath)) {
    throw new Error(`manifest does not exist: ${selectedPath}`);
  }
  if (existsSync(selectedPath)) {
    selected = readManifestFile(selectedPath);
  } else {
    if (!primaryExtensions) throw new Error("a primary extension is required when no manifest is supplied");
    selected = { paths: trackedPrimary, bytes: Buffer.from(`${trackedPrimary.join("\n")}\n`, "utf8"), sourceBytes: null };
    if (selected.paths.length === 0) throw new Error("the pinned Git tree contains no files matching the requested extension");
    mkdirSync(dirname(selectedPath), { recursive: true });
    writeFileSync(selectedPath, selected.bytes);
  }
  const selectedSet = new Set(selected.paths);
  for (const path of selected.paths) {
    regularBlob(tree.get(path), path);
    if (primaryExtensions && !extensionMatches(path, primaryExtensions)) {
      throw new Error(`manifest path does not match the requested primary extension: ${path}`);
    }
  }
  const excluded = primaryExtensions ? trackedPrimary.filter((path) => !selectedSet.has(path)) : [];
  return {
    path: selectedPath,
    paths: selected.paths,
    bytes: selected.bytes,
    hash: sha256Bytes(selected.bytes),
    tree,
    trackedPrimary,
    excluded,
    extensions: primaryExtensions,
  };
}

export function writeCanonicalManifest(manifest, destination) {
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, manifest.bytes);
}

export function resolveSafePath(repositoryRoot, relativePath) {
  validateRelativePath(relativePath, "repository path");
  const root = canonicalRepositoryRoot(repositoryRoot);
  const candidate = resolve(root, ...relativePath.split("/"));
  const candidateRelative = relative(root, candidate);
  if (!candidateRelative || candidateRelative === ".." || candidateRelative.startsWith(`..${sep}`) || candidateRelative.startsWith(sep)) {
    throw new Error(`path escapes repository root: ${relativePath}`);
  }
  if (!existsSync(candidate)) throw new Error(`repository file is missing: ${relativePath}`);
  const stats = lstatSync(candidate);
  if (!stats.isFile()) throw new Error(`repository path is not a regular file: ${relativePath}`);
  const realCandidate = realpathSync(candidate);
  const realRelative = relative(root, realCandidate);
  if (!realRelative || realRelative === ".." || realRelative.startsWith(`..${sep}`) || realRelative.startsWith(sep)) {
    throw new Error(`repository path resolves outside root: ${relativePath}`);
  }
  return candidate;
}

export function verifyWorkingTree(repositoryRoot, revision, paths) {
  const chunks = [];
  for (let offset = 0; offset < paths.length; offset += 128) chunks.push(paths.slice(offset, offset + 128));
  for (const chunk of chunks) {
    const result = spawnSync("git", ["diff", "--quiet", revision, "--", ...chunk], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.error) throw new Error(`unable to compare checkout with pinned revision: ${result.error.message}`);
    if (result.status !== 0) {
      const details = String(result.stderr ?? "").trim();
      throw new Error(`working tree source differs from pinned revision${details ? `: ${details}` : ""}`);
    }
  }
  for (const path of paths) resolveSafePath(repositoryRoot, path);
}

function recursiveFiles(root, prefix = "") {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const relativeName = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = resolve(root, entry.name);
    if (entry.isDirectory()) files.push(...recursiveFiles(absolute, relativeName));
    else if (entry.isFile()) files.push(relativeName);
    else throw new Error(`outline artifact contains a non-regular entry: ${relativeName}`);
  }
  return files;
}

export function hashDirectory(directory) {
  const files = sortStrings(recursiveFiles(directory));
  const hash = createHash("sha256");
  for (const file of files) {
    const bytes = readFileSync(resolve(directory, ...file.split("/")));
    hash.update(Buffer.from(`${file}\0${bytes.length}\0`, "utf8"));
    hash.update(bytes);
  }
  return { hash: hash.digest("hex"), files };
}

export function renderMcpResponse(payload) {
  const response = payload && typeof payload === "object" && payload.response && !Array.isArray(payload.response)
    ? payload.response
    : payload;
  if (!response || typeof response !== "object") throw new Error("outline response must be a JSON object");
  if (response.isError === true) throw new Error("outline response isError=true");
  if (!Array.isArray(response.content)) throw new Error("outline response is missing content[]");
  const textBlocks = [];
  const blockTypes = [];
  for (const block of response.content) {
    if (!block || typeof block !== "object" || typeof block.type !== "string") {
      throw new Error("outline response contains a malformed content block");
    }
    blockTypes.push(block.type);
    if (block.type === "text") {
      if (typeof block.text !== "string") throw new Error("outline text block is missing text");
      textBlocks.push(block.text);
    }
  }
  return {
    response,
    text: textBlocks.join("\n"),
    blockTypes,
    ignoredBlockTypes: blockTypes.filter((type) => type !== "text"),
  };
}

export function truncationMarker(text) {
  return /^Warning: truncated output \(original token count: [0-9]+\)$/m.test(text);
}

export function isTruncatedResponse(payload, renderedText) {
  return payload?.truncated === true || payload?.response?.truncated === true || truncationMarker(renderedText);
}

export function assertNoTruncation(payload, renderedText) {
  if (isTruncatedResponse(payload, renderedText)) throw new Error("outline response is truncated");
}

export function parseBoolean(value, optionName) {
  if (value === true || value === false) return value;
  const normalized = String(value).toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error(`${optionName} expects true or false`);
}

export function requireOption(options, name) {
  const value = options[name];
  if (value === undefined || value === null || value === "") throw new Error(`missing required option --${name}`);
  return value;
}

export function parseOptions(argv, repeatable = new Set()) {
  const options = {};
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--") {
      positional.push(...argv.slice(index + 1));
      break;
    }
    if (!argument.startsWith("--")) {
      positional.push(argument);
      continue;
    }
    const equals = argument.indexOf("=");
    const name = (equals >= 0 ? argument.slice(2, equals) : argument.slice(2));
    if (!name) throw new Error("empty option name");
    let value;
    if (equals >= 0) value = argument.slice(equals + 1);
    else if (name.startsWith("no-") && (index + 1 >= argv.length || argv[index + 1].startsWith("--"))) value = false;
    else {
      if (index + 1 >= argv.length) throw new Error(`missing value for --${name}`);
      value = argv[++index];
    }
    if (repeatable.has(name)) options[name] = [...(options[name] ?? []), value];
    else if (options[name] !== undefined) throw new Error(`duplicate option --${name}`);
    else options[name] = value;
  }
  return { options, positional };
}

export function parseEncodings(rawValues) {
  const values = (rawValues?.length ? rawValues : SUPPORTED_ENCODINGS)
    .flatMap((value) => String(value).split(","))
    .map((value) => value.trim())
    .filter(Boolean);
  const unique = [...new Set(values)];
  if (unique.length === 0) throw new Error(`at least one tokenizer encoding is required; choose ${SUPPORTED_ENCODINGS.join(" or ")}`);
  for (const encoding of unique) {
    if (!SUPPORTED_ENCODINGS.includes(encoding)) {
      throw new Error(`unsupported tokenizer encoding ${encoding}; choose ${SUPPORTED_ENCODINGS.join(" or ")}`);
    }
  }
  return sortStrings(unique);
}
