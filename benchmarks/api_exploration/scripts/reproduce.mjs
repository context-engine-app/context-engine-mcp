import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const PORTABLE_WORKSPACE_ROOT = "<repository-root>";
const scriptsRoot = dirname(fileURLToPath(import.meta.url));
const benchmarkRoot = resolve(scriptsRoot, "..");

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)))
        .map((key) => [key, sortValue(value[key])]),
    );
  }
  return value;
}

function stableJson(value) {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`;
}

function writeStableJson(path, value) {
  const content = stableJson(value);
  writeFileSync(path, content);
  return createHash("sha256").update(content).digest("hex");
}

function requiredOption(values, name) {
  const value = values[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`--${name} is required`);
  }
  return value;
}

function artifactDirectory(repository) {
  const repositoryDirectory = join(
    benchmarkRoot,
    "artifacts",
    repository,
  );
  if (!existsSync(repositoryDirectory)) {
    throw new Error(`unknown repository: ${repository}`);
  }
  const revisions = readdirSync(repositoryDirectory).filter((entry) =>
    statSync(join(repositoryDirectory, entry)).isDirectory(),
  );
  if (revisions.length !== 1) {
    throw new Error(
      `${repositoryDirectory} must contain exactly one pinned revision`,
    );
  }
  return join(repositoryDirectory, revisions[0]);
}

function materializeOutlines(portableDirectory, checkout, destination) {
  cpSync(portableDirectory, destination, { recursive: true });
  const indexPath = join(destination, "index.json");
  const index = JSON.parse(readFileSync(indexPath, "utf8"));
  if (index.capture.workspace_root !== PORTABLE_WORKSPACE_ROOT) {
    throw new Error("capture does not use the portable workspace sentinel");
  }
  index.capture.workspace_root = checkout;

  for (const batch of index.batch_policy.batches) {
    if (
      batch.request?.args?.workspace_root !== PORTABLE_WORKSPACE_ROOT
    ) {
      throw new Error(`${batch.id} does not use the portable workspace sentinel`);
    }
    batch.request.args.workspace_root = checkout;
    const responsePath = join(destination, batch.response_file);
    const payload = JSON.parse(readFileSync(responsePath, "utf8"));
    if (
      payload.request?.args?.workspace_root !== PORTABLE_WORKSPACE_ROOT
    ) {
      throw new Error(
        `${batch.response_file} does not use the portable workspace sentinel`,
      );
    }
    payload.request.args.workspace_root = checkout;
    batch.response_sha256 = writeStableJson(responsePath, payload);
  }

  writeStableJson(indexPath, index);
  return index;
}

function assertExpectedMetrics(result, expected, encodings) {
  if (stableJson(result.repository) !== stableJson(expected.repository)) {
    throw new Error("repository metadata differs from expected metrics");
  }
  if (
    result.manifest.file_count !== expected.manifest.file_count ||
    result.manifest.hash !== expected.manifest.hash
  ) {
    throw new Error("manifest metadata differs from expected metrics");
  }
  if (
    !Array.isArray(expected.primary_extensions) ||
    expected.primary_extensions.length === 0 ||
    stableJson(result.exclusions.primary_extensions) !==
      stableJson(expected.primary_extensions)
  ) {
    throw new Error(
      "primary-language extension metadata differs from expected metrics",
    );
  }
  if (result.exclusions.excluded_paths.length !== 0) {
    throw new Error(
      `manifest omits tracked primary-language files: ${result.exclusions.excluded_paths.join(", ")}`,
    );
  }

  const metricNames = [
    "multiplier",
    "outline_bytes",
    "outline_tokens",
    "raw_bytes",
    "raw_tokens",
    "reduction_percent",
    "version",
  ];
  for (const encoding of encodings) {
    const actualMetrics = result.tokenizers[encoding];
    const expectedMetrics = expected.tokenizers[encoding];
    if (!actualMetrics || !expectedMetrics) {
      throw new Error(`missing expected metrics for ${encoding}`);
    }
    for (const metric of metricNames) {
      if (actualMetrics[metric] !== expectedMetrics[metric]) {
        throw new Error(
          `${encoding}.${metric}: expected ${expectedMetrics[metric]}, received ${actualMetrics[metric]}`,
        );
      }
    }
  }
}

function main() {
  const { values } = parseArgs({
    options: {
      checkout: { type: "string" },
      encoding: {
        type: "string",
        multiple: true,
        default: ["o200k_base"],
      },
      output: { type: "string" },
      repo: { type: "string" },
    },
    strict: true,
  });

  const repository = requiredOption(values, "repo");
  const checkout = realpathSync(requiredOption(values, "checkout"));
  const artifacts = artifactDirectory(repository);
  const expected = JSON.parse(
    readFileSync(join(artifacts, "expected-metrics.json"), "utf8"),
  );
  const encodings = values.encoding;
  const output = resolve(
    values.output ??
      join(benchmarkRoot, "results", `${repository}.json`),
  );
  mkdirSync(dirname(output), { recursive: true });

  const temporaryRoot = mkdtempSync(
    join(tmpdir(), "ce-api-exploration-"),
  );
  try {
    const materializedOutlines = join(temporaryRoot, "outline-artifacts");
    const index = materializeOutlines(
      join(artifacts, "outline-artifacts"),
      checkout,
      materializedOutlines,
    );
    const argumentsForMeasurement = [
      join(scriptsRoot, "measure_repository_outline_tokens.mjs"),
      "--repo-root",
      checkout,
      "--revision",
      index.repository.revision,
      "--outline-artifacts",
      materializedOutlines,
      "--output-json",
      output,
      "--manifest",
      join(artifacts, "manifest.txt"),
      "--name",
      index.repository.display_name,
      "--language",
      index.repository.language,
    ];
    for (const extension of expected.primary_extensions) {
      argumentsForMeasurement.push("--extension", extension);
    }
    for (const encoding of encodings) {
      argumentsForMeasurement.push("--encoding", encoding);
    }
    const completed = spawnSync(process.execPath, argumentsForMeasurement, {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    });
    if (completed.error) throw completed.error;
    if (completed.status !== 0) {
      process.stderr.write(completed.stderr);
      throw new Error(
        `measurement exited with status ${completed.status ?? "unknown"}`,
      );
    }

    const result = JSON.parse(readFileSync(output, "utf8"));
    assertExpectedMetrics(result, expected, encodings);
    result.capture.workspace_root = PORTABLE_WORKSPACE_ROOT;
    writeStableJson(output, result);
    for (const encoding of encodings) {
      const metrics = result.tokenizers[encoding];
      console.log(
        `${result.repository.display_name} ${encoding}: ${metrics.raw_tokens.toLocaleString("en-US")} raw tokens -> ${metrics.outline_tokens.toLocaleString("en-US")} outline tokens (${metrics.reduction_percent.toFixed(1)}% fewer, ${metrics.multiplier.toFixed(2)}x)`,
      );
    }
    console.log(`Verified result: ${output}`);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(`reproduce: ${error.message ?? error}`);
  process.exitCode = 1;
}
