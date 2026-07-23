# Context Engine API-exploration benchmark

This benchmark compares the tokens in every tracked primary-language source file at a pinned repository revision with
the tokens in Context Engine's complete `outline` responses for the same files.

The published homepage figures use `tiktoken/o200k_base`:

| Repository | Language | Files | Raw source tokens | Outline tokens | Fewer tokens | Raw / outline |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [Django](https://github.com/django/django/tree/b34b834378adc590a771cccd44b9fb0b953cdca2) | Python | 2,924 | 4,183,402 | 1,470,516 | 64.8% | 2.84x |
| [Tokio](https://github.com/tokio-rs/tokio/tree/dac81bf8c8de0a3e35f1626643674ba9faf9569c) | Rust | 790 | 1,392,015 | 516,868 | 62.9% | 2.69x |
| [Gin](https://github.com/gin-gonic/gin/tree/34dac209ffb6ef85cc78c5d217bbb7ad001d68fd) | Go | 99 | 193,563 | 64,781 | 66.5% | 2.99x |
| [Cliffy](https://github.com/c4spar/cliffy/tree/c266907b722f2acec2f978f5911a8f3e3cac9ef5) | TypeScript | 361 | 335,276 | 182,324 | 45.6% | 1.84x |

This is a retrieved-context measurement, not an end-to-end task benchmark. `outline` maps structural API; an agent can
selectively fetch exact implementations, types, documentation, definitions, and usages when the task requires them.

## Reproduce the results

Prerequisites:

- Git
- Node.js 24 or later
- npm

Install the locked tokenizer dependency:

```sh
cd benchmarks/api_exploration
npm ci --prefix launch-artifacts/tools
```

Clone the repositories and check out the measured revisions:

```sh
mkdir -p checkouts

git clone https://github.com/django/django.git checkouts/django
git -C checkouts/django checkout --detach b34b834378adc590a771cccd44b9fb0b953cdca2

git clone https://github.com/tokio-rs/tokio.git checkouts/tokio
git -C checkouts/tokio checkout --detach dac81bf8c8de0a3e35f1626643674ba9faf9569c

git clone https://github.com/gin-gonic/gin.git checkouts/gin
git -C checkouts/gin checkout --detach 34dac209ffb6ef85cc78c5d217bbb7ad001d68fd

git clone https://github.com/c4spar/cliffy.git checkouts/cliffy
git -C checkouts/cliffy checkout --detach c266907b722f2acec2f978f5911a8f3e3cac9ef5
```

Replay each measurement:

```sh
node scripts/reproduce.mjs --repo django --checkout checkouts/django
node scripts/reproduce.mjs --repo tokio --checkout checkouts/tokio
node scripts/reproduce.mjs --repo gin --checkout checkouts/gin
node scripts/reproduce.mjs --repo cliffy --checkout checkouts/cliffy
```

Each command:

1. verifies that the checkout resolves to the pinned revision;
2. independently enumerates every tracked primary-language file and rejects any manifest omission;
3. verifies every manifest file against the corresponding Git blob;
4. validates capture completeness, ordering, hashes, and truncation rejection;
5. tokenizes raw source and the preserved outline response text with `tiktoken/o200k_base`;
6. compares the result with the committed expected metrics.

The complete result is written to `results/<repository>.json`, with its local checkout path replaced by
`<repository-root>`. Token and byte metrics are deterministic; artifact hashes that cover materialized request envelopes
can differ when the checkout path differs. To measure both supported encodings, append:

```sh
--encoding o200k_base --encoding cl100k_base
```

## Accounting contract

Raw source:

- includes every Git-tracked file listed in the committed manifest;
- defines primary-language files as `.py` for Django, `.rs` for Tokio, `.go` for Gin, and `.ts` for Cliffy;
- measures UTF-8 source bytes and tokenizer counts per file;
- adds no separators between files.

Outline context:

- includes every final accepted `outline` response exactly once and in manifest order;
- joins text blocks within each MCP response with one line feed;
- includes Context Engine service guidance and saved receipts;
- excludes host-tool wrapper text that is not returned by Context Engine;
- adds no separators between responses.

The tokenized outline text is preserved verbatim in
`artifacts/<repository>/<revision>/outline-artifacts/*.response.json`. Capture request envelopes originally contained
local absolute workspace paths. The published artifacts replace only those non-tokenized paths with `<repository-root>`.
The reproduction runner restores the selected checkout path in a temporary copy so the original strict validation script
can run; it does not modify any measured `response.content[].text`.

## Provenance

- Tokenizer: `tiktoken` 1.0.22, locked by `package-lock.json`.
- Repository revisions and complete file manifests are committed with the captures.
- Each capture index records the Context Engine binary SHA-256, protocol version, language-server version, batching
  policy, per-response hashes, and acceptance state.
- The measurement script rejects revision drift, source drift, missing files, extra artifacts, reordered batches,
  changed response text, partial failures, and truncated responses.
- `capture_repository_outlines.mjs` is retained beside the measurement scripts because its SHA-256 is part of the
  capture provenance.

The capture files let anyone reproduce the published token accounting without uploading source code or requiring access
to the closed-source Context Engine binary.

Generated outlines can retain declarations and documentation from their source repositories. Their original license
notices are preserved in [`third-party-licenses/`](third-party-licenses/).
