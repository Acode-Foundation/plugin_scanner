# Acode Plugin Scanner

Rust CLI for scanning Acode plugin zip packages before publishing. It validates
`plugin.json`, checks archive safety, parses JavaScript with Oxc, and emits a
deterministic security report. The scanner is report-only: it does not block
publishing by itself.

## Usage

```sh
cargo run --manifest-path tools/plugin_scanner/Cargo.toml -- scan plugin.zip
```

By default, the scanner renders a terminal report with source annotations.

```sh
# Terminal report, default
plugin_scanner scan plugin.zip

# JSON report for server ingestion
plugin_scanner scan plugin.zip --json
plugin_scanner scan plugin.zip --format json

# Markdown report
plugin_scanner scan plugin.zip --markdown
plugin_scanner scan plugin.zip --format md

# Concise user-facing Markdown capability summary
plugin_scanner scan plugin.zip --summary
plugin_scanner scan plugin.zip --format summary
```

Use `--all-js` to scan every JavaScript-like file in the archive. Without it,
the scanner follows Acode runtime behavior and scans the manifest `main` entry,
falls back to `main.js` when needed, and includes JavaScript files referenced by
the manifest.

```sh
plugin_scanner scan plugin.zip --all-js
```

## Report Formats

The JSON report contains:

- `scanner_version`
- `plugin`
- `summary`
- `findings`
- `errors`
- `stats`

Terminal output uses Ariadne annotations. For minified bundles, annotations show
a compact excerpt around each finding instead of printing the whole one-line
bundle.

## What It Checks

Manifest and archive checks:

- missing or malformed `plugin.json`
- missing required fields: `id`, `name`, `main`, `version`
- referenced files that do not exist
- unsafe paths, duplicate zip entries, oversized files, and nested archives
- Acode `dist/main.js` and `main.js` loading behavior alignment

JavaScript checks:

- network use: `fetch`, `XMLHttpRequest`, websocket use, hardcoded URLs
- dynamic code: `eval`, `Function`, string timers, dynamic script injection
- Cordova and Acode privileged APIs: `cordova.exec`, `intent`, `system`,
  `sdcard`, `Executor`, `Terminal`, `CreateServer`, `ftp`, `sftp`,
  `cordova.websocket`
- filesystem and storage: `fsOperation`, file reads/writes/deletes,
  sensitive storage constants, `localStorage`, cookies
- persistence and hooks: plugin init/unmount hooks, global mutation, command and
  formatter registration, event and intent handlers
- Acode module registry usage: `acode.require(...)` imports, including modules
  exported by Acode or by other plugins, and `acode.define(...)` APIs exposed by
  the scanned plugin for other plugins to import
- obfuscation: very long minified lines, base64-like blobs, decoder APIs, hex
  payload arrays

The rules are intentionally explainable. Findings describe risky capability use
and include severity, confidence, category, file, span, message, and evidence.
Severity is a capability-risk signal, not proof that a plugin is malicious.
Use `--summary` when you want a compact disclosure of APIs/capabilities a user
should know about; use `--markdown` or `--json` when you need the full audit
trail with every raw finding.

## Development

Run tests:

```sh
cargo test --manifest-path tools/plugin_scanner/Cargo.toml
```

Run Clippy:

```sh
cargo clippy --manifest-path tools/plugin_scanner/Cargo.toml --all-targets -- -D warnings
```

Build:

```sh
cargo build --manifest-path tools/plugin_scanner/Cargo.toml --release
```
