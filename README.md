# Acode Plugin Scanner

Security scanner for Acode plugin zips. It reads the archive the same way the
Acode installer does, analyses every JavaScript/HTML file with Oxc (including
semantic scope analysis), and returns a verdict: **pass**, **review**, or
**block**. A `diff` command compares two versions, which is the view that
matters when an approved plugin is updated.

The scanner only reports. It never changes or rejects a plugin on its own;
the site or CI decides what to do with the verdict.

## Quick start

```sh
cargo build --release

# Human-readable report (default)
plugin_scanner scan plugin.zip

# JSON for servers; exit code 1 if the verdict is review or worse
plugin_scanner scan plugin.zip --json --fail-on review

# Compare the published version with an uploaded update
plugin_scanner diff published.zip update.zip --format json --fail-on review
```

| Command / flag | What it does |
| --- | --- |
| `scan <zip>` | Full scan. Formats: `--format terminal` (default), `json`, `md` (reviewer report), `summary` (short user-facing disclosure). Shorthands: `--json`, `--markdown`, `--summary`. |
| `diff <old> <new>` | What changed between two versions: new or escalated findings, new hosts, modules, permissions, changed files. `--format terminal\|json\|md`. |
| `--fail-on <level>` | Exit 1 when reached. For `scan`: `info`…`critical` (highest severity) or `review` / `block` (recommendation). For `diff`: `review` / `block`. |
| `--entry-only` | Only analyse the script Acode loads. By default every JS/HTML file is analysed, because the entry script can load the rest at runtime. |
| `--max-entry-bytes`, `--max-total-bytes`, `--max-entries` | Zip-bomb limits (defaults: 32 MiB per entry, 256 MiB total, 5000 entries). |

Exit codes: `0` scan finished (threshold not reached), `1` `--fail-on`
threshold reached, `2` unreadable archive or other error.

## Verdict

| Recommendation | Meaning | Typical cause |
| --- | --- | --- |
| `pass` | Nothing above Medium. Safe to publish without a human look. | Normal editor plugins: fs, fetch, commands, storage, settings. |
| `review` | Something powerful enough that a person should look. | Shell/terminal access, all-files permission, Play billing, obfuscation, tampering with other plugins, decoded code execution, scan incomplete. |
| `block` | A Critical finding: no legitimate plugin needs it, or the zip is built to confuse the installer. | Remote code execution, core-module hijack, download-and-run shell commands, plugin-context bridge calls, exfiltration to webhooks, install-path collisions, no `plugin.json`. |

For **updates**, use `diff`. A terminal plugin always comes out as `review`
on a full scan, but if nothing new appears in the diff, the update is `pass`.
Updates that add a High/Critical capability, a new declared permission, or a
new flagged host are `review` (or `block`).

Severity guide:

- **Critical**: no legitimate plugin does this.
- **High**: powerful; a person should look.
- **Medium**: worth telling users; normal for some plugins.
- **Low / Info**: inventory only, never affects the verdict.

## How it avoids false positives

The first version matched API names in text, which flagged almost every real
plugin as critical (`e.read()`, `n.copy()`, `window.cordova`, webpack's
`Function("return this")`, font base64, every URL). Now:

- **Locals vs globals.** Oxc's semantic analysis means a parameter called
  `system` or a local `fetch` is not the Acode global.
- **Real Acode surface.** Rules are keyed on what Acode exposes: `window.*`
  globals from `src/lib`, Cordova clobbers (`system`, `sdcard`, `Executor`,
  `Terminal`, `ftp`, `sftp`, `iap`, `CreateServer`, `cordova.plugin.http`) and
  the modules registered in `lib/acode.js`. Generic method names on unknown
  receivers are, at most, Low-confidence hints.
- **Context-graded sinks.** `eval(x)` with an unknown argument is Medium. It
  becomes High when the argument comes from a decoder (`atob`,
  `fromCharCode`...) and Critical when it comes from a network response.
  Bundler idioms (`Function("return this")`, `<script>` chunk loaders with
  relative URLs) are ignored.
- **Aggregation.** One finding per rule, stable key, and file, with an
  occurrence count and up to 8 locations.
- **Endpoints are inventory.** URLs go into an `endpoints` list. Only known
  exfiltration or payload hosts become findings: webhooks, request bins,
  Telegram bot API, Apps Script, paste sites, tunnels, shorteners, raw public
  IPs, `.onion`.
- **Base64 is decoded.** A long base64 string is only flagged when it decodes
  to JavaScript.

## How it avoids being fooled

- **Installer-accurate archive model.** Acode installs with JSZip and its own
  `sanitizeZipPath`, which collapses `..` instead of rejecting it and keeps the
  last duplicate. The scanner mirrors that exactly, and flags these cases:
  - `x/../main.js` overwriting `main.js`
  - duplicate entries
  - absolute paths
  - encrypted entries
  - compression methods other than stored/deflate
  - native binaries detected by magic bytes

  Overwritten entries are still analysed.
- **Entry resolution like `installPlugin.js`.** `main` is looked up by exact
  key, so `"./dist/main.js"` falls back to `main.js`, just as on device.
- **Alias and constant-string resolution.** These all resolve:
  - `const w = window`, `const { exec } = cordova`
  - `acode.require("fs")` stored in a variable
  - `window["ev" + "al"]`, `atob("ZXZhbA==")`
  - `String.fromCharCode(...)`, `[...].join("")`, `"lave".split("").reverse().join("")`
  - `(0, fn)(...)`
- **One-hop taint.** Values built from `fetch` / `XMLHttpRequest` responses or
  decoders are tracked through variables and `.then(...)` chains.
- **Zip-bomb safe.** Reads are capped by the limits, not by declared sizes.
  Hitting a limit marks the scan incomplete, which forces `review`.

## Rules

| Area | Rule IDs (severity) |
| --- | --- |
| Archive | `install_path_collision` (C), `path_traversal`, `duplicate_entry`, `encrypted_entry`, `unsupported_compression`, `oversized_entry`, `total_size_limit`, `too_many_entries`, `native_binary` (H), `absolute_path`, `nested_archive` (M) |
| Manifest | `missing`, `invalid_json`, `no_entrypoint` (C), `missing_id/name/version` (H), `invalid_id`, `invalid_version`, `invalid_price`, `invalid_min_version_code`, `missing_icon`, `missing_readme`, `non_js_entry` (M), `dependencies`, `icon_too_large` (L), `main_fallback` (I) |
| Shell | `dangerous_command` (C/H/M: download-and-run, decode-and-run, reverse shell, miner, wiping `/sdcard`/`$HOME`, other apps' data, `su`, shell-profile persistence), `load_library` (C), `exec`, `terminal_module` (H), `terminal_environment`, `process_control` (M/H) |
| Native | `plugin_context_bridge` (`cordova.exec` to `Tee`), `cordova_exec_dynamic` (C), `cordova_exec`, `manage_all_files`, `in_app_purchase` (H), `permission_request`, `launch_app`, `intent_access`, `purchase_read`, `cordova_require`, `cordova_plugin` (M), `file_intent`, `device_setting`, `os_integration` (L) |
| Tampering | `core_module_override` (`acode.define("fs")` etc.) (C), `acode_api`, `cordova_bridge`, `network_hook`, `other_plugin`, `plugin_files` (writes into another plugin's folder), `rewards` (H), `editor_manager`, `define_dynamic`, `unmount_dynamic` (M) |
| Dynamic code | `remote_code`, `remote_import` (C), `remote_script`, `remote_worker`, `decoded_exec`, `indirect_function_constructor` (H), `eval`, `function_constructor`, `inline_script`, `script_blob`, `html_script` (M), `string_timer`, `script_element`, `import_expression` (L) |
| Network | `suspicious_endpoint` (H/M/L by host type), `remote_command` (H), `native_http`, `remote_storage`, `local_server`, `beacon` (M), `fetch`, `xhr`, `websocket`, `event_source`, `open_browser` (L) |
| Filesystem / storage | `delete`, `sdcard_write`, `system_write`, `system_exec_bits`, `storage_access_request`, `cordova_file` (M), `write`, `sdcard_read`, `system_read`, `cookies`, `clipboard_read` (L), `read`, `module`, `plugin_dir`, `web_storage`, `indexeddb` (I) |
| Obfuscation | `obfuscator_tool`, `packer`, `jsfuck`, `encoded_js_payload` (H), `js.parse_failed`, `js.too_large`, `js.invalid_utf8` (M), `escaped_strings`, `hex_array` (L) |
| Correlation | `exfiltration` (C): reads user data (files, editor text, storage, clipboard, keys) and talks to a data-capture endpoint |

Prefixes are omitted in the table; full IDs look like `shell.exec`.

## JSON report (`schema_version: 2`)

```jsonc
{
  "schema_version": 2,
  "scanner_version": "0.2.0",
  "rules_version": "2026.10.1",        // rescan stored plugins when this changes
  "plugin": { "id", "name", "version", "main", "entry", "permissions", "dependencies", ... },
  "verdict": { "risk": "high", "recommendation": "review", "complete": true, "reasons": ["..."] },
  "summary": { "total_findings", "by_severity", "by_category" },
  "capabilities": [{ "category", "title", "description", "severity", "rules", "evidence" }],
  "endpoints": [{ "host", "count", "example", "tags" }],
  "modules": { "required": ["fs", "terminal"], "defined": ["myapi"] },
  "findings": [{
    "id", "severity", "category", "confidence", "file", "span", "message", "evidence",
    "key",                              // stable across rebuilds; used by diff
    "occurrences", "examples", "locations"
  }],
  "files": [{ "path", "size", "sha256", "kind" }],
  "errors": [{ "file", "message" }],
  "stats": { "archive_entries", "installed_files", "bytes_uncompressed", "js_files_parsed", "js_bytes_parsed", "minified_files" }
}
```

`diff --format json` returns `recommendation`, `reasons`, `new_findings`,
`escalated`, `removed_findings`, `new_endpoints`, `new_required_modules`,
`new_defined_modules`, `new_permissions`, and `files` (added/removed/changed).

## Using it on acode.app

Suggested flow for `POST /api/plugin` (new) and `PUT /api/plugin` (update):

1. Run the existing `exploreZip`/`validatePlugin` checks, then save the zip to
   a quarantine path, not `data/plugins/{id}.zip`.
2. Run the scanner in a child process with a timeout. Store the JSON with the
   zip's SHA-256, `scanner_version`, and `rules_version`.
3. Decide:
   - New plugin: always goes to admin review, with the Markdown report attached.
   - Update: `diff published.zip quarantine.zip`. If it passes, promote the
     zip. Otherwise hold it as pending and email admins.
4. Show `scan --summary` (or `capabilities` from the JSON) on the plugin page.
5. When `rules_version` changes, rescan every published zip.

```js
const { execFile } = require('node:child_process');

function scan(args) {
  return new Promise((resolve, reject) => {
    execFile('plugin_scanner', args, { timeout: 30_000, maxBuffer: 32 * 1024 * 1024 }, (error, stdout) => {
      // Exit code 1 only means the --fail-on threshold was reached.
      if (error && error.code !== 1) return reject(error);
      resolve(JSON.parse(stdout));
    });
  });
}

const report = await scan(['scan', quarantinePath, '--json']);
const diff = published ? await scan(['diff', publishedPath, quarantinePath, '--format', 'json']) : null;
```

Run it as an unprivileged user with no network access and a memory limit
(e.g. `prlimit --as=1G`). It parses untrusted input.

### Calibrating against the registry

`scripts/scan-dir.sh` scans every zip in a folder and prints one line per
plugin plus totals. Run it on the server against `data/plugins` to see the
verdict mix before turning on automatic holds. Don't download from the public
API for this: downloads are counted.

```sh
scripts/scan-dir.sh /path/to/acode-app/data/plugins > scan-results.tsv
```

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

When adding a rule:
- Put it in `src/rules.rs`.
- Give it a stable `key` (no minified names) so `diff` stays quiet across rebuilds.
- Add a positive and a negative test.
- Bump `RULES_VERSION` in `src/report.rs`.
