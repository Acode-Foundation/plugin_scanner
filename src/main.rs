mod analysis;
mod archive;
mod cli;
mod diff;
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
    analysis::ScanOptions,
    cli::{Cli, Command, DiffFormat, OutputFormat},
    report::Report,
};

/// Scan finished and nothing reached `--fail-on`.
const EXIT_OK: u8 = 0;
/// Scan finished and the `--fail-on` threshold was reached.
const EXIT_THRESHOLD: u8 = 1;
/// The archive couldn't be read or the report couldn't be written.
const EXIT_ERROR: u8 = 2;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("plugin_scanner: {error}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Scan {
            zip,
            format,
            json,
            markdown,
            summary,
            terminal: _,
            entry_only,
            all_js: _,
            gate,
            limits,
        } => {
            let options = ScanOptions {
                entry_only,
                limits: limits.into(),
            };
            let report = analysis::scan_zip(&zip, options).map_err(|error| error.to_string())?;
            let format = OutputFormat::from_flags(format, json, markdown, summary);
            println!("{}", render_report(&report, format)?);
            let failed = gate.fail_on.is_some_and(|level| {
                level.triggered(report.verdict.risk, report.verdict.recommendation)
            });
            Ok(if failed { EXIT_THRESHOLD } else { EXIT_OK })
        }
        Command::Diff {
            old,
            new,
            format,
            fail_on,
            limits,
        } => {
            let options = ScanOptions {
                entry_only: false,
                limits: limits.into(),
            };
            let old_report = analysis::scan_zip(&old, options)
                .map_err(|error| format!("{}: {error}", old.display()))?;
            let new_report = analysis::scan_zip(&new, options)
                .map_err(|error| format!("{}: {error}", new.display()))?;
            let diff = diff::diff(&old_report, &new_report);
            let output = match format {
                DiffFormat::Json => {
                    serde_json::to_string_pretty(&diff).map_err(|error| error.to_string())?
                }
                DiffFormat::Md => diff::render_text(&diff, true),
                DiffFormat::Terminal => diff::render_text(&diff, false),
            };
            println!("{output}");
            let failed = fail_on.is_some_and(|level| level.triggered(diff.recommendation));
            Ok(if failed { EXIT_THRESHOLD } else { EXIT_OK })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{report::Recommendation, severity::Severity};

    #[test]
    fn fail_on_thresholds() {
        use cli::FailOn;
        assert!(FailOn::High.triggered(Some(Severity::Critical), Recommendation::Block));
        assert!(!FailOn::High.triggered(Some(Severity::Medium), Recommendation::Pass));
        assert!(!FailOn::High.triggered(None, Recommendation::Pass));
        assert!(FailOn::Review.triggered(Some(Severity::High), Recommendation::Review));
        assert!(!FailOn::Block.triggered(Some(Severity::High), Recommendation::Review));
    }
}
