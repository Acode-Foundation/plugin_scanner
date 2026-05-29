use std::path::PathBuf;

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(author, version, about = "Scan Acode plugin zip archives")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(group(
		ArgGroup::new("output_format")
			.args(["format", "json", "markdown", "terminal"])
			.multiple(false)
	))]
    Scan {
        /// Path to the plugin zip archive.
        zip: PathBuf,
        /// Output format: terminal, json, or md.
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Emit a human-readable Markdown report.
        #[arg(long, short = 'm')]
        markdown: bool,
        /// Emit a terminal-friendly table report.
        #[arg(long, short = 't')]
        terminal: bool,
        /// Scan every JavaScript file in the archive, including generated chunks.
        ///
        /// By default the scanner mirrors Acode runtime loading: it scans the resolved
        /// entry script plus JS files explicitly referenced by manifest `files`.
        #[arg(long)]
        all_js: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    #[value(alias = "markdown")]
    Md,
    Terminal,
}

impl OutputFormat {
    pub fn from_flags(format: Option<Self>, json: bool, markdown: bool, terminal: bool) -> Self {
        if let Some(format) = format {
            format
        } else if json {
            Self::Json
        } else if markdown {
            Self::Md
        } else {
            let _ = terminal;
            Self::Terminal
        }
    }
}
