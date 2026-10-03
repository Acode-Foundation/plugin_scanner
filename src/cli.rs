use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::{archive::Limits, report::Recommendation, severity::Severity};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Security scanner for Acode plugin zip archives"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan one plugin zip.
    #[command(group(
        ArgGroup::new("output_format")
            .args(["format", "json", "markdown", "summary", "terminal"])
            .multiple(false)
    ))]
    Scan {
        /// Path to the plugin zip archive.
        zip: PathBuf,
        /// Output format.
        #[arg(long, value_enum)]
        format: Option<OutputFormat>,
        /// Emit JSON (for servers).
        #[arg(long)]
        json: bool,
        /// Emit the full Markdown report (for reviewers).
        #[arg(long, short = 'm')]
        markdown: bool,
        /// Emit a short Markdown capability summary (for plugin pages).
        #[arg(long)]
        summary: bool,
        /// Emit an annotated terminal report (default).
        #[arg(long, short = 't')]
        terminal: bool,
        /// Only analyse the script Acode loads (`main` or main.js). By default
        /// every JavaScript and HTML file is analysed, because the entry script
        /// can load the rest at runtime.
        #[arg(long)]
        entry_only: bool,
        /// Kept for compatibility; scanning all JS is now the default.
        #[arg(long, hide = true)]
        all_js: bool,
        #[command(flatten)]
        gate: Gate,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Compare two versions of a plugin and report what changed.
    Diff {
        /// Currently published zip.
        old: PathBuf,
        /// Uploaded update.
        new: PathBuf,
        #[arg(long, value_enum, default_value_t = DiffFormat::Terminal)]
        format: DiffFormat,
        /// Exit with code 1 when the diff recommendation is at least this.
        #[arg(long, value_enum)]
        fail_on: Option<RecommendationLevel>,
        #[command(flatten)]
        limits: LimitArgs,
    },
}

#[derive(Debug, Args)]
pub struct Gate {
    /// Exit with code 1 when the scan reaches this level: a severity
    /// (info..critical) or a recommendation (review, block).
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOn>,
}

#[derive(Debug, Clone, Copy, Args)]
pub struct LimitArgs {
    /// Maximum uncompressed size of one archive entry, in bytes.
    #[arg(long, default_value_t = Limits::default().max_entry_bytes)]
    pub max_entry_bytes: u64,
    /// Maximum total uncompressed size, in bytes.
    #[arg(long, default_value_t = Limits::default().max_total_bytes)]
    pub max_total_bytes: u64,
    /// Maximum number of archive entries.
    #[arg(long, default_value_t = Limits::default().max_entries)]
    pub max_entries: usize,
}

impl From<LimitArgs> for Limits {
    fn from(args: LimitArgs) -> Self {
        Self {
            max_entries: args.max_entries,
            max_entry_bytes: args.max_entry_bytes,
            max_total_bytes: args.max_total_bytes,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    #[value(alias = "markdown")]
    Md,
    #[value(alias = "md-summary", alias = "markdown-summary")]
    Summary,
    Terminal,
}

impl OutputFormat {
    pub fn from_flags(format: Option<Self>, json: bool, markdown: bool, summary: bool) -> Self {
        match format {
            Some(format) => format,
            None if json => Self::Json,
            None if summary => Self::Summary,
            None if markdown => Self::Md,
            None => Self::Terminal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffFormat {
    Json,
    #[value(alias = "markdown")]
    Md,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Review,
    Block,
}

impl FailOn {
    pub fn triggered(self, max: Option<Severity>, recommendation: Recommendation) -> bool {
        let severity = match self {
            Self::Info => Severity::Info,
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
            Self::Review => return recommendation >= Recommendation::Review,
            Self::Block => return recommendation >= Recommendation::Block,
        };
        max.is_some_and(|max| max >= severity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RecommendationLevel {
    Review,
    Block,
}

impl RecommendationLevel {
    pub fn triggered(self, recommendation: Recommendation) -> bool {
        match self {
            Self::Review => recommendation >= Recommendation::Review,
            Self::Block => recommendation >= Recommendation::Block,
        }
    }
}
