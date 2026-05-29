use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::severity::{Category, Confidence, Severity};

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub scanner_version: String,
    pub plugin: Option<PluginSummary>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
    pub stats: Stats,
    #[serde(skip)]
    pub sources: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub main: Option<String>,
    pub version: Option<String>,
    pub min_version_code: Option<u64>,
    pub price: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub total_findings: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_category: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub file: Option<String>,
    pub span: Option<SourceSpan>,
    pub message: String,
    pub evidence: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SourceSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanError {
    pub file: Option<String>,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub js_files_parsed: usize,
}

impl Report {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            scanner_version: version.into(),
            ..Self::default()
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_finding(
        &mut self,
        id: impl Into<String>,
        severity: Severity,
        category: Category,
        file: Option<String>,
        span: Option<SourceSpan>,
        message: impl Into<String>,
        evidence: impl Into<String>,
        confidence: Confidence,
    ) {
        self.findings.push(Finding {
            id: id.into(),
            severity,
            category,
            file,
            span,
            message: message.into(),
            evidence: evidence.into(),
            confidence,
        });
    }

    pub fn refresh_summary(&mut self) {
        let mut by_severity = BTreeMap::new();
        let mut by_category = BTreeMap::new();
        for finding in &self.findings {
            *by_severity
                .entry(format!("{:?}", finding.severity).to_ascii_lowercase())
                .or_insert(0) += 1;
            *by_category
                .entry(format!("{:?}", finding.category).to_ascii_snake_case())
                .or_insert(0) += 1;
        }

        self.summary = Summary {
            total_findings: self.findings.len(),
            by_severity,
            by_category,
        };
    }

    pub fn deduplicate_findings(&mut self) {
        let mut seen = HashSet::new();
        self.findings.retain(|finding| {
            let key = (
                finding.id.clone(),
                finding.file.clone(),
                finding.evidence.clone(),
            );
            seen.insert(key)
        });
    }
}

trait SnakeCase {
    fn to_ascii_snake_case(&self) -> String;
}

impl SnakeCase for str {
    fn to_ascii_snake_case(&self) -> String {
        let mut out = String::new();
        for (index, ch) in self.chars().enumerate() {
            if ch.is_ascii_uppercase() {
                if index > 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}
