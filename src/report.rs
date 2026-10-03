use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::severity::{Category, Confidence, Severity};

/// Bumped whenever the JSON shape changes incompatibly.
pub const SCHEMA_VERSION: u32 = 2;
/// Bumped whenever rules or severities change, so stored reports can be rescanned.
pub const RULES_VERSION: &str = "2026.10.1";

/// Upper bound on extra source locations kept per aggregated finding.
const MAX_LOCATIONS: usize = 8;
/// Upper bound on distinct evidence samples kept per aggregated finding.
const MAX_EXAMPLES: usize = 6;

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub scanner_version: String,
    pub rules_version: String,
    pub plugin: Option<PluginSummary>,
    pub verdict: Verdict,
    pub summary: Summary,
    pub capabilities: Vec<Capability>,
    pub endpoints: Vec<Endpoint>,
    pub modules: Modules,
    pub findings: Vec<Finding>,
    pub files: Vec<FileEntry>,
    pub errors: Vec<ScanError>,
    pub stats: Stats,
    #[serde(skip)]
    pub sources: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PluginSummary {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    /// `main` as written in plugin.json.
    pub main: Option<String>,
    /// The script Acode actually loads after its `main.js` fallback.
    pub entry: Option<String>,
    pub min_version_code: Option<i64>,
    pub price: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    pub repository: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    /// Nothing above medium; safe to publish without a human look.
    #[default]
    Pass,
    /// Something a reviewer should look at before publishing.
    Review,
    /// Strong evidence of malicious or installer-confusing content.
    Block,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Verdict {
    pub risk: Option<Severity>,
    pub recommendation: Recommendation,
    /// False when limits were hit or files could not be analysed.
    pub complete: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub total_findings: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_category: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub category: Category,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub rules: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Endpoint {
    pub host: String,
    pub count: usize,
    pub example: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Modules {
    /// Names passed to `acode.require`, lowercased like Acode does.
    pub required: BTreeSet<String>,
    /// Names passed to `acode.define`, lowercased like Acode does.
    pub defined: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub confidence: Confidence,
    pub file: Option<String>,
    pub span: Option<SourceSpan>,
    pub message: String,
    pub evidence: String,
    /// Stable identity used to compare two versions of a plugin. It never
    /// contains minified variable names, so rebuilding doesn't change it.
    pub key: String,
    pub occurrences: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SourceSpan>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        category: Category,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        let id = id.into();
        Self {
            key: id.clone(),
            id,
            severity,
            category,
            confidence: Confidence::High,
            file: None,
            span: None,
            message: message.into(),
            evidence: evidence.into(),
            occurrences: 1,
            examples: Vec::new(),
            locations: Vec::new(),
        }
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn keyed(mut self, detail: impl AsRef<str>) -> Self {
        self.key = format!("{}:{}", self.id, detail.as_ref());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanError {
    pub file: Option<String>,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub archive_entries: usize,
    pub installed_files: usize,
    pub bytes_uncompressed: u64,
    pub js_files_parsed: usize,
    pub js_bytes_parsed: u64,
    pub minified_files: usize,
}

impl Report {
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            rules_version: RULES_VERSION.to_string(),
            verdict: Verdict {
                complete: true,
                ..Verdict::default()
            },
            ..Self::default()
        }
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn error(&mut self, file: Option<&str>, message: impl Into<String>) {
        self.errors.push(ScanError {
            file: file.map(str::to_string),
            message: message.into(),
        });
    }

    pub fn mark_incomplete(&mut self) {
        self.verdict.complete = false;
    }

    #[cfg(test)]
    pub fn has(&self, id: &str) -> bool {
        self.findings.iter().any(|finding| finding.id == id)
    }

    /// Collapses repeated hits of the same rule into one finding per
    /// (rule, key, file), keeping a few locations and evidence samples.
    pub fn aggregate_findings(&mut self) {
        let mut order: Vec<(String, String, Option<String>)> = Vec::new();
        let mut groups: HashMap<(String, String, Option<String>), Finding> = HashMap::new();

        for finding in self.findings.drain(..) {
            let group_key = (
                finding.id.clone(),
                finding.key.clone(),
                finding.file.clone(),
            );
            match groups.get_mut(&group_key) {
                Some(existing) => {
                    existing.occurrences += finding.occurrences;
                    existing.severity = existing.severity.max(finding.severity);
                    existing.confidence = existing.confidence.max(finding.confidence);
                    if let Some(span) = finding.span
                        && existing.locations.len() < MAX_LOCATIONS
                        && existing.span != Some(span)
                    {
                        existing.locations.push(span);
                    }
                    if finding.evidence != existing.evidence
                        && !existing.examples.contains(&finding.evidence)
                        && existing.examples.len() < MAX_EXAMPLES
                    {
                        existing.examples.push(finding.evidence);
                    }
                }
                None => {
                    order.push(group_key.clone());
                    groups.insert(group_key, finding);
                }
            }
        }

        self.findings = order
            .into_iter()
            .filter_map(|key| groups.remove(&key))
            .collect();
        self.findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.category.cmp(&right.category))
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| left.file.cmp(&right.file))
        });
    }

    pub fn refresh_summary(&mut self) {
        let mut by_severity = BTreeMap::new();
        let mut by_category = BTreeMap::new();
        for finding in &self.findings {
            *by_severity
                .entry(finding.severity.key().to_string())
                .or_insert(0) += 1;
            *by_category
                .entry(finding.category.key().to_string())
                .or_insert(0) += 1;
        }
        self.summary = Summary {
            total_findings: self.findings.len(),
            by_severity,
            by_category,
        };
    }
}
