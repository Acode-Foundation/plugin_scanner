//! Compares two versions of a plugin. For updates this is the useful view:
//! a terminal plugin always runs shell commands, but a terminal plugin that
//! suddenly talks to a webhook or starts decoding code is news.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{
    report::{Endpoint, Finding, Recommendation, Report, SCHEMA_VERSION},
    severity::Severity,
};

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub schema_version: u32,
    pub scanner_version: String,
    pub old: VersionInfo,
    pub new: VersionInfo,
    pub recommendation: Recommendation,
    pub reasons: Vec<String>,
    pub new_findings: Vec<Finding>,
    pub escalated: Vec<Escalation>,
    pub removed_findings: Vec<String>,
    pub new_endpoints: Vec<Endpoint>,
    pub removed_endpoints: Vec<String>,
    pub new_required_modules: Vec<String>,
    pub new_defined_modules: Vec<String>,
    pub new_permissions: Vec<String>,
    pub files: FileChanges,
}

#[derive(Debug, Serialize)]
pub struct VersionInfo {
    pub id: Option<String>,
    pub version: Option<String>,
    pub risk: Option<Severity>,
    pub recommendation: Recommendation,
}

#[derive(Debug, Serialize)]
pub struct Escalation {
    pub key: String,
    pub from: Severity,
    pub to: Severity,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct FileChanges {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

fn info(report: &Report) -> VersionInfo {
    VersionInfo {
        id: report.plugin.as_ref().and_then(|plugin| plugin.id.clone()),
        version: report
            .plugin
            .as_ref()
            .and_then(|plugin| plugin.version.clone()),
        risk: report.verdict.risk,
        recommendation: report.verdict.recommendation,
    }
}

/// Highest-severity finding per stable key, ignoring which file it came from
/// (bundlers move code between chunks freely).
fn by_key(report: &Report) -> BTreeMap<&str, &Finding> {
    let mut map: BTreeMap<&str, &Finding> = BTreeMap::new();
    for finding in report
        .findings
        .iter()
        .filter(|finding| finding.severity > Severity::Info)
    {
        map.entry(finding.key.as_str())
            .and_modify(|existing| {
                if finding.severity > existing.severity {
                    *existing = finding;
                }
            })
            .or_insert(finding);
    }
    map
}

pub fn diff(old: &Report, new: &Report) -> DiffReport {
    let old_findings = by_key(old);
    let new_findings_map = by_key(new);

    let new_findings: Vec<Finding> = new_findings_map
        .iter()
        .filter(|(key, _)| !old_findings.contains_key(*key))
        .map(|(_, finding)| (*finding).clone())
        .collect();
    let escalated: Vec<Escalation> = new_findings_map
        .iter()
        .filter_map(|(key, finding)| {
            let before = old_findings.get(key)?;
            (finding.severity > before.severity).then(|| Escalation {
                key: key.to_string(),
                from: before.severity,
                to: finding.severity,
                message: finding.message.clone(),
            })
        })
        .collect();
    let removed_findings: Vec<String> = old_findings
        .keys()
        .filter(|key| !new_findings_map.contains_key(*key))
        .map(|key| key.to_string())
        .collect();

    let old_hosts: BTreeSet<&str> = old
        .endpoints
        .iter()
        .map(|endpoint| endpoint.host.as_str())
        .collect();
    let new_hosts: BTreeSet<&str> = new
        .endpoints
        .iter()
        .map(|endpoint| endpoint.host.as_str())
        .collect();
    let new_endpoints: Vec<Endpoint> = new
        .endpoints
        .iter()
        .filter(|endpoint| !old_hosts.contains(endpoint.host.as_str()))
        .cloned()
        .collect();
    let removed_endpoints = old_hosts
        .difference(&new_hosts)
        .map(|host| host.to_string())
        .collect();

    let new_required_modules: Vec<String> = new
        .modules
        .required
        .difference(&old.modules.required)
        .cloned()
        .collect();
    let new_defined_modules: Vec<String> = new
        .modules
        .defined
        .difference(&old.modules.defined)
        .cloned()
        .collect();

    let permissions = |report: &Report| -> BTreeSet<String> {
        report
            .plugin
            .as_ref()
            .map(|plugin| plugin.permissions.iter().cloned().collect())
            .unwrap_or_default()
    };
    let new_permissions: Vec<String> = permissions(new)
        .difference(&permissions(old))
        .cloned()
        .collect();

    let old_files: BTreeMap<&str, &str> = old
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    let new_files: BTreeMap<&str, &str> = new
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();
    let files = FileChanges {
        added: new_files
            .keys()
            .filter(|path| !old_files.contains_key(*path))
            .map(|path| path.to_string())
            .collect(),
        removed: old_files
            .keys()
            .filter(|path| !new_files.contains_key(*path))
            .map(|path| path.to_string())
            .collect(),
        changed: new_files
            .iter()
            .filter(|(path, hash)| old_files.get(*path).is_some_and(|old| old != *hash))
            .map(|(path, _)| path.to_string())
            .collect(),
    };

    let mut reasons = Vec::new();
    let (old_info, new_info) = (info(old), info(new));
    if old_info.id.is_some() && old_info.id != new_info.id {
        reasons.push(format!(
            "Plugin id changed from {:?} to {:?}",
            old_info.id.as_deref().unwrap_or(""),
            new_info.id.as_deref().unwrap_or("")
        ));
    }
    for finding in new_findings
        .iter()
        .filter(|finding| finding.severity >= Severity::High)
    {
        reasons.push(format!(
            "New {}: {} [{}]",
            finding.severity.label(),
            finding.message,
            finding.key
        ));
    }
    for escalation in escalated
        .iter()
        .filter(|escalation| escalation.to >= Severity::High)
    {
        reasons.push(format!(
            "Escalated {} -> {}: {} [{}]",
            escalation.from.label(),
            escalation.to.label(),
            escalation.message,
            escalation.key
        ));
    }
    if !new_permissions.is_empty() {
        reasons.push(format!(
            "New declared permissions: {}",
            new_permissions.join(", ")
        ));
    }
    if !new.verdict.complete {
        reasons.push("New version could not be fully scanned".to_string());
    }

    let recommendation = if new.verdict.recommendation == Recommendation::Block {
        if reasons.is_empty() {
            reasons.push("New version is blocked on its own (see full scan)".to_string());
        }
        Recommendation::Block
    } else if !reasons.is_empty() {
        Recommendation::Review
    } else {
        Recommendation::Pass
    };

    DiffReport {
        schema_version: SCHEMA_VERSION,
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        old: old_info,
        new: new_info,
        recommendation,
        reasons,
        new_findings,
        escalated,
        removed_findings,
        new_endpoints,
        removed_endpoints,
        new_required_modules,
        new_defined_modules,
        new_permissions,
        files,
    }
}

pub fn render_text(diff: &DiffReport, markdown: bool) -> String {
    let heading = |text: &str| {
        if markdown {
            format!("## {text}")
        } else {
            format!("{text}\n{}", "-".repeat(text.len()))
        }
    };
    let mut out = Vec::new();
    out.push(if markdown {
        "# Plugin Update Diff".to_string()
    } else {
        "Plugin Update Diff\n==================".to_string()
    });
    out.push(String::new());
    let version = |info: &VersionInfo| {
        format!(
            "{} {} (risk: {}, {:?})",
            info.id.as_deref().unwrap_or("?"),
            info.version.as_deref().unwrap_or("?"),
            info.risk.map_or("none", Severity::key),
            info.recommendation
        )
    };
    out.push(format!("- Old: {}", version(&diff.old)));
    out.push(format!("- New: {}", version(&diff.new)));
    out.push(
        format!("- **Recommendation: {:?}**", diff.recommendation)
            .replace("**", if markdown { "**" } else { "" }),
    );
    out.push(String::new());

    if !diff.reasons.is_empty() {
        out.push(heading("Why"));
        out.extend(diff.reasons.iter().map(|reason| format!("- {reason}")));
        out.push(String::new());
    }
    if !diff.new_findings.is_empty() {
        out.push(heading("New findings"));
        for finding in &diff.new_findings {
            out.push(format!(
                "- {} `{}` {} ({})",
                finding.severity.label(),
                finding.key,
                finding.message,
                finding.file.as_deref().unwrap_or("archive")
            ));
        }
        out.push(String::new());
    }
    if !diff.escalated.is_empty() {
        out.push(heading("Escalated"));
        for escalation in &diff.escalated {
            out.push(format!(
                "- `{}` {} -> {}: {}",
                escalation.key,
                escalation.from.label(),
                escalation.to.label(),
                escalation.message
            ));
        }
        out.push(String::new());
    }
    if !diff.new_endpoints.is_empty() {
        out.push(heading("New network hosts"));
        for endpoint in &diff.new_endpoints {
            let tags = if endpoint.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", endpoint.tags.join(", "))
            };
            out.push(format!(
                "- `{}`{tags} e.g. {}",
                endpoint.host, endpoint.example
            ));
        }
        out.push(String::new());
    }
    let list = |title: &str, items: &[String], out: &mut Vec<String>| {
        if !items.is_empty() {
            out.push(format!("- {title}: {}", items.join(", ")));
        }
    };
    let mut other = Vec::new();
    list(
        "New acode.require modules",
        &diff.new_required_modules,
        &mut other,
    );
    list(
        "New acode.define modules",
        &diff.new_defined_modules,
        &mut other,
    );
    list("Removed findings", &diff.removed_findings, &mut other);
    list("Removed hosts", &diff.removed_endpoints, &mut other);
    list("Files added", &diff.files.added, &mut other);
    list("Files removed", &diff.files.removed, &mut other);
    list("Files changed", &diff.files.changed, &mut other);
    if !other.is_empty() {
        out.push(heading("Other changes"));
        out.extend(other);
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Category;

    fn report(findings: Vec<Finding>, recommendation: Recommendation) -> Report {
        let mut report = Report::new();
        report.findings = findings;
        report.verdict.recommendation = recommendation;
        report
    }

    #[test]
    fn unchanged_capabilities_pass_even_if_high() {
        let shell = Finding::new(
            "shell.exec",
            Severity::High,
            Category::Shell,
            "Runs shell",
            "ls",
        )
        .keyed("execute");
        let mut moved = shell.clone();
        moved.file = Some("chunk.js".into());
        let diff = diff(
            &report(vec![shell], Recommendation::Review),
            &report(vec![moved], Recommendation::Review),
        );
        assert_eq!(diff.recommendation, Recommendation::Pass);
        assert!(diff.new_findings.is_empty());
    }

    #[test]
    fn new_high_capability_needs_review() {
        let old = report(vec![], Recommendation::Pass);
        let new = report(
            vec![Finding::new(
                "dynamic.decoded_exec",
                Severity::High,
                Category::DynamicCode,
                "Runs decoded",
                "x",
            )],
            Recommendation::Review,
        );
        let diff = diff(&old, &new);
        assert_eq!(diff.recommendation, Recommendation::Review);
        assert_eq!(diff.new_findings.len(), 1);
    }
}
