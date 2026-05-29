use crate::{report::Report, severity::Severity};

pub fn render_markdown(report: &Report) -> String {
    let mut lines = Vec::new();
    lines.push("# Plugin Scan Report".to_string());
    lines.push(String::new());

    if let Some(plugin) = &report.plugin {
        lines.push(format!(
            "- **Plugin:** {}",
            plugin.name.as_deref().unwrap_or("Unknown")
        ));
        lines.push(format!(
            "- **ID:** `{}`",
            plugin.id.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "- **Version:** {}",
            plugin.version.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "- **Main:** `{}`",
            plugin.main.as_deref().unwrap_or("unknown")
        ));
    }

    lines.push(format!(
        "- **Files scanned:** {}",
        report.stats.files_scanned
    ));
    lines.push(format!(
        "- **JavaScript files parsed:** {}",
        report.stats.js_files_parsed
    ));
    lines.push(format!(
        "- **Total findings:** {}",
        report.summary.total_findings
    ));
    lines.push(String::new());

    if !report.summary.by_severity.is_empty() {
        lines.push("## Severity Summary".to_string());
        lines.push(String::new());
        for severity in ["critical", "high", "medium", "low", "info"] {
            if let Some(count) = report.summary.by_severity.get(severity) {
                lines.push(format!("- **{}:** {}", title_case(severity), count));
            }
        }
        lines.push(String::new());
    }

    if !report.summary.by_category.is_empty() {
        lines.push("## Category Summary".to_string());
        lines.push(String::new());
        for (category, count) in &report.summary.by_category {
            lines.push(format!("- **{}:** {}", category.replace('_', " "), count));
        }
        lines.push(String::new());
    }

    if report.findings.is_empty() {
        lines.push("## Findings".to_string());
        lines.push(String::new());
        lines.push("No notable findings were detected.".to_string());
    } else {
        lines.push("## Findings".to_string());
        lines.push(String::new());
        for finding in sorted_findings(report) {
            let location = match (&finding.file, finding.span) {
                (Some(file), Some(span)) => {
                    format!("`{}:{}:{}`", file, span.start_line, span.start_column)
                }
                (Some(file), None) => format!("`{file}`"),
                (None, _) => "`archive`".to_string(),
            };
            lines.push(format!(
                "- **{:?}** `{}` ({:?}, {:?}) at {}",
                finding.severity, finding.id, finding.category, finding.confidence, location
            ));
            lines.push(format!("  - {}", finding.message));
            if !finding.evidence.is_empty() {
                lines.push(format!(
                    "  - Evidence: `{}`",
                    escape_backticks(&finding.evidence)
                ));
            }
        }
    }

    if !report.errors.is_empty() {
        lines.push(String::new());
        lines.push("## Scan Errors".to_string());
        lines.push(String::new());
        for error in &report.errors {
            lines.push(format!(
                "- `{}`: {}",
                error.file.as_deref().unwrap_or("scanner"),
                error.message
            ));
        }
    }

    lines.join("\n")
}

fn sorted_findings(report: &Report) -> Vec<&crate::report::Finding> {
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by_key(|finding| {
        (
            severity_rank(finding.severity),
            finding.file.as_deref().unwrap_or(""),
            finding.id.as_str(),
        )
    });
    findings
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn escape_backticks(value: &str) -> String {
    value.replace('`', "\\`")
}
