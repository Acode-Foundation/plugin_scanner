use ariadne::{Color, Config, IndexType, Label, Report as AriadneReport, ReportKind, sources};

use crate::{
    report::{Finding, Report},
    severity::Severity,
};

const MAX_ANNOTATED_FINDINGS: usize = 20;
const EXCERPT_CONTEXT_CHARS: usize = 40;
const MAX_HIGHLIGHT_CHARS: usize = 64;

pub fn render_terminal(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&summary(report));

    let annotated = sorted_findings(report)
        .into_iter()
        .filter(|finding| finding.span.is_some())
        .take(MAX_ANNOTATED_FINDINGS)
        .collect::<Vec<_>>();

    if annotated.is_empty() {
        out.push_str("\nNo source annotations available for these findings.\n");
        return out;
    }

    out.push_str("\nAnnotated findings:\n\n");
    for finding in annotated {
        if let Some(rendered) = render_finding(report, finding) {
            out.push_str(&rendered);
            if !rendered.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
    }

    let annotated_count = report
        .findings
        .iter()
        .filter(|finding| finding.span.is_some())
        .count();
    if annotated_count > MAX_ANNOTATED_FINDINGS {
        out.push_str(&format!(
			"Showing {MAX_ANNOTATED_FINDINGS} of {annotated_count} source annotations. Use --json or --markdown for the full report.\n"
		));
    }

    if !report.errors.is_empty() {
        out.push_str("\nScan errors:\n");
        for error in &report.errors {
            out.push_str(&format!(
                "- {}: {}\n",
                error.file.as_deref().unwrap_or("scanner"),
                error.message
            ));
        }
    }

    out
}

fn summary(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("Plugin Scan Report\n");
    out.push_str("==================\n\n");

    if let Some(plugin) = &report.plugin {
        out.push_str(&format!(
            "Plugin:  {}\n",
            plugin.name.as_deref().unwrap_or("Unknown")
        ));
        out.push_str(&format!(
            "ID:      {}\n",
            plugin.id.as_deref().unwrap_or("unknown")
        ));
        out.push_str(&format!(
            "Version: {}\n",
            plugin.version.as_deref().unwrap_or("unknown")
        ));
        out.push_str(&format!(
            "Main:    {}\n",
            plugin.main.as_deref().unwrap_or("unknown")
        ));
    }

    out.push_str(&format!("Files:   {}\n", report.stats.files_scanned));
    out.push_str(&format!("JS:      {}\n", report.stats.js_files_parsed));
    out.push_str(&format!("Findings: {}\n\n", report.summary.total_findings));

    if !report.summary.by_severity.is_empty() {
        out.push_str("Severity: ");
        for severity in ["critical", "high", "medium", "low", "info"] {
            if let Some(count) = report.summary.by_severity.get(severity) {
                out.push_str(&format!("{severity}={count} "));
            }
        }
        out.push('\n');
    }

    if !report.summary.by_category.is_empty() {
        out.push_str("Categories: ");
        for (category, count) in &report.summary.by_category {
            out.push_str(&format!("{category}={count} "));
        }
        out.push('\n');
    }

    out
}

fn render_finding(report: &Report, finding: &Finding) -> Option<String> {
    let file = finding.file.as_deref()?;
    let span = finding.span?;
    let source = report.sources.get(file)?;
    let excerpt = excerpt_for_span(source, span.start_byte, span.end_byte)?;
    let file_id = file.to_string();

    let mut bytes = Vec::new();
    let kind = report_kind(finding.severity);
    let color = severity_color(finding.severity);
    let range = excerpt.highlight_start..excerpt.highlight_end;
    AriadneReport::build(kind, (file_id.clone(), range.clone()))
        .with_config(Config::default().with_index_type(IndexType::Byte))
        .with_code(&finding.id)
        .with_message(format!("{:?}: {}", finding.severity, finding.message))
        .with_label(
            Label::new((file_id.clone(), range))
                .with_color(color)
                .with_message(shorten(&finding.evidence, 120)),
        )
        .with_note(format!(
            "location={}:{}:{}, category={:?}, confidence={:?}",
            file, span.start_line, span.start_column, finding.category, finding.confidence
        ))
        .finish()
        .write_for_stdout(sources([(file_id, excerpt.source.as_str())]), &mut bytes)
        .ok()?;

    String::from_utf8(bytes).ok()
}

struct SourceExcerpt {
    source: String,
    highlight_start: usize,
    highlight_end: usize,
}

fn excerpt_for_span(source: &str, start: usize, end: usize) -> Option<SourceExcerpt> {
    if source.is_empty() {
        return None;
    }

    let start = previous_char_boundary(source, start.min(source.len()));
    let mut end = next_char_boundary(source, end.min(source.len()));
    if end <= start {
        end = next_char_boundary(source, (start + 1).min(source.len()));
    }
    if end <= start {
        return None;
    }

    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let line_end = source[end..]
        .find('\n')
        .map_or(source.len(), |index| end + index);

    let highlight_end = move_forward_chars(source, start, end, MAX_HIGHLIGHT_CHARS);
    let excerpt_start = move_back_chars(source, line_start, start, EXCERPT_CONTEXT_CHARS);
    let excerpt_end = move_forward_chars(source, highlight_end, line_end, EXCERPT_CONTEXT_CHARS);

    let prefix = if excerpt_start > line_start {
        "..."
    } else {
        ""
    };
    let suffix = if excerpt_end < line_end { "..." } else { "" };

    let mut excerpt = String::new();
    excerpt.push_str(prefix);
    excerpt.push_str(&source[excerpt_start..excerpt_end]);
    excerpt.push_str(suffix);

    let offset = prefix.len();
    let highlight_start = offset + start.saturating_sub(excerpt_start);
    let mut highlight_end = offset + highlight_end.saturating_sub(excerpt_start);
    if highlight_end <= highlight_start {
        highlight_end = (highlight_start + 1).min(excerpt.len());
    }

    Some(SourceExcerpt {
        source: excerpt,
        highlight_start,
        highlight_end,
    })
}

fn previous_char_boundary(source: &str, mut index: usize) -> usize {
    while index > 0 && !source.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn next_char_boundary(source: &str, mut index: usize) -> usize {
    while index < source.len() && !source.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn move_back_chars(source: &str, min_index: usize, mut index: usize, max_chars: usize) -> usize {
    for _ in 0..max_chars {
        if index <= min_index {
            return min_index;
        }
        index = source[min_index..index]
            .char_indices()
            .last()
            .map_or(min_index, |(offset, _)| min_index + offset);
    }
    index
}

fn move_forward_chars(source: &str, mut index: usize, max_index: usize, max_chars: usize) -> usize {
    for _ in 0..max_chars {
        if index >= max_index {
            return max_index;
        }
        index = source[index..max_index]
            .chars()
            .next()
            .map_or(max_index, |ch| index + ch.len_utf8());
    }
    index
}

fn sorted_findings(report: &Report) -> Vec<&Finding> {
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

fn report_kind(severity: Severity) -> ReportKind<'static> {
    match severity {
        Severity::Critical | Severity::High => ReportKind::Error,
        Severity::Medium | Severity::Low => ReportKind::Warning,
        Severity::Info => ReportKind::Advice,
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Yellow,
        Severity::Medium => Color::Blue,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::Green,
    }
}

fn shorten(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{shortened}...")
    } else {
        shortened
    }
}
