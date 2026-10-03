use std::io::IsTerminal;

use ariadne::{Color, Config, IndexType, Label, Report as AriadneReport, ReportKind, sources};

use crate::{
    markdown::recommendation_label,
    report::{Finding, Recommendation, Report},
    severity::Severity,
};

const MAX_ANNOTATED_FINDINGS: usize = 20;
const EXCERPT_CONTEXT_CHARS: usize = 40;
const MAX_HIGHLIGHT_CHARS: usize = 64;

pub fn render_terminal(report: &Report) -> String {
    let mut out = header(report);

    let annotated: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::Low)
        .take(MAX_ANNOTATED_FINDINGS)
        .collect();
    if !annotated.is_empty() {
        out.push_str("\nFindings:\n\n");
    }
    for finding in &annotated {
        match render_finding(report, finding) {
            Some(rendered) => out.push_str(&rendered),
            None => out.push_str(&format!(
                "[{}] {}: {}\n   {} — {}\n",
                finding.severity.label(),
                finding.id,
                finding.message,
                finding.file.as_deref().unwrap_or("archive"),
                shorten(&finding.evidence, 160)
            )),
        }
        out.push('\n');
    }

    let hidden_info = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Info)
        .count();
    let remaining = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= Severity::Low)
        .count()
        .saturating_sub(annotated.len());
    if remaining > 0 || hidden_info > 0 {
        out.push_str(&format!(
            "{remaining} more finding(s) and {hidden_info} info item(s) not shown; use --markdown or --json for everything.\n"
        ));
    }

    if !report.errors.is_empty() {
        out.push_str(&format!(
            "\n{} scan error(s); first: {}\n",
            report.errors.len(),
            report.errors[0].message
        ));
    }
    out
}

fn header(report: &Report) -> String {
    let mut out = String::from("Plugin Scan Report\n==================\n\n");
    if let Some(plugin) = &report.plugin {
        out.push_str(&format!(
            "Plugin:   {} ({}) {}\n",
            plugin.name.as_deref().unwrap_or("Unknown"),
            plugin.id.as_deref().unwrap_or("unknown"),
            plugin.version.as_deref().unwrap_or("")
        ));
        out.push_str(&format!(
            "Entry:    {}\n",
            plugin.entry.as_deref().unwrap_or("(none)")
        ));
    }
    out.push_str(&format!(
        "Analysed: {} JS/HTML file(s), {} installed file(s)\n\n",
        report.stats.js_files_parsed, report.stats.installed_files
    ));

    let verdict = &report.verdict;
    let marker = match verdict.recommendation {
        Recommendation::Pass => "✔",
        Recommendation::Review => "!",
        Recommendation::Block => "✘",
    };
    out.push_str(&format!(
        "{marker} Recommendation: {}   risk: {}{}\n",
        recommendation_label(verdict.recommendation),
        verdict.risk.map_or("none", Severity::key),
        if verdict.complete {
            ""
        } else {
            "   (scan incomplete)"
        }
    ));
    for reason in &verdict.reasons {
        out.push_str(&format!("  - {reason}\n"));
    }

    if !report.capabilities.is_empty() {
        out.push_str("\nCapabilities:\n");
        for capability in &report.capabilities {
            out.push_str(&format!(
                "  {:<8} {:<34} {}\n",
                capability.severity.key(),
                capability.title,
                shorten(&capability.evidence.join(", "), 90)
            ));
        }
    }

    let flagged: Vec<_> = report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.tags.iter().any(|tag| tag != "local"))
        .collect();
    let plain = report.endpoints.len() - flagged.len();
    if !report.endpoints.is_empty() {
        out.push_str(&format!(
            "\nNetwork hosts: {} ({} flagged)\n",
            report.endpoints.len(),
            flagged.len()
        ));
        for endpoint in flagged {
            out.push_str(&format!(
                "  ! {} [{}]\n",
                endpoint.host,
                endpoint.tags.join(", ")
            ));
        }
        if plain > 0 {
            let names: Vec<_> = report
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.tags.is_empty())
                .take(8)
                .map(|endpoint| endpoint.host.as_str())
                .collect();
            out.push_str(&format!(
                "  {}{}\n",
                names.join(", "),
                if plain > names.len() { ", …" } else { "" }
            ));
        }
    }
    out
}

fn render_finding(report: &Report, finding: &Finding) -> Option<String> {
    let file = finding.file.as_deref()?;
    let span = finding.span?;
    let source = report.sources.get(file)?;
    let excerpt = excerpt_for_span(source, span.start_byte, span.end_byte)?;
    // Ariadne positions are relative to the excerpt, so label it as one; the
    // real location is in the note.
    let file_id = format!("{file} (excerpt)");
    let range = excerpt.highlight_start..excerpt.highlight_end;
    let occurrences = if finding.occurrences > 1 {
        format!(", {} occurrences", finding.occurrences)
    } else {
        String::new()
    };

    let mut bytes = Vec::new();
    AriadneReport::build(
        report_kind(finding.severity),
        (file_id.clone(), range.clone()),
    )
    .with_config(
        Config::default()
            .with_index_type(IndexType::Byte)
            .with_color(std::io::stdout().is_terminal()),
    )
    .with_code(&finding.id)
    .with_message(format!("{}: {}", finding.severity.label(), finding.message))
    .with_label(
        Label::new((file_id.clone(), range))
            .with_color(severity_color(finding.severity))
            .with_message(shorten(&finding.evidence, 120)),
    )
    .with_note(format!(
        "{}:{}:{} · {} · {:?} confidence{occurrences}",
        file,
        span.start_line,
        span.start_column,
        finding.category.key(),
        finding.confidence
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
    let start = floor_boundary(source, start.min(source.len()));
    let mut end = ceil_boundary(source, end.min(source.len()));
    if end <= start {
        end = ceil_boundary(source, (start + 1).min(source.len()));
    }
    if end <= start {
        return None;
    }
    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let line_end = source[end..]
        .find('\n')
        .map_or(source.len(), |index| end + index);

    let highlight_end = forward_chars(source, start, end, MAX_HIGHLIGHT_CHARS);
    let excerpt_start = back_chars(source, line_start, start, EXCERPT_CONTEXT_CHARS);
    let excerpt_end = forward_chars(source, highlight_end, line_end, EXCERPT_CONTEXT_CHARS);

    let prefix = if excerpt_start > line_start {
        "..."
    } else {
        ""
    };
    let suffix = if excerpt_end < line_end { "..." } else { "" };
    let text = format!("{prefix}{}{suffix}", &source[excerpt_start..excerpt_end]);

    let highlight_start = prefix.len() + (start - excerpt_start);
    let mut highlight_end = prefix.len() + (highlight_end - excerpt_start);
    if highlight_end <= highlight_start {
        highlight_end = (highlight_start + 1).min(text.len());
    }
    Some(SourceExcerpt {
        source: text,
        highlight_start,
        highlight_end,
    })
}

fn floor_boundary(source: &str, mut index: usize) -> usize {
    while index > 0 && !source.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_boundary(source: &str, mut index: usize) -> usize {
    while index < source.len() && !source.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn back_chars(source: &str, min: usize, index: usize, count: usize) -> usize {
    source[min..index]
        .char_indices()
        .rev()
        .nth(count.saturating_sub(1))
        .map_or(min, |(offset, _)| min + offset)
}

fn forward_chars(source: &str, index: usize, max: usize, count: usize) -> usize {
    source[index..max]
        .char_indices()
        .nth(count)
        .map_or(max, |(offset, _)| index + offset)
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
        format!("{shortened}…")
    } else {
        shortened
    }
}
