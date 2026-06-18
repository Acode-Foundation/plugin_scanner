use std::collections::{BTreeMap, BTreeSet};

use crate::{
    report::{Finding, Report, SourceSpan},
    severity::Severity,
};

const MAX_DETAIL_SNIPPETS_PER_GROUP: usize = 5;
const SNIPPET_CONTEXT_CHARS: usize = 90;
const MAX_SNIPPET_CHARS: usize = 260;

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

pub fn render_markdown_summary(report: &Report) -> String {
    let mut lines = Vec::new();
    lines.push("# Plugin Security Summary".to_string());
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
    lines.push(String::new());

    lines.push("## Review Priority".to_string());
    lines.push(String::new());
    lines.push(review_priority(report));
    lines.push(String::new());
    lines.push(
        "Severity is a capability-risk signal, not proof that the plugin is malicious.".to_string(),
    );
    lines.push(String::new());

    lines.push("## APIs and Capabilities Users Should Know".to_string());
    lines.push(String::new());
    let mut emitted = false;
    emitted |= push_capability_group(
        &mut lines,
        "Shell command execution",
        "can use Acode terminal/Executor APIs to run local commands or manage terminal sessions",
        report,
        is_shell_finding,
    );
    emitted |= push_capability_group(
        &mut lines,
        "Filesystem and local storage access",
        "can read, write, delete, list, or persist data through browser storage, Acode filesystem APIs, SD card APIs, or System plugin file APIs",
        report,
        is_filesystem_finding,
    );
    emitted |= push_capability_group(
        &mut lines,
        "Android/Cordova native access",
        "can call native Cordova or Android integration APIs outside normal web-plugin behavior",
        report,
        is_android_finding,
    );
    emitted |= push_capability_group(
        &mut lines,
        "Network and remote storage access",
        "can contact web services, use sockets, or upload/download through FTP/SFTP-style APIs",
        report,
        is_network_finding,
    );
    emitted |= push_capability_group(
        &mut lines,
        "Dynamic code or obfuscation",
        "uses patterns that can load, generate, decode, or hide executable JavaScript",
        report,
        is_dynamic_finding,
    );
    emitted |= push_capability_group(
        &mut lines,
        "Acode module registry, plugin APIs, and editor hooks",
        "can integrate with Acode lifecycle, private modules, community/plugin-defined modules, commands, editor/file hooks, active editor state, or define APIs that other plugins can import",
        report,
        is_acode_finding,
    );
    if !emitted {
        lines.push("No sensitive Acode, Cordova, filesystem, network, dynamic-code, or persistence capabilities were detected.".to_string());
    }
    lines.push(String::new());

    let hosts = hardcoded_network_hosts(report);
    if !hosts.is_empty() {
        lines.push("## Network Hosts Found".to_string());
        lines.push(String::new());
        for (host, count) in hosts {
            lines.push(format!("- `{host}` ({count})"));
        }
        lines.push(String::new());
    }

    lines.push("## Raw Counts".to_string());
    lines.push(String::new());
    lines.push(format!(
        "- **Total findings:** {}",
        report.summary.total_findings
    ));
    for severity in ["critical", "high", "medium", "low", "info"] {
        if let Some(count) = report.summary.by_severity.get(severity) {
            lines.push(format!("- **{}:** {}", title_case(severity), count));
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

fn push_capability_group(
    lines: &mut Vec<String>,
    title: &str,
    description: &str,
    report: &Report,
    predicate: fn(&Finding) -> bool,
) -> bool {
    let mut findings = report
        .findings
        .iter()
        .filter(|finding| predicate(finding))
        .collect::<Vec<_>>();
    if findings.is_empty() {
        return false;
    }
    findings.sort_by_key(|finding| {
        (
            severity_rank(finding.severity),
            finding.file.as_deref().unwrap_or(""),
            finding
                .span
                .map(|span| span.start_byte)
                .unwrap_or(usize::MAX),
            finding.id.as_str(),
        )
    });

    let max = findings
        .iter()
        .map(|finding| finding.severity)
        .min_by_key(|severity| severity_rank(*severity))
        .unwrap_or(Severity::Info);
    lines.push(format!(
        "- **{title}** ({}) — {description}",
        severity_label(max)
    ));

    let mut evidence = BTreeSet::new();
    for finding in &findings {
        evidence.insert(preferred_evidence(finding));
    }
    let shown = evidence.iter().take(8).cloned().collect::<Vec<_>>();
    if !shown.is_empty() {
        lines.push(format!(
            "  - APIs/evidence: {}",
            shown
                .iter()
                .map(|item| format!("`{}`", escape_backticks(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if evidence.len() > shown.len() {
        lines.push(format!(
            "  - Plus {} more matching finding(s).",
            evidence.len() - shown.len()
        ));
    }

    push_source_details(lines, report, &findings);

    true
}

fn push_source_details(lines: &mut Vec<String>, report: &Report, findings: &[&Finding]) {
    let snippets = findings
        .iter()
        .filter_map(|finding| source_snippet(report, finding))
        .take(MAX_DETAIL_SNIPPETS_PER_GROUP)
        .collect::<Vec<_>>();

    if snippets.is_empty() {
        return;
    }

    lines.push("  - Relevant code:".to_string());

    for snippet in &snippets {
        lines.push(format!(
            "    - `{}:{}:{}` — `{}` ({})",
            snippet.file,
            snippet.span.start_line,
            snippet.span.start_column,
            escape_backticks(&snippet.finding_id),
            severity_label(snippet.severity)
        ));
        lines.push(String::new());
        lines.push("      ```js".to_string());
        lines.push(indent_code(&snippet.code, 6));
        lines.push("      ```".to_string());
        lines.push(String::new());
    }

    let snippetable_count = findings
        .iter()
        .filter(|finding| can_render_source_snippet(report, finding))
        .count();
    if snippetable_count > snippets.len() {
        lines.push(format!(
            "    - _Showing {} of {} matching source locations._",
            snippets.len(),
            snippetable_count
        ));
    }
}

struct SourceSnippet {
    file: String,
    span: SourceSpan,
    finding_id: String,
    severity: Severity,
    code: String,
}

fn source_snippet(report: &Report, finding: &Finding) -> Option<SourceSnippet> {
    let file = finding.file.as_deref()?;
    let span = finding.span?;
    let source = report.sources.get(file)?;
    Some(SourceSnippet {
        file: file.to_string(),
        span,
        finding_id: finding.id.clone(),
        severity: finding.severity,
        code: excerpt_for_span(source, span.start_byte, span.end_byte)?,
    })
}

fn can_render_source_snippet(report: &Report, finding: &Finding) -> bool {
    finding
        .file
        .as_deref()
        .is_some_and(|file| finding.span.is_some() && report.sources.contains_key(file))
}

fn excerpt_for_span(source: &str, start: usize, end: usize) -> Option<String> {
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

    let excerpt_start = move_back_chars(source, line_start, start, SNIPPET_CONTEXT_CHARS);
    let initial_end = move_forward_chars(source, end, line_end, SNIPPET_CONTEXT_CHARS);
    let excerpt_end = move_forward_chars(source, excerpt_start, initial_end, MAX_SNIPPET_CHARS);

    let prefix = if excerpt_start > line_start {
        "..."
    } else {
        ""
    };
    let suffix = if excerpt_end < line_end { "..." } else { "" };

    Some(format!(
        "{prefix}{}{suffix}",
        source[excerpt_start..excerpt_end].trim()
    ))
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

fn review_priority(report: &Report) -> String {
    if report.findings.is_empty() {
        return "Low: no notable scanner findings were detected.".to_string();
    }

    if report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
    {
        return "Critical: the plugin uses at least one capability that can cross normal editor/plugin boundaries, such as command execution, direct Cordova access, or known exfiltration-style network endpoints.".to_string();
    }

    if report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::High)
    {
        return "High: the plugin uses sensitive APIs such as filesystem mutation, Android/system integration, plugin management, or privileged Acode modules.".to_string();
    }

    if report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::Medium)
    {
        return "Medium: the plugin uses capabilities worth disclosing, but no high-risk primitive was detected by these rules.".to_string();
    }

    "Low: findings are mostly informational or low-risk disclosure items.".to_string()
}

fn is_shell_finding(finding: &Finding) -> bool {
    matches!(
        finding.id.as_str(),
        "acode.require_terminal"
            | "cordova.executor"
            | "cordova.executor_reference"
            | "cordova.terminal"
    )
}

fn is_filesystem_finding(finding: &Finding) -> bool {
    finding.id.starts_with("filesystem.")
        || finding.id.starts_with("sdcard.")
        || matches!(
            finding.id.as_str(),
            "acode.require_filesystem"
                | "storage.local_storage"
                | "storage.session_storage"
                | "storage.indexeddb"
                | "storage.document_cookie"
                | "system.file_write"
                | "system.file_delete"
                | "system.file_metadata"
                | "system.set_executable"
                | "system.symlink"
        )
}

fn is_android_finding(finding: &Finding) -> bool {
    matches!(
        finding.id.as_str(),
        "system.manage_all_files"
            | "system.permission_request"
            | "system.launch_app"
            | "system.intent_access"
            | "system.file_intent"
            | "system.device_setting"
            | "system.os_integration"
            | "acode.require_intent"
            | "cordova.exec"
            | "cordova.plugins_access"
            | "cordova.window_global"
            | "cordova.plugin_api"
    )
}

fn is_network_finding(finding: &Finding) -> bool {
    finding.id.starts_with("network.") || finding.id.starts_with("remote_storage.")
}

fn is_dynamic_finding(finding: &Finding) -> bool {
    finding.id.starts_with("dynamic.") || finding.id.starts_with("obfuscation.")
}

fn is_acode_finding(finding: &Finding) -> bool {
    matches!(
        finding.id.as_str(),
        "persistence.plugin_init"
            | "persistence.plugin_unmount"
            | "persistence.intent_handler"
            | "persistence.plugin_install"
            | "persistence.editor_hook"
            | "persistence.command_hook"
            | "persistence.input_monitor"
            | "editor.active_file"
            | "editor.manager_access"
            | "acode.require_plugin"
            | "acode.require_module"
            | "acode.require_dynamic"
            | "acode.require_acodex"
            | "acode.define_module"
    )
}

fn hardcoded_network_hosts(report: &Report) -> Vec<(String, usize)> {
    let mut hosts = BTreeMap::<String, usize>::new();
    for finding in &report.findings {
        if !matches!(
            finding.id.as_str(),
            "network.hardcoded_url"
                | "network.hardcoded_websocket_url"
                | "network.exfiltration_endpoint"
        ) {
            continue;
        }
        if let Some(host) = host_from_url(&finding.evidence) {
            *hosts.entry(host).or_insert(0) += 1;
        }
    }
    let mut hosts = hosts.into_iter().collect::<Vec<_>>();
    hosts.sort_by(|(left_host, left_count), (right_host, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_host.cmp(right_host))
    });
    hosts
}

fn host_from_url(value: &str) -> Option<String> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .or_else(|| value.strip_prefix("wss://"))
        .or_else(|| value.strip_prefix("ws://"))?;
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn preferred_evidence(finding: &Finding) -> String {
    if matches!(
        finding.id.as_str(),
        "network.hardcoded_url"
            | "network.hardcoded_websocket_url"
            | "network.exfiltration_endpoint"
    ) {
        if let Some(host) = host_from_url(&finding.evidence) {
            return format!("host:{host}");
        }
    }

    if !finding.evidence.is_empty() {
        return shorten(&finding.evidence, 120);
    }
    finding.id.clone()
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
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

fn indent_code(value: &str, spaces: usize) -> String {
    let indent = " ".repeat(spaces);
    value
        .lines()
        .map(|line| format!("{indent}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
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
