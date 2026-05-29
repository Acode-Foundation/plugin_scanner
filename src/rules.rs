use oxc_span::Span;

use crate::{
    report::{Finding, SourceSpan},
    severity::{Category, Confidence, Severity},
};

const LARGE_JS_BYTES: usize = 1024 * 1024;
const LONG_LINE_BYTES: usize = 200_000;
const BASE64_MIN_LEN: usize = 160;
const EXFIL_ENDPOINTS: &[&str] = &[
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "webhook.site",
    "pastebin.com",
    "api.ipify.org",
];
const BENIGN_DOCUMENT_URL_PREFIXES: &[&str] = &[
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://json-schema.org/",
    "https://json-schema.org/",
    "https://github.com/zloirock/core-js",
];

#[derive(Debug)]
pub struct RuleContext<'a> {
    pub file: &'a str,
    pub source: &'a str,
    line_starts: Vec<usize>,
    pub findings: Vec<Finding>,
}

impl<'a> RuleContext<'a> {
    pub fn new(file: &'a str, source: &'a str) -> Self {
        Self {
            file,
            source,
            line_starts: line_starts(source),
            findings: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        id: impl Into<String>,
        severity: Severity,
        category: Category,
        span: Option<Span>,
        message: impl Into<String>,
        evidence: impl Into<String>,
        confidence: Confidence,
    ) {
        let source_span = span.map(|span| self.to_source_span(span));
        self.findings.push(Finding {
            id: id.into(),
            severity,
            category,
            file: Some(self.file.to_string()),
            span: source_span,
            message: message.into(),
            evidence: evidence.into(),
            confidence,
        });
    }

    pub fn snippet(&self, span: Span) -> String {
        let start = span.start as usize;
        let end = span.end as usize;
        self.source
            .get(start..end)
            .unwrap_or("")
            .chars()
            .take(200)
            .collect()
    }

    fn to_source_span(&self, span: Span) -> SourceSpan {
        let (start_line, start_column) =
            offset_to_line_column(&self.line_starts, span.start as usize);
        let (end_line, end_column) = offset_to_line_column(&self.line_starts, span.end as usize);
        SourceSpan {
            start_byte: span.start as usize,
            end_byte: span.end as usize,
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }
}

pub fn scan_source_text(context: &mut RuleContext<'_>) {
    if context.source.len() > LARGE_JS_BYTES {
        context.add(
            "obfuscation.large_js",
            Severity::Medium,
            Category::Obfuscation,
            None,
            "Large JavaScript file",
            format!("file length is {} bytes", context.source.len()),
            Confidence::Medium,
        );
    }

    if context
        .source
        .lines()
        .any(|line| line.len() > LONG_LINE_BYTES)
    {
        context.add(
            "obfuscation.minified_long_line",
            Severity::Low,
            Category::Obfuscation,
            None,
            "Very long JavaScript line",
            "source contains a line usually produced by minified or packed code",
            Confidence::Medium,
        );
    }

    if contains_base64_blob(context.source) && !looks_like_framework_bundle(context.source) {
        context.add(
            "obfuscation.base64_blob",
            Severity::Medium,
            Category::Obfuscation,
            None,
            "Large base64-like string detected",
            "encoded payloads can hide dynamically decoded code or data",
            Confidence::Medium,
        );
    }

    for marker in ["atob(", "btoa(", "fromCharCode(", "unescape("] {
        if context.source.contains(marker) {
            if looks_like_framework_bundle(context.source)
                && matches!(marker, "atob(" | "btoa(" | "fromCharCode(")
            {
                continue;
            }
            context.add(
                "obfuscation.decoder_api",
                Severity::Low,
                Category::Obfuscation,
                None,
                "Decoder-like API usage",
                marker,
                Confidence::Medium,
            );
        }
    }
}

pub fn classify_call(
    context: &mut RuleContext<'_>,
    callee: &str,
    span: Span,
    first_arg_string: Option<&str>,
) {
    match callee {
        "fetch" | "window.fetch" | "globalThis.fetch" => context.add(
            "network.fetch",
            Severity::Medium,
            Category::Network,
            Some(span),
            "Network request via fetch",
            first_arg_string.unwrap_or(callee),
            Confidence::High,
        ),
        "XMLHttpRequest" | "window.XMLHttpRequest" | "globalThis.XMLHttpRequest" => context.add(
            "network.xhr",
            Severity::Medium,
            Category::Network,
            Some(span),
            "XMLHttpRequest usage",
            callee,
            Confidence::High,
        ),
        "WebSocket" | "window.WebSocket" | "cordova.websocket.connect" => context.add(
            "network.websocket",
            Severity::High,
            Category::Network,
            Some(span),
            "WebSocket usage",
            first_arg_string.unwrap_or(callee),
            Confidence::High,
        ),
        "eval" | "window.eval" | "globalThis.eval" => context.add(
            "dynamic.eval",
            Severity::High,
            Category::DynamicCode,
            Some(span),
            "Dynamic code execution via eval",
            callee,
            Confidence::High,
        ),
        "Function" | "window.Function" | "globalThis.Function" => context.add(
            "dynamic.function_constructor",
            Severity::High,
            Category::DynamicCode,
            Some(span),
            "Dynamic code execution via Function constructor",
            callee,
            Confidence::High,
        ),
        "setTimeout" | "window.setTimeout" | "setInterval" | "window.setInterval"
            if first_arg_string.is_some() =>
        {
            context.add(
                "dynamic.string_timer",
                Severity::Medium,
                Category::DynamicCode,
                Some(span),
                "Timer executes a string argument",
                first_arg_string.unwrap_or(callee),
                Confidence::High,
            );
        }
        "document.createElement" if first_arg_string == Some("script") => context.add(
            "dynamic.script_injection",
            Severity::High,
            Category::DynamicCode,
            Some(span),
            "Dynamic script element creation",
            "document.createElement('script')",
            Confidence::High,
        ),
        "cordova.exec" | "window.cordova.exec" => context.add(
            "cordova.exec",
            Severity::Critical,
            Category::Cordova,
            Some(span),
            "Direct Cordova bridge call",
            context.snippet(span),
            Confidence::High,
        ),
        "Executor.execute"
        | "window.Executor.execute"
        | "Executor.start"
        | "window.Executor.start"
        | "Executor.spawnStream"
        | "window.Executor.spawnStream"
        | "Executor.loadLibrary"
        | "window.Executor.loadLibrary"
        | "Executor.BackgroundExecutor.execute"
        | "window.Executor.BackgroundExecutor.execute"
        | "Executor.BackgroundExecutor.start"
        | "window.Executor.BackgroundExecutor.start" => {
            context.add(
                "cordova.executor",
                Severity::Critical,
                Category::Cordova,
                Some(span),
                "Terminal executor command API usage",
                first_arg_string.unwrap_or(callee),
                Confidence::High,
            );
        }
        "Terminal.init"
        | "window.Terminal.init"
        | "Terminal.install"
        | "window.Terminal.install" => {
            context.add(
                "cordova.terminal",
                Severity::High,
                Category::Cordova,
                Some(span),
                "Terminal API usage",
                callee,
                Confidence::High,
            );
        }
        "CreateServer" | "window.CreateServer" => context.add(
            "cordova.local_server",
            Severity::High,
            Category::Cordova,
            Some(span),
            "Local server API usage",
            callee,
            Confidence::High,
        ),
        "acode.setPluginInit" | "window.acode.setPluginInit" => context.add(
            "persistence.plugin_init",
            Severity::Info,
            Category::PersistenceOrHooks,
            Some(span),
            "Plugin registers an init hook",
            callee,
            Confidence::High,
        ),
        "acode.setPluginUnmount" | "window.acode.setPluginUnmount" => context.add(
            "persistence.plugin_unmount",
            Severity::Info,
            Category::PersistenceOrHooks,
            Some(span),
            "Plugin registers an unmount hook",
            callee,
            Confidence::High,
        ),
        "acode.addIntentHandler" | "window.acode.addIntentHandler" => context.add(
            "persistence.intent_handler",
            Severity::Medium,
            Category::PersistenceOrHooks,
            Some(span),
            "Plugin registers an intent handler",
            callee,
            Confidence::High,
        ),
        "acode.installPlugin" | "window.acode.installPlugin" => context.add(
            "persistence.plugin_install",
            Severity::High,
            Category::PersistenceOrHooks,
            Some(span),
            "Plugin can request installation of another plugin",
            first_arg_string.unwrap_or(callee),
            Confidence::High,
        ),
        "acode.registerFormatter"
        | "window.acode.registerFormatter"
        | "acode.registerFileHandler"
        | "window.acode.registerFileHandler" => context.add(
            "persistence.editor_hook",
            Severity::Medium,
            Category::PersistenceOrHooks,
            Some(span),
            "Plugin registers editor/file handling hooks",
            callee,
            Confidence::High,
        ),
        "acode.addCommand"
        | "window.acode.addCommand"
        | "acode.commands.addCommand"
        | "window.acode.commands.addCommand" => context.add(
            "persistence.command_hook",
            Severity::Medium,
            Category::PersistenceOrHooks,
            Some(span),
            "Plugin registers a command or keybinding command hook",
            callee,
            Confidence::High,
        ),
        "acode.require" | "window.acode.require" => {
            classify_acode_require(context, span, first_arg_string);
        }
        "addEventListener"
        | "window.addEventListener"
        | "document.addEventListener"
        | "globalThis.addEventListener" => {
            if matches!(
                first_arg_string,
                Some("input" | "keyup" | "keydown" | "keypress")
            ) {
                context.add(
                    "persistence.input_monitor",
                    Severity::High,
                    Category::PersistenceOrHooks,
                    Some(span),
                    "Global input or keyboard monitoring hook",
                    first_arg_string.unwrap_or(callee),
                    Confidence::High,
                );
            }
        }
        _ => {
            if !classify_known_api_call(context, callee, span, first_arg_string) {
                classify_prefix_call(context, callee, span, first_arg_string);
            }
        }
    }
}

pub fn classify_identifier(context: &mut RuleContext<'_>, name: &str, span: Span) {
    match name {
        "Executor" => context.add(
            "cordova.executor_reference",
            Severity::Critical,
            Category::Cordova,
            Some(span),
            "Executor global reference",
            "Executor",
            Confidence::Medium,
        ),
        "fetch" => {}
        "localStorage" => context.add(
            "storage.local_storage",
            Severity::Medium,
            Category::Filesystem,
            Some(span),
            "localStorage access",
            "localStorage",
            Confidence::High,
        ),
        "sessionStorage" => context.add(
            "storage.session_storage",
            Severity::Medium,
            Category::Filesystem,
            Some(span),
            "sessionStorage access",
            "sessionStorage",
            Confidence::High,
        ),
        "indexedDB" => context.add(
            "storage.indexeddb",
            Severity::Medium,
            Category::Filesystem,
            Some(span),
            "IndexedDB access",
            "indexedDB",
            Confidence::High,
        ),
        "DATA_STORAGE" | "CACHE_STORAGE" | "PLUGIN_DIR" => context.add(
            "filesystem.sensitive_path_constant",
            Severity::Medium,
            Category::Filesystem,
            Some(span),
            "Sensitive Acode storage path constant access",
            name,
            Confidence::High,
        ),
        "eval" | "Function" => {}
        "encodeURIComponent" | "escape" | "unescape" | "btoa" | "atob" => {}
        "activeFile" => context.add(
            "editor.active_file",
            Severity::Medium,
            Category::PersistenceOrHooks,
            Some(span),
            "Active editor file access",
            "activeFile",
            Confidence::Medium,
        ),
        _ => {}
    }
}

pub fn classify_member_access(
    context: &mut RuleContext<'_>,
    member_path: &str,
    span: Span,
    is_dynamic_window_access: bool,
) {
    if is_dynamic_window_access {
        context.add(
            "dynamic.window_property_access",
            Severity::Medium,
            Category::DynamicCode,
            Some(span),
            "Dynamic window property access",
            "window[...]",
            Confidence::Medium,
        );
    }

    match member_path {
        "cordova.plugins" | "window.cordova.plugins" => context.add(
            "cordova.plugins_access",
            Severity::Critical,
            Category::Cordova,
            Some(span),
            "Cordova native plugin registry access",
            member_path,
            Confidence::High,
        ),
        "window.cordova" => context.add(
            "cordova.window_global",
            Severity::Critical,
            Category::Cordova,
            Some(span),
            "window.cordova global reference",
            member_path,
            Confidence::High,
        ),
        "document.cookie" | "window.document.cookie" => context.add(
            "storage.document_cookie",
            Severity::Medium,
            Category::Filesystem,
            Some(span),
            "document.cookie access",
            member_path,
            Confidence::High,
        ),
        "editorManager.activeFile" | "window.editorManager.activeFile" => context.add(
            "editor.active_file",
            Severity::Medium,
            Category::PersistenceOrHooks,
            Some(span),
            "Active editor file access",
            member_path,
            Confidence::High,
        ),
        path if path.starts_with("editorManager.") || path.starts_with("window.editorManager.") => {
            context.add(
                "editor.manager_access",
                Severity::Info,
                Category::PersistenceOrHooks,
                Some(span),
                "editorManager API access",
                member_path,
                Confidence::Medium,
            );
        }
        _ => classify_file_operation_member(context, member_path, span),
    }
}

pub fn classify_hex_array(
    context: &mut RuleContext<'_>,
    span: Span,
    total: usize,
    hex_like: usize,
) {
    if total > 20 && hex_like * 10 >= total * 7 {
        context.add(
            "obfuscation.hex_array",
            Severity::High,
            Category::Obfuscation,
            Some(span),
            "Hex-like obfuscated array mapping",
            format!("{hex_like}/{total} array elements are hex-like"),
            Confidence::Medium,
        );
    }
}

pub fn classify_string_literal(context: &mut RuleContext<'_>, value: &str, span: Span) {
    if is_benign_documentation_url(value) || is_synthetic_url_fixture(value) {
        return;
    }

    if value.starts_with("http://") || value.starts_with("https://") {
        context.add(
            if EXFIL_ENDPOINTS
                .iter()
                .any(|endpoint| value.contains(endpoint))
            {
                "network.exfiltration_endpoint"
            } else {
                "network.hardcoded_url"
            },
            if EXFIL_ENDPOINTS
                .iter()
                .any(|endpoint| value.contains(endpoint))
            {
                Severity::Critical
            } else {
                Severity::Low
            },
            Category::Network,
            Some(span),
            if EXFIL_ENDPOINTS
                .iter()
                .any(|endpoint| value.contains(endpoint))
            {
                "Known exfiltration-style endpoint string"
            } else {
                "Hardcoded URL string"
            },
            value,
            if EXFIL_ENDPOINTS
                .iter()
                .any(|endpoint| value.contains(endpoint))
            {
                Confidence::High
            } else {
                Confidence::Medium
            },
        );
    }

    if value.starts_with("ws://") || value.starts_with("wss://") {
        context.add(
            "network.hardcoded_websocket_url",
            Severity::Low,
            Category::Network,
            Some(span),
            "Hardcoded WebSocket URL string",
            value,
            Confidence::Medium,
        );
    }

    if value.contains("../") || value.contains("..\\") {
        context.add(
            "filesystem.path_traversal_literal",
            Severity::Medium,
            Category::Filesystem,
            Some(span),
            "Path traversal-like string literal",
            value,
            Confidence::Medium,
        );
    }
}

fn classify_acode_require(context: &mut RuleContext<'_>, span: Span, module_name: Option<&str>) {
    match module_name {
        Some("fs" | "fsOperation") => context.add(
            "acode.require_filesystem",
            Severity::High,
            Category::Filesystem,
            Some(span),
            "Acode filesystem module import",
            module_name.unwrap_or("[dynamic]"),
            Confidence::High,
        ),
        Some("terminal") => context.add(
            "acode.require_terminal",
            Severity::Critical,
            Category::Cordova,
            Some(span),
            "Acode terminal module import",
            "terminal",
            Confidence::High,
        ),
        Some("intent") => context.add(
            "acode.require_intent",
            Severity::High,
            Category::Cordova,
            Some(span),
            "Acode Android intent module import",
            "intent",
            Confidence::High,
        ),
        Some("plugin") => context.add(
            "acode.require_plugin",
            Severity::High,
            Category::PersistenceOrHooks,
            Some(span),
            "Acode plugin management module import",
            "plugin",
            Confidence::High,
        ),
        Some(module) => context.add(
            "acode.require_module",
            Severity::Info,
            Category::PersistenceOrHooks,
            Some(span),
            "Acode platform module import",
            module,
            Confidence::Medium,
        ),
        None => context.add(
            "acode.require_dynamic",
            Severity::Medium,
            Category::PersistenceOrHooks,
            Some(span),
            "Dynamic Acode platform module import",
            "acode.require([dynamic])",
            Confidence::Medium,
        ),
    }
}

fn classify_file_operation_member(context: &mut RuleContext<'_>, member_path: &str, span: Span) {
    let Some(property) = member_path.rsplit('.').next() else {
        return;
    };
    let known_filesystem_receiver = has_known_filesystem_receiver(member_path);

    let (id, severity, message) = match property {
        "readFile" | "readFileSync" | "read" => (
            "filesystem.read_operation",
            Severity::High,
            "File read operation",
        ),
        "writeFile" | "writeFileSync" => (
            "filesystem.write_operation",
            Severity::High,
            "File write operation",
        ),
        "write" if known_filesystem_receiver => (
            "filesystem.write_operation",
            Severity::High,
            "File write operation",
        ),
        "lsDir" | "readDir" | "readdir" | "listDirectory" | "listChildren" => (
            "filesystem.directory_listing",
            Severity::Medium,
            "Directory listing operation",
        ),
        "deleteFile" | "unlink" | "rm" => (
            "filesystem.delete_operation",
            Severity::High,
            "File deletion operation",
        ),
        "delete" if known_filesystem_receiver => (
            "filesystem.delete_operation",
            Severity::High,
            "File deletion operation",
        ),
        "copyTo" | "moveTo" | "renameFile" | "copy" | "move" | "rename" => (
            "filesystem.move_or_copy_operation",
            Severity::Medium,
            "File move, copy, or rename operation",
        ),
        _ => return,
    };

    context.add(
        id,
        severity,
        Category::Filesystem,
        Some(span),
        message,
        member_path,
        Confidence::Medium,
    );
}

fn has_known_filesystem_receiver(member_path: &str) -> bool {
    member_path.starts_with("fs.")
        || member_path.starts_with("fsOperation.")
        || member_path.starts_with("sdcard.")
        || member_path.starts_with("system.")
        || member_path.starts_with("window.sdcard.")
        || member_path.starts_with("window.system.")
        || member_path.contains("FileSystem")
}

fn classify_known_api_call(
    context: &mut RuleContext<'_>,
    callee: &str,
    span: Span,
    first_arg_string: Option<&str>,
) -> bool {
    let normalized = callee
        .strip_prefix("window.")
        .or_else(|| callee.strip_prefix("globalThis."))
        .unwrap_or(callee);

    if let Some(method) = normalized.strip_prefix("system.") {
        classify_system_call(context, method, span, first_arg_string);
        return true;
    }

    if let Some(method) = normalized.strip_prefix("sdcard.") {
        classify_sdcard_call(context, method, span, first_arg_string);
        return true;
    }

    if let Some(method) = normalized.strip_prefix("ftp.") {
        classify_remote_storage_call(context, "ftp", method, span, first_arg_string);
        return true;
    }

    if let Some(method) = normalized.strip_prefix("sftp.") {
        classify_remote_storage_call(context, "sftp", method, span, first_arg_string);
        return true;
    }

    false
}

fn classify_system_call(
    context: &mut RuleContext<'_>,
    method: &str,
    span: Span,
    first_arg_string: Option<&str>,
) {
    let (id, severity, category, message) = match method {
        "requestStorageManager" | "manageAllFiles" => (
            "system.manage_all_files",
            Severity::Critical,
            Category::Cordova,
            "Requests Android manage-all-files access",
        ),
        "requestPermission" | "requestPermissions" => (
            "system.permission_request",
            Severity::High,
            Category::Cordova,
            "Requests Android runtime permissions",
        ),
        "launchApp" => (
            "system.launch_app",
            Severity::High,
            Category::Cordova,
            "Launches another Android app/activity",
        ),
        "setIntentHandler" | "getCordovaIntent" => (
            "system.intent_access",
            Severity::High,
            Category::Cordova,
            "Accesses Android intent data or intent callbacks",
        ),
        "fileAction" => (
            "system.file_intent",
            Severity::High,
            Category::Cordova,
            "Opens a file through an Android intent action",
        ),
        "openInBrowser" | "inAppBrowser" => (
            "system.browser_launch",
            Severity::Medium,
            Category::Network,
            "Launches external or in-app browser",
        ),
        "createSymlink" => (
            "system.symlink",
            Severity::High,
            Category::Filesystem,
            "Creates filesystem symlinks",
        ),
        "setExec" => (
            "system.set_executable",
            Severity::High,
            Category::Filesystem,
            "Changes executable bit on a file",
        ),
        "writeText" | "copyToUri" => (
            "system.file_write",
            Severity::High,
            Category::Filesystem,
            "Writes or copies files through the System plugin",
        ),
        "deleteFile" => (
            "system.file_delete",
            Severity::High,
            Category::Filesystem,
            "Deletes files through the System plugin",
        ),
        "listChildren" | "getParentPath" | "getFilesDir" => (
            "system.file_metadata",
            Severity::Medium,
            Category::Filesystem,
            "Reads filesystem metadata through the System plugin",
        ),
        "getGlobalSetting" | "setInputType" | "setNativeContextMenuDisabled" => (
            "system.device_setting",
            Severity::Medium,
            Category::Cordova,
            "Reads or changes device/editor system settings",
        ),
        "shareText" | "addShortcut" | "pinShortcut" | "pinFileShortcut" => (
            "system.os_integration",
            Severity::Medium,
            Category::Cordova,
            "Uses Android sharing or shortcut integration",
        ),
        _ => return,
    };

    context.add(
        id,
        severity,
        category,
        Some(span),
        message,
        first_arg_string.unwrap_or(method),
        Confidence::High,
    );
}

fn classify_sdcard_call(
    context: &mut RuleContext<'_>,
    method: &str,
    span: Span,
    first_arg_string: Option<&str>,
) {
    let (id, severity, message) = match method {
        "getStorageAccessPermission" => (
            "sdcard.storage_access_permission",
            Severity::High,
            "Requests user-selected storage tree access",
        ),
        "openDocumentFile" | "getImage" => (
            "sdcard.document_picker",
            Severity::Medium,
            "Opens Android document/image picker",
        ),
        "watchFile" => (
            "sdcard.file_watch",
            Severity::Medium,
            "Watches filesystem changes",
        ),
        "read" | "listDir" | "getPath" | "stats" | "listStorages" => (
            "sdcard.file_read",
            Severity::High,
            "Reads files or storage metadata through SDcard plugin",
        ),
        "write" | "createFile" | "createDir" | "copy" | "move" | "rename" => (
            "sdcard.file_write",
            Severity::High,
            "Writes or mutates files through SDcard plugin",
        ),
        "delete" => (
            "sdcard.file_delete",
            Severity::High,
            "Deletes files through SDcard plugin",
        ),
        _ => return,
    };

    context.add(
        id,
        severity,
        Category::Filesystem,
        Some(span),
        message,
        first_arg_string.unwrap_or(method),
        Confidence::High,
    );
}

fn classify_remote_storage_call(
    context: &mut RuleContext<'_>,
    protocol: &str,
    method: &str,
    span: Span,
    first_arg_string: Option<&str>,
) {
    let (id, severity, category, message) = match method {
        "connect" | "connectUsingPassword" | "connectUsingKeyFile" => (
            "remote_storage.connect",
            Severity::High,
            Category::Network,
            "Connects to remote FTP/SFTP storage",
        ),
        "uploadFile" | "putFile" => (
            "remote_storage.upload",
            Severity::High,
            Category::Network,
            "Uploads local files to remote storage",
        ),
        "downloadFile" | "getFile" => (
            "remote_storage.download",
            Severity::High,
            Category::Network,
            "Downloads remote files into local storage",
        ),
        "execCommand" | "exec" => (
            "remote_storage.command",
            Severity::High,
            Category::Network,
            "Executes a remote FTP/SFTP command",
        ),
        "deleteFile" | "deleteDirectory" | "rm" | "rename" | "mkdir" | "createFile" => (
            "remote_storage.mutate",
            Severity::Medium,
            Category::Network,
            "Mutates remote FTP/SFTP files",
        ),
        _ => return,
    };

    context.add(
        id,
        severity,
        category,
        Some(span),
        message,
        format!("{protocol}.{method}: {}", first_arg_string.unwrap_or("")),
        Confidence::High,
    );
}

fn classify_prefix_call(
    context: &mut RuleContext<'_>,
    callee: &str,
    span: Span,
    first_arg_string: Option<&str>,
) {
    let filesystem_prefixes = [
        "sdcard.",
        "window.sdcard.",
        "system.",
        "window.system.",
        "fsOperation.",
        "acode.require.fileSystem.",
    ];
    let cordova_prefixes = [
        "ftp.",
        "window.ftp.",
        "sftp.",
        "window.sftp.",
        "cordova.websocket.",
        "window.cordova.websocket.",
    ];

    if filesystem_prefixes
        .iter()
        .any(|prefix| callee.starts_with(prefix))
    {
        context.add(
            "filesystem.privileged_api",
            Severity::High,
            Category::Filesystem,
            Some(span),
            "Privileged filesystem API usage",
            first_arg_string.unwrap_or(callee),
            Confidence::High,
        );
        return;
    }

    if cordova_prefixes
        .iter()
        .any(|prefix| callee.starts_with(prefix))
    {
        context.add(
            "cordova.plugin_api",
            Severity::Medium,
            Category::Cordova,
            Some(span),
            "Cordova plugin API usage",
            first_arg_string.unwrap_or(callee),
            Confidence::High,
        );
    }
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, ch) in source.char_indices() {
        if ch == '\n' {
            starts.push(index + 1);
        }
    }
    starts
}

fn offset_to_line_column(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let line_index = match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    };
    let column = offset.saturating_sub(line_starts[line_index]) + 1;
    (line_index + 1, column)
}

fn contains_base64_blob(source: &str) -> bool {
    let mut run = 0;
    for ch in source.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=') {
            run += 1;
            if run >= BASE64_MIN_LEN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn looks_like_framework_bundle(source: &str) -> bool {
    source.contains("__webpack_require__")
        || source.contains("react.production.min")
        || source.contains("react-dom.production.min")
        || source.contains("Symbol.for(\"react.")
        || source.contains("core-js")
}

fn is_benign_documentation_url(value: &str) -> bool {
    BENIGN_DOCUMENT_URL_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn is_synthetic_url_fixture(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    host.len() <= 1 || (!host.contains('.') && host != "localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_offsets_to_line_columns() {
        let context = RuleContext::new("x.js", "a\nbc\n");
        let span = context.to_source_span(Span::new(2, 4));
        assert_eq!(span.start_line, 2);
        assert_eq!(span.start_column, 1);
        assert_eq!(span.end_line, 2);
        assert_eq!(span.end_column, 3);
    }

    #[test]
    fn detects_base64_blob() {
        let source = "A".repeat(200);
        let mut context = RuleContext::new("x.js", &source);
        scan_source_text(&mut context);
        assert!(
            context
                .findings
                .iter()
                .any(|finding| finding.id == "obfuscation.base64_blob")
        );
    }
}
