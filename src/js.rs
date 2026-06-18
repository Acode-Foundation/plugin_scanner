use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, ArrayExpression, ArrayExpressionElement, CallExpression, ChainElement,
    ComputedMemberExpression, Expression, IdentifierReference, ImportExpression, NewExpression,
    StaticMemberExpression, StringLiteral,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

use crate::{
    report::{Report, ScanError},
    rules::{
        RuleContext, classify_call, classify_hex_array, classify_identifier,
        classify_member_access, classify_string_literal,
    },
};

pub fn parse_and_scan(context: &mut RuleContext<'_>, report: &mut Report) {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(std::path::Path::new(context.file))
        .unwrap_or_else(|_| SourceType::default());
    let parser_return = Parser::new(&allocator, context.source, source_type).parse();

    for error in parser_return.errors {
        report.errors.push(ScanError {
            file: Some(context.file.to_string()),
            message: format!("{error:?}"),
        });
    }

    let mut visitor = ScannerVisitor { context };
    visitor.visit_program(&parser_return.program);
}

struct ScannerVisitor<'ctx, 'src> {
    context: &'ctx mut RuleContext<'src>,
}

impl<'a> Visit<'a> for ScannerVisitor<'_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let callee = expression_name(&it.callee);
        let first_arg_string = first_string_argument(&it.arguments);
        if let Some(callee) = callee.as_deref() {
            classify_call(self.context, callee, it.span, first_arg_string.as_deref());
        }
        walk::walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Some(callee) = expression_name(&it.callee) {
            let first_arg_string = first_string_argument(&it.arguments);
            classify_call(self.context, &callee, it.span, first_arg_string.as_deref());
        }
        walk::walk_new_expression(self, it);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        let source = string_expression_value(&it.source);
        self.context.add(
            "dynamic.import",
            crate::severity::Severity::Medium,
            crate::severity::Category::DynamicCode,
            Some(it.span),
            "Dynamic import expression",
            source.unwrap_or_else(|| "import(...)".to_string()),
            crate::severity::Confidence::High,
        );
        walk::walk_import_expression(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        classify_identifier(self.context, it.name.as_str(), it.span());
        walk::walk_identifier_reference(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        if let Some(path) = static_member_expression_name(it) {
            classify_member_access(self.context, &path, it.span, false);
        }
        walk::walk_static_member_expression(self, it);
    }

    fn visit_computed_member_expression(&mut self, it: &ComputedMemberExpression<'a>) {
        let path = computed_member_expression_name(it);
        let dynamic_window_access = matches!(
            expression_name(&it.object).as_deref(),
            Some("window" | "globalThis")
        ) && string_expression_value(&it.expression).is_none();
        if let Some(path) = path.as_deref() {
            classify_member_access(self.context, path, it.span, dynamic_window_access);
        } else if dynamic_window_access {
            classify_member_access(self.context, "window.[dynamic]", it.span, true);
        }
        walk::walk_computed_member_expression(self, it);
    }

    fn visit_array_expression(&mut self, it: &ArrayExpression<'a>) {
        let total = it.elements.len();
        let hex_like = it
            .elements
            .iter()
            .filter(|element| is_hex_like_element(element))
            .count();
        classify_hex_array(self.context, it.span, total, hex_like);
        walk::walk_array_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        classify_string_literal(self.context, it.value.as_str(), it.span());
        walk::walk_string_literal(self, it);
    }
}

fn first_string_argument(arguments: &[Argument<'_>]) -> Option<String> {
    for argument in arguments {
        if let Argument::StringLiteral(string) = argument {
            return Some(string.value.to_string());
        }
        if let Argument::SpreadElement(spread) = argument {
            return string_expression_value(&spread.argument);
        }
    }
    None
}

fn string_expression_value(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::StringLiteral(string) => Some(string.value.to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => template
            .quasis
            .first()
            .map(|quasi| quasi.value.cooked.unwrap_or(quasi.value.raw).to_string()),
        _ => None,
    }
}

fn expression_name(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier.name.to_string()),
        Expression::StaticMemberExpression(member) => {
            let object = expression_name(&member.object)?;
            Some(format!("{object}.{}", member.property.name))
        }
        Expression::ComputedMemberExpression(member) => {
            let object = expression_name(&member.object)?;
            let property = string_expression_value(&member.expression)?;
            Some(format!("{object}.{property}"))
        }
        Expression::ChainExpression(chain) => chain_element_name(&chain.expression),
        Expression::ParenthesizedExpression(parenthesized) => {
            expression_name(&parenthesized.expression)
        }
        Expression::PrivateFieldExpression(_) => None,
        _ => None,
    }
}

fn static_member_expression_name(member: &StaticMemberExpression<'_>) -> Option<String> {
    let object = receiver_name(&member.object)?;
    Some(format!("{object}.{}", member.property.name))
}

fn computed_member_expression_name(member: &ComputedMemberExpression<'_>) -> Option<String> {
    let object = receiver_name(&member.object)?;
    let property = string_expression_value(&member.expression)?;
    Some(format!("{object}.{property}"))
}

fn receiver_name(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::CallExpression(call) => expression_name(&call.callee),
        _ => expression_name(expression),
    }
}

fn chain_element_name(element: &ChainElement<'_>) -> Option<String> {
    match element {
        ChainElement::CallExpression(call) => expression_name(&call.callee),
        ChainElement::TSNonNullExpression(non_null) => expression_name(&non_null.expression),
        ChainElement::StaticMemberExpression(member) => {
            let object = expression_name(&member.object)?;
            Some(format!("{object}.{}", member.property.name))
        }
        ChainElement::ComputedMemberExpression(member) => {
            let object = expression_name(&member.object)?;
            let property = string_expression_value(&member.expression)?;
            Some(format!("{object}.{property}"))
        }
        ChainElement::PrivateFieldExpression(_) => None,
    }
}

fn is_hex_like_element(element: &ArrayExpressionElement<'_>) -> bool {
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

#[allow(dead_code)]
fn span_from_expression(expression: &Expression<'_>) -> Span {
    expression.span()
}

#[cfg(test)]
mod tests {
    use crate::{report::Report, rules::RuleContext};

    use super::*;

    fn finding_ids(source: &str) -> Vec<String> {
        let mut context = RuleContext::new("main.js", source);
        let mut report = Report::new("test");
        parse_and_scan(&mut context, &mut report);
        context
            .findings
            .into_iter()
            .map(|finding| finding.id)
            .collect()
    }

    #[test]
    fn detects_fetch() {
        assert!(finding_ids("fetch('https://example.com')").contains(&"network.fetch".to_string()));
    }

    #[test]
    fn detects_eval() {
        assert!(finding_ids("eval(code)").contains(&"dynamic.eval".to_string()));
    }

    #[test]
    fn detects_cordova_exec() {
        assert!(
            finding_ids("cordova.exec(null, null, 'System', 'deleteFile', [])")
                .contains(&"cordova.exec".to_string())
        );
    }

    #[test]
    fn detects_executor_execute() {
        assert!(finding_ids("Executor.execute('ls')").contains(&"cordova.executor".to_string()));
    }

    #[test]
    fn detects_script_injection() {
        assert!(
            finding_ids("document.createElement('script')")
                .contains(&"dynamic.script_injection".to_string())
        );
    }

    #[test]
    fn detects_acode_sensitive_module_imports() {
        let ids = finding_ids("acode.require('terminal'); acode.require('fsOperation');");
        assert!(ids.contains(&"acode.require_terminal".to_string()));
        assert!(ids.contains(&"acode.require_filesystem".to_string()));
    }

    #[test]
    fn detects_acode_plugin_defined_modules() {
        let ids = finding_ids("acode.define('myPluginApi', { run() {} });");
        assert!(ids.contains(&"acode.define_module".to_string()));
    }

    #[test]
    fn detects_storage_and_cookie_access() {
        let ids = finding_ids("localStorage.x = document.cookie; indexedDB.open('x');");
        assert!(ids.contains(&"storage.local_storage".to_string()));
        assert!(ids.contains(&"storage.document_cookie".to_string()));
        assert!(ids.contains(&"storage.indexeddb".to_string()));
    }

    #[test]
    fn detects_acode_and_system_security_apis() {
        let ids = finding_ids(
            "acode.installPlugin('x'); acode.addCommand({name:'x'}); system.requestPermission('android.permission.CAMERA'); system.manageAllFiles(); system.launchApp('pkg');",
        );
        assert!(ids.contains(&"persistence.plugin_install".to_string()));
        assert!(ids.contains(&"persistence.command_hook".to_string()));
        assert!(ids.contains(&"system.permission_request".to_string()));
        assert!(ids.contains(&"system.manage_all_files".to_string()));
        assert!(ids.contains(&"system.launch_app".to_string()));
    }

    #[test]
    fn detects_sdcard_remote_storage_and_executor_apis() {
        let ids = finding_ids(
            "sdcard.getStorageAccessPermission('primary'); sdcard.watchFile('/sdcard/a',()=>{}); sftp.connectUsingPassword('host'); ftp.uploadFile(1,'local','remote'); Executor.spawnStream(['sh'],()=>{}); Executor.loadLibrary('/tmp/x.so');",
        );
        assert!(ids.contains(&"sdcard.storage_access_permission".to_string()));
        assert!(ids.contains(&"sdcard.file_watch".to_string()));
        assert!(ids.contains(&"remote_storage.connect".to_string()));
        assert!(ids.contains(&"remote_storage.upload".to_string()));
        assert!(ids.contains(&"cordova.executor".to_string()));
    }

    #[test]
    fn detects_global_input_monitoring() {
        assert!(
            finding_ids("window.addEventListener('keydown', () => {})")
                .contains(&"persistence.input_monitor".to_string())
        );
    }

    #[test]
    fn detects_exfiltration_endpoint() {
        assert!(
            finding_ids("fetch('https://discord.com/api/webhooks/abc')")
                .contains(&"network.exfiltration_endpoint".to_string())
        );
    }

    #[test]
    fn detects_hex_obfuscation_array() {
        let ids = finding_ids(
            "const x = [0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x60,0x61];",
        );
        assert!(ids.contains(&"obfuscation.hex_array".to_string()));
    }

    #[test]
    fn ignores_common_framework_documentation_urls() {
        let ids = finding_ids(
            "const a='http://www.w3.org/2000/svg'; const b='https://json-schema.org/draft/2020-12/schema';",
        );
        assert!(!ids.contains(&"network.hardcoded_url".to_string()));
    }

    #[test]
    fn ignores_minified_generic_write_and_delete_methods() {
        let ids = finding_ids("e.delete(x); n.write(y); fsOperation(file).delete();");
        assert_eq!(
            ids.iter()
                .filter(|id| id.as_str() == "filesystem.delete_operation")
                .count(),
            1
        );
        assert!(!ids.contains(&"filesystem.write_operation".to_string()));
    }
}
