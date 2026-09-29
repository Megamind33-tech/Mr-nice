//! RuleCompiler: payload text → matcher, with acceptance statistics.

use gg_rules_engine::{parse_list, Category, RuleMatcher};

#[derive(Debug)]
pub struct CompiledList {
    pub matcher: RuleMatcher,
    pub rule_count: usize,
    pub error_lines: usize,
}

pub struct RuleCompiler;

impl RuleCompiler {
    pub fn compile(payload: &str) -> CompiledList {
        let parsed = parse_list(payload, Category::Other("uncategorized".into()));
        let rule_count = parsed.rules.len();
        CompiledList {
            matcher: RuleMatcher::from_rules(parsed.rules),
            rule_count,
            error_lines: parsed.errors.len(),
        }
    }
}
