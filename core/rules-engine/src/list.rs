//! Plain-text rule list parsing.
//!
//! Format: one rule per line, optional `# comment` lines, optional
//! `[category_id]` section headers that set the category for following rules.
//! Invalid lines are collected as errors instead of aborting, so the caller
//! (the blocklist updater) can decide whether a list is acceptable.

use crate::category::Category;
use crate::rule::{Rule, RuleParseError};

#[derive(Debug, PartialEq, Eq)]
pub struct LineError {
    pub line: usize,
    pub error: RuleParseError,
}

#[derive(Debug, Default)]
pub struct ParsedList {
    pub rules: Vec<Rule>,
    pub errors: Vec<LineError>,
}

pub fn parse_list(text: &str, default_category: Category) -> ParsedList {
    let mut out = ParsedList::default();
    let mut category = default_category;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(id) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            category = id.parse().expect("Category::from_str is infallible");
            continue;
        }
        match Rule::parse(line, category.clone()) {
            Ok(rule) => out.rules.push(rule),
            Err(error) => out.errors.push(LineError {
                line: idx + 1,
                error,
            }),
        }
    }
    out
}
