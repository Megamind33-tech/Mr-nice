//! Compiled rule matching.
//!
//! Rules are compiled into a trie keyed by labels in reverse order
//! (`com` → `example` → `www`). A lookup walks the query from the TLD down,
//! so cost is O(number of labels) regardless of rule-set size, and there is
//! no substring matching anywhere.
//!
//! Precedence is deterministic:
//! 1. The rule attached to the deepest (most specific) trie node wins.
//! 2. At the same node, `Exact` beats `DomainAndSubdomains` beats
//!    `SubdomainsOnly` — only those whose scope applies are considered.
//! 3. At equal node and scope, `Block` beats `Allow`.

use std::collections::HashMap;

use crate::category::Category;
use crate::domain::{Domain, DomainError};
use crate::rule::{Action, Rule, RuleId, Scope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block { rule: RuleId, category: Category },
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchDetail {
    pub rule: RuleId,
    pub action: Action,
    pub category: Category,
}

#[derive(Debug, Default)]
struct Slot {
    block: Option<(RuleId, Category)>,
    allow: Option<RuleId>,
}

impl Slot {
    fn set(&mut self, id: RuleId, rule: &Rule) {
        // First rule for a slot wins so compilation is order-stable.
        match rule.action {
            Action::Block => {
                self.block.get_or_insert((id, rule.category.clone()));
            }
            Action::Allow => {
                self.allow.get_or_insert(id);
            }
        }
    }

    fn resolve(&self) -> Option<MatchDetail> {
        if let Some((rule, category)) = &self.block {
            return Some(MatchDetail {
                rule: *rule,
                action: Action::Block,
                category: category.clone(),
            });
        }
        self.allow.map(|rule| MatchDetail {
            rule,
            action: Action::Allow,
            category: Category::UserDefined,
        })
    }
}

#[derive(Debug, Default)]
struct Node {
    children: HashMap<Box<str>, Node>,
    exact: Slot,
    subtree: Slot,
    subdomains: Slot,
}

#[derive(Debug, Default)]
pub struct RuleMatcher {
    root: Node,
    rules: Vec<Rule>,
}

impl RuleMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_rules(rules: impl IntoIterator<Item = Rule>) -> Self {
        let mut m = Self::new();
        for r in rules {
            m.insert(r);
        }
        m
    }

    pub fn insert(&mut self, rule: Rule) -> RuleId {
        let id = RuleId(u32::try_from(self.rules.len()).expect("rule count fits in u32"));
        let mut node = &mut self.root;
        for label in rule.domain.labels().rev() {
            node = node.children.entry(label.into()).or_default();
        }
        match rule.scope {
            Scope::Exact => node.exact.set(id, &rule),
            Scope::DomainAndSubdomains => node.subtree.set(id, &rule),
            Scope::SubdomainsOnly => node.subdomains.set(id, &rule),
        }
        self.rules.push(rule);
        id
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rule(&self, id: RuleId) -> Option<&Rule> {
        self.rules.get(id.0 as usize)
    }

    /// Find the governing rule for an already-normalized domain.
    pub fn lookup(&self, domain: &Domain) -> Option<MatchDetail> {
        let labels: Vec<&str> = domain.labels().rev().collect();
        let mut node = &self.root;
        let mut best: Option<MatchDetail> = None;

        for (depth, label) in labels.iter().enumerate() {
            let Some(next) = node.children.get(*label) else {
                break;
            };
            node = next;
            let is_last = depth + 1 == labels.len();
            let candidate = if is_last {
                node.exact.resolve().or_else(|| node.subtree.resolve())
            } else {
                node.subtree.resolve().or_else(|| node.subdomains.resolve())
            };
            if candidate.is_some() {
                best = candidate;
            }
        }
        best
    }

    pub fn verdict(&self, domain: &Domain) -> Verdict {
        match self.lookup(domain) {
            Some(MatchDetail {
                rule,
                action: Action::Block,
                category,
            }) => Verdict::Block { rule, category },
            _ => Verdict::Allow,
        }
    }

    /// Normalize raw input then match. Unparseable names are allowed through
    /// here; callers that see them from the network should treat them as
    /// malformed traffic, not as a policy decision.
    pub fn check(&self, raw: &str) -> Result<Verdict, DomainError> {
        Ok(self.verdict(&Domain::parse(raw)?))
    }
}
