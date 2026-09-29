use gg_rules_engine::{parse_list, Action, Category, Domain, Rule, RuleMatcher, Scope, Verdict};

fn matcher(lines: &[&str]) -> RuleMatcher {
    RuleMatcher::from_rules(
        lines
            .iter()
            .map(|l| Rule::parse(l, Category::OnlineCasino).unwrap()),
    )
}

fn blocked(m: &RuleMatcher, d: &str) -> bool {
    m.check(d).unwrap().is_blocked()
}

#[test]
fn plain_rule_blocks_apex_and_subdomains() {
    let m = matcher(&["example-gambling-domain.com"]);
    assert!(blocked(&m, "example-gambling-domain.com"));
    assert!(blocked(&m, "www.example-gambling-domain.com"));
    assert!(blocked(&m, "a.b.c.example-gambling-domain.com"));
    assert!(blocked(&m, "WWW.EXAMPLE-GAMBLING-DOMAIN.COM."));
}

#[test]
fn no_substring_or_suffix_string_matching() {
    let m = matcher(&["bet.com"]);
    assert!(!blocked(&m, "alphabet.com"));
    assert!(!blocked(&m, "bet.com.evil.org"));
    assert!(!blocked(&m, "notbet.com"));
    assert!(!blocked(&m, "bet.co"));
    assert!(!blocked(&m, "com"));
}

#[test]
fn wildcard_blocks_subdomains_only() {
    let m = matcher(&["*.example.com"]);
    assert!(!blocked(&m, "example.com"));
    assert!(blocked(&m, "casino.example.com"));
    assert!(blocked(&m, "deep.casino.example.com"));
}

#[test]
fn exact_rule_blocks_only_that_host() {
    let m = matcher(&["=casino.example.com"]);
    assert!(blocked(&m, "casino.example.com"));
    assert!(!blocked(&m, "www.casino.example.com"));
    assert!(!blocked(&m, "example.com"));
}

#[test]
fn specific_subdomain_rule() {
    let m = matcher(&["casino.example.com"]);
    assert!(blocked(&m, "casino.example.com"));
    assert!(blocked(&m, "m.casino.example.com"));
    assert!(!blocked(&m, "example.com"));
    assert!(!blocked(&m, "news.example.com"));
}

#[test]
fn more_specific_allow_overrides_broader_block() {
    let m = matcher(&["example.com", "@@help.example.com"]);
    assert!(blocked(&m, "example.com"));
    assert!(blocked(&m, "casino.example.com"));
    assert!(!blocked(&m, "help.example.com"));
    assert!(!blocked(&m, "x.help.example.com"));
}

#[test]
fn more_specific_block_overrides_broader_allow() {
    let m = matcher(&["@@example.com", "casino.example.com"]);
    assert!(!blocked(&m, "example.com"));
    assert!(blocked(&m, "casino.example.com"));
}

#[test]
fn block_wins_tie_with_allow_at_same_scope() {
    for order in [
        ["example.com", "@@example.com"],
        ["@@example.com", "example.com"],
    ] {
        let m = matcher(&order);
        assert!(blocked(&m, "example.com"), "order {order:?}");
    }
}

#[test]
fn idn_rule_matches_punycode_query_and_vice_versa() {
    let m = matcher(&["казино.example"]);
    let puny = Domain::parse("казино.example").unwrap();
    assert!(puny.as_str().starts_with("xn--"));
    assert!(blocked(&m, puny.as_str()));
    assert!(blocked(&m, "WWW.КАЗИНО.example"));
}

#[test]
fn verdict_reports_rule_and_category() {
    let mut m = RuleMatcher::new();
    let id = m.insert(Rule::parse("poker.test", Category::Poker).unwrap());
    assert_eq!(
        m.check("www.poker.test").unwrap(),
        Verdict::Block {
            rule: id,
            category: Category::Poker
        }
    );
    assert_eq!(m.rule(id).unwrap().scope, Scope::DomainAndSubdomains);
}

#[test]
fn empty_matcher_allows_everything() {
    let m = RuleMatcher::new();
    assert_eq!(m.check("anything.com").unwrap(), Verdict::Allow);
}

#[test]
fn removing_a_rule_restores_access() {
    // Rule sets are immutable once compiled; removal = recompile without it.
    let with = matcher(&["gambling-test.local", "other.test"]);
    assert!(blocked(&with, "gambling-test.local"));
    let without = matcher(&["other.test"]);
    assert!(!blocked(&without, "gambling-test.local"));
}

#[test]
fn rejects_mid_label_wildcards() {
    assert!(Rule::parse("casino*.com", Category::UserDefined).is_err());
    assert!(Rule::parse("a.*.com", Category::UserDefined).is_err());
}

#[test]
fn list_parsing_with_sections_comments_and_errors() {
    let text = "\
# header comment
[sports_betting]
bet-site.test        # inline comment
*.odds.test

[future_category_v9]
new.test
@@ok.new.test
bad..entry
";
    let parsed = parse_list(text, Category::UserDefined);
    assert_eq!(parsed.rules.len(), 4);
    assert_eq!(parsed.errors.len(), 1);
    assert_eq!(parsed.errors[0].line, 9);
    assert_eq!(parsed.rules[0].category, Category::SportsBetting);
    assert_eq!(
        parsed.rules[2].category,
        Category::Other("future_category_v9".into())
    );
    assert_eq!(parsed.rules[3].action, Action::Allow);

    let m = RuleMatcher::from_rules(parsed.rules);
    assert!(blocked(&m, "www.bet-site.test"));
    assert!(blocked(&m, "live.odds.test"));
    assert!(!blocked(&m, "odds.test"));
    assert!(blocked(&m, "new.test"));
    assert!(!blocked(&m, "ok.new.test"));
}

#[test]
fn category_ids_round_trip() {
    for id in [
        "sports_betting",
        "crypto_casino",
        "skin_betting",
        "gambling_mirrors",
    ] {
        let c: Category = id.parse().unwrap();
        assert!(!matches!(c, Category::Other(_)));
        assert_eq!(c.id(), id);
    }
}

#[test]
fn large_list_lookup_is_correct() {
    let rules =
        (0..50_000).map(|i| Rule::parse(&format!("site{i}.test"), Category::Slots).unwrap());
    let m = RuleMatcher::from_rules(rules);
    assert!(blocked(&m, "www.site49999.test"));
    assert!(!blocked(&m, "site50000.test"));
}
