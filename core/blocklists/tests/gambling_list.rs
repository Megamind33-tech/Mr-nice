use gg_blocklist::bundled::*;
use gg_blocklist::{RuleCompiler, UpdatePolicy, VerifiedList};
use gg_crypto::PublicKey;
use gg_rules_engine::Verdict;

fn verified() -> VerifiedList {
    let key = PublicKey::from_hex(DEV_SIGNING_KEY).unwrap();
    VerifiedList::verify(
        &[key],
        GAMBLING_MANIFEST.as_bytes(),
        GAMBLING_PAYLOAD.as_bytes(),
    )
    .expect("bundled list verifies against pinned key")
}

#[test]
fn bundled_list_verifies_and_meets_policy() {
    let list = verified();
    let compiled = RuleCompiler::compile(&list.payload);
    assert_eq!(compiled.error_lines, 0);
    assert_eq!(compiled.rule_count as u64, list.manifest.rule_count);
    assert!(compiled.rule_count >= UpdatePolicy::default().min_rules);
}

#[test]
fn representative_gambling_domains_are_blocked_with_category() {
    let m = RuleCompiler::compile(&verified().payload).matcher;
    let cases = [
        ("www.bet365.com", "sports_betting"),
        ("sports.williamhill.com", "sports_betting"),
        ("sportsbook.draftkings.com", "sports_betting"),
        ("SPORTSBOOK.FANDUEL.COM.", "sports_betting"),
        ("www.sportpesa.com", "sports_betting"),
        ("www.888casino.com", "online_casino"),
        ("www.pokerstars.com", "poker"),
        ("www.foxybingo.com", "bingo"),
        ("www.lottoland.com", "lotteries"),
        ("www.betfair.com", "betting_exchange"),
        ("app.prizepicks.com", "fantasy_betting"),
        ("www.rivalry.com", "esports_betting"),
        ("stake.com", "crypto_casino"),
        ("csgoempire.com", "skin_betting"),
        ("www.oddschecker.com", "gambling_affiliates"),
        ("www.bet365.es", "gambling_mirrors"),
    ];
    for (domain, category) in cases {
        match m.check(domain).unwrap() {
            Verdict::Block { category: c, .. } => assert_eq!(c.id(), category, "{domain}"),
            Verdict::Allow => panic!("{domain} not blocked"),
        }
    }
}

#[test]
fn legitimate_lookalikes_are_not_blocked() {
    let m = RuleCompiler::compile(&verified().payload).matcher;
    for domain in [
        "google.com",
        "wikipedia.org",
        "bbc.co.uk",
        "espn.com",         // sports news; only espnbet.com is listed
        "www.fanatics.com", // merchandise; only sportsbook.fanatics.com is listed
        "alphabet.com",
        "betterhelp.com",
        "stake.com.evil.test",
        "notbet365.com",
        "gamcare.org.uk", // gambling support services must stay reachable
        "begambleaware.org",
        "gamblersanonymous.org",
    ] {
        assert!(
            !m.check(domain).unwrap().is_blocked(),
            "{domain} wrongly blocked"
        );
    }
}

#[test]
fn tampering_with_bundled_payload_is_detected() {
    let key = PublicKey::from_hex(DEV_SIGNING_KEY).unwrap();
    let edited = GAMBLING_PAYLOAD.replace("bet365.com\n", "");
    assert!(VerifiedList::verify(&[key], GAMBLING_MANIFEST.as_bytes(), edited.as_bytes()).is_err());
}
