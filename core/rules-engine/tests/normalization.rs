use gg_rules_engine::{normalize_domain, DomainError};

#[test]
fn case_and_trailing_dot_normalize_identically() {
    for input in [
        "WWW.BETTING-SITE.COM",
        "www.betting-site.com.",
        "  www.Betting-Site.com  ",
    ] {
        assert_eq!(normalize_domain(input).unwrap(), "www.betting-site.com");
    }
}

#[test]
fn unicode_idn_converts_to_punycode() {
    assert_eq!(
        normalize_domain("bücher.example").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(
        normalize_domain("BÜCHER.example.").unwrap(),
        "xn--bcher-kva.example"
    );
}

#[test]
fn punycode_input_is_preserved() {
    assert_eq!(
        normalize_domain("XN--BCHER-KVA.example").unwrap(),
        "xn--bcher-kva.example"
    );
}

#[test]
fn unicode_and_punycode_forms_are_equal() {
    assert_eq!(
        normalize_domain("казино.example").unwrap(),
        normalize_domain(&normalize_domain("казино.example").unwrap()).unwrap()
    );
}

#[test]
fn rejects_malformed() {
    assert_eq!(normalize_domain(""), Err(DomainError::Empty));
    assert_eq!(normalize_domain("."), Err(DomainError::Empty));
    assert_eq!(normalize_domain("a..b"), Err(DomainError::EmptyLabel));
    assert_eq!(normalize_domain(".a.b"), Err(DomainError::EmptyLabel));
    assert_eq!(normalize_domain("a.b.."), Err(DomainError::EmptyLabel));
    assert_eq!(normalize_domain("-a.com"), Err(DomainError::HyphenPosition));
    assert_eq!(normalize_domain("a-.com"), Err(DomainError::HyphenPosition));
    assert_eq!(
        normalize_domain("a b.com"),
        Err(DomainError::InvalidCharacter)
    );
    assert_eq!(
        normalize_domain("a/b.com"),
        Err(DomainError::InvalidCharacter)
    );
}

#[test]
fn length_limits() {
    let label63 = "a".repeat(63);
    assert!(normalize_domain(&format!("{label63}.com")).is_ok());
    assert_eq!(
        normalize_domain(&format!("{}.com", "a".repeat(64))),
        Err(DomainError::LabelTooLong)
    );
    let long = [label63.as_str(); 4].join(".");
    assert_eq!(long.len(), 255);
    assert_eq!(normalize_domain(&long), Err(DomainError::TooLong));
}

#[test]
fn underscore_labels_accepted() {
    assert_eq!(
        normalize_domain("_dmarc.Example.com").unwrap(),
        "_dmarc.example.com"
    );
}
