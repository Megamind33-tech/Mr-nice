use gg_dns_filter::message::*;

#[test]
fn parses_standard_query_and_lowercases_name() {
    let q = build_query(0xBEEF, "WwW.GaMbLiNg-TeSt.LoCaL", TYPE_A);
    let parsed = parse_query(&q).unwrap();
    assert_eq!(parsed.id, 0xBEEF);
    assert_eq!(parsed.name.as_deref(), Some("www.gambling-test.local"));
    assert_eq!(parsed.qtype, TYPE_A);
    assert_eq!(parsed.qclass, CLASS_IN);
    assert_eq!(parsed.head, &q[..]);
}

#[test]
fn root_query_has_empty_name() {
    let q = build_query(1, ".", 2);
    assert_eq!(parse_query(&q).unwrap().name.as_deref(), Some(""));
}

#[test]
fn rejects_short_responses_and_bad_counts() {
    assert_eq!(parse_query(&[0; 5]), Err(ParseError::TooShort));
    let mut resp = build_query(1, "a.test", TYPE_A);
    resp[2] |= 0x80;
    assert_eq!(parse_query(&resp), Err(ParseError::NotAQuery));
    let mut two = build_query(1, "a.test", TYPE_A);
    two[5] = 2;
    assert_eq!(parse_query(&two), Err(ParseError::QuestionCount));
    let mut update = build_query(1, "a.test", TYPE_A);
    update[2] |= 5 << 3; // opcode UPDATE
    assert_eq!(parse_query(&update), Err(ParseError::UnsupportedOpcode));
}

#[test]
fn rejects_truncated_and_compressed_questions() {
    let q = build_query(1, "casino.test", TYPE_A);
    for cut in 13..q.len() {
        assert!(parse_query(&q[..cut]).is_err(), "cut at {cut}");
    }
    let mut ptr = q[..12].to_vec();
    ptr.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
    assert_eq!(parse_query(&ptr), Err(ParseError::Malformed));
}

#[test]
fn label_with_dot_or_binary_is_not_a_valid_name() {
    // One label "casino.test" (literal dot inside) must not be read as two labels.
    let mut q = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11];
    q.extend_from_slice(b"casino.test");
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(parse_query(&q).unwrap().name, None);
}

#[test]
fn sinkhole_a_and_aaaa() {
    for (qtype, rdata) in [(TYPE_A, vec![0u8; 4]), (TYPE_AAAA, vec![0u8; 16])] {
        let q = build_query(7, "Casino.Test", qtype);
        let resp = blocked_response(&parse_query(&q).unwrap(), BlockResponse::Sinkhole);
        let s = summarize_response(&resp).unwrap();
        assert_eq!((s.id, s.rcode, s.answer_count), (7, 0, 1));
        assert_eq!(s.first_rdata.unwrap(), rdata);
        // Question echoed verbatim, preserving the client's casing.
        assert_eq!(&resp[12..q.len()], &q[12..]);
    }
}

#[test]
fn sinkhole_other_types_are_empty_noerror() {
    let q = build_query(9, "casino.test", 65); // HTTPS RR
    let resp = blocked_response(&parse_query(&q).unwrap(), BlockResponse::Sinkhole);
    let s = summarize_response(&resp).unwrap();
    assert_eq!((s.rcode, s.answer_count), (0, 0));
}

#[test]
fn nxdomain_mode() {
    let q = build_query(9, "casino.test", TYPE_A);
    let resp = blocked_response(&parse_query(&q).unwrap(), BlockResponse::NxDomain);
    let s = summarize_response(&resp).unwrap();
    assert_eq!((s.rcode, s.answer_count), (3, 0));
}

#[test]
fn response_preserves_rd_flag() {
    let q = build_query(3, "casino.test", TYPE_A);
    let resp = blocked_response(&parse_query(&q).unwrap(), BlockResponse::Sinkhole);
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(flags & 0x8000, 0x8000, "QR");
    assert_eq!(flags & 0x0100, 0x0100, "RD");
    assert_eq!(flags & 0x0080, 0x0080, "RA");
}
