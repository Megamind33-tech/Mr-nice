//! Minimal DNS wire-format handling (RFC 1035).
//!
//! The filter only needs to read the question of incoming queries and to
//! synthesize a small set of responses. Allowed queries are forwarded
//! upstream byte-for-byte, so EDNS options, DNSSEC bits and 0x20 case
//! randomization pass through untouched.

use thiserror::Error;

pub const HEADER_LEN: usize = 12;
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

const FLAG_QR: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_CD: u16 = 0x0010;

/// TTL on synthesized block answers. Short, so removing a rule restores
/// access quickly once caches expire.
pub const BLOCK_TTL_SECS: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Too short to hold a header; there is nothing to answer.
    #[error("packet shorter than DNS header")]
    TooShort,
    /// Header readable but the message is not an answerable query.
    #[error("malformed query")]
    Malformed,
    #[error("message is a response, not a query")]
    NotAQuery,
    #[error("unsupported opcode")]
    UnsupportedOpcode,
    #[error("query must contain exactly one question")]
    QuestionCount,
}

/// How a blocked name is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockResponse {
    /// `A 0.0.0.0` / `AAAA ::`; other types get an empty NOERROR answer.
    /// Connection attempts fail immediately instead of retrying other
    /// resolvers, which some stacks do after NXDOMAIN.
    #[default]
    Sinkhole,
    NxDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query<'a> {
    pub id: u16,
    pub flags: u16,
    /// Lower-cased dotted name without trailing dot; empty for the root.
    /// `None` when a label contains bytes that cannot appear in a hostname.
    pub name: Option<String>,
    pub qtype: u16,
    pub qclass: u16,
    /// Header + question exactly as received (preserves 0x20 casing).
    pub head: &'a [u8],
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]))
}

/// Read only the transaction ID, for error replies to unparseable queries.
pub fn read_id(buf: &[u8]) -> Option<u16> {
    read_u16(buf, 0)
}

pub fn parse_query(buf: &[u8]) -> Result<Query<'_>, ParseError> {
    if buf.len() < HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    let id = read_u16(buf, 0).ok_or(ParseError::TooShort)?;
    let flags = read_u16(buf, 2).ok_or(ParseError::TooShort)?;
    if flags & FLAG_QR != 0 {
        return Err(ParseError::NotAQuery);
    }
    if flags & OPCODE_MASK != 0 {
        return Err(ParseError::UnsupportedOpcode);
    }
    if read_u16(buf, 4) != Some(1) {
        return Err(ParseError::QuestionCount);
    }

    let mut pos = HEADER_LEN;
    let mut name = String::new();
    let mut valid = true;
    loop {
        let len = *buf.get(pos).ok_or(ParseError::Malformed)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // The question is the first name in the message, so a compression
        // pointer (or the reserved 0x40/0x80 label types) is never legal.
        if len & 0xC0 != 0 {
            return Err(ParseError::Malformed);
        }
        let label = buf.get(pos..pos + len).ok_or(ParseError::Malformed)?;
        pos += len;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                name.push(b.to_ascii_lowercase() as char);
            } else {
                valid = false;
            }
        }
        if name.len() > 255 {
            return Err(ParseError::Malformed);
        }
    }
    let qtype = read_u16(buf, pos).ok_or(ParseError::Malformed)?;
    let qclass = read_u16(buf, pos + 2).ok_or(ParseError::Malformed)?;
    pos += 4;

    Ok(Query {
        id,
        flags,
        name: valid.then_some(name),
        qtype,
        qclass,
        head: &buf[..pos],
    })
}

fn response_header(out: &mut Vec<u8>, id: u16, query_flags: u16, rcode: Rcode, qd: u16, an: u16) {
    let flags = FLAG_QR | FLAG_RA | (query_flags & (FLAG_RD | FLAG_CD)) | rcode as u16;
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&an.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
}

/// Response echoing the question with the given rcode and no records.
pub fn error_response(query: &Query<'_>, rcode: Rcode) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.head.len());
    response_header(&mut out, query.id, query.flags, rcode, 1, 0);
    out.extend_from_slice(&query.head[HEADER_LEN..]);
    out
}

/// Header-only error reply for input whose question cannot be parsed.
pub fn bare_error_response(id: u16, rcode: Rcode) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    response_header(&mut out, id, 0, rcode, 0, 0);
    out
}

pub fn blocked_response(query: &Query<'_>, mode: BlockResponse) -> Vec<u8> {
    if mode == BlockResponse::NxDomain {
        return error_response(query, Rcode::NxDomain);
    }
    let rdata: &[u8] = match (query.qclass, query.qtype) {
        (CLASS_IN, TYPE_A) => &[0; 4],
        (CLASS_IN, TYPE_AAAA) => &[0; 16],
        _ => return error_response(query, Rcode::NoError),
    };
    let mut out = Vec::with_capacity(query.head.len() + 12 + rdata.len());
    response_header(&mut out, query.id, query.flags, Rcode::NoError, 1, 1);
    out.extend_from_slice(&query.head[HEADER_LEN..]);
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to question name
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&BLOCK_TTL_SECS.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

/// Build a standard recursive query. Used by tests and health probes.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// Fields of a response needed to validate upstream replies and in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSummary {
    pub id: u16,
    pub rcode: u8,
    pub answer_count: u16,
    /// RDATA of the first answer record, if any.
    pub first_rdata: Option<Vec<u8>>,
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

pub fn summarize_response(buf: &[u8]) -> Option<ResponseSummary> {
    let id = read_u16(buf, 0)?;
    let flags = read_u16(buf, 2)?;
    if flags & FLAG_QR == 0 {
        return None;
    }
    let qd = read_u16(buf, 4)?;
    let an = read_u16(buf, 6)?;
    let mut pos = HEADER_LEN;
    for _ in 0..qd {
        pos = skip_name(buf, pos)? + 4;
    }
    let first_rdata = if an > 0 {
        let p = skip_name(buf, pos)?;
        let rdlen = read_u16(buf, p + 8)? as usize;
        Some(buf.get(p + 10..p + 10 + rdlen)?.to_vec())
    } else {
        None
    };
    Some(ResponseSummary {
        id,
        rcode: (flags & 0x000F) as u8,
        answer_count: an,
        first_rdata,
    })
}
