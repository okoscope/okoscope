use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use event_model::{
    DnsAddressAnswer, DnsCname, DnsName, DnsQueryType, DnsResponseCode, MAX_DNS_ANSWERS,
    MAX_DNS_CNAME_CHAIN,
};
use thiserror::Error;

const DNS_HEADER_LEN: usize = 12;
const MAX_POINTER_HOPS: usize = 16;
const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub truncated: bool,
    pub name: DnsName,
    pub query_type: DnsQueryType,
    pub response_code: DnsResponseCode,
    pub answers: Vec<DnsAddressAnswer>,
    pub cname_chain: Vec<DnsCname>,
    pub effective_ttl_seconds: Option<u32>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DnsParseError {
    #[error("DNS message is truncated or has invalid bounds")]
    Bounds,
    #[error("DNS compression pointer is malformed")]
    Compression,
    #[error("DNS header or question shape is unsupported")]
    Unsupported,
    #[error("DNS name is not canonicalizable within platform bounds")]
    Name,
    #[error("DNS answer count or TTL exceeds platform bounds")]
    Limit,
}

pub fn parse_message(
    bytes: &[u8],
    max_ttl_seconds: u32,
) -> Result<ParsedDnsMessage, DnsParseError> {
    if bytes.len() < DNS_HEADER_LEN || max_ttl_seconds == 0 {
        return Err(DnsParseError::Bounds);
    }
    let flags = read_u16(bytes, 2)?;
    let opcode = (flags >> 11) & 0x0f;
    let qd_count = read_u16(bytes, 4)?;
    let answer_count = usize::from(read_u16(bytes, 6)?);
    if opcode != 0 || qd_count != 1 || answer_count > MAX_DNS_ANSWERS + MAX_DNS_CNAME_CHAIN {
        return Err(DnsParseError::Unsupported);
    }
    let (name, mut offset) = decode_name(bytes, DNS_HEADER_LEN)?;
    let raw_query_type = read_u16(bytes, offset)?;
    let query_type = query_type(raw_query_type)?;
    if read_u16(bytes, offset + 2)? != CLASS_IN {
        return Err(DnsParseError::Unsupported);
    }
    offset += 4;
    let is_response = flags & 0x8000 != 0;
    let response_code = response_code((flags & 0x0f) as u8)?;
    let mut answers = Vec::new();
    let mut cname_chain = Vec::new();
    let mut effective_ttl_seconds = None;
    for _ in 0..answer_count {
        let (record_name, next) = decode_name(bytes, offset)?;
        offset = next;
        let record_type = read_u16(bytes, offset)?;
        let class = read_u16(bytes, offset + 2)?;
        let ttl = read_u32(bytes, offset + 4)?.min(max_ttl_seconds);
        let data_len = usize::from(read_u16(bytes, offset + 8)?);
        let data_offset = offset.checked_add(10).ok_or(DnsParseError::Bounds)?;
        let data_end = data_offset
            .checked_add(data_len)
            .ok_or(DnsParseError::Bounds)?;
        if data_end > bytes.len() {
            return Err(DnsParseError::Bounds);
        }
        if class == CLASS_IN && ttl > 0 {
            match (record_type, data_len) {
                (TYPE_A, 4) if answers.len() < MAX_DNS_ANSWERS => {
                    let address = Ipv4Addr::new(
                        bytes[data_offset],
                        bytes[data_offset + 1],
                        bytes[data_offset + 2],
                        bytes[data_offset + 3],
                    );
                    answers.push(
                        DnsAddressAnswer::new(record_name, IpAddr::V4(address), ttl)
                            .map_err(|_| DnsParseError::Limit)?,
                    );
                    effective_ttl_seconds =
                        Some(effective_ttl_seconds.map_or(ttl, |value: u32| value.min(ttl)));
                }
                (TYPE_AAAA, 16) if answers.len() < MAX_DNS_ANSWERS => {
                    let octets = <[u8; 16]>::try_from(&bytes[data_offset..data_end])
                        .map_err(|_| DnsParseError::Bounds)?;
                    answers.push(
                        DnsAddressAnswer::new(record_name, IpAddr::V6(Ipv6Addr::from(octets)), ttl)
                            .map_err(|_| DnsParseError::Limit)?,
                    );
                    effective_ttl_seconds =
                        Some(effective_ttl_seconds.map_or(ttl, |value: u32| value.min(ttl)));
                }
                (TYPE_CNAME, _) if cname_chain.len() < MAX_DNS_CNAME_CHAIN => {
                    let (canonical, consumed) = decode_name(bytes, data_offset)?;
                    if consumed > data_end && bytes[data_offset] & 0xc0 != 0xc0 {
                        return Err(DnsParseError::Bounds);
                    }
                    cname_chain.push(
                        DnsCname::new(record_name, canonical, ttl)
                            .map_err(|_| DnsParseError::Limit)?,
                    );
                    effective_ttl_seconds =
                        Some(effective_ttl_seconds.map_or(ttl, |value: u32| value.min(ttl)));
                }
                (TYPE_A | TYPE_AAAA, _) => return Err(DnsParseError::Bounds),
                _ => {}
            }
        }
        offset = data_end;
    }
    Ok(ParsedDnsMessage {
        transaction_id: read_u16(bytes, 0)?,
        is_response,
        truncated: flags & 0x0200 != 0,
        name,
        query_type,
        response_code,
        answers,
        cname_chain,
        effective_ttl_seconds,
    })
}

fn decode_name(bytes: &[u8], start: usize) -> Result<(DnsName, usize), DnsParseError> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut next = None;
    for _ in 0..MAX_POINTER_HOPS {
        let length = *bytes.get(cursor).ok_or(DnsParseError::Bounds)?;
        if length == 0 {
            let consumed = next.unwrap_or(cursor + 1);
            return DnsName::new(labels.join("."))
                .map(|name| (name, consumed))
                .map_err(|_| DnsParseError::Name);
        }
        if length & 0xc0 == 0xc0 {
            let low = usize::from(*bytes.get(cursor + 1).ok_or(DnsParseError::Bounds)?);
            let pointer = (usize::from(length & 0x3f) << 8) | low;
            if pointer >= bytes.len() || pointer >= cursor {
                return Err(DnsParseError::Compression);
            }
            next.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length > 63 || length & 0xc0 != 0 {
            return Err(DnsParseError::Compression);
        }
        let label_start = cursor + 1;
        let label_end = label_start + usize::from(length);
        let label = bytes
            .get(label_start..label_end)
            .ok_or(DnsParseError::Bounds)?;
        if label
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
        {
            return Err(DnsParseError::Name);
        }
        labels.push(
            String::from_utf8(label.iter().map(u8::to_ascii_lowercase).collect())
                .map_err(|_| DnsParseError::Name)?,
        );
        cursor = label_end;
    }
    Err(DnsParseError::Compression)
}

fn query_type(value: u16) -> Result<DnsQueryType, DnsParseError> {
    match value {
        TYPE_A => Ok(DnsQueryType::A),
        TYPE_AAAA => Ok(DnsQueryType::Aaaa),
        _ => Err(DnsParseError::Unsupported),
    }
}

fn response_code(value: u8) -> Result<DnsResponseCode, DnsParseError> {
    match value {
        0 => Ok(DnsResponseCode::NoError),
        1 => Ok(DnsResponseCode::FormErr),
        2 => Ok(DnsResponseCode::ServFail),
        3 => Ok(DnsResponseCode::NxDomain),
        4 => Ok(DnsResponseCode::NotImp),
        5 => Ok(DnsResponseCode::Refused),
        _ => Err(DnsParseError::Unsupported),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DnsParseError> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(DnsParseError::Bounds)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DnsParseError> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(DnsParseError::Bounds)?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normalized_a_response_and_ignores_edns() {
        let bytes = hex::decode("12348180000100010000000103415049074578616d706c6503636f6d0000010001c00c000100010000012c0004cb00710700002904d0000000000000").unwrap();
        let parsed = parse_message(&bytes, 60).unwrap();
        assert_eq!(parsed.name.as_str(), "api.example.com");
        assert_eq!(
            parsed.answers[0].address,
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(parsed.answers[0].ttl_seconds, 60);
        assert_eq!(parsed.effective_ttl_seconds, Some(60));
    }

    #[test]
    fn parses_nxdomain_without_inventing_answers() {
        let bytes =
            hex::decode("12348183000100000000000003617069076578616d706c6503636f6d0000010001")
                .unwrap();
        let parsed = parse_message(&bytes, 60).unwrap();
        assert_eq!(parsed.response_code, DnsResponseCode::NxDomain);
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn rejects_forward_or_looping_compression_and_malformed_lengths() {
        let forward = hex::decode("123401000001000000000000c00e0001000100").unwrap();
        assert_eq!(parse_message(&forward, 60), Err(DnsParseError::Compression));
        let short = hex::decode("1234818000010001000000000361706900").unwrap();
        assert_eq!(parse_message(&short, 60), Err(DnsParseError::Bounds));
    }

    #[test]
    fn accepts_idna_wire_name_and_multiple_a_answers_with_cname() {
        let idna = hex::decode(
            "1234010000010000000000000c786e2d2d653161666d6b666408786e2d2d703161690000010001",
        )
        .unwrap();
        assert_eq!(
            parse_message(&idna, 60).unwrap().name.as_str(),
            "xn--e1afmkfd.xn--p1ai"
        );

        let response = hex::decode(concat!(
            "123481800001000300000000",
            "03777777076578616d706c6503636f6d0000010001",
            "c00c000500010000003c0011",
            "0363646e076578616d706c6503636f6d00",
            "c00c000100010000003c0004cb007107",
            "c00c000100010000001e0004cb007108"
        ))
        .unwrap();
        let parsed = parse_message(&response, 45).unwrap();
        assert_eq!(parsed.cname_chain.len(), 1);
        assert_eq!(parsed.cname_chain[0].canonical.as_str(), "cdn.example.com");
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.effective_ttl_seconds, Some(30));
        assert_eq!(parsed.answers[0].ttl_seconds, 45);
        assert_eq!(parsed.answers[1].ttl_seconds, 30);
    }

    #[test]
    fn unsupported_txt_and_edns_data_is_not_retained() {
        let response = hex::decode(concat!(
            "123481800001000100000001",
            "03617069076578616d706c6503636f6d0000010001",
            "c00c001000010000003c0006736563726574",
            "00002904d0000000000000"
        ))
        .unwrap();
        let parsed = parse_message(&response, 60).unwrap();
        assert!(parsed.answers.is_empty());
        assert!(parsed.cname_chain.is_empty());
        assert_eq!(parsed.effective_ttl_seconds, None);
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn every_truncated_prefix_is_rejected_without_panicking() {
        let packet = hex::decode(
            "12348180000100010000000003617069076578616d706c6503636f6d0000010001c00c000100010000003c0004cb007107",
        )
        .unwrap();
        for end in 0..packet.len() {
            assert!(parse_message(&packet[..end], 60).is_err(), "prefix {end}");
        }
        assert!(parse_message(&packet, 60).is_ok());
    }
}
