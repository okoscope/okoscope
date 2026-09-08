use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use agent_ebpf_common::{
    ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_IPV6, DNS_DIRECTION_EGRESS, DNS_DIRECTION_INGRESS,
    DNS_TRANSPORT_TCP, DNS_TRANSPORT_UDP, DnsPacketRecord,
};
use chrono::Utc;
use event_model::{
    DnsDirection, DnsTransport, EventPayload, NetworkDnsQuery, NetworkDnsResponse, ProcessIdentity,
};

use crate::{
    config::DnsObservationConfig,
    counters::Counters,
    dns::{ParsedDnsMessage, parse_message},
    dns_state::{DnsState, PendingQueryKey},
    dns_tcp::{TcpDnsReassembler, TcpDnsStreamKey},
};

#[derive(Debug)]
pub struct DnsProcessor {
    state: DnsState,
    tcp: TcpDnsReassembler,
    max_ttl_seconds: u32,
}

#[derive(Clone, Copy)]
struct PacketContext {
    direction: DnsDirection,
    transport: DnsTransport,
    resolver_address: IpAddr,
    now: Instant,
}

impl DnsProcessor {
    #[must_use]
    pub fn new(config: &DnsObservationConfig) -> Self {
        Self {
            state: DnsState::new(
                config.max_pending_transactions,
                config.max_names_per_address,
                Duration::from_secs(5),
                Duration::from_secs(u64::from(config.max_ttl_seconds)),
            ),
            tcp: TcpDnsReassembler::new(
                config.max_tcp_streams,
                config.max_captured_bytes,
                Duration::from_secs(5),
            ),
            max_ttl_seconds: config.max_ttl_seconds,
        }
    }

    pub fn process(
        &mut self,
        packet: &DnsPacketRecord,
        counters: &Counters,
    ) -> Option<(ProcessIdentity, EventPayload)> {
        let transport = transport(packet.transport)?;
        let direction = direction(packet.direction)?;
        let resolver_address = resolver_address(packet)?;
        let payload_len = usize::from(packet.payload_len);
        let payload = packet.payload.get(..payload_len)?;
        let now = Instant::now();
        let message = if transport == DnsTransport::Tcp {
            match self.tcp.push(
                TcpDnsStreamKey {
                    cgroup_id: packet.cgroup_id,
                    socket_cookie: packet.socket_cookie,
                    direction: packet.direction,
                },
                packet.sequence,
                payload,
                now,
            ) {
                Ok(Some(message)) => message,
                Ok(None) => return None,
                Err(_) => {
                    counters.dns_tcp_reassembly.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        } else {
            payload.to_vec()
        };
        let parsed = match parse_message(&message, self.max_ttl_seconds) {
            Ok(parsed) => parsed,
            Err(error) => {
                match error {
                    crate::dns::DnsParseError::Compression => {
                        counters
                            .dns_malformed_compression
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::dns::DnsParseError::Unsupported => {
                        counters
                            .dns_unsupported_record
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        counters
                            .dns_packet_decode_failed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                return None;
            }
        };
        if parsed.truncated {
            counters.dns_truncated.fetch_add(1, Ordering::Relaxed);
        }
        self.typed_event(
            packet,
            parsed,
            PacketContext {
                direction,
                transport,
                resolver_address,
                now,
            },
            counters,
        )
    }

    pub fn attach_context(&mut self, cgroup_id: u64, payload: &mut EventPayload) {
        if let EventPayload::NetworkConnect(connect) = payload {
            connect.dns_context =
                self.state
                    .context_for(cgroup_id, connect.destination_address, Utc::now());
        }
    }

    fn typed_event(
        &mut self,
        packet: &DnsPacketRecord,
        parsed: ParsedDnsMessage,
        context: PacketContext,
        counters: &Counters,
    ) -> Option<(ProcessIdentity, EventPayload)> {
        let key = PendingQueryKey {
            cgroup_id: packet.cgroup_id,
            transport: context.transport,
            resolver_address: context.resolver_address,
            transaction_id: parsed.transaction_id,
            name: parsed.name.clone(),
            query_type: parsed.query_type,
        };
        if !parsed.is_response {
            if context.direction != DnsDirection::Egress {
                counters
                    .dns_correlation_miss
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let process = process_identity(packet);
            if !self.state.register_query(key, process.clone(), context.now) {
                counters
                    .dns_correlation_capacity
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let query = NetworkDnsQuery {
                transaction_id: parsed.transaction_id,
                direction: context.direction,
                transport: context.transport,
                resolver_address: context.resolver_address,
                name: parsed.name,
                query_type: parsed.query_type,
            };
            return Some((process, EventPayload::NetworkDnsQuery(query)));
        }
        if context.direction != DnsDirection::Ingress {
            counters
                .dns_correlation_miss
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let response = NetworkDnsResponse {
            transaction_id: parsed.transaction_id,
            direction: context.direction,
            transport: context.transport,
            resolver_address: context.resolver_address,
            name: parsed.name,
            query_type: parsed.query_type,
            response_code: parsed.response_code,
            truncated: parsed.truncated,
            answers: parsed.answers,
            cname_chain: parsed.cname_chain,
            effective_ttl_seconds: parsed.effective_ttl_seconds,
        };
        if let Ok(process) = self
            .state
            .correlate_response(&key, &response, context.now, Utc::now())
        {
            Some((process, EventPayload::NetworkDnsResponse(response)))
        } else {
            counters
                .dns_correlation_miss
                .fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn process_identity(packet: &DnsPacketRecord) -> ProcessIdentity {
    ProcessIdentity {
        cgroup_id: packet.cgroup_id,
        pid: u32::try_from(packet.pid_tgid & u64::from(u32::MAX)).unwrap_or_default(),
        tgid: u32::try_from(packet.pid_tgid >> 32).unwrap_or_default(),
        command: command(&packet.command),
    }
}

fn resolver_address(packet: &DnsPacketRecord) -> Option<IpAddr> {
    match packet.address_family {
        ADDRESS_FAMILY_IPV4 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&packet.resolver_address[..4]).ok()?,
        ))),
        ADDRESS_FAMILY_IPV6 => Some(IpAddr::V6(Ipv6Addr::from(packet.resolver_address))),
        _ => None,
    }
}

fn transport(value: u8) -> Option<DnsTransport> {
    match value {
        DNS_TRANSPORT_UDP => Some(DnsTransport::Udp),
        DNS_TRANSPORT_TCP => Some(DnsTransport::Tcp),
        _ => None,
    }
}

fn direction(value: u8) -> Option<DnsDirection> {
    match value {
        DNS_DIRECTION_EGRESS => Some(DnsDirection::Egress),
        DNS_DIRECTION_INGRESS => Some(DnsDirection::Ingress),
        _ => None,
    }
}

fn command(bytes: &[u8; 16]) -> String {
    let command = String::from_utf8_lossy(
        &bytes[..bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len())],
    )
    .into_owned();
    if command.is_empty() {
        "dns".into()
    } else {
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_model::{NetworkAddressFamily, NetworkConnect, NetworkConnectOutcome};

    fn packet(direction: u8, payload: &[u8]) -> DnsPacketRecord {
        let mut record = DnsPacketRecord {
            timestamp_ns: 1,
            cgroup_id: 42,
            socket_cookie: 7,
            pid_tgid: if direction == DNS_DIRECTION_EGRESS {
                (100_u64 << 32) | 100
            } else {
                0
            },
            sequence: 0,
            payload_len: u16::try_from(payload.len()).unwrap(),
            resolver_port: 53,
            address_family: ADDRESS_FAMILY_IPV4,
            transport: DNS_TRANSPORT_UDP,
            direction,
            tcp_flags: 0,
            resolver_address: [0; 16],
            command: [0; 16],
            payload: [0; agent_ebpf_common::DNS_CAPTURE_BYTES],
        };
        record.resolver_address[..4].copy_from_slice(&[10, 96, 0, 10]);
        record.command[..4].copy_from_slice(b"curl");
        record.payload[..payload.len()].copy_from_slice(payload);
        record
    }

    #[test]
    fn query_response_pipeline_attaches_exact_workload_context() {
        let config = DnsObservationConfig::default();
        let mut processor = DnsProcessor::new(&config);
        let counters = Counters::default();
        let query =
            hex::decode("12340100000100000000000003617069076578616d706c6503636f6d0000010001")
                .unwrap();
        let response = hex::decode(
            "12348180000100010000000003617069076578616d706c6503636f6d0000010001c00c000100010000003c0004cb007107",
        )
        .unwrap();
        let (query_process, query_payload) = processor
            .process(&packet(DNS_DIRECTION_EGRESS, &query), &counters)
            .unwrap();
        assert_eq!(query_process.command, "curl");
        assert!(matches!(query_payload, EventPayload::NetworkDnsQuery(_)));
        let (response_process, response_payload) = processor
            .process(&packet(DNS_DIRECTION_INGRESS, &response), &counters)
            .unwrap();
        assert_eq!(response_process, query_process);
        assert!(matches!(
            response_payload,
            EventPayload::NetworkDnsResponse(_)
        ));

        let connect = NetworkConnect::new(
            NetworkAddressFamily::Ipv4,
            "203.0.113.7".parse().unwrap(),
            443,
            NetworkConnectOutcome::Succeeded,
            None,
        )
        .unwrap();
        let mut matching = EventPayload::NetworkConnect(connect.clone());
        processor.attach_context(42, &mut matching);
        let EventPayload::NetworkConnect(matching) = matching else {
            unreachable!()
        };
        assert_eq!(
            matching.dns_context.unwrap().names[0].as_str(),
            "api.example.com"
        );
        let mut other_scope = EventPayload::NetworkConnect(connect);
        processor.attach_context(43, &mut other_scope);
        let EventPayload::NetworkConnect(other_scope) = other_scope else {
            unreachable!()
        };
        assert!(other_scope.dns_context.is_none());
    }
}
