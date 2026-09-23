use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use event_model::{
    DnsContext, DnsName, DnsQueryType, DnsTransport, NetworkDnsResponse, ProcessIdentity,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingQueryKey {
    pub cgroup_id: u64,
    pub transport: DnsTransport,
    pub resolver_address: IpAddr,
    pub transaction_id: u16,
    pub name: DnsName,
    pub query_type: DnsQueryType,
}

#[derive(Debug)]
pub struct DnsState {
    pending: HashMap<PendingQueryKey, PendingQuery>,
    pending_order: VecDeque<PendingQueryKey>,
    addresses: HashMap<(u64, IpAddr), Vec<CachedName>>,
    max_pending: usize,
    max_names_per_address: usize,
    transaction_timeout: Duration,
    max_ttl: Duration,
}

#[derive(Clone, Debug)]
struct CachedName {
    name: DnsName,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct PendingQuery {
    created_at: Instant,
    process: ProcessIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrelationOutcome {
    Matched,
    Miss,
}

impl DnsState {
    #[must_use]
    pub fn new(
        max_pending: usize,
        max_names_per_address: usize,
        transaction_timeout: Duration,
        max_ttl: Duration,
    ) -> Self {
        Self {
            pending: HashMap::new(),
            pending_order: VecDeque::new(),
            addresses: HashMap::new(),
            max_pending,
            max_names_per_address,
            transaction_timeout,
            max_ttl,
        }
    }

    pub fn register_query(
        &mut self,
        key: PendingQueryKey,
        process: ProcessIdentity,
        now: Instant,
    ) -> bool {
        self.expire_pending(now);
        if self.pending.len() >= self.max_pending {
            return false;
        }
        self.pending.insert(
            key.clone(),
            PendingQuery {
                created_at: now,
                process,
            },
        );
        self.pending_order.push_back(key);
        true
    }

    pub fn correlate_response(
        &mut self,
        key: &PendingQueryKey,
        response: &NetworkDnsResponse,
        now: Instant,
        observed_at: DateTime<Utc>,
    ) -> Result<ProcessIdentity, CorrelationOutcome> {
        self.expire_pending(now);
        let Some(pending) = self.pending.remove(key) else {
            return Err(CorrelationOutcome::Miss);
        };
        for answer in &response.answers {
            let ttl = Duration::from_secs(u64::from(answer.ttl_seconds)).min(self.max_ttl);
            let Ok(delta) = chrono::Duration::from_std(ttl) else {
                continue;
            };
            let entry = self
                .addresses
                .entry((key.cgroup_id, answer.address))
                .or_default();
            entry.retain(|cached| cached.expires_at > observed_at && cached.name != key.name);
            if entry.len() < self.max_names_per_address {
                entry.push(CachedName {
                    name: key.name.clone(),
                    observed_at,
                    expires_at: observed_at + delta,
                });
            }
        }
        Ok(pending.process)
    }

    pub fn context_for(
        &mut self,
        cgroup_id: u64,
        address: IpAddr,
        now: DateTime<Utc>,
    ) -> Option<DnsContext> {
        let key = (cgroup_id, address);
        let values = self.addresses.get_mut(&key)?;
        values.retain(|cached| cached.expires_at > now);
        if values.is_empty() {
            self.addresses.remove(&key);
            return None;
        }
        values.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
        values.dedup_by(|left, right| left.name == right.name);
        let names = values.iter().map(|cached| cached.name.clone()).collect();
        let observed_at = values.iter().map(|cached| cached.observed_at).max()?;
        let expires_at = values.iter().map(|cached| cached.expires_at).min()?;
        DnsContext::new(names, observed_at, expires_at).ok()
    }

    fn expire_pending(&mut self, now: Instant) {
        while let Some(key) = self.pending_order.front() {
            let Some(pending) = self.pending.get(key) else {
                self.pending_order.pop_front();
                continue;
            };
            if now.duration_since(pending.created_at) < self.transaction_timeout {
                break;
            }
            self.pending.remove(key);
            self.pending_order.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_model::{DnsAddressAnswer, DnsDirection, DnsResponseCode};

    fn key(name: &str, cgroup_id: u64) -> PendingQueryKey {
        PendingQueryKey {
            cgroup_id,
            transport: DnsTransport::Udp,
            resolver_address: "10.96.0.10".parse().unwrap(),
            transaction_id: 7,
            name: DnsName::new(name).unwrap(),
            query_type: DnsQueryType::A,
        }
    }

    fn response(key: &PendingQueryKey, address: IpAddr, ttl: u32) -> NetworkDnsResponse {
        NetworkDnsResponse {
            transaction_id: key.transaction_id,
            direction: DnsDirection::Ingress,
            transport: key.transport,
            resolver_address: key.resolver_address,
            name: key.name.clone(),
            query_type: key.query_type,
            response_code: DnsResponseCode::NoError,
            truncated: false,
            answers: vec![DnsAddressAnswer::new(key.name.clone(), address, ttl).unwrap()],
            cname_chain: vec![],
            effective_ttl_seconds: Some(ttl),
        }
    }

    fn process(cgroup_id: u64) -> ProcessIdentity {
        ProcessIdentity {
            cgroup_id,
            pid: 10,
            tgid: 10,
            command: "resolver".into(),
        }
    }

    #[test]
    fn correlates_exact_scope_and_expires_context() {
        let instant = Instant::now();
        let observed = Utc::now();
        let address = "203.0.113.8".parse().unwrap();
        let query = key("api.example.com", 10);
        let mut state = DnsState::new(2, 2, Duration::from_secs(5), Duration::from_secs(30));
        assert!(state.register_query(query.clone(), process(10), instant));
        assert_eq!(
            state
                .correlate_response(&query, &response(&query, address, 300), instant, observed)
                .unwrap(),
            process(10)
        );
        assert!(state.context_for(11, address, observed).is_none());
        let context = state.context_for(10, address, observed).unwrap();
        assert_eq!(context.names, vec![query.name]);
        assert!(
            state
                .context_for(10, address, observed + chrono::Duration::seconds(31))
                .is_none()
        );
    }

    #[test]
    fn bounds_capacity_and_marks_shared_ip_ambiguous() {
        let instant = Instant::now();
        let observed = Utc::now();
        let address = "203.0.113.9".parse().unwrap();
        let first = key("one.example", 10);
        let mut second = key("two.example", 10);
        second.transaction_id = 8;
        let mut state = DnsState::new(2, 2, Duration::from_secs(5), Duration::from_secs(60));
        for query in [&first, &second] {
            assert!(state.register_query(query.clone(), process(10), instant));
            assert_eq!(
                state
                    .correlate_response(query, &response(query, address, 60), instant, observed)
                    .unwrap(),
                process(10)
            );
        }
        assert!(state.context_for(10, address, observed).unwrap().ambiguous);
        assert_eq!(
            state.correlate_response(&first, &response(&first, address, 60), instant, observed),
            Err(CorrelationOutcome::Miss)
        );
    }
}
