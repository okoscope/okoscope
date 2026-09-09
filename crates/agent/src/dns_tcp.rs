use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpDnsStreamKey {
    pub cgroup_id: u64,
    pub socket_cookie: u64,
    pub direction: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpReassemblyError {
    Capacity,
    InvalidSequence,
    Oversize,
    InvalidFraming,
}

#[derive(Debug)]
struct Stream {
    next_sequence: u32,
    updated_at: Instant,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct TcpDnsReassembler {
    streams: HashMap<TcpDnsStreamKey, Stream>,
    max_streams: usize,
    max_message_bytes: usize,
    timeout: Duration,
}

impl TcpDnsReassembler {
    #[must_use]
    pub fn new(max_streams: usize, max_message_bytes: usize, timeout: Duration) -> Self {
        Self {
            streams: HashMap::new(),
            max_streams,
            max_message_bytes,
            timeout,
        }
    }

    pub fn push(
        &mut self,
        key: TcpDnsStreamKey,
        sequence: u32,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, TcpReassemblyError> {
        self.expire(now);
        if payload.is_empty() {
            return Ok(None);
        }
        if !self.streams.contains_key(&key) && self.streams.len() >= self.max_streams {
            return Err(TcpReassemblyError::Capacity);
        }
        let stream = self.streams.entry(key).or_insert_with(|| Stream {
            next_sequence: sequence,
            updated_at: now,
            bytes: Vec::new(),
        });
        if sequence != stream.next_sequence {
            self.streams.remove(&key);
            return Err(TcpReassemblyError::InvalidSequence);
        }
        if stream.bytes.len().saturating_add(payload.len()) > self.max_message_bytes + 2 {
            self.streams.remove(&key);
            return Err(TcpReassemblyError::Oversize);
        }
        stream.bytes.extend_from_slice(payload);
        stream.next_sequence =
            sequence.wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
        stream.updated_at = now;
        if stream.bytes.len() < 2 {
            return Ok(None);
        }
        let message_len = usize::from(u16::from_be_bytes([stream.bytes[0], stream.bytes[1]]));
        if message_len == 0 || message_len > self.max_message_bytes {
            self.streams.remove(&key);
            return Err(TcpReassemblyError::InvalidFraming);
        }
        if stream.bytes.len() < message_len + 2 {
            return Ok(None);
        }
        if stream.bytes.len() != message_len + 2 {
            self.streams.remove(&key);
            return Err(TcpReassemblyError::InvalidFraming);
        }
        let message = stream.bytes[2..].to_vec();
        self.streams.remove(&key);
        Ok(Some(message))
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.streams.len();
        self.streams
            .retain(|_, stream| now.duration_since(stream.updated_at) < self.timeout);
        before - self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TcpDnsStreamKey {
        TcpDnsStreamKey {
            cgroup_id: 1,
            socket_cookie: 2,
            direction: 1,
        }
    }

    #[test]
    fn reassembles_exact_segments_and_expires_incomplete_streams() {
        let now = Instant::now();
        let mut value = TcpDnsReassembler::new(2, 32, Duration::from_secs(1));
        assert_eq!(value.push(key(), 100, &[0, 4, 1], now).unwrap(), None);
        assert_eq!(
            value.push(key(), 103, &[2, 3, 4], now).unwrap(),
            Some(vec![1, 2, 3, 4])
        );
        assert_eq!(value.push(key(), 200, &[0], now).unwrap(), None);
        assert_eq!(value.expire(now + Duration::from_secs(2)), 1);
    }

    #[test]
    fn rejects_overlap_oversize_and_extra_frames() {
        let now = Instant::now();
        let mut value = TcpDnsReassembler::new(1, 4, Duration::from_secs(1));
        assert_eq!(value.push(key(), 1, &[0, 4, 1], now).unwrap(), None);
        assert_eq!(
            value.push(key(), 2, &[2], now),
            Err(TcpReassemblyError::InvalidSequence)
        );
        assert_eq!(
            value.push(key(), 1, &[0, 5], now),
            Err(TcpReassemblyError::InvalidFraming)
        );
        assert_eq!(
            value.push(key(), 1, &[0, 1, 7, 8], now),
            Err(TcpReassemblyError::InvalidFraming)
        );
    }
}
