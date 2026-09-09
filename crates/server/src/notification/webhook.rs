use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebhookEnvelope {
    pub schema_version: u16,
    pub delivery_id: Uuid,
    pub event: String,
    pub created_at: DateTime<Utc>,
    pub source: String,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub event_kind: Option<String>,
    pub semantic_summary: Option<Value>,
}

#[derive(Clone, Debug)]
pub struct WebhookPolicy {
    pub allow_http: bool,
    pub allow_private_ips: bool,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookResponse {
    pub status: StatusCode,
    pub response_excerpt: String,
    pub duration: Duration,
    pub retry_after: Option<Duration>,
}

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("invalid webhook URL: {0}")]
    InvalidUrl(&'static str),
    #[error("webhook target resolved to a prohibited address")]
    UnsafeAddress,
    #[error("webhook DNS resolution failed: {0}")]
    Resolution(std::io::Error),
    #[error("webhook client construction failed: {0}")]
    Client(reqwest::Error),
    #[error("webhook request failed: {0}")]
    Request(reqwest::Error),
    #[error("webhook response body failed: {0}")]
    Response(reqwest::Error),
    #[error("webhook payload serialization failed: {0}")]
    Serialization(serde_json::Error),
    #[error("webhook signing key is invalid")]
    SigningKey,
}

pub fn serialize_envelope(envelope: &WebhookEnvelope) -> Result<Vec<u8>, WebhookError> {
    serde_json::to_vec(envelope).map_err(WebhookError::Serialization)
}

pub fn signature(secret: &[u8], timestamp: i64, body: &[u8]) -> Result<String, WebhookError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).map_err(|_| WebhookError::SigningKey)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
}

pub fn parse_url(value: &str, policy: &WebhookPolicy) -> Result<Url, WebhookError> {
    let url = Url::parse(value).map_err(|_| WebhookError::InvalidUrl("malformed URL"))?;
    if url.scheme() != "https" && !(policy.allow_http && url.scheme() == "http") {
        return Err(WebhookError::InvalidUrl("HTTPS is required"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WebhookError::InvalidUrl("credentials are prohibited"));
    }
    if url.fragment().is_some() {
        return Err(WebhookError::InvalidUrl("fragments are prohibited"));
    }
    if url.host_str().is_none() {
        return Err(WebhookError::InvalidUrl("host is required"));
    }
    Ok(url)
}

pub async fn resolve_target(
    url: &Url,
    policy: &WebhookPolicy,
) -> Result<Vec<SocketAddr>, WebhookError> {
    let host = url
        .host_str()
        .ok_or(WebhookError::InvalidUrl("host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or(WebhookError::InvalidUrl("port is required"))?;
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .map_err(WebhookError::Resolution)?
        .collect();
    if addresses.is_empty() {
        return Err(WebhookError::InvalidUrl("host has no addresses"));
    }
    if !policy.allow_private_ips && addresses.iter().any(|address| is_unsafe_ip(address.ip())) {
        return Err(WebhookError::UnsafeAddress);
    }
    Ok(addresses)
}

pub async fn send(
    target: &str,
    policy: &WebhookPolicy,
    secret: &[u8],
    envelope: &WebhookEnvelope,
) -> Result<WebhookResponse, WebhookError> {
    let url = parse_url(target, policy)?;
    let addresses = resolve_target(&url, policy).await?;
    let host = url
        .host_str()
        .ok_or(WebhookError::InvalidUrl("host is required"))?;
    let client = client(host, &addresses, policy)?;
    let body = serialize_envelope(envelope)?;
    let timestamp = Utc::now().timestamp();
    let signature = signature(secret, timestamp, &body)?;
    let started = Instant::now();
    let mut response = client
        .post(url)
        .header("content-type", "application/json")
        .header("okoscope-delivery", envelope.delivery_id.to_string())
        .header("okoscope-event", &envelope.event)
        .header("okoscope-timestamp", timestamp.to_string())
        .header("okoscope-signature", signature)
        .body(body)
        .send()
        .await
        .map_err(WebhookError::Request)?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs);
    let mut excerpt = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(WebhookError::Response)? {
        let remaining = policy.max_response_bytes.saturating_sub(excerpt.len());
        excerpt.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if excerpt.len() >= policy.max_response_bytes {
            break;
        }
    }
    Ok(WebhookResponse {
        status,
        response_excerpt: String::from_utf8_lossy(&excerpt).into_owned(),
        duration: started.elapsed(),
        retry_after,
    })
}

fn client(
    host: &str,
    addresses: &[SocketAddr],
    policy: &WebhookPolicy,
) -> Result<Client, WebhookError> {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.request_timeout)
        .resolve_to_addrs(host, addresses)
        .build()
        .map_err(WebhookError::Client)
}

#[must_use]
pub fn is_unsafe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => unsafe_v4(ip),
        IpAddr::V6(ip) => unsafe_v6(ip),
    }
}

fn unsafe_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || octets[0] >= 240
}

fn unsafe_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || ip.to_ipv4_mapped().is_some_and(unsafe_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> WebhookPolicy {
        WebhookPolicy {
            allow_http: false,
            allow_private_ips: false,
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            max_response_bytes: 1024,
        }
    }

    #[test]
    fn payload_and_signature_are_stable() {
        let envelope = WebhookEnvelope {
            schema_version: 1,
            delivery_id: Uuid::from_u128(1),
            event: "runtime_group.first_seen".into(),
            created_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            source: "live".into(),
            organization_id: Uuid::from_u128(2),
            project_id: Uuid::from_u128(3),
            application_id: Some(Uuid::from_u128(4)),
            group_id: Some(Uuid::from_u128(5)),
            event_kind: Some("process.exec".into()),
            semantic_summary: Some(serde_json::json!({"executable":"sh"})),
        };
        let body = serialize_envelope(&envelope).unwrap();
        assert_eq!(body, serialize_envelope(&envelope).unwrap());
        assert_eq!(
            signature(b"secret", 1_700_000_000, &body).unwrap(),
            signature(b"secret", 1_700_000_000, &body).unwrap()
        );
    }

    #[test]
    fn rejects_unsafe_url_syntax_and_addresses() {
        assert!(parse_url("http://example.com/hook", &policy()).is_err());
        assert!(parse_url("https://user:pass@example.com/hook", &policy()).is_err());
        assert!(parse_url("https://example.com/hook#fragment", &policy()).is_err());
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(is_unsafe_ip(address.parse().unwrap()), "{address}");
        }
        assert!(!is_unsafe_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_unsafe_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolves_literal_target_and_rejects_private_literal() {
        let public = parse_url("https://1.1.1.1/hook", &policy()).unwrap();
        assert!(resolve_target(&public, &policy()).await.is_ok());
        let private = parse_url("https://127.0.0.1/hook", &policy()).unwrap();
        assert!(matches!(
            resolve_target(&private, &policy()).await,
            Err(WebhookError::UnsafeAddress)
        ));
    }
}
