#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

helm dependency build "$root/deploy/helm/okoscope" --skip-refresh
helm lint "$root/deploy/helm/okoscope"
helm lint "$root/deploy/helm/okoscope-agent" -f "$root/deploy/helm/fixtures/agent-hosted.yaml"

helm template okoscope "$root/deploy/helm/okoscope" > "$work/self-hosted.yaml"
helm template okoscope "$root/deploy/helm/okoscope" -f "$root/deploy/helm/fixtures/self-hosted-ingress.yaml" > "$work/self-hosted-ingress.yaml"
helm template tls-origin "$root/deploy/helm/okoscope" \
  -f "$root/deploy/helm/fixtures/self-hosted-ingress.yaml" \
  --set ingress.web.host=observability.acme.test > "$work/self-hosted-tls-origin.yaml"
helm template http-origin "$root/deploy/helm/okoscope" \
  --set ingress.web.enabled=true \
  --set ingress.web.className=nginx \
  --set ingress.web.host=console.customer.example > "$work/self-hosted-http.yaml"
helm template extra-origins "$root/deploy/helm/okoscope" \
  -f "$root/deploy/helm/fixtures/self-hosted-ingress.yaml" \
  --set-json 'server.corsOrigins=["http://127.0.0.1:3000","https://admin.customer.example"]' \
  > "$work/self-hosted-extra-origins.yaml"
helm template explicit-origin "$root/deploy/helm/okoscope" \
  --set-json 'server.corsOrigins=["http://127.0.0.1:8080"]' \
  > "$work/self-hosted-explicit-origin.yaml"
helm template okoscope "$root/deploy/helm/okoscope" -f "$root/deploy/helm/fixtures/self-hosted-agent.yaml" > "$work/self-hosted-agent.yaml"
helm template agent "$root/deploy/helm/okoscope-agent" -f "$root/deploy/helm/fixtures/agent-hosted.yaml" > "$work/agent.yaml"
helm template agent "$root/deploy/helm/okoscope-agent" -f "$root/deploy/helm/fixtures/agent-labels.yaml" > "$work/agent-labels.yaml"

for manifest in "$work"/*.yaml; do
  if grep -Eq 'oko_app_v1_|postgresql://[^[:space:]]+:[^[:space:]]+@|image: .+:(latest|main|master)([[:space:]]|$)|__[A-Z0-9_]+__' "$manifest"; then
    echo "unsafe or unresolved value in $manifest" >&2
    exit 1
  fi
done

if grep -Eq '^kind: (StatefulSet|PersistentVolumeClaim)$|name: postgres' "$work/self-hosted.yaml"; then
  echo "the Okoscope chart must not provision PostgreSQL" >&2
  exit 1
fi
grep -q 'helm.sh/hook: pre-install,pre-upgrade' "$work/self-hosted.yaml"
grep -q 'name: production-database' "$work/self-hosted-ingress.yaml"
grep -q 'OKOSCOPE_CORS_ORIGINS: "https://okoscope.example.com"' "$work/self-hosted-ingress.yaml"
grep -q 'OKOSCOPE_CORS_ORIGINS: "https://observability.acme.test"' "$work/self-hosted-tls-origin.yaml"
grep -q 'OKOSCOPE_CORS_ORIGINS: "http://console.customer.example"' "$work/self-hosted-http.yaml"
grep -q 'OKOSCOPE_CORS_ORIGINS: "https://okoscope.example.com,http://127.0.0.1:3000,https://admin.customer.example"' "$work/self-hosted-extra-origins.yaml"
grep -q 'OKOSCOPE_CORS_ORIGINS: "http://127.0.0.1:8080"' "$work/self-hosted-explicit-origin.yaml"
if grep -q '^  tls:' "$work/self-hosted-http.yaml"; then
  echo 'HTTP Web ingress must not render TLS configuration' >&2
  exit 1
fi
grep -q 'nginx.ingress.kubernetes.io/backend-protocol: GRPC' "$work/self-hosted-ingress.yaml"
helm template okoscope "$root/deploy/helm/okoscope" -f "$root/deploy/helm/fixtures/self-hosted-ingress.yaml" \
  --set ingress.grpc.className=traefik > "$work/self-hosted-traefik.yaml"
grep -q 'traefik.ingress.kubernetes.io/service.serversscheme: h2c' "$work/self-hosted-traefik.yaml"
grep -q '^kind: DaemonSet$' "$work/self-hosted-agent.yaml"
grep -q 'name: okoscope-application-credentials' "$work/agent.yaml"
grep -q 'name: payments-observability' "$work/agent-labels.yaml"
grep -q 'name: worker-observability' "$work/agent-labels.yaml"

if helm template rejected "$root/deploy/helm/okoscope" --set database.url=postgresql://unsafe >/dev/null 2>&1; then
  echo 'database.url must be rejected by the values schema' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope" \
  --set-json 'server.corsOrigins=["https://first.example,https://second.example"]' >/dev/null 2>&1; then
  echo 'CORS origins containing commas must be rejected by the values schema' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope" \
  --set ingress.web.enabled=true \
  --set-json 'ingress.web.host="first.example,https://second.example"' >/dev/null 2>&1; then
  echo 'Web ingress host must not inject additional comma-separated origins' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope" \
  --set ingress.grpc.enabled=true --set ingress.grpc.host=grpc.customer.example >/dev/null 2>&1; then
  echo 'production gRPC ingress without TLS must be rejected' >&2
  exit 1
fi
helm template okoscope "$root/deploy/helm/okoscope" -f "$root/deploy/helm/fixtures/self-hosted-ingress.yaml" \
  --set server.registrationEnabled=true \
  --set mail.enabled=true \
  --set mail.publicWebUrl=https://okoscope.example.com \
  --set mail.smtp.host=smtp.example.com \
  --set mail.smtp.existingSecret=okoscope-smtp \
  --set mail.sender.address=noreply@example.com \
  > "$work/self-hosted-public-registration.yaml"
grep -q 'OKOSCOPE_REGISTRATION_ENABLED: "true"' "$work/self-hosted-public-registration.yaml"
grep -q 'OKOSCOPE_MAIL_ENABLED: "true"' "$work/self-hosted-public-registration.yaml"
grep -q '^kind: Ingress$' "$work/self-hosted-public-registration.yaml"
grep -q 'OKOSCOPE_REGISTRATION_ENABLED: "false"' "$work/self-hosted-ingress.yaml"
grep -q 'OKOSCOPE_REGISTRATION_ENABLED: "false"' "$work/self-hosted.yaml"
if helm template rejected "$root/deploy/helm/okoscope" \
  --set server.registrationEnabled=true >/dev/null 2>&1; then
  echo 'public registration without usable mail must be rejected' >&2
  exit 1
fi
grep -q 'name: OKOSCOPE_SETUP_TOKEN' "$work/self-hosted.yaml"
grep -A1 'name: OKOSCOPE_API_BASE_URL' "$work/self-hosted.yaml" | grep -q 'value: /'
grep -A1 'name: OKOSCOPE_API_UPSTREAM' "$work/self-hosted.yaml" | grep -q 'value: http://okoscope-server:8080'
grep -q 'kind: Secret' "$work/self-hosted.yaml"
helm template custom-ca "$root/deploy/helm/okoscope" \
  --set agentInstallation.publicGrpcEndpoint=grpc.example.com:443 \
  --set agentInstallation.tlsMode=custom_ca \
  --set agentInstallation.caSecret.name=okoscope-private-ca \
  --set agentInstallation.caSecret.key=root.crt > "$work/self-hosted-custom-ca.yaml"
grep -q 'OKOSCOPE_AGENT_CA_SECRET_NAME: "okoscope-private-ca"' "$work/self-hosted-custom-ca.yaml"
grep -q 'OKOSCOPE_AGENT_CA_SECRET_KEY: "root.crt"' "$work/self-hosted-custom-ca.yaml"
if helm template rejected "$root/deploy/helm/okoscope" --set agentInstallation.tlsMode=custom_ca >/dev/null 2>&1; then
  echo 'custom_ca mode without a CA Secret name must be rejected' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope" --set agentInstallation.caSecret.name=unexpected-ca >/dev/null 2>&1; then
  echo 'system roots mode with a CA Secret name must be rejected' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope" --set setupAuthorization.token=unsafe >/dev/null 2>&1; then
  echo 'plaintext setup authorization must be rejected by the values schema' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope-agent" -f "$root/deploy/helm/fixtures/agent-hosted.yaml" --set applicationCredential=oko_app_v1_unsafe >/dev/null 2>&1; then
  echo 'plaintext Application credentials must be rejected by the values schema' >&2
  exit 1
fi
if helm template rejected "$root/deploy/helm/okoscope-agent" -f "$root/deploy/helm/fixtures/agent-hosted.yaml" --set image.tag=latest >/dev/null 2>&1; then
  echo 'mutable production image tags must be rejected' >&2
  exit 1
fi

if command -v kubeconform >/dev/null; then
  kubeconform -strict -summary -ignore-missing-schemas "$work"/*.yaml
fi

true
