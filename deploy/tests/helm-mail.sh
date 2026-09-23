#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d /tmp/okoscope-mail-chart-test.XXXXXX)
trap 'rm -rf "$work"' EXIT
chart="$root/deploy/helm/okoscope"

helm lint "$chart"
helm template mail-default "$chart" >"$work/default.yaml"
grep -q 'OKOSCOPE_MAIL_ENABLED: "false"' "$work/default.yaml"
! grep -q 'name: OKOSCOPE_SMTP_PASSWORD' "$work/default.yaml"

helm template mail-enabled "$chart" \
  --set mail.enabled=true \
  --set mail.publicWebUrl=https://okoscope.example.com \
  --set mail.smtp.host=smtp.example.com \
  --set mail.smtp.port=587 \
  --set mail.smtp.tls=starttls \
  --set mail.smtp.existingSecret=okoscope-smtp \
  --set mail.sender.address=noreply@example.com \
  --set server.replicas=3 >"$work/enabled.yaml"
helm template mail-upgrade "$chart" --is-upgrade \
  --set mail.enabled=true \
  --set mail.publicWebUrl=https://okoscope.example.com \
  --set mail.smtp.host=smtp.example.com \
  --set mail.smtp.existingSecret=okoscope-smtp \
  --set mail.sender.address=noreply@example.com >"$work/upgrade.yaml"

grep -q 'OKOSCOPE_PUBLIC_WEB_URL: "https://okoscope.example.com"' "$work/enabled.yaml"
grep -q 'OKOSCOPE_SMTP_HOST: "smtp.example.com"' "$work/enabled.yaml"
grep -q 'OKOSCOPE_SMTP_TLS: "starttls"' "$work/enabled.yaml"
grep -q 'replicas: 3' "$work/enabled.yaml"
grep -A2 'name: OKOSCOPE_SMTP_USERNAME' "$work/enabled.yaml" | grep -q 'name: okoscope-smtp'
grep -A2 'name: OKOSCOPE_SMTP_PASSWORD' "$work/enabled.yaml" | grep -q 'name: okoscope-smtp'
grep -A2 'name: OKOSCOPE_MAIL_ENCRYPTION_KEY' "$work/enabled.yaml" | grep -q 'key: mail-encryption-key'
grep -q 'mail-encryption-key:' "$work/enabled.yaml"
[[ $(grep -c 'name: OKOSCOPE_SMTP_PASSWORD' "$work/enabled.yaml") -eq 1 ]]
! sed -n '/component: migration/,/kind: Service/p' "$work/enabled.yaml" | grep -q 'OKOSCOPE_SMTP_PASSWORD'

helm template external-secrets "$chart" \
  --set mail.enabled=true \
  --set mail.publicWebUrl=https://okoscope.example.com \
  --set mail.smtp.host=smtp.example.com \
  --set mail.smtp.existingSecret=okoscope-smtp \
  --set mail.sender.address=noreply@example.com \
  --set internalSecret.existingSecret=okoscope-internal >"$work/external.yaml"
! grep -q '^kind: Secret$' "$work/external.yaml"
grep -A2 'name: OKOSCOPE_MAIL_ENCRYPTION_KEY' "$work/external.yaml" | grep -q 'name: okoscope-internal'

for rejected in \
  'server.registrationEnabled=true' \
  'mail.enabled=true' \
  'mail.smtp.password=plaintext-secret' \
  'mail.enabled=true,mail.publicWebUrl=http://okoscope.example.com,mail.smtp.host=smtp.example.com,mail.smtp.existingSecret=okoscope-smtp,mail.sender.address=noreply@example.com' \
  'mail.enabled=true,mail.publicWebUrl=https://okoscope.example.com,mail.smtp.host=smtp.example.com,mail.smtp.existingSecret=okoscope-smtp,mail.smtp.tls=plaintext,mail.sender.address=noreply@example.com'; do
  if helm template rejected "$chart" --set "$rejected" >/dev/null 2>&1; then
    echo "invalid mail configuration unexpectedly rendered: $rejected" >&2
    exit 1
  fi
done

helm template development "$chart" \
  --set mail.enabled=true \
  --set mail.developmentPlaintext=true \
  --set mail.publicWebUrl=http://127.0.0.1:3000 \
  --set mail.smtp.host=mailpit \
  --set mail.smtp.port=1025 \
  --set mail.smtp.tls=plaintext \
  --set mail.smtp.existingSecret=mailpit-auth \
  --set mail.sender.address=noreply@example.test >"$work/development.yaml"
grep -q 'OKOSCOPE_SMTP_TLS: "plaintext"' "$work/development.yaml"

for manifest in "$work"/*.yaml; do
  ! grep -Eq 'smtp-password-value|oko_(verify|reset)_v1_|#token=|postgresql://[^[:space:]]+:[^[:space:]]+@' "$manifest"
done

grep -q 'hasKey $existing.data .Values.internalSecret.mailEncryptionKey' \
  "$chart/templates/internal-secret.yaml"

for expected in \
  'mail.smtp.existingSecret' \
  'okoscope_mail_queue_depth' \
  'smtp.timeweb.ru' \
  'https://timeweb.cloud/docs/cms/otpravka-pochty-cherez-smtp' \
  'Organization creation sends no separate email'; do
  grep -R -q "$expected" \
    "$root/docs/installation.md" \
    "$root/docs/self-hosted-deployment.md" \
    "$root/docs/helm-values.md" \
    "$root/docs/deployment.md"
done

! grep -R -q 'mail.auditRecipients\|OKOSCOPE_MAIL_AUDIT_RECIPIENTS' \
  "$chart" "$root/docs/installation.md" "$root/docs/self-hosted-deployment.md" \
  "$root/docs/helm-values.md" "$root/docs/deployment.md"

echo 'Helm transactional-mail tests passed'
