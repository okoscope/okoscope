KUBE_CONTEXT ?= aliens
KUBE_NAMESPACE ?= okoscope
HELM_RELEASE ?= okoscope
HELM_CHART ?= oci://ghcr.io/okoscope/charts/okoscope
DEPLOY_TIMEOUT ?= 10m
VERSION ?=
VALUES ?=

HELM_UPGRADE = helm upgrade "$(HELM_RELEASE)" "$(HELM_CHART)" \
	--namespace "$(KUBE_NAMESPACE)" --version "$(VERSION)" \
	--reset-then-reuse-values $(if $(VALUES),--values "$(VALUES)") \
	--wait --timeout "$(DEPLOY_TIMEOUT)"

.PHONY: build build-ebpf check test proto-check deployment-test deploy-check deploy-preview deploy deploy-status

build:
	cargo build --workspace --exclude agent-ebpf

build-ebpf:
	cargo +nightly build -p agent-ebpf --target bpfel-unknown-none -Z build-std=core
	$(MAKE) -C crates/agent-ebpf-core

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --exclude agent-ebpf --all-targets -- -D warnings

test:
	cargo test --workspace --exclude agent-ebpf

proto-check:
	cargo check -p protocol

deployment-test:
	deploy/tests/manifest-policy.sh
	deploy/tests/secret-preflight.sh

# Existing Helm releases only. Migrations run through the chart's upgrade hook.
deploy-check:
	@test -n "$(VERSION)" || { echo 'Usage: make deploy VERSION=<published-chart-version> [VALUES=path/to/values.yaml]' >&2; exit 1; }
	$(if $(VALUES),@test -f "$(VALUES)" || { echo 'VALUES file does not exist' >&2; exit 1; },@true)

deploy-preview: deploy-check
	kubectx "$(KUBE_CONTEXT)"
	$(HELM_UPGRADE) --dry-run=server --hide-secret

deploy: deploy-check
	kubectx "$(KUBE_CONTEXT)"
	$(HELM_UPGRADE)

deploy-status:
	kubectx "$(KUBE_CONTEXT)"
	helm status "$(HELM_RELEASE)" --namespace "$(KUBE_NAMESPACE)"
	kubectl get deployment,daemonset,pod -n "$(KUBE_NAMESPACE)" -l "app.kubernetes.io/instance=$(HELM_RELEASE)"
