# Legacy/internal Kustomize resources

These resources are retained for existing Okoscope-operated environments during one compatibility window. They are not the supported interface for new user installations and may include environment-specific assumptions.

New installations use the OCI Helm charts under `deploy/helm`. In particular, do not use the PostgreSQL manifests here for a new Okoscope installation: PostgreSQL must already exist and remains entirely user-owned. Existing Kustomize installations require a documented manual clean migration; the first Helm release does not automatically adopt them.
