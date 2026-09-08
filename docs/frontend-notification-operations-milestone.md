# Frontend milestone prompt: notification operations

Implement the next Okoscope Web milestone for notification delivery operations against the generated OpenAPI client. Keep the existing React 19, TypeScript, Vite, TanStack Router/Query, Tailwind, shadcn/ui, runtime configuration, ephemeral bearer credential, request-ID error handling, accessibility, container, and CI conventions.

Deliver a project-scoped Notifications area with:

- destination list and creation flow for HTTPS webhooks;
- one-time signing secret presentation that cannot be reopened, copied into logs, persisted in browser storage, or exposed by telemetry;
- explicit secret rotation confirmation and the same one-time handling for the replacement secret;
- test-delivery action with pending, success, retryable failure, and terminal failure feedback;
- cursor-paginated delivery history with status, attempt count, next attempt, last error category, timestamps, runtime-group link, and destination identity, but never URL credentials, signing secrets, or unrestricted response bodies;
- runtime-group notification summary and deep links between group detail and delivery history;
- activation-disabled guidance explaining that destinations and queued work remain durable while the deployment-level worker is off;
- bounded worker-health presentation for disabled, idle, backlogged, retrying, failing, and draining states when the API exposes it;
- accessible loading, empty, partial-error, authorization, and stale-data states, including request IDs in support-ready error details.

Use only typed schemas generated from OpenAPI. If a required response remains `additionalProperties: true`, a pagination field is missing, or worker health is unavailable, record it as a backend contract blocker instead of inventing a frontend-only shape. Preserve organization/project tenant scoping in every route and query key. Never cache one-time secrets in TanStack Query.

Add Vitest coverage for secret lifecycle and status mapping, MSW-style API contract tests for pagination and error/request-ID behavior, Playwright happy/failure paths, axe checks, and a production container smoke test. Update operational documentation with the exact backend endpoints consumed and a redacted manual acceptance checklist.
