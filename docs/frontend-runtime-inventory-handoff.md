# Frontend handoff: application runtime inventory

The Web UI is developed separately. This document defines the acceptance boundary for consuming the versioned runtime inventory API in `openapi/okoscope-v1.yaml`. Fixture data is available in [`fixtures/runtime-inventory.json`](fixtures/runtime-inventory.json).

## Contract synchronization gate

Backend source revision inspected for this handoff: `c6bddcb5878e1da41ae31f7e8fcaa04ddd6946ee` plus the reviewed hardening working-tree changes.

Reviewed artifacts:

- `openapi/okoscope-v1.yaml`: SHA-256 `4020645d961320aaa38d78b46332b69abac9088d977dd046466f439e35c95dc5`;
- `docs/fixtures/runtime-inventory.json`: SHA-256 `e70e83d22bb755a8eedd848b011d1b32fb44f7458e52f5f0e80d9be2b4a1f5ea`.

The frontend's pinned snapshot and generated declarations must match the authoritative backend artifact. From the frontend repository, run:

```bash
cp ../okoscope/openapi/okoscope-v1.yaml openapi/okoscope-v1.yaml
mkdir -p docs/fixtures
cp ../okoscope/docs/fixtures/runtime-inventory.json docs/fixtures/runtime-inventory.json
npm run api:generate
npm run api:check
npm run typecheck
npm test
```

`npm run api:generate` invokes `openapi-typescript` and writes `src/shared/api/schema.d.ts`. `npm run api:check` regenerates it and fails when either the pinned OpenAPI file or generated declarations have an uncommitted diff. Cross-repository CI must provide the reviewed backend artifact or copy it before this check; otherwise it only verifies internal consistency of the pinned frontend snapshot.

Before Runtime Inventory UI work is accepted, verify that both the pinned snapshot and generated schema contain these operations and types:

- `getApplicationRuntimeInventorySummary`, including every operational scope filter;
- `listApplicationRuntimeInventoryFacetOptions`, the closed five-value facet path enum, opaque cursor, and 200-item page bound;
- inventory list, item detail, release presence, sightings, groups, and occurrences operations;
- `InventorySummary`, `InventoryFacetPage`, `InventoryItemDetail`, `InventoryEvidenceLinks`, and the correlated `Error` envelope;
- typed evidence child routes for releases, sightings, groups, and occurrences.

## Application inventory route

Add an Application-level **Runtime inventory** view. Keep the active Project, Application, release, cluster, namespace, workload, container, and observation-window scope visible whenever filters are applied.

The initial view requests:

- `GET .../runtime-inventory/summary` for aggregate cards;
- `GET .../runtime-inventory?kind=...` for a shared paginated list;
- list filters exactly as described by OpenAPI.

Render four tabs: Processes, Destinations, Domains, and Syscalls. Each row shows its typed safe identity, first and last observation, occurrence count, and bounded release, cluster, namespace, workload, Pod, container, and runtime-group counts. Do not infer totals from the current page.

## Item detail

Selecting an item opens a detail route or drawer. Construct evidence collection URLs from the typed OpenAPI path parameters (`project_id`, `application_id`, and `item_id`) and one of the four closed child routes. Returned `evidence` strings are optional convenience hints only: never fetch one unless it exactly matches the corresponding root-relative OpenAPI route for the current scope. Do not accept schemes, authorities, queries, fragments, traversal, encoded separators, or different identifiers. Present these independently paginated collections:

- release evidence;
- Kubernetes sightings;
- contributing runtime groups;
- raw occurrences.

Do not imply process → DNS → connection causality. Links between these behaviors are outside this milestone.

## Release wording

Use these exact meanings:

- `observed`: trusted attributed occurrences support the relation;
- `not_observed`: the release has other attributed evidence, but this item was not seen in that evidence;
- `unknown`: no trusted attributed evidence is available for evaluation.

Never relabel `not_observed` as “absent”, “removed”, or “safe”. Show `release_evidence_count` and the occurrence time bounds when present.

## Pagination and bounds

- Treat every cursor as opaque, including UUID-shaped cursors.
- Never request a limit greater than 200.
- Replace rather than concatenate results when the user changes scope, filters, identity version, or search.
- Support empty first pages and an empty terminal page.
- Do not embed or preload every Pod, release, group, or occurrence from the list view.

## Display safety

All executable, command, domain, namespace, workload, Pod, and container values are observed untrusted text. Render them through text nodes only. Do not use raw HTML, convert values to links automatically, interpret Markdown, or execute URL-like strings. DNS names are evidence, not navigation targets.

Use the `unsafe_display_text` fixture to verify inert rendering. No fixture string may create an element, navigation, event handler, or script execution.

## Acceptance checklist

- Overview cards use the summary response and include all four kinds.
- Each tab uses the typed semantic identity appropriate to its kind.
- Active scope and filters remain visible and shareable without exposing credentials.
- Search is debounced and limited to 200 characters.
- Item detail exposes release, sighting, group, and occurrence evidence navigation.
- All three release states use evidence-qualified wording.
- Loading, empty, invalid-cursor, unauthorized, not-found, and server-error states are distinct.
- `next_cursor` is treated as opaque and pages contain at most 200 items.
- Markup-like observed values remain inert in list, detail, filters, tooltips, and copied text previews.
