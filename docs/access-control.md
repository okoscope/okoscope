# Authentication and access-control operations

Okoscope separates a person's global identity from authority at three scopes. A
user may have no tenant membership, may belong to several Organizations and
Projects, and may independently hold the personal platform `super_admin` role.
The server derives every effective role from current database state; clients do
not submit trusted role or tenant claims.

## Roles and effective Project access

| Scope | Role | Authority |
| --- | --- | --- |
| Platform | `super_admin` | Global discovery and supported management of users, Organizations, Projects, Applications, memberships, invitations, status, audit, and safe credential lifecycle operations. Platform access does not create a tenant membership or impersonate an owner. |
| Organization | `owner` | Full Organization administration, including owner changes, plus inherited access to every Project. The final usable owner cannot be removed, demoted, disabled, or deleted. |
| Organization | `admin` | Inherited access to every Project; may create Projects and Applications and manage members, Project admins, and Project members, but cannot grant or modify an owner. |
| Organization | `member` | Tenant identity only. Access to each Project requires an explicit Project membership. |
| Project | `admin` | Operates the Project and its Applications and may manage Project members, but cannot grant Project admin or change Organization roles. |
| Project | `member` | Uses the Project and its supported observability resources without access administration or credential management. |

There is no single numeric ordering across scopes. For example, a Project admin
has no authority in another Project, while an Organization admin inherits access
to all Projects without Project-membership rows. Collection queries filter by
effective access before pagination. Unknown, cross-tenant, and unassigned Project
identifiers use the same tenant-safe not-found response.

A sole Organization owner can create and operate Projects and Applications
without inviting another user and without receiving Project-membership rows.

## First platform setup

On a new installation, `GET /api/v1/setup/status` reports
`platform_admin_required`. Retrieve the setup token from the configured Kubernetes
Secret and enter it only in the HTTPS `/setup` flow together with the first user's
email, password, display name, and locale. Setup atomically creates a verified
identity, `super_admin` assignment, privileged session, and audit record. It
creates no Organization, Project, or tenant membership and closes once an active
super-administrator exists.

The super-administrator then chooses one of two Organization provisioning paths:

- Create a `pending_owner` Organization and send its first `owner` invitation.
- Explicitly become owner; the Organization becomes active without mail, while
  platform and Organization roles remain separate.

In `single` Organization mode, a second Organization is rejected. In `multiple`
mode, the same roles and invitation behavior apply to every Organization.

## Authentication and active Organization

Password login authenticates the global identity. It returns bounded available
Organizations and platform state. A session has a nullable active Organization:

- exactly one usable membership may be activated automatically;
- several memberships require explicit selection;
- zero memberships still allow identity, invitation, and authorized platform
  operations, but no tenant operation.

Selecting another available Organization rotates the opaque session token. A
membership removal or disablement invalidates access immediately. Password reset,
password change, locale, current-user, and logout remain identity operations and
do not depend on an arbitrary first membership.

Sensitive platform mutations require the current password to establish a bounded
recent-privilege marker. It expires independently of the base session. Platform
navigation remains visibly attributable to the signed-in super-administrator and
never fabricates an owner membership.

## Invitation lifecycle

Organization invitations grant `owner`, `admin`, or `member`. Project invitations
grant `admin` or `member`; acceptance creates a base Organization `member` only
when the recipient has no Organization membership and never upgrades an existing
Organization role. One live invitation is allowed per normalized recipient and
target scope.

The default lifetime is seven days. Issuance and resend are rate-limited by the
configured hourly bounds. Resend replaces the bearer token and invalidates the
old link. Revocation makes a pending token immediately unusable without removing
an existing membership.

Tokens contain at least 32 bytes of randomness. Only digests are stored in
invitation state. Plaintext link data exists only inside the encrypted mail
outbox, and the browser link carries the token in its URL fragment. Loading the
route cannot accept the invitation; the user must explicitly submit it.

An anonymous inspection returns only bounded scope, role, inviter display, expiry,
and whether sign-in or invite-bound registration is required. A new recipient
supplies password, display name, and locale; email and grants come only from the
locked invitation, and the resulting identity is verified. An existing recipient
must sign in with the matching verified email. Malformed, unknown, expired,
revoked, replaced, and unusable tokens share a stable non-enumerating failure.

Public signup is independent. With `server.publicSignupEnabled: false`, setup and
invite-bound registration still work, while an uninvited visitor cannot create a
user or Organization. Explicit public signup requires usable mail and `multiple`
Organization mode; it creates an unverified identity, new Organization, and owner
membership, then requires email verification. It never grants `super_admin`.

## Mail and Secret requirements

Before issuing invitations, configure `mail.enabled`, an HTTPS
`mail.publicWebUrl`, certificate-validated STARTTLS or implicit TLS, sender
identity, an existing SMTP credential Secret, and a stable 64-hex-character mail
encryption key in the internal Secret. If mail or encryption is unusable, issuance
returns `mail_unavailable` (HTTP 503) and commits no partial invitation or mail
intent.

SMTP acceptance does not prove inbox delivery. Inspect bounded mail queue metrics,
safe invitation delivery state, and provider diagnostics. Metrics and logs omit
recipient addresses, tenant/user/request identifiers as labels, subjects, bodies,
links, tokens, digests, encrypted payloads, and provider text that may contain
recipient data.

## Audit and last-authority protection

Access mutations record the actor kind and user when applicable, action, scope,
target, old/new role, outcome, request correlation, and time. Global audit reads
are super-admin-only; Organization owners may read their tenant audit. Both are
bounded and cursor-paginated. Audit never includes passwords, hashes, session or
action tokens, invitation tokens/digests, mail bodies, encrypted payloads, or
credential material.

The final active super-administrator and final enabled verified Organization owner
are protected against concurrent disablement, deletion, removal, revocation, or
demotion. Appoint and verify a second authority before changing the first.

## Break-glass recovery

Normal platform administration requires a personal user session. The configured
`OKOSCOPE_ADMIN_CREDENTIAL` is accepted only for setup compatibility and the
operator recovery command; it is never a browser, tenant, or Application
credential.

Recovery requires an existing enabled, verified user with the normalized email:

```bash
kubectl -n okoscope-system exec deployment/okoscope-server -- \
  server recover-super-admin --email operator@example.com
```

The container receives recovery authority from its Secret-backed
`OKOSCOPE_ADMIN_CREDENTIAL`; do not pass a credential, password, or token as a CLI
argument. The command does not reset the user's password. It idempotently restores
an active `super_admin` assignment and records `platform_recovery.completed` with
actor kind `system_recovery`. Output and logs are bounded and secret-free. Verify
that the recovered user can sign in and inspect platform audit, then retain the
Secret for future recovery according to the operator's access policy.

## Troubleshooting denied access

Check, in order:

1. The identity is enabled and email-verified, and the session has not expired or
   been revoked.
2. The selected active Organization matches the intended tenant and is `active`.
3. The current Organization membership and role are usable.
4. For an Organization `member`, an active membership exists for the target
   Project; owners/admins should see `organization` as the inherited source.
5. The attempted mutation is in the actor's explicit grant set and does not target
   a protected final authority or higher role.
6. The invitation is pending, unexpired, not replaced/revoked, and addressed to
   the signed-in verified email.
7. Audit records show the bounded denial or transition; mail metrics show queue
   health without requiring Secret or ciphertext inspection.

After a role or membership change, refresh current-user/session context. Do not
work around a denial by changing client-side roles, querying secret columns,
enabling public signup, or editing PostgreSQL directly.

## Infrastructure trust boundary

Application RBAC limits actions through Okoscope's API. Administrators of the
self-hosted Kubernetes cluster, PostgreSQL service, container runtime, and Secret
store remain infrastructure-trusted and can affect availability or data outside
that API boundary. A super-administrator has global product authority but API
responses still do not reveal stored passwords, token digests, encrypted outbox
payloads, or historical plaintext credentials; newly issued Application
credentials are returned only once.

## Existing notification, agent, and runtime behavior

Access control changes who may discover a Project and call its existing routes; it
does not change notification delivery semantics, retention calculations, agent
installation, Application ingestion credentials, observation protocols, or
runtime-event grouping. Notification and runtime collection reads are now bounded
by effective Project access before their existing pagination and lifecycle rules
apply. The standalone agent continues to authenticate each stream with its
one-time Application credential and does not receive a user, Organization, or
Project role. Existing agent installation and runtime operator guides therefore
remain valid; only their calling user must now have effective access to the target
Project. Retention guides explicitly preserve their owner-only write rule while
limiting reads to inherited or explicit Project access.
