ALTER TABLE users
    ADD COLUMN display_name TEXT;

UPDATE users
SET display_name = split_part(email, '@', 1)
WHERE display_name IS NULL;

ALTER TABLE users
    ALTER COLUMN display_name SET DEFAULT 'User',
    ALTER COLUMN display_name SET NOT NULL,
    ADD CONSTRAINT users_display_name_check
        CHECK (
            display_name = btrim(display_name)
            AND char_length(display_name) BETWEEN 1 AND 120
        );

ALTER TABLE organizations
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending_owner', 'active')),
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE organization_memberships
    DROP CONSTRAINT organization_memberships_role_check,
    ADD CONSTRAINT organization_memberships_role_check
        CHECK (role IN ('owner', 'admin', 'member'));

CREATE TABLE platform_role_assignments (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role = 'super_admin'),
    granted_by_user_id UUID REFERENCES users(id) ON DELETE RESTRICT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE INDEX platform_role_assignments_active_idx
    ON platform_role_assignments (granted_at, user_id)
    WHERE revoked_at IS NULL;

CREATE TABLE project_memberships (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, user_id)
        REFERENCES organization_memberships(organization_id, user_id) ON DELETE CASCADE,
    UNIQUE (organization_id, project_id, user_id)
);

CREATE INDEX project_memberships_user_idx
    ON project_memberships (user_id, organization_id, created_at, project_id);

-- Preserve every existing user's visibility. Administrators can narrow it later.
INSERT INTO project_memberships (organization_id, project_id, user_id, role)
SELECT p.organization_id, p.id, m.user_id,
       CASE WHEN m.role = 'owner' THEN 'admin' ELSE 'member' END
FROM projects p
JOIN organization_memberships m ON m.organization_id = p.organization_id
ON CONFLICT (project_id, user_id) DO NOTHING;

ALTER TABLE user_sessions
    ALTER COLUMN organization_id DROP NOT NULL,
    ADD COLUMN privileged_until TIMESTAMPTZ,
    ADD CONSTRAINT user_sessions_privileged_until_check
        CHECK (privileged_until IS NULL OR privileged_until > created_at);

CREATE TABLE invitations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id UUID,
    recipient_email TEXT NOT NULL,
    role TEXT NOT NULL,
    inviter_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    locale TEXT NOT NULL CHECK (locale IN ('en', 'ru')),
    token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ,
    replaced_at TIMESTAMPTZ,
    replaced_by_invitation_id UUID REFERENCES invitations(id) ON DELETE SET NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE,
    CHECK (recipient_email = lower(recipient_email)),
    CHECK (recipient_email = btrim(recipient_email)),
    CHECK (char_length(recipient_email) BETWEEN 3 AND 254),
    CHECK (
        (project_id IS NULL AND role IN ('owner', 'admin', 'member'))
        OR (project_id IS NOT NULL AND role IN ('admin', 'member'))
    ),
    CHECK (expires_at > created_at),
    CHECK (retain_until > expires_at),
    CHECK ((accepted_at IS NULL) = (accepted_by_user_id IS NULL)),
    CHECK (accepted_at IS NULL OR accepted_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (replaced_at IS NULL OR replaced_at >= created_at),
    CHECK ((replaced_at IS NULL) = (replaced_by_invitation_id IS NULL)),
    CHECK (num_nonnulls(accepted_at, revoked_at, replaced_at) <= 1)
);

CREATE UNIQUE INDEX invitations_live_scope_email_idx
    ON invitations (
        organization_id,
        coalesce(project_id, '00000000-0000-0000-0000-000000000000'::uuid),
        recipient_email
    )
    WHERE accepted_at IS NULL AND revoked_at IS NULL AND replaced_at IS NULL;
CREATE INDEX invitations_scope_page_idx
    ON invitations (organization_id, project_id, created_at DESC, id DESC);
CREATE INDEX invitations_live_expiry_idx
    ON invitations (expires_at, id)
    WHERE accepted_at IS NULL AND revoked_at IS NULL AND replaced_at IS NULL;
CREATE INDEX invitations_retention_idx ON invitations (retain_until, id);

ALTER TABLE transactional_mail_outbox
    DROP CONSTRAINT transactional_mail_outbox_template_kind_check,
    ADD CONSTRAINT transactional_mail_outbox_template_kind_check
        CHECK (template_kind IN (
            'verify_email', 'reset_password', 'password_changed',
            'application_created', 'organization_invitation', 'project_invitation'
        )),
    ADD COLUMN invitation_id UUID REFERENCES invitations(id) ON DELETE SET NULL,
    ADD CONSTRAINT transactional_mail_outbox_action_shape_check
        CHECK (num_nonnulls(action_id, invitation_id) <= 1);

CREATE TABLE access_audit_records (
    id UUID PRIMARY KEY,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'system_recovery')),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (action IN (
        'setup.completed', 'platform_role.granted', 'platform_role.revoked',
        'user.disabled', 'user.enabled', 'organization.created',
        'organization.deleted', 'organization_member.role_changed',
        'organization_member.removed', 'project.created',
        'project_member.added', 'project_member.role_changed',
        'project_member.removed', 'invitation.created', 'invitation.resent',
        'invitation.revoked', 'invitation.accepted', 'privilege.confirmed',
        'platform_recovery.completed', 'credential.issued', 'credential.revoked'
    )),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    invitation_id UUID REFERENCES invitations(id) ON DELETE SET NULL,
    previous_role TEXT,
    new_role TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'rejected')),
    request_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retain_until TIMESTAMPTZ NOT NULL,
    CHECK (
        (actor_kind = 'user' AND actor_user_id IS NOT NULL)
        OR (actor_kind = 'system_recovery' AND actor_user_id IS NULL)
    ),
    CHECK (request_id IS NULL OR char_length(request_id) BETWEEN 1 AND 128),
    CHECK (retain_until > created_at)
);

CREATE INDEX access_audit_global_page_idx
    ON access_audit_records (created_at DESC, id DESC);
CREATE INDEX access_audit_org_page_idx
    ON access_audit_records (organization_id, created_at DESC, id DESC);
CREATE INDEX access_audit_retention_idx ON access_audit_records (retain_until, id);

CREATE OR REPLACE FUNCTION protect_last_super_admin() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM platform_role_assignments p
           JOIN users u ON u.id = p.user_id
           WHERE p.revoked_at IS NULL AND u.disabled_at IS NULL
             AND u.email_verified_at IS NOT NULL AND p.user_id <> OLD.user_id
       ) THEN
        RAISE EXCEPTION 'last active super administrator cannot be revoked'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER protect_last_super_admin_update
BEFORE UPDATE OF revoked_at ON platform_role_assignments
FOR EACH ROW EXECUTE FUNCTION protect_last_super_admin();

CREATE OR REPLACE FUNCTION protect_user_authority() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    becoming_ineligible BOOLEAN := TG_OP = 'DELETE';
BEGIN
    IF TG_OP = 'UPDATE' THEN
        becoming_ineligible := OLD.disabled_at IS NULL
            AND OLD.email_verified_at IS NOT NULL
            AND (NEW.disabled_at IS NOT NULL OR NEW.email_verified_at IS NULL);
    END IF;
    IF NOT becoming_ineligible THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    IF EXISTS (
        SELECT 1 FROM platform_role_assignments p
        WHERE p.user_id = OLD.id AND p.revoked_at IS NULL
    ) AND NOT EXISTS (
        SELECT 1 FROM platform_role_assignments p
        JOIN users u ON u.id = p.user_id
        WHERE p.revoked_at IS NULL AND p.user_id <> OLD.id
          AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'last active super administrator cannot be disabled or deleted'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM organization_memberships owned
        JOIN organizations o ON o.id = owned.organization_id
        WHERE owned.user_id = OLD.id AND owned.role = 'owner' AND o.status = 'active'
          AND NOT EXISTS (
              SELECT 1 FROM organization_memberships replacement
              JOIN users u ON u.id = replacement.user_id
              WHERE replacement.organization_id = owned.organization_id
                AND replacement.role = 'owner' AND replacement.user_id <> OLD.id
                AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL
          )
    ) THEN
        RAISE EXCEPTION 'last active organization owner cannot be disabled or deleted'
            USING ERRCODE = '23514';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER protect_user_authority_update
BEFORE UPDATE OF disabled_at, email_verified_at ON users
FOR EACH ROW EXECUTE FUNCTION protect_user_authority();
CREATE TRIGGER protect_user_authority_delete
BEFORE DELETE ON users
FOR EACH ROW EXECUTE FUNCTION protect_user_authority();

CREATE OR REPLACE FUNCTION protect_last_organization_owner() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    target_organization UUID := OLD.organization_id;
BEGIN
    IF OLD.role = 'owner'
       AND (TG_OP = 'DELETE' OR NEW.role <> 'owner')
       AND EXISTS (SELECT 1 FROM organizations WHERE id = target_organization AND status = 'active')
       AND NOT EXISTS (
           SELECT 1
           FROM organization_memberships m
           JOIN users u ON u.id = m.user_id
           WHERE m.organization_id = target_organization AND m.role = 'owner'
             AND u.disabled_at IS NULL AND u.email_verified_at IS NOT NULL
             AND m.user_id <> OLD.user_id
       ) THEN
        RAISE EXCEPTION 'last active organization owner cannot be removed'
            USING ERRCODE = '23514';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER protect_last_organization_owner_update
BEFORE UPDATE OF role ON organization_memberships
FOR EACH ROW EXECUTE FUNCTION protect_last_organization_owner();
CREATE TRIGGER protect_last_organization_owner_delete
BEFORE DELETE ON organization_memberships
FOR EACH ROW EXECUTE FUNCTION protect_last_organization_owner();
