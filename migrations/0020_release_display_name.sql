ALTER TABLE releases
    ADD CONSTRAINT releases_display_name_inputs_nonempty
    CHECK (char_length(btrim(version)) BETWEEN 1 AND 200);

CREATE OR REPLACE FUNCTION release_display_name(
    application_name TEXT,
    release_source TEXT,
    release_version TEXT,
    release_identity_digest BYTEA,
    release_identity_components JSONB
) RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    component_count INTEGER;
    result TEXT;
BEGIN
    IF release_source = 'manual' THEN
        result := btrim(release_version);
        IF result IS NULL OR result = '' THEN
            RAISE EXCEPTION 'manual Release version must be non-empty';
        END IF;
        RETURN result;
    END IF;

    IF release_source IS DISTINCT FROM 'observed'
        OR application_name IS NULL
        OR btrim(application_name) = ''
        OR release_identity_digest IS NULL
        OR octet_length(release_identity_digest) <> 32
        OR release_identity_components IS NULL
        OR jsonb_typeof(release_identity_components) <> 'array'
    THEN
        RAISE EXCEPTION 'observed Release display-name inputs are invalid';
    END IF;
    component_count := jsonb_array_length(release_identity_components);
    IF component_count < 1 THEN
        RAISE EXCEPTION 'observed Release must contain image components';
    END IF;
    RETURN format(
        '%s · %s %s · %s',
        btrim(application_name),
        component_count,
        CASE WHEN component_count = 1 THEN 'image' ELSE 'images' END,
        substr(encode(release_identity_digest, 'hex'), 1, 8)
    );
END;
$$;
