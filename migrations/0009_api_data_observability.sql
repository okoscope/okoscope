CREATE INDEX runtime_inventory_items_distribution_idx
    ON runtime_inventory_items (
        organization_id, project_id, application_id, identity_version,
        inventory_kind, occurrence_count DESC, identity_digest ASC
    )
    INCLUDE (id, semantic_summary);

CREATE INDEX runtime_event_group_releases_release_group_idx
    ON runtime_event_group_releases (release_id, group_id)
    INCLUDE (occurrence_count);
