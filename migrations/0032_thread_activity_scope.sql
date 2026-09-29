DO $$
DECLARE
    constraint_name name;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'thread_activity_windows'::regclass
      AND contype = 'u';

    IF constraint_name IS NULL THEN
        RAISE EXCEPTION 'thread activity uniqueness constraint is missing';
    END IF;

    EXECUTE format('ALTER TABLE thread_activity_windows DROP CONSTRAINT %I', constraint_name);
END $$;

ALTER TABLE thread_activity_windows
    ADD CONSTRAINT thread_activity_windows_scoped_window_unique
    UNIQUE (organization_id, project_id, application_id, agent_id, process_cgroup_id, process_tgid,
            process_generation, observation_epoch, window_started_at, window_ended_at);

DROP INDEX thread_activity_windows_process_scope_idx;

CREATE INDEX thread_activity_windows_process_scope_idx
    ON thread_activity_windows
    (organization_id, application_id, agent_id, process_cgroup_id, process_tgid,
     process_generation, observation_epoch, window_started_at DESC, id DESC);
