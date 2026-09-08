-- Replace the UUID literals before running. Queries expose bounded identity and
-- rollout metadata only; image tags and credentials are intentionally omitted.

-- Observed versus manual Release inventory for one Application.
SELECT source, count(*) AS release_count,
       count(*) FILTER (WHERE identity_digest IS NOT NULL) AS identified_count
FROM releases
WHERE organization_id = '00000000-0000-0000-0000-000000000000'
  AND project_id = '00000000-0000-0000-0000-000000000000'
  AND application_id = '00000000-0000-0000-0000-000000000000'
GROUP BY source
ORDER BY source;

-- Recent deployment episodes and Ready Pod share. This share is not traffic.
SELECT e.id, e.release_id, e.revision_id, e.cluster_id, e.state,
       e.transition_kind, e.first_observed_at, e.first_ready_at,
       e.last_observed_at, e.ended_at, e.pod_count, e.ready_pod_count,
       e.workload_ready_pod_count,
       CASE WHEN e.workload_ready_pod_count > 0
            THEN e.ready_pod_count::double precision / e.workload_ready_pod_count
       END AS ready_pod_share
FROM deployment_episodes e
WHERE e.organization_id = '00000000-0000-0000-0000-000000000000'
  AND e.application_id = '00000000-0000-0000-0000-000000000000'
ORDER BY e.last_observed_at DESC, e.id DESC
LIMIT 100;

-- Transition predecessors used by rollback-aware default comparisons.
SELECT p.episode_id, p.predecessor_episode_id, p.observed_at, p.concurrent,
       target.release_id AS target_release_id,
       predecessor.release_id AS predecessor_release_id,
       target.transition_kind
FROM deployment_episode_predecessors p
JOIN deployment_episodes target ON target.id = p.episode_id
JOIN deployment_episodes predecessor ON predecessor.id = p.predecessor_episode_id
WHERE p.organization_id = '00000000-0000-0000-0000-000000000000'
  AND p.application_id = '00000000-0000-0000-0000-000000000000'
ORDER BY p.observed_at DESC, p.episode_id DESC
LIMIT 100;

-- Snapshot health: partial/discontinuous snapshots are retained but cannot
-- close an episode.
SELECT initialized, continuous, count(*) AS snapshot_count,
       max(observed_at) AS latest_observed_at
FROM kubernetes_revision_snapshots
WHERE organization_id = '00000000-0000-0000-0000-000000000000'
  AND application_id = '00000000-0000-0000-0000-000000000000'
GROUP BY initialized, continuous
ORDER BY initialized, continuous;
