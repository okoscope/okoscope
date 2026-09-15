\set ON_ERROR_STOP on
\set organization_id 10000000-0000-0000-0000-000000000001
\set project_id 20000000-0000-0000-0000-000000000001
\set application_id 30000000-0000-0000-0000-000000000001

INSERT INTO organizations(id,slug,name) VALUES(:'organization_id','reset-test-org','Reset test');
INSERT INTO projects(id,organization_id,slug,name) VALUES(:'project_id',:'organization_id','reset-test-project','Reset test');
INSERT INTO clusters(id,organization_id,external_id,name) VALUES('40000000-0000-0000-0000-000000000001',:'organization_id','reset-test','Reset test');
INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES
  (:'application_id',:'organization_id',:'project_id','target','Target'),
  ('30000000-0000-0000-0000-000000000002',:'organization_id',:'project_id','other','Other');
INSERT INTO users(id,email,password_hash,display_name,email_verified_at) VALUES
  ('50000000-0000-0000-0000-000000000001','reset@example.invalid',repeat('x',32),'Reset tester',now());
INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES
  ('60000000-0000-0000-0000-000000000001',:'organization_id','40000000-0000-0000-0000-000000000001','node','test');
INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES
  ('70000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','reset-preserved',now());
INSERT INTO application_ingestion_credentials(id,organization_id,project_id,application_id,name,credential_hash,token_hint) VALUES
  ('71000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','reset-test',decode(repeat('33',32),'hex'),'1234');
INSERT INTO application_agents(organization_id,project_id,application_id,cluster_id,agent_id) VALUES
  (:'organization_id',:'project_id',:'application_id','40000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000001');
INSERT INTO resource_contributions(id,organization_id,project_id,application_id,cluster_id,agent_id,release_id,schema_version,interval_start,interval_end,covered_usec,sample_count,contributing_containers,namespace,workload_uid,workload_kind,workload_name,container_name,node_name,unavailable_sources,values) VALUES
  ('72000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','40000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000001',1,now()-interval '1 minute',now(),60000000,1,1,'default','workload','Deployment','api','api','node',0,'{}');

INSERT INTO runtime_events(id,event_id,organization_id,project_id,cluster_id,application_id,agent_id,observed_at,node_name,namespace,pod_uid,pod_name,container_id,container_name,workload_uid,workload_kind,workload_name,cgroup_id,pid,tgid,process_command,event_kind,event_schema_version,payload,release_id) VALUES
  ('80000000-0000-0000-0000-000000000001','80000000-0000-0000-0000-000000000002',:'organization_id',:'project_id','40000000-0000-0000-0000-000000000001',:'application_id','60000000-0000-0000-0000-000000000001',now(),'node','default','pod','pod','container','api','workload','Deployment','api',1,1,1,'worker','syscall',1,'{"name":"openat"}','70000000-0000-0000-0000-000000000001');
INSERT INTO runtime_event_groups(id,organization_id,project_id,cluster_id,application_id,namespace,workload_kind,workload_name,fingerprint_version,fingerprint_digest,event_kind,semantic_summary,status,first_seen_at,last_seen_at,occurrence_count,representative_event_id) VALUES
  ('81000000-0000-0000-0000-000000000001',:'organization_id',:'project_id','40000000-0000-0000-0000-000000000001',:'application_id','default','Deployment','api',1,decode(repeat('11',32),'hex'),'syscall','{"process_command":"worker","syscall":"openat"}','open',now(),now(),1,'80000000-0000-0000-0000-000000000001');
INSERT INTO runtime_event_group_memberships(organization_id,project_id,application_id,event_id,group_id,fingerprint_version) VALUES
  (:'organization_id',:'project_id',:'application_id','80000000-0000-0000-0000-000000000001','81000000-0000-0000-0000-000000000001',1);
INSERT INTO runtime_history_snapshots(id,organization_id,project_id,application_id,group_id,release_id,day,occurrence_count,first_observed_at,last_observed_at) VALUES
  ('82000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','81000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000001',(now() AT TIME ZONE 'UTC')::date,1,date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC');
INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES
  ('83000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','syscall',2,decode(repeat('22',32),'hex'),'{"syscall":"openat"}',now(),now(),1);
INSERT INTO runtime_inventory_event_memberships(organization_id,project_id,application_id,event_id,item_id,identity_version) VALUES
  (:'organization_id',:'project_id',:'application_id','80000000-0000-0000-0000-000000000001','83000000-0000-0000-0000-000000000001',2);
INSERT INTO runtime_inventory_group_links(organization_id,project_id,application_id,item_id,group_id) VALUES
  (:'organization_id',:'project_id',:'application_id','83000000-0000-0000-0000-000000000001','81000000-0000-0000-0000-000000000001');
INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) VALUES
  (:'organization_id',:'project_id',:'application_id','83000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','default','Deployment','api','pod','pod','api',1,now(),now());
INSERT INTO runtime_behavior_user_labels(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,display_name,created_by_user_id,updated_by_user_id) VALUES
  ('84000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','syscall',2,decode(repeat('22',32),'hex'),'Open files','50000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001');

INSERT INTO runtime_policies(id,organization_id,project_id,application_id,name,created_by_user_id) VALUES
  ('85000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','Expected openat','50000000-0000-0000-0000-000000000001');
INSERT INTO runtime_policy_revisions(id,policy_id,organization_id,project_id,application_id,revision_number,enabled,inventory_kind,identity_version,identity_digest,behavior_matcher,inside_effect,source_inventory_item_id,source_runtime_group_id,created_by_user_id) VALUES
  ('86000000-0000-0000-0000-000000000001','85000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id',1,true,'syscall',2,decode(repeat('22',32),'hex'),'{"kind":"syscall","syscall":"openat"}','expected','83000000-0000-0000-0000-000000000001','81000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001');
UPDATE runtime_policies SET current_revision_id='86000000-0000-0000-0000-000000000001' WHERE id='85000000-0000-0000-0000-000000000001';
INSERT INTO runtime_policy_states(organization_id,project_id,application_id,state_version) VALUES(:'organization_id',:'project_id',:'application_id',1);
INSERT INTO runtime_policy_recomputations(id,organization_id,project_id,application_id,identity_version,identity_digest,requested_policy_revision_id) VALUES
  ('87000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id',2,decode(repeat('22',32),'hex'),'86000000-0000-0000-0000-000000000001');
INSERT INTO runtime_policy_suppressions(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,behavior_matcher,reason,expires_at,source_inventory_item_id,source_runtime_group_id,created_by_user_id) VALUES
  ('88000000-0000-0000-0000-000000000001',:'organization_id',:'project_id',:'application_id','syscall',2,decode(repeat('22',32),'hex'),'{"kind":"syscall","syscall":"openat"}','test',now()+interval '1 day','83000000-0000-0000-0000-000000000001','81000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001');
INSERT INTO runtime_group_policy_evaluations(organization_id,project_id,application_id,group_id,policy_state_version,evaluator_version,verdict,reason_code,winning_revision_id,explanation) VALUES
  (:'organization_id',:'project_id',:'application_id','81000000-0000-0000-0000-000000000001',1,1,'expected','inside_placement','86000000-0000-0000-0000-000000000001','{}');
INSERT INTO runtime_sighting_policy_evaluations(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name,policy_state_version,evaluator_version,verdict,reason_code,winning_revision_id,explanation) VALUES
  (:'organization_id',:'project_id',:'application_id','83000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','default','Deployment','api','pod','api',1,1,'expected','inside_placement','86000000-0000-0000-0000-000000000001','{}');

INSERT INTO outbox_messages(id,organization_id,project_id,topic,aggregate_id,schema_version,payload) VALUES
  ('89000000-0000-0000-0000-000000000001',:'organization_id',:'project_id','runtime_group.first_seen','81000000-0000-0000-0000-000000000001',1,'{}');
INSERT INTO webhook_destinations(id,organization_id,project_id,name,url,encrypted_secret,secret_nonce) VALUES
  ('90000000-0000-0000-0000-000000000001',:'organization_id',:'project_id','Preserved','https://example.invalid',decode('00','hex'),decode(repeat('00',24),'hex'));
INSERT INTO notification_deliveries(id,organization_id,project_id,destination_id,outbox_message_id,origin,source,event_name,payload,status,max_attempts) VALUES
  ('91000000-0000-0000-0000-000000000001',:'organization_id',:'project_id','90000000-0000-0000-0000-000000000001','89000000-0000-0000-0000-000000000001','outbox','live','runtime_group.first_seen','{}','pending',3);

\ir ../queries/reset-application-runtime.sql

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM runtime_events WHERE application_id='30000000-0000-0000-0000-000000000001')
    OR EXISTS (SELECT 1 FROM runtime_event_groups WHERE application_id='30000000-0000-0000-0000-000000000001')
    OR EXISTS (SELECT 1 FROM runtime_inventory_items WHERE application_id='30000000-0000-0000-0000-000000000001')
    OR EXISTS (SELECT 1 FROM runtime_policies WHERE application_id='30000000-0000-0000-0000-000000000001')
    OR EXISTS (SELECT 1 FROM outbox_messages WHERE id='89000000-0000-0000-0000-000000000001')
    OR EXISTS (SELECT 1 FROM notification_deliveries WHERE id='91000000-0000-0000-0000-000000000001') THEN
    RAISE EXCEPTION 'target reset left representative state';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM applications WHERE id='30000000-0000-0000-0000-000000000002')
    OR NOT EXISTS (SELECT 1 FROM releases WHERE id='70000000-0000-0000-0000-000000000001')
    OR NOT EXISTS (SELECT 1 FROM application_ingestion_credentials WHERE id='71000000-0000-0000-0000-000000000001')
    OR NOT EXISTS (SELECT 1 FROM resource_contributions WHERE id='72000000-0000-0000-0000-000000000001')
    OR NOT EXISTS (SELECT 1 FROM webhook_destinations WHERE id='90000000-0000-0000-0000-000000000001') THEN
    RAISE EXCEPTION 'reset removed preserved controls';
  END IF;
END $$;
