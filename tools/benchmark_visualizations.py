#!/usr/bin/env python3
"""Synthetic aggregate acceptance. Requires a NEW migrated local database and server binary.
Usage: python3 tools/benchmark_visualizations.py postgres://... /tmp/results.json
Writes fixtures only to an empty database; never use a shared/deployed database.
"""
import base64
import hashlib
import http.client
import json
import math
import pathlib
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parents[1]
DB, OUTPUT = sys.argv[1:]
assert urlparse(DB).hostname in ('127.0.0.1', 'localhost', '::1'), 'Local isolated databases only'


def sql(statement):
    return subprocess.check_output(
        ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', DB],
        input=statement, text=True,
    ).strip()


def literal(value):
    if value is None:
        return 'NULL'
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def explain(query, params):
    expanded = re.sub(r'\$(\d+)', lambda m: literal(params[int(m[1]) - 1]), query)
    return json.loads(sql('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + expanded))


assert sql('SELECT count(*) FROM organizations') == '0', 'Requires an empty isolated database'
org, project, app, cluster, agent, baseline, target, user = [str(uuid.uuid4()) for _ in range(8)]
token = 'oko_session_v1_' + base64.urlsafe_b64encode(bytes(32)).decode().rstrip('=')
scope = f"'{org}','{project}','{app}'"
sql(f"""
BEGIN;
INSERT INTO organizations(id,slug,name) VALUES('{org}','viz-bench','Visualization benchmark');
INSERT INTO projects(id,organization_id,slug,name) VALUES('{project}','{org}','bench','Bench');
INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES('{app}','{org}','{project}','bench','Bench');
INSERT INTO clusters(id,organization_id,external_id,name) VALUES('{cluster}','{org}','bench','Bench');
INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES('{agent}','{org}','{cluster}','bench','bench');
INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES
('{baseline}',{scope},'baseline',now()-interval '1 day'),('{target}',{scope},'target',now());
INSERT INTO users(id,email,password_hash) VALUES('{user}','bench@example.test',repeat('x',32));
INSERT INTO organization_memberships VALUES('{org}','{user}','owner',now());
INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at)
VALUES(gen_random_uuid(),'{user}','{org}',decode('{hashlib.sha256(token.encode()).hexdigest()}','hex'),now()+interval '4 hours');
CREATE TEMP TABLE fixture AS
SELECT n, md5('item-'||n)::uuid id, decode(md5('identity-'||n)||md5('identity-tail-'||n),'hex') digest,
CASE n%4 WHEN 0 THEN 'process' WHEN 1 THEN 'destination' WHEN 2 THEN 'domain' ELSE 'syscall' END kind,
CASE n%4 WHEN 0 THEN 'process.exec' WHEN 1 THEN 'network.connect' WHEN 2 THEN 'network.dns_query' ELSE 'syscall' END event_kind,
CASE n%4
WHEN 0 THEN jsonb_build_object('executable','/app/bin/worker-'||n)
WHEN 1 THEN jsonb_build_object('process_command','worker-'||n,'address_family','ipv4','destination_address','10.0.'||(n/256%256)||'.'||(n%256),'destination_port',443,'protocol','tcp')
WHEN 2 THEN jsonb_build_object('process_command','worker-'||n,'name','service-'||n||'.example.test','query_type','A')
ELSE jsonb_build_object('process_command','worker-'||n,'syscall','read') END summary,
1+n%100 occurrences
FROM generate_series(1,40000) n;
INSERT INTO runtime_events(id,event_id,organization_id,project_id,application_id,cluster_id,agent_id,observed_at,node_name,namespace,pod_uid,pod_name,container_id,container_name,workload_uid,workload_kind,workload_name,cgroup_id,pid,tgid,process_command,event_kind,event_schema_version,payload,release_id)
SELECT id,id,{scope},'{cluster}','{agent}',now(),'bench','ns-'||(n%20),'pod-'||(n%2000),'pod-'||(n%2000),'c-'||n,'app','workload','Deployment','workload-'||(n%100),1,n,n,'worker-'||n,event_kind,1,summary,
CASE WHEN n%3=0 THEN '{baseline}'::uuid ELSE '{target}'::uuid END FROM fixture;
INSERT INTO runtime_event_groups(id,organization_id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,fingerprint_digest,event_kind,semantic_summary,first_seen_at,last_seen_at,occurrence_count,representative_event_id,first_seen_event_id)
SELECT id,{scope},'{cluster}','ns-'||(n%20),'Deployment','workload-'||(n%100),1,digest,event_kind,summary,now()-interval '7 days',now(),occurrences,id,id FROM fixture;
INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count)
SELECT id,{scope},kind,1,digest,summary,now()-interval '7 days',now(),occurrences FROM fixture;
INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at)
SELECT {scope},id,'{cluster}','ns-'||(n%20),'Deployment','workload-'||(n%100),'pod-'||(n%2000),'pod-'||(n%2000),'app',occurrences,now()-interval '7 days',now() FROM fixture;
ANALYZE runtime_events;
ANALYZE runtime_event_groups;
ANALYZE runtime_inventory_items;
INSERT INTO runtime_event_group_releases(organization_id,project_id,application_id,release_id,group_id,occurrence_count,first_seen_at,last_seen_at,representative_event_id)
SELECT {scope},r.release_id,id,CASE WHEN r.release_id='{baseline}' THEN 1 ELSE occurrences END,now()-interval '7 days',now(),id
FROM fixture CROSS JOIN (VALUES('{baseline}'::uuid),('{target}'::uuid)) r(release_id)
WHERE (r.release_id='{baseline}' AND n%3<>1) OR (r.release_id='{target}' AND n%3<>0);
INSERT INTO runtime_inventory_releases(organization_id,project_id,application_id,item_id,release_id,occurrence_count,first_seen_at,last_seen_at)
SELECT organization_id,project_id,application_id,group_id,release_id,occurrence_count,first_seen_at,last_seen_at FROM runtime_event_group_releases;
COMMIT;
ANALYZE;
""")

inventory_source = (ROOT / 'crates/server/src/inventory_api.rs').read_text()
release_source = (ROOT / 'crates/server/src/releases.rs').read_text().split('async fn runtime_diff_summary(')[1]
inventory_query = re.search(r'"(WITH scoped AS MATERIALIZED .*?)",', inventory_source)[1]
diff_queries = re.findall(r'"(WITH b AS .*?)",', release_source)
results = {
    'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    'postgres': sql('SELECT version()'),
    'settings': sql("SELECT name||'='||setting||coalesce(unit,'') FROM pg_settings WHERE name IN ('shared_buffers','work_mem','max_connections','random_page_cost')"),
    'fixture': {'items': 40000, 'items_per_kind': 10000, 'groups': 40000, 'event_rows': 40000, 'sightings': 40000, 'pods': 2000, 'namespaces': 20, 'workloads': 100, 'samples': 300, 'warmups': 10},
    'measurements': {}, 'plans': {},
}
for kind in ['process', 'destination', 'domain', 'syscall']:
    results['plans'][kind] = explain(inventory_query, [org, project, app, 1, kind] + [None]*10 + [10])
results['plans']['scoped_process'] = explain(inventory_query, [org, project, app, 1, 'process', baseline, None, 'ns-0', 'Deployment'] + [None]*6 + [10])
for index, query in enumerate(diff_queries):
    results['plans'][f'diff_{index}'] = explain(query, [baseline, target, org, project, app, 10])

log = open(str(OUTPUT) + '.server.log', 'w')
server = subprocess.Popen([str(ROOT / 'target/debug/server'), '--database-url', DB,
    '--development-plaintext', '--admin-credential', 'isolated-benchmark-admin-credential-local-only', '--health-addr', '127.0.0.1:58089', '--grpc-addr', '127.0.0.1:54389'], stdout=log, stderr=log)
connection = http.client.HTTPConnection('127.0.0.1', 58089, timeout=60)


def request(path):
    started = time.perf_counter()
    connection.request('GET', path, headers={'Cookie': 'okoscope_session=' + token})
    response = connection.getresponse()
    body = response.read()
    return response.status, json.loads(body), len(body), (time.perf_counter()-started)*1000


try:
    for _ in range(100):
        if server.poll() is not None:
            raise RuntimeError('Benchmark server failed; see ' + str(OUTPUT) + '.server.log')
        try:
            connection.request('GET', '/healthz')
            connection.getresponse().read()
            break
        except OSError:
            connection.close()
            time.sleep(.1)
    base = f'/api/v1/projects/{project}/applications/{app}'
    routes = {kind: base + '/runtime-inventory/distribution?kind=' + kind for kind in ['process','destination','domain','syscall']}
    routes['scoped_process'] = routes['process'] + f'&release_id={baseline}&namespace=ns-0&workload_kind=Deployment'
    routes['diff'] = base + f'/releases/{target}/runtime-diff/summary?baseline_id={baseline}'
    for name, route in routes.items():
        field = 'largest_changes' if name == 'diff' else 'entries'
        for suffix, expected in [('',5),('&limit=1',1),('&limit=10',10)]:
            status, data, _, _ = request(route+suffix)
            assert status == 200, data
            assert len(data[field]) == expected
        for limit in [0,11]:
            assert request(route+f'&limit={limit}')[0] == 400
        for limit in [5,10]:
            samples, sizes = [], []
            for iteration in range(310):
                status, data, size, duration = request(route+f'&limit={limit}')
                assert status == 200, data
                assert len(data[field]) == limit
                if name == 'diff':
                    assert data['total_item_count'] == 40000
                    assert sum(c['item_count'] for c in data['classifications']) == 40000
                else:
                    expected_items = 1333 if name == 'scoped_process' else 10000
                    assert data['total_item_count'] == expected_items, data['total_item_count']
                    assert sum(e['item_count'] for e in data[field])+data['other']['item_count'] == expected_items
                    assert sum(e['occurrence_count'] for e in data[field])+data['other']['occurrence_count'] == data['total_occurrence_count']
                if iteration >= 10:
                    samples.append(duration)
                    sizes.append(size)
            samples.sort()
            result = {f'p{p}_ms': samples[math.ceil(len(samples)*p/100)-1] for p in [50,95,99]}
            result.update(max_ms=max(samples), max_bytes=max(sizes), samples_ms=samples)
            results['measurements'][f'{name}_limit_{limit}'] = result
            print(name, limit, {k:v for k,v in result.items() if k!='samples_ms'}, flush=True)
    # Demonstrate whether top-N is also a byte cap. This is a separate oversized-label probe.
    sql("UPDATE runtime_inventory_items SET semantic_summary=jsonb_build_object('executable',repeat('x',131072)) WHERE inventory_kind='process'")
    status, _, size, _ = request(routes['process']+'&limit=10')
    results['oversized_label_probe'] = {'status':status, 'response_bytes':size, 'label_bytes':131072, 'limit':10}
finally:
    pathlib.Path(OUTPUT).write_text(json.dumps(results, indent=2)+'\n')
    connection.close()
    server.terminate()
    server.wait(timeout=30)
    log.close()
