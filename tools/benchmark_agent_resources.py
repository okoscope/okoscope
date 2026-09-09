#!/usr/bin/env python3
"""Bounded live test of the existing aliens quickstart demo; no deployment changes."""
import concurrent.futures
import argparse
import datetime
import json
import pathlib
import re
import subprocess
import time

NODES = [f'worker-192.168.0.{i}' for i in (7, 8, 9)]

def run(*args):
    return subprocess.check_output(args, text=True, timeout=40)

def kubectl(*args):
    return run('kubectl', '--context', 'aliens', *args)

def optional_kubectl(*args):
    completed = subprocess.run(('kubectl', '--context', 'aliens', *args), text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=40, check=False)
    return completed.stdout if completed.returncode == 0 else None

def sample(node):
    data = json.loads(kubectl('get', '--raw', f'/api/v1/nodes/{node}/proxy/stats/summary'))
    return {'node': node, 'cpu': data['node'].get('cpu'),
            'memory': data['node'].get('memory'),
            'pods': [{k: p[k] for k in ('podRef', 'containers', 'network') if k in p}
                     for p in data['pods'] if p['podRef']['namespace'] in
                     ('okoscope-system', 'okoscope-quickstart')]}

def throttling():
    raw = kubectl('get', '--raw', '/api/v1/nodes/worker-192.168.0.9/proxy/metrics/cadvisor')
    return [line for line in raw.splitlines()
            if line.startswith('container_cpu_cfs_')
            and ('container="agent"' in line or 'container="demo"' in line)]

def counters():
    pods = json.loads(kubectl('-n', 'okoscope-system', 'get', 'pods', '-o', 'json'))
    result = {}
    for pod in pods['items']:
        name = pod['metadata']['name']
        process_io = optional_kubectl('-n', 'okoscope-system', 'exec', name, '--',
                                      'cat', '/proc/1/io')
        result[name] = {'status': pod['status'], 'logs': kubectl('-n', 'okoscope-system',
                         'logs', name, '--tail=12'), 'process_io': process_io}
    return result

def selected_pods(all_pods):
    if not all_pods:
        return ['deployment/quickstart-demo']
    pods = json.loads(kubectl('-n', 'okoscope-quickstart', 'get', 'pods',
                             '-l', 'app=quickstart-demo', '-o', 'json'))
    return sorted(item['metadata']['name'] for item in pods['items']
                  if item['status'].get('phase') == 'Running')

def workload(name, seconds, workers, delay, all_pods):
    action = '/bin/busybox true' if name == 'process_burst' else 'wget -q -T 2 -O /dev/null http://127.0.0.1:8080/'
    if name.startswith('http'):
        action = f"busybox time -f 'latency=%e' sh -c '{action}'"
    worker = f'''read up rest < /proc/uptime; end=$(( ${{up%%.*}} + {seconds} )); n=0; failed=0
while :; do
 read up rest < /proc/uptime
 [ "${{up%%.*}}" -ge "$end" ] && break
 if {action}; then n=$((n+1)); else failed=$((failed+1)); fi
 {('sleep ' + delay) if delay else ':'}
done
printf 'worker successes=%s failures=%s\\n' "$n" "$failed"
'''
    shell = '\n'.join("sh -c '" + worker.replace("'", "'\\''") + "' &" for _ in range(workers)) + '\nwait'
    return [subprocess.Popen(['kubectl', '--context', 'aliens', '-n', 'okoscope-quickstart',
                              'exec', pod, '--', 'sh', '-c', shell], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for pod in selected_pods(all_pods)]

def collect_workloads(processes):
    outputs = []
    latencies = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=40)
        outputs.append({'stdout': stdout, 'stderr': stderr,
                        'returncode': process.returncode})
        latencies.extend(float(value) for value in
                         re.findall(r'latency=([0-9]+(?:\.[0-9]+)?)', stderr))
    latencies.sort()
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] \
        if latencies else None
    return {'processes': outputs, 'latency_samples': len(latencies),
            'latency_p95_seconds': p95}

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='docs/benchmarks/agent-resources-2026-09-07.json')
    parser.add_argument('--profile', default='current')
    parser.add_argument('--all-pods', action='store_true')
    parser.add_argument('--short', action='store_true',
                        help='Use 45/60 second phases for repeated A/B canaries')
    return parser.parse_args()

def main():
    args = arguments()
    out = pathlib.Path(args.output)
    quiet, active = (45, 60) if args.short else (90, 120)
    phases = [('baseline', quiet, 0, ''), ('http_paced', active, 1, '0.1'),
              ('http_burst', active, 4, ''), ('process_burst', active, 4, ''),
              ('recovery', quiet, 0, '')]
    run('kubectx', 'aliens')
    result = {'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'revision': run('git', 'rev-parse', 'HEAD').strip(),
              'profile': args.profile, 'all_pods': args.all_pods, 'phases': [],
              'agent_daemonset': json.loads(kubectl('-n', 'okoscope-system', 'get', 'ds', '-o', 'json')),
              'agent_config': json.loads(kubectl('-n', 'okoscope-system', 'get', 'cm', 'okoscope-agent-okoscope-agent', '-o', 'json'))}
    for name, seconds, workers, delay in phases:
        phase = {'name': name, 'duration_target_s': seconds, 'workers': workers,
                 'delay_s': delay, 'before': counters(), 'throttling_before': throttling(), 'samples': []}
        phase['started_epoch'] = time.time()
        processes = workload(name, seconds, workers, delay, args.all_pods) if workers else []
        print(f'START {name}', flush=True)
        deadline = time.monotonic() + seconds
        while True:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                phase['samples'].append({'epoch': time.time(), 'nodes': list(pool.map(sample, NODES))})
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(10, remaining))
        if processes:
            phase['generator'] = collect_workloads(processes)
        phase['after'] = counters()
        phase['throttling_after'] = throttling()
        phase['finished_epoch'] = time.time()
        result['phases'].append(phase)
        out.write_text(json.dumps(result, indent=2) + '\n')
        print(f'DONE {name}: {phase.get("generator", {})}', flush=True)
    print(str(out), flush=True)

if __name__ == '__main__':
    main()
