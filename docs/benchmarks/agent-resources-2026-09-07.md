# Live agent resource benchmark — 2026-09-07

Measured on the existing `aliens` Kubernetes cluster using deployed agents and the already observed `okoscope-quickstart/quickstart-demo` Deployment. This is a bounded resource test of the current configuration, not a maximum-capacity or long-duration soak test.

The raw samples and configuration are in `agent-resources-2026-09-07.json`; the executable scenario is `tools/benchmark_agent_resources.py`. The script executes transient commands inside the demo container and generates real telemetry in its existing Application. It does not alter Deployments, agent configuration, resource limits, or cluster infrastructure.

## Configuration and method

- Three workers, each with one CPU and approximately 1.8 GiB allocatable memory. The loaded worker runs Linux 6.8.0-137-generic; controls run 5.15.0-138/139-generic; all use containerd 1.7.30. Only `worker-192.168.0.9` runs the observed demo; the other two agents provide background controls.
- Agent image: `ghcr.io/okoscope/okoscope-agent@sha256:35e3d167e332085043cd0126b77a57531dbf95a0428b219c12b0a6641baf3dc1`.
- Agent requests: 100m CPU / 96 MiB RAM; limits: 500m / 512 MiB.
- Process exec/exit and TCP connect/listen/accept enabled. DNS and file observation disabled; syscall allowlist empty. One observed Deployment and Application.
- Queue capacity 4096, batch size 256, maximum event rate 1000/s, accepted-connection cap 25/s.
- The demo has a 100m CPU / 32 MiB memory limit. Requests are local HTTP requests to its BusyBox httpd; each client request starts a `wget` process. Process-only load runs `/bin/busybox true` repeatedly.
- Phases: 90 seconds baseline; 120 seconds paced HTTP (one worker, 100 ms pause); 120 seconds unpaced HTTP (four workers); 120 seconds process starts (four workers); 90 seconds recovery.
- Kubelet `/stats/summary` sampled approximately every 10 seconds on all workers. CPU means use differences in cumulative container CPU time divided by differences in the metric's own timestamps. The first 20 seconds of each phase and duplicate cached CPU timestamps are excluded from steady-state summaries. CPU maxima are sampled kubelet rates, not instantaneous peaks.
- Memory is container working set, with RSS reported separately. Network is pod eth0 RX/TX including transport and Kubernetes metadata traffic; loopback demo requests do not appear in its eth0 counters.
- Agent status counters are logged every 15 seconds. Boundary snapshots are asynchronous and can include nearby transition activity; sent and acknowledged deltas need not match at an individual boundary.
- Container metrics do not isolate total eBPF overhead charged to observed processes or kernel execution. This test does not measure an agent-disabled A/B baseline or total application slowdown.

## Results

Steady-state measurements for the agent on `worker-192.168.0.9` (1000m CPU = one core):

| Scenario | Achieved load | Mean CPU | Sampled max CPU | Mean / max working set | TX |
|---|---:|---:|---:|---:|---:|
| Background | No synthetic load | 40.94m | 47.09m | 56.50 / 56.54 MiB | 0.24 KiB/s |
| Paced HTTP | 1,063 successes / 120 s ≈ 8.9 req/s | 54.52m | 57.81m | 56.52 / 56.54 MiB | 30.75 KiB/s |
| HTTP burst | 2,869 successes / 120 s ≈ 23.9 req/s | 58.55m | 65.18m | 56.52 / 56.52 MiB | 70.91 KiB/s |
| Process burst | 4,581 starts / 120 s ≈ 38.2 starts/s | 64.36m | 75.87m | 56.53 / 56.55 MiB | 59.70 KiB/s |
| Recovery | No synthetic load; backlog draining | 49.06m | 77.21m | 56.51 / 56.54 MiB | 5.69 KiB/s |

All workload commands exited successfully and reported zero failures. Rates use the nominal 120-second workload duration; worker deadlines are rounded to node uptime seconds, so these are approximate rates. Paced HTTP also launches sleep processes; it is a mixed process/network scenario, not a pure network microbenchmark.

Agent RSS stayed at approximately 22.84 MiB on the loaded worker. RSS alone significantly understates the container working set used for resource sizing. Control agents averaged approximately 26–27m and 34–38m CPU, with 47–59 MiB working sets across these phases. Their workloads, kernels, and node background activity differ, so they are not interchangeable A/B baselines.

The demo averaged 100m CPU in both burst scenarios. The 100m generator limit therefore restricts the experiment; the agent's 500m limit was not approached. The observed agent CPU increase over its background mean was about 14m for paced HTTP, 18m for HTTP burst, and 23m for process burst.

## Event delivery and observation quality

Counter deltas on the loaded agent:

| Phase | Sent | Acknowledged | Retried | Capacity dropped | Inbound rate limited | Exit before observation |
|---|---:|---:|---:|---:|---:|---:|
| Background | 18 | 18 | 0 | 0 | 0 | 9 |
| Paced HTTP | 6,750 | 6,731 | 7 | 0 | 0 | 977 |
| HTTP burst | 13,279 | 9,186 | 3,414 | 624 | 122 | 2,814 |
| Process burst | 8,775 | 9,425 | 6,980 | 105 | 1 | 89 |
| Recovery | 18 | 2,953 | 659 | 0 | 0 | 9 |

Across the entire approximately 9.5-minute run, including inter-phase gaps, sent and acknowledged both increased by **30,249**; retried increased by **11,060**, capacity-dropped by **729**, inbound-rate-limited by **123**, and exit-before-observation by **4,004**. At the final status snapshot, cumulative sent and acknowledged were both 38,224: the backlog of sent events had drained. This does not recover events discarded before delivery. Per-phase windows exclude small gaps and therefore need not sum to whole-run deltas.

These are different counters, not disjoint categories that can be summed into a loss percentage. Acknowledgements in a phase may include earlier events; retries are not unique events. `capacity_dropped` aggregates several capacity/rate-limit paths. There was no increase in the recorded kernel-lost or decode-failed counters during these phases. Low resource usage does **not** demonstrate lossless capture or delivery.

The agent logs contain recurring gRPC `INTERNAL_ERROR` / HTTP/2 stream resets and reconnections, including during the baseline before load. They are a pre-existing confounder for delivery/backlog behavior. The test does not establish the cause of the disconnects. Exit-correlation counters also grew substantially in the HTTP scenarios, so process-exit coverage needs separate verification before treating this configuration as complete telemetry.

All three agents remained Ready with zero restarts. The final loaded-agent sample was **39.13m CPU / 56.51 MiB**, close to background. The recovery mean is higher because it includes backlog processing. The generator's final process listing contained only httpd and the inspection command; all transient load workers had exited.

Supplemental cAdvisor measurements span approximately 544 seconds, starting near the end of baseline and covering all load phases and recovery. Agent throttling increased by only **0.0323 seconds across 2 of 5,538 periods** (0.036% of periods). Demo throttling increased by **108.69 seconds across 2,372 of 3,634 periods** (65.3% of periods). These counters confirm that generator CPU limits materially constrained the load while agent CPU limits did not. Raw timestamped lines are retained in the JSON under `supplemental_throttling`. The runner was subsequently extended to capture these counters at each phase boundary for future runs; this run used the separate sampler recorded in the JSON.

The measured CPU and memory fit within the existing 100m / 96 MiB requests for this profile. There is no evidence from this test to increase the 500m / 512 MiB limits, and these short, generator-limited scenarios do not justify lowering production limits. Resolve the delivery/correlation findings and run higher-rate, longer tests before choosing general production sizing.

## Reproduction

From the repository root with authorized cluster access, run `python3 tools/benchmark_agent_resources.py`. It selects `aliens` and targets the existing quickstart Deployment. Review the fixed configuration and output path before reuse: rerunning overwrites the dated raw JSON. Raw configuration records the deployed image; the recorded Git revision identifies the local checkout, not necessarily that image.

## Scope of interpretation

These measurements apply to this deployed image, one small workload, and the enabled observers above. The demo's CPU limit can cap achieved load before the agent saturates. They do not establish requirements for DNS/file/syscall observation, many Applications, large Pod inventories, backend outages, or sustained production peaks. A short recovery window cannot establish the absence of memory leaks.

No production implementation was changed. Public installation and translated UI documentation do not need behavior changes for this measurement-only task; the benchmark report records the tested configuration and limitations.
