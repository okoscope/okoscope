# Frontend handoff: process termination and restarts

Render evidence as inert, source-labelled fields:

- normal exit: `Exited with status N`;
- signal: canonical name and number, plus `conventional_exit_code` labelled
  derived; show `core_dump_flag` as “core-dumping signal flag”, never “core file created”;
- Kubernetes termination: reason, runtime exit code, start/finish timestamps;
- restart: exact count and delta; when `observation_gap=true`, do not invent
  per-restart timestamps;
- waiting reason such as `CrashLoopBackOff` separately from termination;
- restart loop: projection version, threshold, window bounds and observed count.

Never display SIGKILL/137 as OOM without separately labelled, qualified
Kubernetes `OOMKilled` evidence. Ambiguous correlation must say “multiple
candidates”; absent correlation must not hide either source occurrence.

Required investigation fixtures: normal exit, SIGSEGV, SIGKILL with unknown
cause, qualified SIGKILL plus OOMKilled/137, and three restarts in ten minutes.
