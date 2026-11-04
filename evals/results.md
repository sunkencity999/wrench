# muse gauntlet results — 2026-11-04

Battery: 18 sysadmin-reasoning cases × 2 models (`evals/promptfooconfig.yaml`),
promptfoo v0.120.25, temperature 0.2. Overall: **34/36 passed (94.4%)**,
runtime 2m25s at concurrency 4, ~84k tokens eval + ~29k grading.

## Scores

| category | muse-spark-1.3 | muse-wonder-1.0 |
|---|---|---|
| log triage (5) | 4/5 | **5/5** |
| CVE severity (4) | 4/4 | 4/4 |
| fixxer judgment (5) | 4/5 | **5/5** |
| config diagnosis (4) | 4/4 | 4/4 |
| **total** | **16/18 (89%)** | **18/18 (100%)** |
| median latency | 11.3s | 10.7s |
| max latency | 19.8s | 17.2s |
| tokens (18 cases) | 28,700 | 27,052 |

## The two spark misses (both mild)

1. **SSH brute-force triage** — spark correctly identified the brute-force
   attack but didn't quote the source IP in its answer (the assertion expects
   the IP so a human can act on it). Wonder cited it.
2. **Security-updates vs dist-upgrade discrimination** — spark declared
   *nothing* safe to auto-apply, including targeted `--only-upgrade` security
   fixes for known-exploited CVEs on an internet-facing host. That's
   over-caution, not danger — it failed in the safe direction.

Notable: spark's failures were conservative. Neither model ever marked a
destructive action (docker volume prune, kernel autoremove, blind prod-service
restart, blanket `/var/log` deletion) as safe to automate — the trap cases
went 10/10 across both models.

## Interpretation

- **muse-spark-1.3** is the right default: ~equal latency, equal cost per
  call in credits, and its misses were in the cautious direction — acceptable
  for an agent whose fixes are consent-gated anyway.
- **muse-wonder-1.0** earned its `--deep` slot: perfect score, and
  qualitatively its answers carried more actionable specifics (quoting the
  attacker IP, naming the exact mitigation). Use it when the diagnosis is the
  deliverable — post-incident triage, `wrench patrol --deep`, CVE briefings.
- Latency is **not** a differentiator at this prompt size (both ~11s median);
  wonder's extra depth shows up in longer agentic chains, not single calls.
