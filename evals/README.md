# wrench evals — the muse gauntlet

A [promptfoo](https://promptfoo.dev) battery comparing Meta's two muse models
on the four kinds of judgment wrench actually asks of them:

| category | cases | what it measures |
|---|---|---|
| log triage | 5 | real-looking syslog/journald excerpts → identify the root cause (OOM kill, disk full, SSH brute-force, crash loop + start-limit, DNS failure) |
| CVE severity | 4 | OSV-style advisory JSON → correct severity + urgency call, incl. the "no fixed build exists yet" trap |
| fixxer judgment | 5 | given a findings list, which fixes are safe to auto-apply unattended vs need a human — correct answers favor caution |
| config diagnosis | 4 | broken nginx / sshd / fstab / systemd unit files → find the actual problem |

Deterministic assertions (`icontains` / `icontains-any`) where possible;
nuanced caution-judgment cases use `llm-rubric` graded by `muse-spark-1.3`.

## Run it yourself

```bash
# needs promptfoo (npm i -g promptfoo) and a Meta Model API key
export META_API_KEY="$(tr -d '\n' < /path/to/your/meta_api_key.txt)"
cd evals
promptfoo eval -c promptfooconfig.yaml -o results.json
promptfoo view     # browse per-case outputs in the browser
```

One full run (18 cases × 2 models + rubric grading) costs roughly 85k tokens.
Both muse models are reasoning models — the config keeps `max_tokens ≥ 4096`
because they spend 300–500+ tokens thinking before producing visible output;
smaller budgets return null content.

Latest results: see [results.md](results.md) and the
"Which muse model should I pick?" section of the main README.
