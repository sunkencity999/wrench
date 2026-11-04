# examples — real output from a real box

Everything here was produced by wrench running live on the dev box ("devbox")
during the hackathon build, then sanitized (hostname, paths, private service
names). Nothing is mocked.

## HTML patrol reports (open in a browser)
- `patrol-20261103-195542.html` — first-ever patrol, `muse-spark-1.3`: found a
  broken smartd mail alert, triaged docker fleet, checked disk pressure.
- `patrol-20261103-200319.html` — deep patrol, `muse-wonder-1.0`: caught a
  *failing disk* (pending sectors), PCIe AER errors, a dead user timer, and an
  automation making suspicious sudo attempts — with evidence and a fix list.

## Terminal transcripts
- `transcript-ask-swap.txt` — "why is swap so high while free memory exists?"
  8 tool calls → "that 37Gi is history, not pressure; don't act" with
  /proc/vmstat evidence. The correct answer, and the boring one.
- `transcript-ask-disk.txt` — "which mount fills up first, and what's the hog?"
- `transcript-ask-wonder-plan.txt` — `--deep` maintenance plan: P1 "your disk
  is dying AND the thing that was supposed to email you about it is broken."
