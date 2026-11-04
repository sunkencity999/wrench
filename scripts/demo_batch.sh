#!/usr/bin/env bash
# hackathon demo batch: varied agent calls (burns Meta credits, collects transcripts)
set -u
export META_API_KEY=$(tr -d '\n' < ~/.openclaw/credentials/meta_llama_api_key.txt)
OUT=.wrench-dev/demo_transcripts
mkdir -p "$OUT"

run() {
  local name="$1"; shift
  echo "=== $name: wrench $* ==="
  { time wrench "$@" ; } > "$OUT/$name.txt" 2>&1
  echo "    -> $(grep -c . "$OUT/$name.txt") lines"
}

run ask-disk        ask "which mount will fill up first at current growth, and what's the biggest space hog on it?"
run ask-ports       ask "list every listening port that is NOT bound to localhost and tell me if any look risky"
run ask-failed      ask "are there any failed or flapping systemd units? triage them"
run ask-swap        ask "why is swap usage so high while free memory exists? should I act?"
run ask-docker      ask "summarize my docker fleet: what's running, what's stopped, anything unhealthy?"
run ask-journal     ask "scan the last 200 journal lines at err priority and group them by root cause"
run explain-ssh     explain sshd
run explain-port    explain :8188
run ask-deep-io     ask --deep "investigate current disk I/O patterns and tell me if the failing /dev/sda drive is being actively used by anything important"
run ask-security    ask "quick security review: logins, sudo failures, odd listening services. verdict?"
run ask-uptime      ask "if this box rebooted right now, what services would NOT come back automatically?"
run ask-wonder-plan ask --deep "write a prioritized 5-item maintenance plan for this box based on what you can observe"

echo "=== batch complete ==="
