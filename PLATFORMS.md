# Platform support matrix

wrench runs on **Linux, macOS, and Windows**. Core sensing is built on
[psutil](https://github.com/giampaolo/psutil) and is identical everywhere;
OS-native tools (systemd, journald, launchd, Windows Event Log, …) are
**optional enrichers** that light up when present and degrade gracefully when
absent — wrench never crashes because a binary is missing.

Honesty legend:

- ✅ **tested** — exercised live on real hardware
- 🟡 **implemented** — code-complete with unit-tested platform branches (mocked),
  not yet exercised natively
- ➖ not available on that OS (wrench degrades gracefully and says so)

| capability | Linux | macOS | Windows |
|---|---|---|---|
| sensors: CPU / memory / swap / load / processes | ✅ | ✅ | 🟡 psutil (load emulated) |
| sensors: disks | ✅ real volumes only | ✅ APFS container fill; system/snapshot/DMG volumes ignored | 🟡 fixed drives |
| sensors: Docker / NVIDIA GPU | ✅ | 🟡 docker CLI · ➖ GPU | 🟡 |
| health score (`wrench score`) | ✅ | ✅ | 🟡 |
| deterministic patrol (no model) | ✅ | ✅ | 🟡 |
| drift: listening ports | ✅ `ss` | ✅ psutil → `lsof` (this user's sockets without root) | 🟡 psutil |
| drift: running services | ✅ systemd | ✅ `launchctl list` (per-app labels filtered) | 🟡 Windows services |
| drift: installed packages | ✅ dpkg / rpm / pacman / apk | ✅ Homebrew | ➖ (no fast census) |
| drift: user accounts | ✅ | ✅ account database | 🟡 `net user` |
| drift: scheduled jobs | ✅ cron | ✅ cron + LaunchAgents/Daemons | 🟡 `schtasks` |
| security: auth-log watch | ✅ auth.log / journald | ➖ reported as "not watched" | ➖ reported as "not watched" |
| security: privilege + `authorized_keys` drift | ✅ | ✅ | ➖ |
| CVE matching (OS packages) | ✅ dpkg / rpm | ➖ (pip/npm via `wrench cve`) | ➖ (pip/npm via `wrench cve`) |
| OS end-of-life | ✅ | ✅ | 🟡 |
| compliance packs | ✅ `cis-ubuntu-essentials`, `wrench-baseline` | ✅ `macos-baseline` | 🟡 `windows-baseline` |
| backups | ✅ cron + systemd timers | ✅ Time Machine (+ cron) | ➖ reported as "not checked" |
| fixxer | ✅ apt · 🟡 dnf/pacman | 🟡 Homebrew (detection ✅, apply untested) | 🟡 winget |
| agent tools: logs / service status / listeners / disk tree | ✅ | ✅ unified log · `launchctl` · `lsof` · `du -d` | 🟡 wevtutil · `sc` |
| `wrench install-service` | ✅ systemd user timer | 🟡 launchd agent (PATH + log file) | 🟡 Scheduled Task |
| `wrench web` dashboard + access control | ✅ | ✅ | 🟡 |
| fleet node + hub | ✅ | ✅ | 🟡 |
| owner-only data dir / config / tokens | ✅ | ✅ | ➖ relies on profile ACLs |
| LLM providers | ✅ | 🟡 pure requests | 🟡 pure requests |

Data directory per OS:

| | config | data (SQLite + HTML reports) |
|---|---|---|
| Linux | `~/.config/wrench/config.toml` | `~/.local/share/wrench/` |
| macOS | `~/Library/Application Support/wrench/config.toml` | `~/Library/Application Support/wrench/` |
| Windows | `%APPDATA%\wrench\config.toml` | `%LOCALAPPDATA%\wrench\` |

Both honor `WRENCH_CONFIG_DIR` / `WRENCH_DATA_DIR` env overrides.

## Install

- **Linux / macOS:** `curl -fsSL https://raw.githubusercontent.com/sunkencity999/wrench/main/scripts/install.sh | bash`
- **Windows (PowerShell):** `irm https://raw.githubusercontent.com/sunkencity999/wrench/main/scripts/install.ps1 | iex`
- **Anywhere with pipx:** `pipx install git+https://github.com/sunkencity999/wrench`

## Current status

**Linux** is the original development platform and is tested end-to-end (real
patrols, real timer, real dashboard).

**macOS** had its first native pass for 3.0 on Apple Silicon (macOS 27): status,
score, drift, security, comply, backups, cve, forecast, fixxer `--dry-run`,
deterministic patrols, the dashboard, and a fleet hub + node were all run for
real, and the failures that pass exposed are fixed — phantom APFS volumes, an
empty listener inventory, invisible user accounts, Linux-only compliance packs,
no Time Machine awareness, a patrol crash. Not yet run natively: `install-service`
(the launchd plan is unit-tested), `fixxer` apply, and the LLM providers.

**Windows** shares the platform abstraction (`wrench/platforms.py`), has its own
compliance pack and probes, and runs the test suite and a CLI smoke in CI on
every push, where it is green and gates like Linux and macOS. Checks that have
no Windows meaning (POSIX mode bits, owners, cron-based backup detection) report
"skipped" there rather than passing or failing. It has **not** had a hands-on
native pass. If you run wrench on Windows, please open an issue with
your `wrench doctor` output, good or bad.
