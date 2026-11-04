# Platform support matrix

wrench runs on **Linux, macOS, and Windows**. Core sensing is built on
[psutil](https://github.com/giampaolo/psutil) and is identical everywhere;
OS-native tools (systemd, journald, launchd, Windows Event Log, …) are
**optional enrichers** that light up when present and degrade gracefully when
absent — wrench never crashes because a binary is missing.

Honesty legend:

- ✅ **tested** — exercised live on real hardware
- 🟡 **implemented** — code-complete with unit-tested platform branches (mocked),
  needs a native smoke test
- ➖ not available on that OS (wrench degrades gracefully and says so)

| capability | Linux | macOS | Windows |
|---|---|---|---|
| sensors: CPU / memory / swap / load | ✅ | 🟡 psutil | 🟡 psutil (load emulated) |
| sensors: disks / network / processes | ✅ | 🟡 psutil | 🟡 psutil |
| sensors: Docker | ✅ | 🟡 docker CLI | 🟡 docker CLI |
| sensors: NVIDIA GPU | ✅ | ➖ | 🟡 nvidia-smi |
| drift: listening ports | ✅ `ss` (+psutil fallback) | 🟡 psutil | 🟡 psutil |
| drift: running services | ✅ systemd | 🟡 `launchctl list` | 🟡 psutil Windows services |
| drift: installed packages | ✅ dpkg / rpm / pacman / apk | 🟡 Homebrew | ➖ (no fast census) |
| drift: user accounts | ✅ | 🟡 `pwd` (service accts filtered) | 🟡 `net user` |
| drift: scheduled jobs | ✅ cron | 🟡 cron + LaunchAgents | 🟡 `schtasks` |
| agent tool: read_logs | ✅ journald | 🟡 unified log (`log show`) | 🟡 `wevtutil` |
| agent tool: service_status | ✅ systemctl | 🟡 `launchctl print` | 🟡 `sc query` |
| agent tool: net_listeners | ✅ `ss` | 🟡 psutil | 🟡 psutil |
| agent tool: proc_top | ✅ psutil | 🟡 psutil | 🟡 psutil |
| agent tool: disk_tree | ✅ `du` | 🟡 `du` | 🟡 pure-Python walk |
| diag/repair allowlists | ✅ | 🟡 launchctl/log/vm_stat/… | 🟡 sc/schtasks/tasklist/… |
| `wrench install-service` | ✅ systemd user timer | 🟡 launchd agent plist | 🟡 Scheduled Task |
| `wrench web` dashboard | ✅ | 🟡 stdlib http | 🟡 stdlib http |
| config/data locations | ✅ XDG | 🟡 `~/Library/Application Support` | 🟡 `%APPDATA%` / `%LOCALAPPDATA%` |
| LLM providers (all six) | ✅ | 🟡 pure requests | 🟡 pure requests |

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

Linux is the development platform and is tested end-to-end (real patrols, real
timer, real dashboard). The macOS and Windows branches are implemented behind a
single platform abstraction (`wrench/platforms.py`), unit-tested with mocked
platforms (`tests/`), and **await native smoke tests** — if you run wrench on a
Mac or Windows box, please open an issue with your `wrench doctor` output,
good or bad.
