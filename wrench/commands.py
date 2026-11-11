"""The command catalog: every command wrench's agent may run, and nothing else.

Two kinds of entry:

  diag — read-only. Runs at every policy tier, no confirmation.
  fix  — changes the machine. Runs only at ``repair`` / ``autonomous``.
         A fix marked ``ask`` needs a person to say yes EVERY time, even at
         ``autonomous`` — unattended, it is refused. Those are the fixes whose
         blast radius is not routine: package upgrades, killing a process,
         enabling a service at boot, deleting a pod.

Rules every entry obeys (tests enforce them):

  * the pattern is matched with ``re.fullmatch`` and spells out its flags —
    nothing may trail an allowed command, no entry ends in ``.*``;
  * every entry carries at least one concrete example, and each example must
    match its own pattern and pass the policy check;
  * a diag entry never writes, never follows a stream forever, and never
    prints a place where secrets live (process environments, ``docker
    inspect`` Config.Env, kube secrets, registry auth, wifi keys).

Entries are grouped into packs so an operator can read the list
(``wrench commands``) and switch a whole pack off (``[policy] disabled_packs``).
The ``os`` tag says where a command exists; it is documentation, not a filter —
a missing binary simply reports "command not found".
"""

from __future__ import annotations

import re

PACKS: dict[str, str] = {
    "services": "Services & units",
    "logs": "Logs",
    "processes": "Processes",
    "performance": "CPU, memory & load",
    "storage": "Disks & filesystems",
    "files": "Files & config",
    "network": "Network state",
    "net-probe": "Connectivity probes (these send packets off the machine)",
    "packages": "Packages & updates",
    "containers": "Containers & VMs",
    "kubernetes": "Kubernetes",
    "security": "Security & firewall",
    "users": "Users, sessions & directory",
    "hardware": "Hardware & firmware",
    "time": "Clock & time sync",
    "apps": "Web, mail, database & cluster software",
    "versions": "Tool versions",
    "cleanup": "Cleanup",
    "desktop": "Endpoint & desktop",
}

OSES = ("linux", "macos", "windows", "unix", "any")


class Cmd:
    __slots__ = ("kind", "pack", "os", "label", "pattern", "examples", "timeout", "ask", "rx")

    def __init__(self, kind, pack, os_, label, pattern, examples, timeout, ask=False):
        assert pack in PACKS and os_ in OSES and examples, (pack, os_, pattern)
        self.kind, self.pack, self.os, self.label = kind, pack, os_, label
        self.pattern, self.examples, self.timeout, self.ask = pattern, tuple(examples), timeout, ask
        # Windows commands and PowerShell cmdlets are case-insensitive
        self.rx = re.compile(pattern, re.ASCII | (re.I if os_ == "windows" else 0))

    def applies(self, plat: str) -> bool:
        if self.os == "any" or plat in ("", "all", "unknown"):
            return True
        if self.os == "unix":
            return plat in ("linux", "macos")
        return self.os == plat


CATALOG: list[Cmd] = []


def _d(pack, os_, label, pattern, *examples, timeout=30):
    CATALOG.append(Cmd("diag", pack, os_, label, pattern, examples, timeout))


def _f(pack, os_, label, pattern, *examples, ask=False, timeout=60):
    CATALOG.append(Cmd("fix", pack, os_, label, pattern, examples, timeout, ask))


# ---------------------------------------------------------------- tokens
# A unit / service name: never starts with "-" (so it can never be read as an
# option, e.g. `systemctl status -Hroot@evil`).
_UNIT = r"[\w@][\w@.\-]*"
# A filesystem path argument: absolute or ~-relative, never an option.
# No spaces: a space would let a second token ("/ -R") ride in as an option.
_PATH = r"[/~][\w/.\-~+]*"
_DEV = r"/dev/[\w/\-]+"
_N = r"\d{1,6}"
_WHEN = r"(?:'[\w :.\-+]+'|\"[\w :.\-+]+\"|[\w:.\-+]+)"
_NAME = r"[A-Za-z0-9][\w.\-]*"
# a package NAME: no "/" or "://" (a URL, a tap, a local file) and no trailing "-"
# (apt reads "pkg-" as REMOVE)
_PKG = r"[A-Za-z0-9](?:[A-Za-z0-9.+_\-]*[A-Za-z0-9+])?(?:[:=][\w.+~:\-]*[\w+~])?"
_BREW = r"[A-Za-z0-9](?:[A-Za-z0-9.+_\-]*[A-Za-z0-9+])?(?:@[\w.]+)?"
_BREWS = rf"{_BREW}(?: {_BREW}){{0,19}}"
_PKGS = rf"{_PKG}(?: {_PKG}){{0,19}}"
_HOST = r"(?:[A-Za-z0-9_][A-Za-z0-9_.\-]{0,252}|[0-9A-Fa-f:]{2,39})"
_IFACE = r"[A-Za-z][\w.\-:@]{0,31}"
_IP = r"(?!0\.|127\.)\d{1,3}(?:\.\d{1,3}){3}(?:/(?:2[4-9]|3[0-2]))?"   # a host or a /24, no wider
_PID = r"(?:[2-9]|[1-9]\d{1,6})"          # never 0 (the process group) or 1 (init)
_REP = r"(?: [1-5] (?:[1-9]|10))?"         # "interval count" — always bounded
_USER = r"[A-Za-z_][\w.\-$]{0,63}"
_NOT_BUILTIN = r"(?!(?i:root|administrator|admin|guest|krbtgt|defaultaccount|wdagutilityaccount)(?: |$))"
# a quoted or bare name that may contain spaces ("Wi-Fi", "Remote Desktop Users")
_QNAME = r"(?:'(?!-)[\w .\-/]+'|\"(?!-)[\w .\-/]+\"|(?!-)[\w.\-]+)"
# free text handed to a tool as ONE argument; never starts with "-" (an option)
_QTEXT = r"(?:'(?!-)[^'\\]+'|(?!-)[\w.\-:/\[\]*?^$]+)"
_LOG = (r"(?!/var/log/installer/)(?:(?:/var/log|/private/var/log|/Library/Logs|~/Library/Logs)/[\w/.\-+@:]+"
        r"|[/~][\w/.\-~+@:]*\.(?:log|out|err)(?:\.\d+)?)")
_PROC_FILES = (r"(meminfo|loadavg|cpuinfo|uptime|version|mounts|swaps|diskstats|vmstat|stat|"
               r"mdstat|interrupts|buddyinfo|partitions|filesystems|cmdline|zoneinfo|slabinfo|"
               r"net/dev|pressure/(cpu|memory|io)|sys/[\w\-]+(?:/[\w\-]+)*)")
_ETC_FILES = (
    r"(?:os-release|lsb-release|redhat-release|debian_version|issue|motd|fstab|hostname|hosts|"
    r"hosts\.allow|hosts\.deny|resolv\.conf|timezone|nsswitch\.conf|group|shells|login\.defs|"
    r"sysctl\.conf|sysctl\.d/[\w.\-]+\.conf|security/limits\.conf|"
    r"security/limits\.d/[\w.\-]+\.conf|logrotate\.conf|logrotate\.d/[\w.\-]+|crontab|"
    r"cron\.d/[\w.\-]+|anacrontab|"
    r"systemd/(?:system|user|journald|logind|resolved|timesyncd|coredump)\.conf|"
    r"ssh/sshd_config|ssh/sshd_config\.d/[\w.\-]+\.conf|ssh/ssh_config|chrony\.conf|"
    r"chrony/chrony\.conf|ntp\.conf|exports|modules|modprobe\.d/[\w.\-]+\.conf|default/grub|"
    r"pam\.d/[\w.\-]+|audit/auditd\.conf|audit/rules\.d/[\w.\-]+\.rules|"
    r"fail2ban/jail\.(?:conf|local)|selinux/config|mdadm/mdadm\.conf|docker/daemon\.json|"
    r"pf\.conf|newsyslog\.conf|auto_master|synthetic\.conf)")
_CT = r"(?:docker|podman|nerdctl)"
# a compose file: YAML, and never from a world-writable temp dir
_YAML = r"(?!/tmp/|/var/tmp/|/dev/shm/|/private/tmp/)[/~][\w/.\-~+]*\.ya?ml"
_K = r"(?:(?:k3s |microk8s )?kubectl|oc)"
_NS = (r"(?:(?:-n|--namespace) [a-z0-9][a-z0-9\-]*|--namespace=[a-z0-9][a-z0-9\-]*"
       r"|-A|--all-namespaces)")
_KP = rf"{_K}(?: {_NS})?"
_KRES = (r"(?:pods?|po|nodes?|no|deployments?|deploy|daemonsets?|ds|statefulsets?|sts|"
         r"replicasets?|rs|jobs?|cronjobs?|cj|services?|svc|ingress(?:es)?|ing|endpoints|ep|"
         r"events?|ev|namespaces?|ns|pv|pvc|persistentvolumes?|persistentvolumeclaims?|"
         r"storageclass(?:es)?|sc|hpa|pdb|all|componentstatuses|cs|networkpolicies|netpol|"
         r"serviceaccounts|sa|limitranges|resourcequotas|quota|crd|apiservices)")
_KWORK = r"(?:deployment|deploy|daemonset|ds|statefulset|sts)"
_PS = r"(?:powershell|pwsh)(?:\.exe)? -NoProfile -Command"
# PowerShell parameters: names and simple values only — no ; | ( ) { } $ " and
# never a parameter that points the cmdlet at another machine or at a file.
# A closed list of parameter NAMES (PowerShell also accepts prefixes and the
# -Name:value form, so a denylist cannot work), none of which points a cmdlet
# at another machine, a file, or extra directory attributes.
_PSARGS = (r"(?: (?!-)[\w.*\-]+)?(?: -(?:Name|DisplayName|Id|LogName|MaxEvents|Newest|EntryType|"
           r"ClassName|State|LocalPort|RemotePort|Group|Online|FeatureName|DriveLetter|"
           r"InterfaceAlias|AddressFamily|TaskName|TaskPath|Identity|Filter|LockedOut|"
           r"AccountDisabled|AccountExpired|PasswordExpired|List|Status|PrinterName|"
           r"FriendlyName|ResultSetSize)(?: (?!-)[\w.*,\-]+)?)*")
_PS_READ = (
    r"(?:Get-Service|Get-Process|Get-HotFix|Get-ComputerInfo|Get-Volume|Get-Disk|"
    r"Get-PhysicalDisk|Get-Partition|Get-PSDrive|Get-StoragePool|Get-SmbShare|Get-SmbSession|"
    r"Get-NetAdapter|Get-NetIPAddress|Get-NetIPConfiguration|Get-NetRoute|Get-NetTCPConnection|"
    r"Get-NetFirewallProfile|Get-DnsClientServerAddress|Get-DnsClientCache|Get-ScheduledTask|"
    r"Get-ScheduledTaskInfo|Get-LocalUser|Get-LocalGroup|Get-LocalGroupMember|"
    r"Get-MpComputerStatus|Get-MpThreat|Get-MpThreatDetection|Get-MpPreference|"
    r"Get-BitLockerVolume|Get-Tpm|Confirm-SecureBootUEFI|Get-ExecutionPolicy|Get-CimInstance|"
    r"Get-PnpDevice|Get-Printer|Get-PrintJob|Get-Date|Get-TimeZone|Get-Uptime|"
    r"Get-WindowsFeature|Get-WindowsOptionalFeature|Get-Package|"
    r"Get-ADUser|Get-ADComputer|Get-ADGroupMember|Get-ADDomain|Get-ADDomainController|"
    r"Search-ADAccount)")


# ================================================================ DIAGNOSTICS

# ---------------- services
_d("services", "linux", "service status",
   rf"systemctl (--user )?status {_UNIT}(?: (?:--no-pager|-l|--full|-n {_N}))*",
   "systemctl status nginx", "systemctl status nginx -l --no-pager")
_d("services", "linux", "unit listing",
   r"systemctl (--user )?list-units"
   r"(?: (?:--failed|--all|--no-pager|--no-legend|--plain|--type=[\w,]+|--state=[\w,\-]+))*",
   "systemctl list-units --failed --no-pager", "systemctl list-units --type=service")
_d("services", "linux", "timer listing",
   r"systemctl (--user )?list-timers(?: (?:--all|--no-pager|--no-legend))*",
   "systemctl list-timers --all")
_d("services", "linux", "unit listing",
   r"systemctl (--user )?(--failed|is-system-running)( --no-pager)?", "systemctl --failed")
_d("services", "linux", "unit state",
   rf"systemctl (--user )?(is-active|is-enabled|is-failed) {_UNIT}( --no-pager)?",
   "systemctl is-active nginx", "systemctl is-enabled nginx")
# `systemctl cat` and a bare `show` print Environment= lines; only named properties
_d("services", "linux", "unit properties (closed list, never Environment)",
   rf"systemctl (--user )?show {_UNIT} (?:-p |--property=)"
   r"(?:(?:ActiveState|SubState|LoadState|UnitFileState|MainPID|ExecMainStatus|ExecMainCode|"
   r"NRestarts|Restart|RestartUSec|MemoryCurrent|MemoryMax|MemoryHigh|CPUUsageNSec|"
   r"TasksCurrent|TasksMax|LimitNOFILE|ActiveEnterTimestamp|InactiveEnterTimestamp|"
   r"StateChangeTimestamp|Result|Type|User|Group|FragmentPath|After|Requires|Wants|WantedBy|"
   r"TriggeredBy|Triggers|Description|Id|Names|WorkingDirectory)(?:,(?=\w))?)+( --no-pager)?",
   "systemctl show nginx -p ActiveState,SubState,NRestarts",
   "systemctl show nginx --property=MemoryCurrent")
_d("services", "linux", "unit listing",
   r"systemctl (--user )?list-unit-files"
   r"(?: (?:--type=[\w,]+|--state=[\w,\-]+|--no-pager|--no-legend))*",
   "systemctl list-unit-files --state=enabled --no-pager")
_d("services", "linux", "socket units",
   r"systemctl (--user )?list-sockets(?: (?:--all|--no-pager|--no-legend))*",
   "systemctl list-sockets")
_d("services", "linux", "unit dependencies",
   rf"systemctl (--user )?list-dependencies(?: (?:--reverse|--all))* {_UNIT}( --no-pager)?",
   "systemctl list-dependencies --reverse nginx")
_d("services", "linux", "queued jobs", r"systemctl (--user )?list-jobs( --no-pager)?",
   "systemctl list-jobs")
_d("services", "linux", "boot analysis",
   rf"systemd-analyze(?: (?:time|blame|critical-chain(?: {_UNIT})?|verify {_UNIT}"
   rf"|security(?: {_UNIT})?))?( --no-pager)?",
   "systemd-analyze blame", "systemd-analyze critical-chain", timeout=60)
_d("services", "linux", "sysv service status",
   rf"service (?:--status-all|{_UNIT} status)", "service --status-all", "service cron status")
_d("services", "macos", "launchd listing", r"launchctl list( (?!-)[\w][\w./\-]*)?", "launchctl list")
_d("services", "macos", "launchd unit detail", r"launchctl print (?!-)[\w][\w./\-]*",
   "launchctl print gui/501/com.example.foo")
_d("services", "macos", "launchd disabled units",
   r"launchctl print-disabled (?:system|gui/\d+|user/\d+)", "launchctl print-disabled system")
_d("services", "unix", "homebrew services", r"brew services(?: list)?", "brew services list")
_d("services", "windows", "service query",
   r"sc query(?:ex)?(?: type= \w+)?(?: state= \w+)?( (?!-)[\w][\w.\-]*)?",
   "sc query", "sc query Spooler", "sc query state= all")
_d("services", "windows", "service config", r"sc (?:qc|qfailure|qdescription) (?!-)[\w][\w.\-]*",
   "sc qc Spooler")
_d("services", "windows", "scheduled tasks",
   r"schtasks /Query(?: (?:/FO (?:CSV|LIST|TABLE)|/V|/NH|/TN (?!-)[\w\\\\. \-]+))*",
   "schtasks /Query /FO CSV /NH")
_d("services", "any", "supervisor status", rf"supervisorctl status(?: {_NAME})?",
   "supervisorctl status")
_d("services", "any", "pm2 process list", r"pm2 (?:list|ls|status)", "pm2 list")

# ---------------- logs
_d("logs", "linux", "journal read",
   r"journalctl"
   rf"(?: (?:--no-pager|--user|--system|--dmesg|-[kbxeraq]+|--utc|--disk-usage|--list-boots"
   rf"|-n {_N}|--lines={_N}|-u {_UNIT}|--unit={_UNIT}|-t (?!-)[\w.\-]+|-p (?!-)[\w.]+|--priority=[\w.]+"
   rf"|-o (?!-)[\w\-]+|--output=[\w\-]+|-b -?\d+|-g (?:'[^'\\]+'|[\w.]+)|_PID=\d+|_UID=\d+"
   rf"|-S {_WHEN}|-U {_WHEN}|--since[= ]{_WHEN}|--until[= ]{_WHEN}))*",
   "journalctl -u nginx -n 100 --no-pager", "journalctl -p err -b --no-pager",
   "journalctl --since '1 hour ago' -u ssh", "journalctl --disk-usage")
_d("logs", "linux", "kernel log",
   r"dmesg(?: (?:--level=\w+(,\w+)*|-T|-H|--ctime|--kernel|-k))*", "dmesg -T --level=err,warn")
_d("logs", "unix", "log file tail",
   rf"(?:tail|head)(?: -n {_N}| -{_N})? {_LOG}",
   "tail -n 200 /var/log/syslog", "tail -n 100 /var/log/nginx/error.log",
   "head -50 /opt/app/logs/app.log")
_d("logs", "unix", "log file search",
   rf"z?grep(?: -[icnvEFwo]+)*(?: -m {_N})?(?: -[ABC] \d{{1,3}})* {_QTEXT} {_LOG}",
   "grep -i -c error /var/log/syslog", "grep -n -m 50 'Out of memory' /var/log/kern.log",
   "zgrep -c Failed /var/log/auth.log.2.gz")
_d("logs", "unix", "log file size", rf"wc -[lc] {_LOG}", "wc -l /var/log/auth.log")
_d("logs", "linux", "core dumps",
   rf"coredumpctl(?: (?:list|info)(?: {_NAME})?)?(?: --no-pager)?(?: -n {_N})?",
   "coredumpctl list --no-pager")
_d("logs", "macos", "unified log read",
   r"log show --last \d{1,3}[smh]( --style \w+)?( --predicate (?:'[^']+'|\"[^\"]+\"))?",
   "log show --last 15m --style compact",
   "log show --last 10m --predicate 'process == \"sshd\"'", timeout=90)
_d("logs", "windows", "event log read",
   r"wevtutil qe \w+ /c:\d{1,4}( /rd:true)?( /f:text)?( /q:[^/\s]+)?",
   "wevtutil qe System /c:50 /rd:true /f:text")
_d("logs", "windows", "event log listing", r"wevtutil (?:el|gl (?!-)[\w\-/]+)", "wevtutil gl System")
_d("logs", "windows", "event log read (powershell)",
   rf"{_PS} (?:Get-WinEvent|Get-EventLog)(?=.* -(?:MaxEvents|Newest) \d{{1,4}}(?: |$)){_PSARGS}",
   "powershell -NoProfile -Command Get-WinEvent -LogName System -MaxEvents 50",
   "powershell -NoProfile -Command Get-EventLog -LogName Application -Newest 30 -EntryType Error")

# ---------------- processes
# no "e" (environment) flag: process environments carry secrets
_d("processes", "unix", "process list",
   r"ps (aux|auxww|-ef|-(?:e|ax|A)o (?!-)[\w,%=]+)(?: --sort=-?%?\w+| -[rm])?",
   "ps aux", "ps aux --sort=-%mem", "ps -eo pid,ppid,stat,etime,cmd --sort=-etime")
_d("processes", "unix", "one process",
   r"ps (?:-fp|-p) \d{1,7}(?:,\d{1,7})*(?: -o (?!-)[\w,%=]+)?", "ps -fp 4242",
   "ps -p 4242 -o pid,ppid,etime,rss,stat")
_d("processes", "linux", "top snapshot",
   rf"top (?:-b -n ?1|-bn ?1)(?: (?:-o [%\w]+|-w {_N}|-c))*", "top -b -n 1", "top -bn1 -o %MEM")
_d("processes", "macos", "top snapshot (macos)",
   rf"top -l 1(?: (?:-n {_N}|-o \w+|-stats (?!-)[\w,]+))*", "top -l 1 -n 15 -o cpu")
_d("processes", "unix", "find a process",
   rf"pgrep(?: -[alfnoxi]+)?(?: -u {_USER})? (?!-)[\w.\-]+", "pgrep -a nginx", "pgrep -fl java")
_d("processes", "linux", "find a process", r"pidof (?!-)[\w.\-]+", "pidof sshd")
_d("processes", "unix", "process tree", r"pstree(?: -[pauUlnh]+)?(?: (?:\d{1,7}|[a-z_][\w\-]*))?",
   "pstree -p", "pstree -p 4242")
_d("processes", "unix", "open files of a process",
   r"lsof(?: -[nP]+)? -p \d{1,7}", "lsof -nP -p 4242")
_d("processes", "unix", "deleted files still held open", r"lsof(?: -[nP]+)? \+L1",
   "lsof -nP +L1")
_d("processes", "linux", "process detail",
   r"cat /proc/\d{1,7}/(?:status|limits|io|cgroup|stat|statm|sched|schedstat|oom_score|"
   r"oom_score_adj|smaps_rollup|comm)", "cat /proc/4242/status", "cat /proc/4242/limits")
_d("processes", "linux", "locks & ipc", r"(?:lslocks|ipcs(?: -[amqstu]+)?)", "lslocks", "ipcs -m")
_d("processes", "linux", "control groups",
   r"(?:systemd-cgtop -b -n 1(?: (?:-[mcpt]|--depth=\d))*|systemd-cgls --no-pager)",
   "systemd-cgtop -b -n 1 -m", "systemd-cgls --no-pager")
_d("processes", "windows", "process list (windows)",
   r"tasklist(?: (?:/V|/SVC|/NH|/FO (?:CSV|LIST|TABLE)))*", "tasklist", "tasklist /SVC")

# ---------------- performance
_d("performance", "linux", "memory", r"free( -[hmgwt]+)?", "free -h")
_d("performance", "unix", "uptime", r"uptime(?: -[ps])?", "uptime")
_d("performance", "linux", "vm statistics", rf"vmstat(?: -[swdta]+)?{_REP}",
   "vmstat 1 5", "vmstat -s")
_d("performance", "linux", "io statistics", rf"iostat(?: -[xdckmyzthNp]+)*{_REP}",
   "iostat -xz 1 3")
_d("performance", "macos", "io statistics (macos)",
   r"iostat(?: -w [1-5])?(?: -c (?:[1-9]|10))", "iostat -w 1 -c 3")
_d("performance", "linux", "per-cpu statistics", rf"mpstat(?: -P (?:ALL|\d{{1,4}}))?{_REP}",
   "mpstat -P ALL 1 3")
_d("performance", "linux", "per-process statistics",
   rf"pidstat(?: -[urdwlht]+)*(?: -p (?:ALL|\d{{1,7}}))?{_REP}", "pidstat -u 1 3")
_d("performance", "linux", "activity history",
   rf"sar(?: -[uqrSbBdWwvyR]+)*(?: -n (?:DEV|EDEV|TCP|ETCP|SOCK|ALL))?(?: -P ALL)?{_REP}",
   "sar -u 1 3", "sar -q", "sar -n DEV 1 3")
_d("performance", "linux", "io by process",
   r"iotop -b(?: -[oPak]+)* -n ?1(?: -[oPak]+)*", "iotop -b -o -n 1")
_d("performance", "linux", "cpu count & layout", r"(?:nproc|lscpu(?: -[eJx])?)", "nproc", "lscpu")
_d("performance", "linux", "swap", r"swapon (?:--show|-s)", "swapon --show")
_d("performance", "linux", "proc read", r"cat /proc/" + _PROC_FILES,
   "cat /proc/meminfo", "cat /proc/pressure/memory", "cat /proc/sys/vm/swappiness")
_d("performance", "unix", "kernel setting read", r"sysctl(?: -n)? (?!-)[\w.]+", "sysctl -n hw.memsize",
   "sysctl vm.swappiness")
_d("performance", "unix", "kernel settings (all)", r"sysctl -a", "sysctl -a")
_d("performance", "linux", "tuned profile", r"tuned-adm (?:active|list|recommend)",
   "tuned-adm active")
_d("performance", "any", "gpu status",
   r"nvidia-smi(?: -L| --query-gpu=[\w,.\-]+ --format=[\w,]+)?",
   "nvidia-smi", "nvidia-smi --query-gpu=name,utilization.gpu --format=csv,noheader")
_d("performance", "macos", "memory stats (macos)", r"(?:vm_stat|memory_pressure|hostinfo)",
   "vm_stat", "memory_pressure")

# ---------------- storage
_d("storage", "unix", "disk free",
   r"df(?: -[hHiTlPkma]+)?(?: -[tx] \w+)*(?: " + _PATH + r")?", "df -h", "df -i /var")
_d("storage", "unix", "disk usage",
   rf"du -[a-zA-Z]+(?: (?:--max-depth={_N}|-d ?{_N}))? {_PATH}", "du -sh /var/log",
   "du -h --max-depth=1 /var", timeout=60)
_d("storage", "linux", "block devices",
   rf"lsblk(?: -[a-zA-Z]+)?(?: -o (?!-)[\w,+]+)?(?: {_DEV})?", "lsblk", "lsblk -f")
_d("storage", "linux", "mounts",
   rf"findmnt(?: -[lDnsu]+)?(?: (?:-t (?!-)[\w,]+|-o (?!-)[\w,]+|--df|--fstab|--real))*(?: {_PATH})?",
   "findmnt", "findmnt --df")
_d("storage", "unix", "mounts", r"mount(?: -l)?", "mount")
_d("storage", "linux", "filesystem ids", rf"blkid(?: {_DEV})?", "blkid")
_d("storage", "linux", "partition tables", rf"(?:fdisk -l(?: {_DEV})?|parted -l)", "fdisk -l")
_d("storage", "unix", "smart status",
   rf"smartctl (?:-[aHixAc]|--all|--health|--info|--xall|-l (?:error|selftest|scttemp))"
   rf"(?: -d (?!-)[\w,]+)? {_DEV}", "smartctl -a /dev/sda", "smartctl -H /dev/nvme0",
   "smartctl -l selftest /dev/sda")
_d("storage", "unix", "smart device scan", r"smartctl --scan(?:-open)?", "smartctl --scan")
_d("storage", "linux", "nvme health",
   r"nvme (?:list|(?:smart-log|error-log|id-ctrl) /dev/nvme\w+)", "nvme list",
   "nvme smart-log /dev/nvme0")
_d("storage", "linux", "software raid",
   r"mdadm --detail(?: --scan| /dev/md[\w/]+)", "mdadm --detail /dev/md0")
_d("storage", "unix", "zfs pools",
   rf"zpool (?:status|list|iostat)(?: -[vxTLP]+)?(?: {_NAME})?", "zpool status -x", "zpool list")
_d("storage", "unix", "zfs datasets",
   r"zfs list(?: -t (?:snapshot|filesystem|volume|all))?(?: -o (?!-)[\w,:]+)?(?: -r)?"
   r"(?: (?!-)[\w][\w/.\-:@]*)?", "zfs list", "zfs list -t snapshot")
_d("storage", "linux", "btrfs",
   rf"btrfs (?:filesystem show|filesystem (?:df|usage) {_PATH}|device stats {_PATH}"
   rf"|scrub status {_PATH}|subvolume list {_PATH})", "btrfs filesystem usage /",
   "btrfs device stats /")
_d("storage", "linux", "lvm",
   r"(?:(?:lvs|vgs|pvs)(?: -[av]+)?(?: -o (?!-)[\w,+]+)?|(?:lvdisplay|vgdisplay|pvdisplay)"
   r"(?: (?!-)[\w/\-]+)?)", "lvs", "vgs", "pvs -a")
_d("storage", "linux", "device mapper & multipath", r"(?:multipath -ll|dmsetup (?:ls|status))",
   "multipath -ll", "dmsetup ls")
_d("storage", "linux", "filesystem detail",
   rf"(?:tune2fs -l {_DEV}|dumpe2fs -h {_DEV}|xfs_info (?:{_DEV}|{_PATH})"
   rf"|cryptsetup status {_NAME})", "tune2fs -l /dev/sda1", "xfs_info /")
_d("storage", "linux", "nfs", r"(?:nfsstat(?: -[cmsn]+)?|exportfs(?: -[sv]+)?)", "nfsstat -m",
   "exportfs -v")
_d("storage", "macos", "disk info (macos)",
   r"diskutil (?:list(?: (?:internal|external|physical|virtual))?|info(?: -all| (?!-)[\w/]+)"
   r"|apfs list(?: \w+)?|apfs listSnapshots (?!-)[\w/]+)", "diskutil list", "diskutil info /",
   "diskutil apfs list")
_d("storage", "macos", "time machine (macos)",
   r"tmutil (?:latestbackup|destinationinfo|listbackups|status|listlocalsnapshots /"
   r"|listlocalsnapshotdates(?: /)?)", "tmutil latestbackup", "tmutil listlocalsnapshots /")
_d("storage", "macos", "spotlight index status", r"mdutil -(?:s /[\w/]*|as|sa)", "mdutil -s /")
_d("storage", "macos", "mounted disk images", r"hdiutil info", "hdiutil info")
_d("storage", "windows", "volume info",
   r"fsutil (?:volume diskfree [a-z]:|dirty query [a-z]:"
   r"|fsinfo (?:drives|volumeinfo [a-z]:|ntfsinfo [a-z]:))", "fsutil volume diskfree C:")
_d("storage", "windows", "shadow copies",
   r"vssadmin list (?:shadows|writers|shadowstorage|providers|volumes)",
   "vssadmin list shadowstorage")
_d("storage", "windows", "fragmentation analysis", r"defrag [a-z]: /A(?: /V)?", "defrag C: /A",
   timeout=300)
_d("storage", "windows", "storage (powershell)",
   rf"{_PS} (?:Get-Volume|Get-Disk|Get-PhysicalDisk|Get-Partition|Get-PSDrive|Get-StoragePool|"
   rf"Get-SmbShare|Get-SmbSession){_PSARGS}",
   "powershell -NoProfile -Command Get-Volume", "powershell -NoProfile -Command Get-PhysicalDisk")

# ---------------- files (metadata, hashes, and a closed list of config files)
_d("files", "unix", "dir listing", r"ls(?: -[alhtrSd1F]+)?(?: " + _PATH + r")?", "ls -la /var/log")
_d("files", "unix", "file stat", rf"stat(?: -[Lfx])? {_PATH}", "stat /etc/hosts")
_d("files", "unix", "file type & links",
   rf"(?:file(?: -[bLi]+)?|readlink(?: -[fenm])?|realpath|namei -[lmov]+) {_PATH}",
   "file /usr/bin/python3", "readlink -f /etc/localtime", "namei -l /var/www/html")
_d("files", "linux", "file acl & attributes",
   rf"(?:getfacl(?: -[pt]+)?|lsattr(?: -[adl]+)?|getcap(?: -r)?) {_PATH}", "getfacl /srv/data",
   "lsattr /etc/resolv.conf")
_d("files", "unix", "file checksum",
   r"(?:sha256sum|sha1sum|md5sum|md5|shasum -a (?:1|256|512)) "
   r"(?:(?:/usr|/bin|/sbin|/opt|/lib\w*|/boot|/Applications|/Library|/System)/[\w/.\-+]+"
   r"|/etc/ssh/[\w.\-]+\.pub)",
   "sha256sum /usr/sbin/sshd", "shasum -a 256 /usr/sbin/sshd")
_d("files", "unix", "find files (never -exec / -delete)",
   rf"find {_PATH}(?: (?:-maxdepth {_N}|-mindepth {_N}|-xdev|-mount|-type [fdlbcps]"
   r"|-size [+\-]?\d+[ckMG]?|-(?:mtime|mmin|atime|ctime|links) [+\-]?\d+"
   rf"|-newer {_PATH}|-(?:name|iname|path) (?:'(?!-)[\w.*?\-\[\] /]+'|(?!-)[\w.*?\-]+)"
   rf"|-(?:user|group) {_USER}|-nouser|-nogroup|-perm [\-/]?[0-7]{{3,4}}"
   r"|-perm [\-/][ugoa]+[+=][rwxst]+|-empty|-ls|-print))*",
   "find /var -xdev -type f -size +500M", "find /etc -maxdepth 2 -mtime -1 -ls",
   "find /usr -xdev -perm -4000 -type f", timeout=90)
_d("files", "unix", "system file read", rf"cat /etc/{_ETC_FILES}",
   "cat /etc/os-release", "cat /etc/fstab", "cat /etc/ssh/sshd_config", "cat /etc/crontab")
_d("files", "linux", "sysfs read",
   r"cat /sys/(?:class|block|devices|fs/cgroup|kernel/mm|module)/[\w/.\-:]+",
   "cat /sys/class/thermal/thermal_zone0/temp", "cat /sys/block/sda/queue/scheduler")

# ---------------- network state (local only)
_d("network", "linux", "socket census", r"ss(?: -[tulnpaHes46]+)+", "ss -tulnp", "ss -s")
_d("network", "linux", "network config",
   rf"ip(?: -(?:4|6|s|br|brief|d|details|o|c|j|h))* (?:addr|address|a|route|r|link|l|neigh|n|"
   rf"rule|maddr|tunnel|netns|vrf)(?: (?:show|list|ls))?(?: (?:dev {_IFACE}|table \w+|up))*",
   "ip addr", "ip -br addr", "ip -s link", "ip route show", "ip neigh")
_d("network", "linux", "route lookup", rf"ip route get {_HOST}", "ip route get 10.0.0.5")
_d("network", "unix", "interfaces", rf"ifconfig(?: -a| {_IFACE})?", "ifconfig", "ifconfig en0")
_d("network", "any", "socket & route tables", r"netstat(?: -[abd-yA-Z46]{1,7})?",
   "netstat -ano", "netstat -rn", "netstat -tulpn")
_d("network", "any", "arp cache", r"arp -(?:a|n|an)", "arp -a")
_d("network", "linux", "routing table", r"route -n", "route -n")
_d("network", "any", "host name", r"hostname(?: -[fisIdA])?", "hostname", "hostname -f")
_d("network", "unix", "open sockets", r"lsof -i( :\d+)?( -[nP]+)?", "lsof -i :443 -nP")
_d("network", "unix", "open sockets", r"lsof -nP -iTCP -sTCP:LISTEN", "lsof -nP -iTCP -sTCP:LISTEN")
_d("network", "linux", "networkmanager",
   rf"nmcli(?: -[tfp]+)* (?:general status|g|device status|device show(?: {_IFACE})?|d"
   r"|connection show(?: --active)?|c|radio|networking connectivity)",
   "nmcli device status", "nmcli connection show --active")
_d("network", "linux", "systemd-networkd", rf"networkctl(?: (?:list|status(?: {_IFACE})?))?"
   r"(?: --no-pager)?", "networkctl status")
_d("network", "linux", "resolver state",
   rf"resolvectl(?: (?:status|statistics|dns|domain)(?: {_IFACE})?)?(?: --no-pager)?",
   "resolvectl status")
_d("network", "linux", "nic detail",
   rf"(?:ethtool(?: -[iSkagc])? {_IFACE}|iw dev(?: {_IFACE} (?:link|info|station dump))?"
   rf"|bridge (?:link|fdb|vlan)(?: show)?|tc(?: -s)? qdisc show(?: dev {_IFACE})?"
   r"|conntrack -[SC])", "ethtool eth0", "ethtool -S eth0", "tc -s qdisc show dev eth0")
_d("network", "linux", "vpn state",
   rf"(?:wg show(?: {_IFACE})?|tailscale (?:status|ip|netcheck)|zerotier-cli (?:info|"
   r"listnetworks|peers)|ipsec status(?:all)?|swanctl --list-sas)", "wg show", "tailscale status")
_d("network", "macos", "network services (macos)",
   rf"networksetup -(?:listallhardwareports|listallnetworkservices|listnetworkserviceorder"
   rf"|getcomputername|(?:getinfo|getdnsservers|getsearchdomains|getwebproxy) {_QNAME}"
   rf"|getairportnetwork {_IFACE}|getairportpower {_IFACE})",
   "networksetup -listallhardwareports", "networksetup -getdnsservers Wi-Fi")
_d("network", "macos", "system configuration (macos)",
   r"scutil --(?:dns|proxy|nwi|nc list|get (?:ComputerName|HostName|LocalHostName))",
   "scutil --dns", "scutil --get ComputerName")
_d("network", "macos", "dhcp lease (macos)", rf"ipconfig (?:getifaddr|getpacket) {_IFACE}",
   "ipconfig getifaddr en0")
_d("network", "windows", "ip configuration", r"ipconfig(?: /(?:all|displaydns))?", "ipconfig /all")
_d("network", "windows", "routing table", r"route print(?: -[46])?", "route print")
_d("network", "windows", "adapters", r"getmac(?: /v)?(?: /fo (?:csv|list|table))?", "getmac /v")
_d("network", "windows", "netsh read",
   r"netsh (?:interface (?:ip|ipv4|ipv6) show (?:config|addresses|dnsservers|interfaces|route)"
   r"|wlan show (?:interfaces|drivers|networks)|winhttp show proxy)",
   "netsh interface ip show config", "netsh wlan show interfaces")
_d("network", "windows", "shares & sessions",
   r"net (?:share|session|use|view|config (?:workstation|server)"
   r"|statistics (?:workstation|server))", "net share", "net use")
_d("network", "windows", "network (powershell)",
   rf"{_PS} (?:Get-NetAdapter|Get-NetIPAddress|Get-NetIPConfiguration|Get-NetRoute|"
   rf"Get-NetTCPConnection|Get-DnsClientServerAddress|Get-DnsClientCache){_PSARGS}",
   "powershell -NoProfile -Command Get-NetAdapter",
   "powershell -NoProfile -Command Get-NetTCPConnection -State Listen")

# ---------------- connectivity probes (these leave the machine)
_d("net-probe", "unix", "ping",
   rf"ping -c (?:[1-9]|10)(?: (?:-[Wwi] \d{{1,2}}|-[nq46]))* {_HOST}",
   "ping -c 3 10.0.0.1", "ping -c 4 -W 2 example.com")
_d("net-probe", "windows", "ping (windows)",
   rf"ping -n (?:[1-9]|10)(?: -w \d{{1,5}})?(?: -[46])? {_HOST}", "ping -n 3 10.0.0.1")
_d("net-probe", "any", "dns lookup",
   rf"dig(?: @{_HOST})?(?: (?:\+(?:short|noall|answer|trace|dnssec|tcp|stats|nocmd|norecurse)"
   rf"|-4|-6))*(?: -x)? {_HOST}"
   r"(?: (?:A|AAAA|MX|NS|TXT|SOA|CNAME|PTR|SRV|CAA|ANY|DNSKEY|DS))?"
   rf"(?: @{_HOST})?(?: \+(?:short|noall|answer|trace|dnssec|tcp|stats|nocmd|norecurse))*",
   "dig +short example.com", "dig example.com MX @1.1.1.1", "dig -x 10.0.0.5 +short")
_d("net-probe", "any", "dns lookup",
   rf"(?:nslookup(?: -type=\w+)? {_HOST}(?: {_HOST})?|host(?: -t \w+)?(?: -[46a])? {_HOST}"
   rf"(?: {_HOST})?)", "nslookup example.com", "host -t MX example.com")
_d("net-probe", "linux", "name service lookup", rf"getent (?:hosts|ahosts) {_HOST}",
   "getent hosts example.com")
_d("net-probe", "linux", "dns lookup (resolved)", rf"resolvectl query {_HOST}",
   "resolvectl query example.com")
_d("net-probe", "macos", "dns lookup (macos)", rf"dscacheutil -q host -a name {_HOST}",
   "dscacheutil -q host -a name example.com")
_d("net-probe", "unix", "route trace",
   rf"traceroute(?: (?:-[nIT46]|-m \d{{1,2}}|-w \d|-q \d|-p \d{{1,5}}))* {_HOST}",
   "traceroute -n -m 15 example.com", timeout=90)
_d("net-probe", "linux", "route trace",
   rf"tracepath(?: -n)?(?: -m \d{{1,2}})? {_HOST}", "tracepath -n example.com", timeout=90)
_d("net-probe", "unix", "route trace (mtr report)",
   rf"mtr(?=.* -(?:[wnbz46]*r|-report))"
   rf"(?: (?:-[rwnbz46]+|--report|--report-wide|--no-dns|-[rwnbz]*c ?(?:[1-9]|10)|-[TU]"
   rf"|-P \d{{1,5}}))+ {_HOST}", "mtr -rwc 5 example.com", "mtr -r -n -c 5 10.0.0.1", timeout=90)
_d("net-probe", "windows", "route trace (windows)",
   rf"tracert(?: -d)?(?: -h \d{{1,2}})?(?: -w \d{{1,5}})?(?: -[46])? {_HOST}",
   "tracert -d -h 15 example.com", timeout=120)
_d("net-probe", "unix", "tcp port check (no data sent)",
   rf"nc(?=.* -[v46nu]*z)(?: (?:-[zv46nu]+|-w ?\d{{1,2}}|-G \d{{1,2}}))+ {_HOST} \d{{1,5}}",
   "nc -zv -w 3 db.internal 5432", "nc -z -w 2 10.0.0.5 443")
_d("net-probe", "any", "http HEAD request (no body, no query string)",
   r"curl(?=.* (?:-[sSLk46]*I[sSLk46]*|--head) )"
   r"(?: (?:-[sSLk46I]+|--head|-m \d{1,2}|--max-time \d{1,2}|--connect-timeout \d{1,2}))+"
   rf" https?://{_HOST}(?::\d{{1,5}})?(?:/[\w./\-~%]*)?",
   "curl -sSI -m 10 https://example.com", "curl -sI --max-time 5 http://localhost:8080/healthz")
_d("net-probe", "unix", "nfs / rpc exports",
   rf"(?:showmount -e {_HOST}|rpcinfo -p(?: {_HOST})?)", "showmount -e nas.internal",
   "rpcinfo -p")
_d("net-probe", "linux", "clock offset against a server (query only)",
   rf"ntpdate -q {_HOST}", "ntpdate -q pool.ntp.org")
_d("net-probe", "macos", "clock offset against a server (query only)",
   rf"sntp {_HOST}", "sntp time.apple.com")
_d("net-probe", "windows", "clock offset against a server",
   rf"w32tm /stripchart /computer:{_HOST} /samples:[1-5] /dataonly",
   "w32tm /stripchart /computer:time.windows.com /samples:3 /dataonly")
_d("net-probe", "windows", "connectivity (powershell)",
   rf"{_PS} (?:Test-NetConnection {_HOST}(?: -Port \d{{1,5}})?(?: -InformationLevel "
   rf"(?:Quiet|Detailed))?|Resolve-DnsName {_HOST}(?: -Type \w+)?(?: -Server {_HOST})?)",
   "powershell -NoProfile -Command Test-NetConnection db.internal -Port 1433",
   "powershell -NoProfile -Command Resolve-DnsName example.com", timeout=60)

# ---------------- packages & updates (read-only)
_d("packages", "linux", "dpkg query",
   rf"(?:dpkg -l(?: (?!-)[\w.+\-:*]+)?|dpkg -[sL] {_PKG}|dpkg -S {_PATH}|dpkg --audit"
   r"|dpkg --get-selections)", "dpkg -l", "dpkg -s openssl", "dpkg -S /usr/bin/curl")
_d("packages", "linux", "apt query",
   rf"(?:apt list(?: --(?:upgradable|installed|all-versions))*(?: (?!-)[\w.+\-:*]+)?"
   rf"|apt-cache (?:policy|show|depends|rdepends|madison)(?: {_PKG})?"
   r"|apt-mark (?:showhold|showauto|showmanual)|apt-get check)",
   "apt list --upgradable", "apt-cache policy nginx", "apt-mark showhold", timeout=60)
_d("packages", "linux", "apt simulation (changes nothing)",
   rf"apt-get (?:-s|--simulate|--dry-run) (?:upgrade|dist-upgrade|full-upgrade|autoremove"
   rf"|install {_PKGS})", "apt-get -s upgrade", timeout=90)
_d("packages", "linux", "pending security updates (dry run)",
   r"(?:unattended-upgrade --dry-run(?: -d)?|needrestart -b(?: -r l)?|needs-restarting(?: -[rs])?)",
   "unattended-upgrade --dry-run", "needrestart -b", "needs-restarting -r", timeout=120)
_d("packages", "linux", "rpm query",
   rf"(?:rpm -q[ailfcR]*(?: --last)?(?: (?!-)[\w.+\-:/]+)?|rpm -V(?:a| {_PKG}))",
   "rpm -qa --last", "rpm -q openssl", "rpm -qf /usr/bin/curl", timeout=180)
_d("packages", "linux", "dnf / yum query",
   rf"(?:dnf|yum)(?: -q)? (?:check-update|list (?:installed|updates|--installed|--upgrades)"
   r"|repolist(?: (?:all|-v))?|history(?: (?:list|info \d+))?"
   r"|updateinfo(?: (?:list|summary|info))?(?: (?:security|--security|bugfix))?"
   rf"|info {_PKG}|needs-restarting(?: -r)?|check)",
   "dnf check-update", "dnf updateinfo list security", "yum history", timeout=180)
_d("packages", "linux", "zypper / pacman / apk query",
   rf"(?:zypper(?: -n| --non-interactive)? (?:lu|list-updates|lp|list-patches|lr|repos|ps -s"
   rf"|patch-check|info {_PKG})|pacman -Q[ueimnqdtk]*(?: {_PKG})?|checkupdates"
   rf"|apk (?:info|version|stats|list (?:--installed|-I))(?: -[vl])?)",
   "zypper lu", "pacman -Qu", "apk version", timeout=180)
_d("packages", "linux", "snap / flatpak query",
   rf"(?:snap (?:list(?: --all)?|refresh --list|changes|services|version|info {_PKG})"
   r"|flatpak (?:list|remotes|remote-ls --updates)(?: --(?:app|runtime|system|user))?)",
   "snap list", "snap refresh --list", "flatpak list", timeout=90)
_d("packages", "linux", "firmware updates available",
   r"fwupdmgr (?:get-devices|get-updates|get-history)", "fwupdmgr get-updates", timeout=90)
_d("packages", "unix", "homebrew query",
   rf"brew (?:list(?: (?:--versions|--cask|--formula|-1))*|outdated(?: --(?:greedy|cask|"
   rf"formula|verbose))*|info {_BREW}|doctor|config|leaves|pinned|tap|missing"
   rf"|uses --installed {_BREW})", "brew outdated", "brew list --versions", "brew doctor",
   timeout=180)
_d("packages", "any", "language package managers",
   rf"(?:(?:pip3?|python3? -m pip) (?:list(?: (?:--outdated|--user|--format=(?:columns|json)))*"
   rf"|show {_PKG}|check)|npm (?:ls|list|outdated) -g(?: --depth[= ]\d)?"
   r"|gem (?:list(?: --local)?|outdated)|pipx list|conda (?:list|info|env list))",
   "pip list --outdated", "npm ls -g --depth=0", "gem outdated", timeout=120)
_d("packages", "macos", "pending updates (macos)", r"softwareupdate (?:-l|--list)",
   "softwareupdate -l", timeout=180)
_d("packages", "macos", "update & install history (macos)",
   r"(?:softwareupdate --history(?: --all)?|pkgutil --pkgs(?:=[\w.*\-]+)?"
   r"|pkgutil --pkg-info (?!-)[\w.\-]+|mas (?:list|outdated))", "softwareupdate --history",
   "pkgutil --pkgs")
_d("packages", "windows", "winget query",
   r"winget (?:list|upgrade|source list|--info)"
   r"(?: --(?:include-unknown|accept-source-agreements|disable-interactivity))*",
   "winget upgrade --include-unknown", "winget list", timeout=180)
_d("packages", "windows", "winget package detail",
   r"winget (?:list|show) --id (?!-)[\w.\-+]+(?: -e| --exact)?(?: --accept-source-agreements)?",
   "winget show --id Git.Git -e", timeout=120)
_d("packages", "windows", "chocolatey / scoop query",
   r"(?:choco (?:list(?: -l| --local-only)?|outdated)(?: -r)?|scoop (?:list|status))",
   "choco outdated", timeout=180)
_d("packages", "windows", "installed updates & features",
   r"(?:dism /Online /Get-(?:Packages|Features|CurrentEdition|Drivers)(?: /Format:(?:Table|List))?"
   r"|dism /Online /Cleanup-Image /(?:CheckHealth|AnalyzeComponentStore))",
   "dism /Online /Cleanup-Image /CheckHealth", "dism /Online /Get-Packages /Format:Table",
   timeout=300)
_d("packages", "windows", "updates (powershell)",
   rf"{_PS} (?:Get-HotFix|Get-Package|Get-WindowsFeature|Get-WindowsOptionalFeature -Online)"
   rf"{_PSARGS}", "powershell -NoProfile -Command Get-HotFix", timeout=120)

# ---------------- containers & VMs
_d("containers", "any", "container list",
   rf"{_CT} (?:ps|container ls)(?: (?:-a|--all|-q|-s|--size|--no-trunc|-l|--latest|-n \d+"
   r"|(?:--filter|-f) (?!-)[\w.=\-]+|--format (?:table|json)))*", "docker ps -a",
   "podman ps --filter status=exited")
_d("containers", "any", "container resource use",
   rf"{_CT} stats --no-stream(?: (?:-a|--all|--no-trunc))*(?: {_NAME})*",
   "docker stats --no-stream")
_d("containers", "any", "container logs (always bounded by --tail)",
   rf"{_CT} logs(?=.* (?:--tail|-n)[= ]\d)(?: (?:--tail[= ]{_N}|-n {_N}|--timestamps|-t"
   rf"|--since[= ]\d+[smhd]|--until[= ]\d+[smhd]))+ {_NAME}",
   "docker logs --tail 200 web", "docker logs --tail 100 --since 30m --timestamps web")
# full `docker inspect` dumps Config.Env (secrets); allow only safe projections
_d("containers", "any", "container detail (no environment)",
   rf"{_CT} inspect (-f|--format) '\{{\{{json \.(State(?:\.\w+)*|RestartCount|Created|Image|Name"
   r"|HostConfig\.(RestartPolicy|Memory|NanoCpus|NetworkMode|Privileged|Binds)"
   r"|NetworkSettings\.(Ports|Networks|IPAddress)|Mounts"
   rf"|Config\.(Image|ExposedPorts|User|WorkingDir))\}}\}}' {_NAME}",
   "docker inspect -f '{{json .State}}' web", "docker inspect -f '{{json .State.Health}}' web")
_d("containers", "any", "images, volumes, networks, disk",
   rf"{_CT} (?:images(?: (?:-a|--all|-q|--digests|--no-trunc|--filter (?!-)[\w.=\-]+))*"
   rf"|system df(?: -v)?|version|info|network ls|network inspect {_NAME}|volume ls"
   rf"|volume inspect {_NAME}|top {_NAME}|port {_NAME})",
   "docker system df", "docker images", "docker top web")
_d("containers", "any", "compose projects",
   rf"{_CT} compose(?: (?:-f {_YAML}|-p {_NAME}))*"
   rf" (?:ls(?: -a)?|ps(?: -a)?|top|images|version|config --(?:services|volumes)"
   rf"|logs --tail[= ]{_N}(?: {_NAME})?)", "docker compose ls",
   "docker compose -f /srv/app/compose.yaml ps")
_d("containers", "any", "swarm",
   rf"docker (?:node ls|service ls|service ps {_NAME}|stack ls|stack ps {_NAME})",
   "docker service ls")
_d("containers", "linux", "cri runtime", r"crictl (?:ps(?: -a)?|pods|images|stats|version)",
   "crictl ps -a")
_d("containers", "linux", "virtualization",
   rf"(?:systemd-detect-virt(?: -[cv])?|virsh list(?: --all)?"
   rf"|virsh (?:dominfo|domstate|domblklist|domiflist|dommemstat) {_NAME}"
   r"|virsh (?:nodeinfo|version|pool-list --all|net-list --all)"
   r"|qm (?:list|status \d+)|pct (?:list|status \d+)|pveversion(?: -v)?|lxc list|lxc-ls(?: -f)?"
   r"|multipass list)", "virsh list --all", "qm list", "systemd-detect-virt")
_d("containers", "any", "desktop hypervisors",
   r"(?:vagrant global-status|VBoxManage list (?:vms|runningvms)|prlctl list -a)",
   "VBoxManage list runningvms")

# ---------------- kubernetes (never secrets, configmaps, or -o yaml/json)
_d("kubernetes", "any", "kube resources",
   rf"{_KP} get {_KRES}(?:,{_KRES})*(?: {_NAME})?"
   rf"(?: (?:{_NS}|-o (?:wide|name)|--show-labels|--no-headers|--sort-by=[\w.]+"
   r"|(?:-l|--selector[= ]) ?[\w./=,!\-]+|--field-selector[= ][\w./=,!\-]+))*",
   "kubectl get pods -A", "kubectl get pods -n prod -o wide", "kubectl get nodes",
   "kubectl get events -n prod --sort-by=.lastTimestamp",
   "kubectl get events -n prod --field-selector involvedObject.name=web-7d4f")
_d("kubernetes", "any", "kube describe (objects that carry no environment)",
   rf"{_KP} describe (?:nodes?|no|pv|pvc|svc|service|ingress|ing|hpa|ns|namespace|"
   rf"storageclass|sc|pdb) {_NAME}(?: {_NS})?", "kubectl describe node worker-1")
_d("kubernetes", "any", "pod logs (always bounded by --tail)",
   rf"{_KP} logs(?=.* --tail[= ]\d)(?: (?:--tail[= ]{_N}|--since[= ]\d+[smh]|--previous|-p"
   rf"|--timestamps|-c {_NAME}|--all-containers|{_NS}))* (?!-)[\w][\w.\-/]*"
   rf"(?: (?:--tail[= ]{_N}|--since[= ]\d+[smh]|--previous|-p|--timestamps|-c {_NAME}"
   rf"|--all-containers|{_NS}))*", "kubectl logs --tail=200 web-7d4f -n prod",
   "kubectl logs deploy/web -n prod --tail=100 --previous")
_d("kubernetes", "any", "kube resource use",
   rf"{_KP} top (?:nodes?|pods?)(?: {_NAME})?(?: (?:{_NS}|--containers"
   r"|--sort-by=(?:cpu|memory)))*", "kubectl top nodes", "kubectl top pods -A --sort-by=memory")
_d("kubernetes", "any", "rollout state",
   rf"{_KP} rollout (?:status|history) {_KWORK}[/ ]{_NAME}(?: {_NS})?",
   "kubectl rollout status deployment/web -n prod", timeout=90)
_d("kubernetes", "any", "cluster info",
   rf"(?:{_K} (?:version(?: --short| --client)?|cluster-info|api-resources"
   r"|config (?:current-context|get-contexts)|get --raw /(?:healthz|readyz|livez))"
   r"|kubeadm (?:version|certs check-expiration))", "kubectl cluster-info",
   "kubectl config current-context", "kubeadm certs check-expiration")
_d("kubernetes", "any", "helm releases",
   rf"helm (?:(?:list|ls)(?: (?:{_NS}|-a|--failed|--pending))*"
   rf"|(?:status|history) {_NAME}(?: {_NS})?|version)", "helm list -A", "helm status web -n prod")

# ---------------- security & firewall
_d("security", "linux", "selinux / apparmor",
   r"(?:sestatus(?: -[vb])?|getenforce|aa-status|apparmor_status)", "sestatus", "aa-status")
_d("security", "linux", "audit subsystem",
   r"(?:auditctl -[sl]|ausearch -m (?!-)[\w,]+(?: -ts (?:recent|today|yesterday|boot|this-week))?"
   r"(?: -i)?|aureport(?: (?:-au|-l|-f|-x|-m|-k|--summary|--failed|-i))*)",
   "auditctl -s", "ausearch -m avc -ts recent", "aureport --summary", timeout=60)
_d("security", "linux", "failed logins",
   rf"(?:lastb(?: -n {_N})?|faillock(?: --user {_USER})?)", "lastb -n 30", "faillock --user deploy")
_d("security", "linux", "firewall rules",
   r"(?:ip6?tables(?: -t (?:filter|nat|mangle|raw|security))? -[nvx]*[LS][nvx]*"
   r"(?: [A-Za-z][\w\-]*)?(?: (?:-[nvx]+|--line-numbers))*|ip6?tables-save"
   r"|nft list (?:ruleset|tables|chains|table \w+ \w+)|ufw status(?: (?:verbose|numbered))?"
   r"|ufw app list|firewall-cmd --(?:state|list-all|list-all-zones|get-active-zones|"
   r"get-default-zone|list-services|list-ports)(?: --zone=[\w\-]+)?)",
   "iptables -L -n -v", "nft list ruleset", "ufw status verbose", "firewall-cmd --list-all")
_d("security", "linux", "fail2ban", rf"fail2ban-client status(?: {_NAME})?",
   "fail2ban-client status sshd")
_d("security", "unix", "ssh daemon config check",
   rf"(?:sshd -[tT]|ssh -V|ssh-keygen -l(?:f| -f) {_PATH})", "sshd -t", "sshd -T",
   "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
_d("security", "unix", "sudoers syntax check", r"visudo -c", "visudo -c")
_d("security", "linux", "password ageing", rf"chage -l {_USER}", "chage -l deploy")
_d("security", "unix", "certificate inspection",
   rf"openssl x509 -in {_PATH} -noout"
   r"(?: -(?:dates|enddate|startdate|subject|issuer|serial|fingerprint|text|checkend \d{1,9}))+",
   "openssl x509 -in /etc/ssl/certs/site.pem -noout -dates -subject")
_d("security", "unix", "issued certificates", r"certbot certificates", "certbot certificates")
_d("security", "linux", "platform hardening state",
   r"(?:update-crypto-policies --show|fips-mode-setup --check|mokutil --sb-state|bootctl status"
   r"|pro status|ubuntu-advantage status)", "mokutil --sb-state", "pro status")
_d("security", "macos", "disk encryption (macos)", r"fdesetup (?:status|list)", "fdesetup status")
_d("security", "macos", "gatekeeper & sip (macos)",
   r"(?:spctl --status|csrutil (?:authenticated-root )?status)", "spctl --status",
   "csrutil status")
_d("security", "macos", "application firewall (macos)",
   r"/usr/libexec/ApplicationFirewall/socketfilterfw --(?:getglobalstate|getstealthmode|"
   r"getblockall|getallowsigned|getloggingmode|listapps)",
   "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
_d("security", "macos", "packet filter (macos)",
   r"pfctl -s (?:info|rules|nat|Tables|timeouts|memory)", "pfctl -s info")
_d("security", "macos", "mdm enrolment & extensions (macos)",
   r"(?:profiles status -type (?:enrollment|bootstraptoken)|profiles list"
   r"|systemextensionsctl list|kmutil showloaded(?: --list-only)?"
   r"|jamf (?:version|checkJSSConnection))",
   "profiles status -type enrollment", "systemextensionsctl list")
_d("security", "macos", "code signature (macos)", rf"codesign -(?:dv+|v) {_PATH}",
   "codesign -dv /usr/local/bin/tool")
_d("security", "macos", "managed preferences (macos)",
   r"defaults read /Library/Preferences/com\.apple\.(?:SoftwareUpdate|alf|loginwindow|commerce|"
   r"TimeMachine)(?: \w+)?", "defaults read /Library/Preferences/com.apple.SoftwareUpdate")
_d("security", "windows", "bitlocker", r"manage-bde -status(?: [a-z]:)?", "manage-bde -status")
_d("security", "windows", "firewall profiles",
   r"netsh advfirewall show (?:allprofiles|currentprofile|domainprofile|privateprofile|"
   r"publicprofile)(?: state)?", "netsh advfirewall show allprofiles")
_d("security", "windows", "group policy result",
   r"gpresult /r(?: /scope (?:user|computer))?", "gpresult /r", timeout=120)
_d("security", "windows", "defender & platform (powershell)",
   rf"{_PS} (?:Get-MpComputerStatus|Get-MpThreat|Get-MpThreatDetection|Get-MpPreference|"
   rf"Get-BitLockerVolume|Get-Tpm|Confirm-SecureBootUEFI|Get-ExecutionPolicy|"
   rf"Get-NetFirewallProfile){_PSARGS}",
   "powershell -NoProfile -Command Get-MpComputerStatus",
   "powershell -NoProfile -Command Get-BitLockerVolume")

# ---------------- users, sessions & directory
_d("users", "unix", "sessions", r"who(?: -[abHqu]+)?", "who -b", "who")
_d("users", "unix", "sessions", rf"w(?: -[hsi]+)?(?: {_USER})?", "w")
_d("users", "unix", "login history",
   rf"last(?: -[aFidwx]+)?(?: -n {_N}| -{_N})?(?: {_USER})?", "last -n 20", "last")
_d("users", "linux", "last login per account", rf"lastlog(?: -u {_USER}| -t \d+| -b \d+)?",
   "lastlog -t 30")
_d("users", "unix", "identity",
   rf"(?:id(?: -[unGgr]+)?(?: {_USER})?|groups(?: {_USER})?|users)", "id deploy", "groups deploy")
_d("users", "any", "current user", r"whoami(?: /(?:groups|priv|all|user|fqdn|upn))?", "whoami",
   "whoami /groups")
_d("users", "linux", "name service lookup",
   r"getent (?:group|services|protocols|networks)(?: (?!-)[\w.\-]+)?", "getent group sudo")
_d("users", "linux", "login sessions",
   r"loginctl(?: (?:list-sessions|list-users|session-status \w+|user-status \w+"
   r"|show-user \w+))?(?: --no-pager)?", "loginctl list-sessions")
_d("users", "unix", "cron tables", rf"crontab (?:-l|-l -u {_USER}|-u {_USER} -l)", "crontab -l",
   "crontab -l -u www-data")
_d("users", "unix", "queued at jobs", r"atq", "atq")
_d("users", "linux", "domain join state",
   rf"(?:realm list|sssctl (?:domain-list|domain-status {_HOST})|klist(?: -[kel]+)?"
   rf"|net ads (?:info|testjoin)|wbinfo -[tp]|adcli info {_HOST})", "realm list", "klist")
_d("users", "macos", "directory lookup (macos)",
   rf"(?:dscl \. -list /(?:Users|Groups)(?: (?:UniqueID|PrimaryGroupID|UserShell|"
   rf"NFSHomeDirectory))?|dscl \. -read /Users/{_USER} (?:UniqueID|UserShell|NFSHomeDirectory|"
   rf"PrimaryGroupID|RealName)|dseditgroup -o checkmember -m {_USER} (?!-)[\w.\-]+"
   rf"|dscacheutil -q (?:user|group)(?: -a name (?!-)[\w.\-]+)?"
   rf"|sysadminctl -secureTokenStatus {_USER})",
   "dscl . -list /Users UniqueID", "dseditgroup -o checkmember -m alice admin")
_d("users", "windows", "local accounts",
   rf"(?:net users?(?: {_USER})?|net localgroup(?: {_QNAME})?|net accounts)",
   "net user", "net localgroup Administrators", "net accounts")
_d("users", "windows", "logon sessions", r"(?:query (?:user|session)|quser|qwinsta)", "query user")
_d("users", "windows", "domain health",
   rf"(?:nltest /(?:dsgetdc|sc_query):{_HOST}|repadmin /(?:replsummary|showrepl)|dcdiag(?: /q)?)",
   "nltest /sc_query:corp.example.com", "repadmin /replsummary", timeout=180)
_d("users", "windows", "accounts & directory (powershell)",
   rf"{_PS} (?:Get-LocalUser|Get-LocalGroup|Get-LocalGroupMember|Get-ADUser|Get-ADComputer|"
   rf"Get-ADGroupMember|Get-ADDomain|Get-ADDomainController|Search-ADAccount){_PSARGS}",
   "powershell -NoProfile -Command Get-LocalGroupMember -Group Administrators",
   "powershell -NoProfile -Command Search-ADAccount -LockedOut", timeout=60)

# ---------------- hardware & firmware
_d("hardware", "unix", "kernel info", r"(?:uname -[a-z]+|arch)", "uname -a")
_d("hardware", "linux", "host identity", r"hostnamectl(?: status)?", "hostnamectl")
_d("hardware", "linux", "buses & modules",
   r"(?:lsmem|lspci(?: -[kvnt]+)*|lsusb(?: -[tv])?|lsmod|modinfo (?!-)[\w\-]+|lsscsi(?: -[sgvl]+)?)",
   "lspci -k", "lsusb", "lsmod")
_d("hardware", "linux", "hardware inventory",
   r"(?:lshw -short(?: -C \w+)?|lshw -C \w+(?: -short)?|hwinfo --short"
   r"|dmidecode -t (?:system|bios|memory|processor|baseboard|chassis|cache|\d{1,3})"
   r"|dmidecode -s (?!-)[\w\-]+)", "lshw -short", "dmidecode -t memory", timeout=60)
_d("hardware", "linux", "temperatures", r"sensors(?: -[fAu])?", "sensors")
_d("hardware", "linux", "bmc / ipmi",
   r"ipmitool (?:sdr(?: (?:list|elist|type \w+))?|sel (?:list|elist|info)|chassis status"
   r"|sensor(?: list)?|fru(?: print)?|mc info|lan print(?: \d)?)", "ipmitool sel elist",
   "ipmitool sdr", timeout=60)
_d("hardware", "linux", "memory errors & power",
   r"(?:edac-util(?: -[vs])?|ras-mc-ctl --(?:summary|errors|status)|upower -(?:e|d|i (?!-)[\w/]+)"
   r"|acpi -[abtVi]+|cpupower frequency-info|efibootmgr(?: -v)?)", "edac-util -v", "acpi -V")
_d("hardware", "linux", "system limits",
   r"getconf (?:PAGESIZE|PAGE_SIZE|_NPROCESSORS_ONLN|_NPROCESSORS_CONF|LONG_BIT|ARG_MAX)",
   "getconf PAGESIZE")
_d("hardware", "macos", "macos version",
   r"sw_vers(?: -(?:productName|productVersion|buildVersion))?", "sw_vers")
_d("hardware", "macos", "system profile (macos)",
   r"system_profiler(?: SP(?:Hardware|Software|Storage|NVMe|SerialATA|Network|Power|Memory|"
   r"Displays|USB|Thunderbolt|Bluetooth|Ethernet|AirPort|Firewall|InstallHistory|Printers|Audio|"
   r"Camera|Diagnostics|StartupItem|Developer|DisabledSoftware|iBridge)DataType)+"
   r"(?: -detailLevel (?:mini|basic|full))?",
   "system_profiler SPHardwareDataType", "system_profiler SPPowerDataType SPStorageDataType",
   timeout=90)
_d("hardware", "macos", "power state (macos)",
   r"pmset -g(?: (?:batt|therm|assertions|custom|sched|ps|cap|live|stats))?", "pmset -g batt")
_d("hardware", "macos", "io registry (macos)", r"ioreg -r(?: -c|n) \w+(?: -d \d)?",
   "ioreg -r -c AppleSmartBattery")
_d("hardware", "windows", "system info (windows)", r"systeminfo", "systeminfo", timeout=90)
_d("hardware", "windows", "wmi read",
   r"wmic (?:logicaldisk|cpu|os|bios|computersystem|memorychip|diskdrive|nic|nicconfig|qfe|"
   r"service|startup|baseboard|csproduct|volume|partition|printer|share|useraccount|group|"
   r"timezone|pagefile|process) (?:get (?!-)[\w,]+|list (?:brief|full))"
   r"(?: /format:(?:list|csv|table))?", "wmic logicaldisk get Caption,FreeSpace,Size",
   "wmic os get Caption,Version", timeout=60)
_d("hardware", "windows", "drivers & power",
   r"(?:driverquery(?: (?:/v|/si|/fo (?:csv|list|table)))*"
   r"|powercfg /(?:a|l|list|getactivescheme|availablesleepstates|lastwake|waketimers|requests))",
   "driverquery", "powercfg /a")
_d("hardware", "windows", "inventory (powershell)",
   rf"{_PS} (?:Get-ComputerInfo|Get-CimInstance|Get-PnpDevice|Get-Printer|Get-PrintJob|"
   rf"Get-Service|Get-Process|Get-ScheduledTask|Get-ScheduledTaskInfo|Get-Uptime)"
   rf"{_PSARGS}", "powershell -NoProfile -Command Get-CimInstance Win32_OperatingSystem",
   "powershell -NoProfile -Command Get-Service -Name Spooler",
   "powershell -NoProfile -Command Get-Process", timeout=60)

# ---------------- clock & time sync
_d("time", "unix", "current time", r"date(?: -u| -R| -Iseconds| \+[\w%:.\-]+)?", "date", "date -u")
_d("time", "linux", "time & sync state",
   r"timedatectl(?: (?:status|show|timesync-status|show-timesync))?(?: --no-pager)?",
   "timedatectl", "timedatectl timesync-status")
_d("time", "linux", "ntp state",
   r"(?:chronyc(?: -n)? (?:tracking|sources(?: -v)?|sourcestats(?: -v)?|activity|rtcdata)"
   r"|ntpq -(?:p|pn|np)|ntpstat|hwclock(?: --show| -r)?(?: (?:--utc|--localtime|--verbose))*)",
   "chronyc tracking", "chronyc sources -v", "ntpq -p")
_d("time", "macos", "system settings read (macos)", r"systemsetup -get\w+",
   "systemsetup -getusingnetworktime", "systemsetup -gettimezone")
_d("time", "windows", "time service",
   r"(?:w32tm /query /(?:status|source|peers|configuration)(?: /verbose)?|w32tm /tz|tzutil /g)",
   "w32tm /query /status")
_d("time", "windows", "time (powershell)", rf"{_PS} (?:Get-Date|Get-TimeZone){_PSARGS}",
   "powershell -NoProfile -Command Get-TimeZone")

# ---------------- web, mail, database & cluster software
_d("apps", "any", "web server config test",
   r"(?:nginx -[tvV]|(?:apachectl|apache2ctl) (?:-[tSMvV]|configtest)|httpd -[tSMvV]"
   r"|caddy validate --config /etc/caddy/(?!-)[\w.\-]+"
   r"|haproxy -c -f /etc/haproxy/(?!-)[\w.\-]+\.cfg"
   r"|php-fpm[\d.]* -t"
   r"|squid -k (?:check|parse)|varnishstat -1)", "nginx -t", "apachectl configtest",
   "haproxy -c -f /etc/haproxy/haproxy.cfg")
_d("apps", "unix", "dns server",
   r"(?:named-checkconf(?: -z)?(?: /etc/(?:bind/[\w.\-]+|named/[\w.\-]+|named)\.conf)?"
   r"|rndc status|unbound-checkconf)",
   "named-checkconf", "rndc status")
_d("apps", "unix", "mail queue & config",
   r"(?:mailq|postqueue -p|postfix (?:check|status)|postconf -n|exim -bpc?|doveconf -n)",
   "mailq", "postfix check")
_d("apps", "any", "database liveness",
   r"(?:pg_lsclusters|pg_isready(?: -p \d{1,5})?"
   r"|mysqladmin (?:ping|status|version)"
   r"|redis-cli(?: -p \d{1,5})? (?:ping|dbsize|info(?: [a-z]+)?))",
   "pg_isready", "pg_lsclusters", "redis-cli ping", "redis-cli info memory")
_d("apps", "any", "message brokers",
   r"(?:rabbitmqctl (?:status|cluster_status|list_queues(?: name messages consumers)?)"
   r"|rabbitmq-diagnostics (?:status|ping|check_running|check_alarms))",
   "rabbitmqctl list_queues name messages consumers")
_d("apps", "unix", "printing", rf"(?:lpstat -[tpoasrdv](?: {_NAME})?|lpq(?: -a| -P {_NAME})?)",
   "lpstat -t", "lpq -a")
_d("apps", "linux", "file sharing", r"(?:smbstatus(?: -[bSpL])?|testparm -s)", "smbstatus -b")
_d("apps", "linux", "cluster & storage clusters",
   r"(?:pcs status|crm status|crm_mon -1|corosync-cfgtool -s|drbdadm status"
   r"|keepalived --config-test"
   r"|ceph (?:status|-s|health(?: detail)?|df|osd (?:tree|df|stat)|mon stat|versions)"
   r"|gluster (?:volume (?:info|status)(?: \w+)?|peer status|pool list))",
   "pcs status", "ceph health detail", "gluster peer status", timeout=60)
_d("apps", "any", "service mesh & coordination",
   r"(?:consul members|nomad (?:node status|server members|status)|vault status"
   r"|etcdctl (?:endpoint (?:health|status)|member list)(?: --cluster)?(?: -w table)?)",
   "consul members", "vault status", "etcdctl endpoint health")

# ---------------- tool versions
_d("versions", "any", "tool version",
   r"(?:python3?|python3\.\d{1,2}|pip3?|node|npm|yarn|pnpm|java|javac|go|rustc|cargo|ruby|gem|"
   r"php|perl|gcc|g\+\+|clang|make|cmake|git|docker|podman|helm|terraform|ansible|vagrant|"
   r"nginx|httpd|apache2|mysql|mysqld|psql|postgres|redis-server|redis-cli|mongod|mongosh|"
   r"sqlite3|openssl|curl|wget|rsync|tar|bash|zsh|pwsh|systemctl|journalctl|dotnet|az|aws|"
   r"gcloud|tmux|screen|jq|brew|snap|flatpak|dpkg|rpm|dnf|yum|apt|apt-get|zypper|pacman|"
   r"certbot|ufw|nft|iptables|chronyd|smartctl|nvme|virsh|restic|borg|rclone|ollama|wrench)"
   r" --version", "python3 --version", "nginx --version", "git --version")
_d("versions", "any", "tool version",
   r"(?:(?:node|npm|php|perl|nginx|httpd|apache2|docker|git|make|screen|redis-server|ruby|gem|"
   r"pip3?|yarn|pnpm) -v|(?:python3?|ssh|psql|postgres|tmux|curl|wget|nginx|httpd|pip3?) -V"
   r"|(?:go|openssl|terraform|helm|podman) version|openssl version -a|java -version"
   r"|dotnet --(?:info|list-sdks|list-runtimes)|xcode-select -p)",
   "node -v", "openssl version", "java -version", "go version")


# ====================================================================== FIXES
# Routine fixes run after a yes at `repair`, unattended at `autonomous`.
# ask=True fixes need a yes every time, at every tier.

# ---------------- services
# Stopping something is never routine: every "stop" spelling asks, at every tier.
_SYSTEMCTL_VERBS = "restart|start|reload|try-restart|reload-or-restart|try-reload-or-restart"
_SVC = r"(?!all$)(?!\d+$)[A-Za-z0-9][\w.\-]*"      # pm2 / supervisor: a name, never "all" or an id
_f("services", "linux", "service lifecycle",
   rf"systemctl (--user )?({_SYSTEMCTL_VERBS}) {_UNIT}",
   "systemctl restart nginx", "systemctl reload nginx", "systemctl --user restart app.service")
_f("services", "linux", "stop a service", rf"systemctl (--user )?stop {_UNIT}",
   "systemctl stop nginx", ask=True)
_f("services", "linux", "clear failed state", rf"systemctl (--user )?reset-failed( {_UNIT})?",
   "systemctl reset-failed nginx")
_f("services", "linux", "reload unit files", r"systemctl (--user )?daemon-reload",
   "systemctl daemon-reload")
_f("services", "linux", "service start at boot",
   rf"systemctl (--user )?(enable|disable|unmask)( --now)? {_UNIT}",
   "systemctl enable --now nginx", "systemctl disable cups", ask=True)
_f("services", "linux", "service lifecycle (sysv)",
   rf"service {_UNIT} (start|restart|reload|force-reload)", "service nginx restart")
_f("services", "linux", "stop a service (sysv)", rf"service {_UNIT} stop", "service nginx stop",
   ask=True)
_f("services", "macos", "service lifecycle (launchd)",
   r"launchctl (start|kickstart) [\w][\w./\-]*", "launchctl kickstart gui/501/com.example.foo")
_f("services", "macos", "stop or force-restart a service (launchd)",
   r"launchctl (stop|kickstart -k) [\w][\w./\-]*",
   "launchctl kickstart -k gui/501/com.example.foo", "launchctl stop com.example.foo", ask=True)
_f("services", "macos", "service start at boot (launchd)",
   r"launchctl (enable|disable) (?:system|gui/\d+|user/\d+)/[\w][\w.\-]*",
   "launchctl enable system/com.example.foo", ask=True)
_f("services", "unix", "service lifecycle (homebrew)",
   r"brew services (start|restart) [A-Za-z0-9][\w.\-@]*",
   "brew services restart postgresql@16")
_f("services", "unix", "stop a service (homebrew)",
   r"brew services stop [A-Za-z0-9][\w.\-@]*", "brew services stop postgresql@16", ask=True)
_f("services", "windows", "service lifecycle (windows)",
   rf"(?:sc start [\w][\w.\-]*|net start [\w][\w.\-]*"
   rf"|{_PS} (Restart|Start)-Service -Name [\w][\w.\-]*(?: -Force)?)",
   "net start Spooler", "sc start Spooler",
   "powershell -NoProfile -Command Restart-Service -Name Spooler -Force")
_f("services", "windows", "stop a service (windows)",
   rf"(?:sc stop [\w][\w.\-]*|net stop [\w][\w.\-]*"
   rf"|{_PS} Stop-Service -Name [\w][\w.\-]*(?: -Force)?)",
   "sc stop Spooler", "net stop Spooler", ask=True)
_f("services", "windows", "service start type (windows)",
   r"sc config [\w][\w.\-]* start= (?:auto|demand|disabled|delayed-auto)",
   "sc config Spooler start= auto", ask=True)
_f("services", "windows", "scheduled task control (windows)",
   rf"schtasks /(?:Run|End) /TN {_QNAME}|schtasks /Change /TN {_QNAME} /(?:ENABLE|DISABLE)",
   "schtasks /Run /TN NightlyBackup", ask=True)
_f("services", "any", "service lifecycle (supervisor / pm2)",
   rf"(?:supervisorctl (restart|start) {_SVC}|pm2 (restart|reload) {_SVC})",
   "supervisorctl restart worker", "pm2 reload api")
_f("services", "any", "stop a service (supervisor / pm2)",
   rf"(?:supervisorctl|pm2) stop {_SVC}", "supervisorctl stop worker", ask=True)
_f("services", "any", "reload supervisor / pm2 definitions",
   r"(?:supervisorctl (?:reread|update)|pm2 resurrect)", "supervisorctl update", ask=True)

# ---------------- cleanup (free space without deleting anything you made)
_f("cleanup", "linux", "journal vacuum (keeps at least 500 MB)",
   r"journalctl --vacuum-size=(?:(?:[5-9]\d{2}|[1-9]\d{3,6})M|[1-9]\d{0,3}G)",
   "journalctl --vacuum-size=500M")
_f("cleanup", "linux", "journal vacuum (keep at least a week)",
   r"journalctl --vacuum-time=(?:(?:[7-9]|[1-9]\d{1,3})d|[1-9]\d{0,2}(?:weeks?|months?))",
   "journalctl --vacuum-time=14d", "journalctl --vacuum-time=2weeks")
_f("cleanup", "linux", "force a log rotation (repeated, this ages logs out)",
   r"(?:journalctl --rotate|logrotate -f /etc/logrotate\.(?:conf|d/(?!-)[\w.\-]+))",
   "journalctl --rotate", "logrotate -f /etc/logrotate.d/nginx", ask=True)
_f("cleanup", "linux", "package cache clean",
   r"(?:(?:apt-get|apt) (?:clean|autoclean)|(?:dnf|yum) clean (?:all|packages|metadata|"
   r"expire-cache)|zypper clean(?: -a)?|paccache -r(?:k ?\d)?)", "apt-get clean", "dnf clean all")
_f("cleanup", "linux", "remove packages nothing depends on",
   r"(?:(?:apt-get|apt) (?:-y autoremove|autoremove -y)|(?:dnf|yum) (?:-y autoremove|"
   r"autoremove -y)|flatpak uninstall --unused -y|pacman -Sc --noconfirm)",
   "apt-get -y autoremove", "dnf -y autoremove", ask=True, timeout=900)
_f("cleanup", "linux", "expired temp files", r"systemd-tmpfiles --clean",
   "systemd-tmpfiles --clean")
_f("cleanup", "unix", "homebrew cleanup", r"brew cleanup(?: -s)?(?: --prune=(?:all|\d{1,3}))?",
   "brew cleanup", timeout=300)
_f("cleanup", "any", "developer caches",
   r"(?:pip3? cache purge|npm cache clean --force|yarn cache clean|go clean -cache"
   r"|conda clean (?:-a|--all) -y)", "pip cache purge", "npm cache clean --force", timeout=300)
_f("cleanup", "any", "container build cache & dangling images",
   rf"{_CT} (?:image|builder|network) prune -f", "docker image prune -f",
   "docker builder prune -f", timeout=600)
_f("cleanup", "any", "container prune (deletes stopped containers / unused images or volumes)",
   rf"{_CT} (?:container prune -f|volume prune -f|image prune -a -f|image prune -af"
   r"|system prune -f|system prune -a -f|system prune -af)", "docker system prune -f",
   "docker container prune -f", ask=True, timeout=900)
_f("cleanup", "macos", "memory & periodic maintenance (macos)",
   r"(?:purge|periodic (?:daily|weekly|monthly)(?: (?:daily|weekly|monthly)){0,2}|qlmanage -r"
   r"(?: cache)?)", "periodic daily weekly monthly", "purge", timeout=600)
_f("cleanup", "macos", "local snapshots & search index (macos)",
   r"(?:tmutil thinlocalsnapshots / \d{9,13} [1-4]|tmutil deletelocalsnapshots \d[\d\-]+"
   r"|mdutil -E /[\w/]*)", "tmutil thinlocalsnapshots / 20000000000 4", "mdutil -E /", ask=True,
   timeout=300)
_f("cleanup", "windows", "component store cleanup (windows)",
   r"dism /Online /Cleanup-Image /StartComponentCleanup(?: /ResetBase)?",
   "dism /Online /Cleanup-Image /StartComponentCleanup", ask=True, timeout=3600)
_f("cleanup", "windows", "empty the recycle bin (windows)",
   rf"{_PS} Clear-RecycleBin -Force(?: -DriveLetter [a-z])?",
   "powershell -NoProfile -Command Clear-RecycleBin -Force", ask=True, timeout=300)

# ---------------- processes
_f("processes", "unix", "lower a process's priority",
   rf"(?:renice (?:-n )?(?:[0-9]|1[0-9]) -p {_PID}|ionice -c ?3 -p {_PID}"
   rf"|ionice -c ?2 -n [4-7] -p {_PID})", "renice -n 10 -p 4242", "ionice -c 3 -p 4242")
_f("processes", "unix", "signal a process",
   rf"kill(?: -(?:TERM|HUP|INT|USR1|USR2|QUIT|15|1|2|3))? {_PID}", "kill 4242",
   "kill -HUP 4242", ask=True)
_f("processes", "unix", "force-kill or freeze a process",
   rf"kill -(?:9|KILL|STOP|CONT) {_PID}", "kill -9 4242", ask=True)
_f("processes", "windows", "end a process (windows)",
   rf"(?:taskkill /PID (?!4(?: |$))[1-9]\d{{0,6}}(?: /T)?(?: /F)?"
   rf"|{_PS} Stop-Process -Id (?!4(?: |$))[1-9]\d{{0,6}}(?: -Force)?)",
   "taskkill /PID 4242 /F", "powershell -NoProfile -Command Stop-Process -Id 4242 -Force",
   ask=True)

# ---------------- performance
_f("performance", "linux", "drop the page cache", r"sysctl -w vm\.drop_caches=[123]",
   "sysctl -w vm.drop_caches=3")
_f("performance", "linux", "re-enable swap", r"swapon -a", "swapon -a")
_f("performance", "linux", "kernel tunable (runtime only, closed list)",
   r"sysctl -w (?:vm\.swappiness=\d{1,3}|vm\.max_map_count=\d{4,10}|vm\.overcommit_memory=[012]"
   r"|fs\.inotify\.max_user_watches=\d{4,9}|fs\.inotify\.max_user_instances=\d{2,6}"
   r"|fs\.file-max=\d{4,10}|net\.core\.somaxconn=\d{2,6})",
   "sysctl -w vm.swappiness=10", "sysctl -w fs.inotify.max_user_watches=524288", ask=True)
_f("performance", "linux", "apply sysctl config / swap off / cpu governor",
   r"(?:sysctl --system|sysctl -p(?: /etc/sysctl(?:\.conf|\.d/[\w.\-]+\.conf))?|swapoff -a"
   r"|cpupower frequency-set -g (?:performance|powersave|ondemand|schedutil|conservative)"
   r"|tuned-adm profile [A-Za-z][\w\-]*)", "sysctl --system", "tuned-adm profile throughput-performance",
   ask=True)

# ---------------- packages & updates
_f("packages", "linux", "refresh package metadata",
   r"(?:(?:apt-get|apt) update|(?:dnf|yum) makecache|zypper(?: -n| --non-interactive)? "
   r"(?:refresh|ref)|apk update|fwupdmgr refresh)", "apt-get update", "dnf makecache",
   timeout=300)
_f("packages", "linux", "install pending updates (apt)",
   rf"(?:(?:apt-get|apt) (?:-y|--yes) (?:upgrade|dist-upgrade|full-upgrade)"
   rf"|(?:apt-get|apt) (?:upgrade|dist-upgrade|full-upgrade) -y"
   rf"|(?:apt-get|apt) (?:-y )?install --only-upgrade(?: -y)? {_PKGS}|unattended-upgrade(?: -v)?)",
   "apt-get -y upgrade", "apt-get install --only-upgrade -y openssl", ask=True, timeout=3600)
_f("packages", "linux", "install pending updates (dnf / yum / zypper / pacman / apk)",
   rf"(?:(?:dnf|yum) -y (?:upgrade|update)(?: --security)?(?: {_PKGS})?"
   rf"|(?:dnf|yum) (?:upgrade|update) -y(?: --security)?(?: {_PKGS})?"
   rf"|zypper (?:-n|--non-interactive) (?:update|up|patch)(?: {_PKGS})?"
   r"|pacman -Syu --noconfirm|apk upgrade)", "dnf -y upgrade --security", "zypper -n patch",
   ask=True, timeout=3600)
_f("packages", "linux", "install a package",
   rf"(?:(?:apt-get|apt) (?:-y install|install -y) {_PKGS}|(?:dnf|yum) (?:-y install|install -y) "
   rf"{_PKGS}|zypper (?:-n|--non-interactive) install {_PKGS}|apk add {_PKGS})",
   "apt-get install -y htop", "dnf -y install sysstat", ask=True, timeout=1800)
_f("packages", "linux", "repair the package database",
   r"(?:dpkg --configure -a|(?:apt-get|apt) (?:-y )?(?:-f|--fix-broken) install(?: -y)?"
   r"|rpm --rebuilddb)", "dpkg --configure -a", "apt-get -f install -y", ask=True, timeout=1800)
_f("packages", "linux", "restart services left on old libraries", r"needrestart -r a",
   "needrestart -r a", ask=True, timeout=600)
_f("packages", "linux", "snap / flatpak update",
   rf"(?:snap refresh(?: {_PKG})?|flatpak update -y(?: (?!-)[\w.\-]+)?)", "snap refresh",
   ask=True, timeout=1800)
_f("packages", "unix", "refresh homebrew", r"brew update", "brew update", timeout=600)
_f("packages", "unix", "homebrew upgrade / install",
   rf"brew (?:upgrade(?: --cask| --formula)?(?: {_BREWS})?|(?:install|reinstall)(?: --cask)? "
   rf"{_BREWS})", "brew upgrade", "brew upgrade openssl@3", "brew install htop", ask=True,
   timeout=3600)
_f("packages", "macos", "install macos updates (never restarts)",
   r"softwareupdate (?:-i|--install) (?:-a|--all|-r|--recommended|'(?!-)[\w .,\-()]+'|(?!-)[\w.\-]+)"
   r"(?: --agree-to-license)?", "softwareupdate -i -r", "softwareupdate --install --all",
   ask=True, timeout=3600)
_f("packages", "windows", "start an update scan (windows)",
   r"(?:UsoClient StartScan|wuauclt /detectnow)", "UsoClient StartScan")
_f("packages", "windows", "install updates (windows)",
   r"(?:UsoClient (?:StartDownload|StartInstall|ScanInstallWait)"
   r"|winget (?:upgrade|install) (?:--id (?!-)[\w.\-+]+(?: -e| --exact)?|--all)"
   r"(?: (?:--silent|-h|--accept-package-agreements|--accept-source-agreements|"
   r"--disable-interactivity|--include-unknown))*"
   r"|choco (?:upgrade|install) (?!-)[\w.\-]+ -y)",
   "winget upgrade --id Git.Git -e --silent --accept-package-agreements",
   "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements",
   ask=True, timeout=3600)

# ---------------- containers & VMs
_f("containers", "any", "container lifecycle",
   rf"{_CT} (?:restart|start|unpause) {_NAME}(?: {_NAME}){{0,9}}",
   "docker restart web", "podman start db")
_f("containers", "any", "stop or pause containers",
   rf"{_CT} (?:stop|pause) {_NAME}(?: {_NAME}){{0,9}}", "docker stop web", ask=True)
_f("containers", "any", "compose service lifecycle",
   rf"{_CT} compose(?: (?:-f {_YAML}|-p {_NAME}))* (?:restart|start|unpause)"
   rf"(?: {_NAME}){{0,9}}", "docker compose -f /srv/app/compose.yaml restart web")
_f("containers", "any", "stop or pause compose services",
   rf"{_CT} compose(?: (?:-f {_YAML}|-p {_NAME}))* (?:stop|pause)(?: {_NAME}){{0,9}}",
   "docker compose -f /srv/app/compose.yaml stop web", ask=True)
_f("containers", "any", "pull / recreate / force-kill containers",
   rf"(?:{_CT} kill {_NAME}|{_CT} pull (?!-)[\w][\w./:\-@]*"
   rf"|{_CT} compose(?: (?:-f {_YAML}|-p {_NAME}))* (?:pull|up -d)(?: {_NAME}){{0,9}}"
   rf"|{_CT} update --restart=(?:no|always|unless-stopped|on-failure(?::\d{{1,2}})?) {_NAME}"
   rf"|docker service update --force {_NAME}|docker service scale {_NAME}=\d{{1,3}})",
   "docker compose -f /srv/app/compose.yaml up -d", "docker pull nginx:1.27",
   "docker update --restart=unless-stopped web", ask=True, timeout=1800)
_f("containers", "linux", "start a virtual machine or system container",
   rf"(?:virsh (?:start|resume|autostart) {_NAME}|qm (?:start|resume) \d{{1,9}}"
   rf"|pct start \d{{1,9}}|lxc (?:start|restart) {_NAME})", "virsh start build-vm",
   "qm start 104", ask=True, timeout=300)

# ---------------- kubernetes (every one asks)
_f("kubernetes", "any", "restart a workload",
   rf"{_KP} rollout restart {_KWORK}[/ ]{_NAME}(?: {_NS})?",
   "kubectl rollout restart deployment/web -n prod", ask=True)
_f("kubernetes", "any", "undo / pause / resume a rollout",
   rf"{_KP} rollout (?:undo|pause|resume) {_KWORK}[/ ]{_NAME}(?: {_NS})?",
   "kubectl rollout undo deployment/web -n prod", ask=True)
_f("kubernetes", "any", "delete one pod (its controller replaces it)",
   rf"{_KP} delete pod {_NAME}(?: {_NS})?(?: --grace-period=\d{{1,4}})?",
   "kubectl delete pod web-7d4f-abcde -n prod", ask=True)
_f("kubernetes", "any", "scale a workload",
   rf"{_KP} scale {_KWORK}[/ ]{_NAME} --replicas=\d{{1,3}}(?: {_NS})?",
   "kubectl scale deployment/web --replicas=3 -n prod", ask=True)
_f("kubernetes", "any", "cordon / drain a node",
   rf"{_K} (?:cordon|uncordon) {_NAME}|{_K} drain {_NAME} --ignore-daemonsets"
   r"(?: --delete-emptydir-data)?(?: --timeout=\d{1,4}s)?", "kubectl cordon worker-1",
   "kubectl drain worker-1 --ignore-daemonsets --timeout=300s", ask=True, timeout=900)
_f("kubernetes", "any", "roll a helm release back",
   rf"helm rollback {_NAME} \d{{1,5}}(?: {_NS})?", "helm rollback web 12 -n prod", ask=True,
   timeout=600)

# ---------------- network
_f("network", "linux", "flush the dns cache",
   r"(?:resolvectl flush-caches|systemd-resolve --flush-caches|nscd -i hosts"
   r"|rndc (?:flush|reload|reconfig)|unbound-control reload)", "resolvectl flush-caches",
   "rndc flush")
_f("network", "macos", "flush the dns cache (macos)",
   r"(?:dscacheutil -flushcache|killall -HUP mDNSResponder)", "dscacheutil -flushcache",
   "killall -HUP mDNSResponder")
_f("network", "windows", "flush the dns cache (windows)",
   r"(?:ipconfig /flushdns|ipconfig /registerdns|nbtstat -RR?)", "ipconfig /flushdns")
_f("network", "windows", "flush the dns cache (powershell)", rf"{_PS} Clear-DnsClientCache",
   "powershell -NoProfile -Command Clear-DnsClientCache")
_f("network", "linux", "reload network definitions",
   r"(?:nmcli (?:connection|con|c) reload|networkctl reload)", "nmcli connection reload")
_f("network", "linux", "bring a connection or interface up",
   rf"(?:nmcli (?:connection|con|c) up (?:id )?{_QNAME}"
   rf"|nmcli (?:device|dev|d) (?:connect|reapply) {_IFACE}|nmcli networking on"
   rf"|nmcli radio wifi on|ip link set(?: dev)? {_IFACE} up|ifup {_IFACE}"
   rf"|networkctl (?:reconfigure|renew) {_IFACE}|dhclient {_IFACE}|netplan apply)",
   "nmcli connection up eth0", "ip link set eth0 up", "netplan apply", ask=True)
_f("network", "macos", "wi-fi power / dhcp renew (macos)",
   rf"(?:networksetup -setairportpower {_IFACE} on|ipconfig set {_IFACE} DHCP)",
   "networksetup -setairportpower en0 on", "ipconfig set en0 DHCP", ask=True)
_f("network", "windows", "network stack repair (windows)",
   rf"(?:ipconfig /renew|netsh winsock reset"
   rf"|netsh interface set interface {_QNAME} admin=enabled?"
   rf"|{_PS} Restart-NetAdapter -Name (?!-)[\w.\-]+)", "ipconfig /renew", "netsh winsock reset",
   ask=True, timeout=120)

# ---------------- time
_f("time", "linux", "step / resync the clock",
   r"(?:chronyc(?: -a)? (?:makestep|burst \d/\d|online|refresh|reload sources)"
   r"|timedatectl set-ntp (?:true|1|yes)|hwclock (?:--systohc|-w))", "chronyc makestep",
   "timedatectl set-ntp true")
_f("time", "windows", "resync the clock (windows)",
   r"(?:w32tm /resync(?: (?:/force|/rediscover|/nowait))*|w32tm /config /update)",
   "w32tm /resync /force")
_f("time", "linux", "set the clock from a named server / change timezone",
   rf"(?:ntpdate(?: -u)? {_HOST}|timedatectl set-timezone [A-Za-z_]+"
   r"(?:/[A-Za-z_\-+0-9]+){0,2})", "timedatectl set-timezone America/Los_Angeles",
   "ntpdate -u pool.ntp.org", ask=True)
_f("time", "macos", "set the clock from a named server (macos)",
   rf"(?:sntp -sS {_HOST}|systemsetup -setusingnetworktime on)", "sntp -sS time.apple.com",
   ask=True)

# ---------------- storage
_f("storage", "unix", "fs sync", r"sync", "sync")
_f("storage", "linux", "trim ssd free space", rf"fstrim (?:-av|-a|-v {_PATH}|{_PATH})",
   "fstrim -av", timeout=600)
_f("storage", "unix", "start / stop a smart self-test",
   rf"smartctl (?:-t (?:short|long|conveyance)|-X) {_DEV}", "smartctl -t short /dev/sda")
_f("storage", "linux", "re-read device & nfs tables",
   r"(?:partprobe|udevadm settle|exportfs -ra)", "exportfs -ra", "udevadm settle")
_f("storage", "linux", "mount what fstab lists",
   rf"(?:mount -a|mount {_PATH}|mount -o remount,rw {_PATH})", "mount -a", "mount /mnt/data",
   ask=True)
_f("storage", "linux", "grow a volume into free space",
   rf"(?:growpart {_DEV} \d{{1,3}}|lvextend(?: -r)? (?:-l \+100%FREE|-L \+\d{{1,6}}[MGT]) {_DEV}"
   rf"|resize2fs {_DEV}|xfs_growfs {_PATH})", "growpart /dev/sda 1",
   "lvextend -r -l +100%FREE /dev/vg0/root", "resize2fs /dev/sda1", "xfs_growfs /", ask=True,
   timeout=900)
_f("storage", "unix", "scrub / clear a zfs pool",
   rf"(?:zpool (?:scrub|clear) {_NAME}|zpool online {_NAME} (?!-)[\w/.\-]+)", "zpool scrub tank",
   ask=True, timeout=300)
_f("storage", "linux", "scrub btrfs / reassemble or re-add software raid",
   rf"(?:btrfs scrub start {_PATH}|mdadm --assemble --scan"
   rf"|mdadm(?: --manage)? /dev/md[\w/]+ --re-add {_DEV})", "btrfs scrub start /",
   "mdadm /dev/md0 --re-add /dev/sdb1", ask=True, timeout=300)
_f("storage", "macos", "time machine backup (macos)",
   r"tmutil (?:startbackup(?: --auto)?|stopbackup|enable)", "tmutil startbackup")
_f("storage", "macos", "mount / verify / repair a volume (macos)",
   r"diskutil (?:mount|verifyVolume|verifyDisk|repairVolume) (?!-)[\w/]+",
   "diskutil verifyVolume /", ask=True, timeout=3600)
_f("storage", "windows", "volume scan (windows, online, read-mostly)",
   rf"(?:dism /Online /Cleanup-Image /ScanHealth|defrag [a-z]: /L"
   rf"|{_PS} Repair-Volume -DriveLetter [a-z] -Scan)",
   "dism /Online /Cleanup-Image /ScanHealth", timeout=3600)
_f("storage", "windows", "repair system files / volumes (windows)",
   rf"(?:sfc /scannow|dism /Online /Cleanup-Image /RestoreHealth|chkdsk [a-z]: /scan"
   rf"|defrag [a-z]: /O|{_PS} Optimize-Volume -DriveLetter [a-z](?: -(?:ReTrim|Defrag|Analyze))?)",
   "sfc /scannow", "dism /Online /Cleanup-Image /RestoreHealth", ask=True, timeout=3600)

# ---------------- security & firewall
_f("security", "linux", "reload firewall / ban list / audit rules",
   r"(?:ufw reload|firewall-cmd --reload|fail2ban-client reload|augenrules --load"
   r"|auditctl -R /etc/audit/audit\.rules)", "ufw reload", "firewall-cmd --reload")
_f("security", "unix", "refresh malware signatures / trust store",
   r"(?:freshclam|update-ca-certificates(?: --fresh)?|update-ca-trust(?: extract)?"
   r"|softwareupdate --background)", "freshclam", "update-ca-certificates", timeout=600)
_f("security", "unix", "renew certificates that are due",
   r"certbot renew(?: (?:--dry-run|--quiet|-q|--no-random-sleep-on-renew))*",
   "certbot renew --dry-run", "certbot renew --quiet", timeout=900)
_f("security", "linux", "block or unblock an address",
   rf"(?:fail2ban-client set {_NAME} (?:banip|unbanip) {_IP}|fail2ban-client unban {_IP}"
   rf"|ufw (?:deny|reject) from {_IP}|ufw delete (?:deny|reject) from {_IP})",
   "fail2ban-client set sshd unbanip 203.0.113.9", "ufw deny from 203.0.113.9", ask=True)
_f("security", "linux", "enforce selinux / apparmor, relabel, load firewall file",
   rf"(?:setenforce (?:1|Enforcing)|restorecon(?: -[RvF]+)? {_PATH}|aa-enforce (?!-)[\w./\-]+"
   r"|nft -f /etc/nftables\.conf|certbot renew --force-renewal)",
   "restorecon -Rv /var/www", "setenforce 1", ask=True, timeout=600)
_f("security", "linux", "unlock a locked-out account",
   rf"(?:faillock --user {_USER} --reset|pam_tally2 --user {_USER} --reset"
   rf"|usermod -U {_NOT_BUILTIN}{_USER}"
   r"|loginctl terminate-session \w+)", "faillock --user deploy --reset", ask=True)
_f("security", "macos", "turn a protection on (macos)",
   r"(?:/usr/libexec/ApplicationFirewall/socketfilterfw --set(?:globalstate|stealthmode) on"
   r"|spctl --(?:master|global)-enable|pfctl -e|pfctl -f /etc/pf\.conf)",
   "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", ask=True)
_f("security", "windows", "refresh policy, signatures, tickets (windows)",
   rf"(?:gpupdate(?: /force)?(?: /target:(?:computer|user))?|klist purge"
   rf"|{_PS} Update-MpSignature|{_PS} Start-MpScan -ScanType QuickScan)",
   "gpupdate /force", "powershell -NoProfile -Command Update-MpSignature", timeout=1800)
_f("security", "windows", "turn a protection on / unlock an account (windows)",
   rf"(?:netsh advfirewall set allprofiles state on|manage-bde -(?:protectors -enable|resume) "
   rf"[a-z]:|net user {_NOT_BUILTIN}{_USER} /active:yes"
   rf"|{_PS} Enable-LocalUser -Name {_NOT_BUILTIN}{_USER}"
   rf"|{_PS} Unlock-ADAccount -Identity {_USER}|logoff \d{{1,5}})",
   "netsh advfirewall set allprofiles state on",
   "powershell -NoProfile -Command Unlock-ADAccount -Identity jdoe", ask=True)

# ---------------- web, mail, database & cluster software
_f("apps", "any", "graceful reload",
   r"(?:nginx -s (?:reload|reopen)|(?:apachectl|apache2ctl) (?:graceful|restart)"
   r"|postfix (?:reload|flush)|postqueue -f|exim -qff|squid -k (?:reconfigure|rotate)"
   r"|rabbitmqctl start_app|pg_ctlcluster \d{1,2} (?!-)[\w\-]+ reload)", "nginx -s reload",
   "apachectl graceful", "postqueue -f")
_f("apps", "linux", "rebuild system caches",
   r"(?:ldconfig|depmod -a|updatedb|newaliases)", "ldconfig", timeout=300)
_f("apps", "linux", "requeue mail / restart a database cluster / bring a tunnel up",
   r"(?:postsuper -r ALL|pg_ctlcluster \d{1,2} (?!-)[\w\-]+ (?:restart|start)"
   rf"|wg-quick up {_IFACE}|tailscale up)", "pg_ctlcluster 16 main restart", ask=True)
_f("apps", "linux", "regenerate boot configuration",
   r"(?:update-grub|grub2-mkconfig -o /boot/grub2/grub\.cfg|update-initramfs -u(?: -k all)?"
   r"|dracut (?:-f|--force)(?: --regenerate-all)?)", "update-initramfs -u", "update-grub",
   ask=True, timeout=900)
_f("apps", "unix", "printing",
   rf"(?:cupsenable {_NAME}|cupsaccept {_NAME})", "cupsenable Office_Printer")
_f("apps", "unix", "cancel every queued print job", rf"cancel -a(?: {_NAME})?", "cancel -a",
   ask=True)

# ---------------- endpoint & desktop
_f("desktop", "macos", "restart a stuck macos interface process",
   r"killall (?:Dock|Finder|SystemUIServer|ControlCenter|NotificationCenter|cfprefsd|"
   r"coreaudiod|bluetoothd)", "killall Dock", "killall cfprefsd", ask=True)
_f("desktop", "macos", "mdm check-in / privacy reset (macos)",
   r"(?:jamf (?:recon|policy)|profiles renew -type enrollment|tccutil reset \w+ (?!-)[\w.\-]+)",
   "jamf recon", "tccutil reset Camera com.example.app", ask=True, timeout=900)


# ==================================================================== queries

def entries(kind: str | None = None, plat: str = "all", pack: str | None = None) -> list[Cmd]:
    return [c for c in CATALOG
            if (kind is None or c.kind == kind) and c.applies(plat)
            and (pack is None or c.pack == pack)]


def match(command: str, kind: str, disabled: frozenset | set = frozenset()) -> Cmd | None:
    """The catalog entry a command falls under, or None.

    For fixes, an ``ask`` entry wins over a routine one: when a command could be
    read either way it gets the stricter treatment.
    """
    cmd = command.strip()
    if not cmd or "\n" in cmd or "\r" in cmd or "\x00" in cmd:
        return None
    hit = None
    for c in CATALOG:
        if c.kind != kind or c.pack in disabled or not c.rx.fullmatch(cmd):
            continue
        if c.ask:
            return c
        hit = hit or c
    return hit


def binary(example: str) -> str:
    """The tool an example is about: the first word, or the PowerShell cmdlet."""
    parts = example.split()
    if "-Command" in parts and parts.index("-Command") + 1 < len(parts):
        return parts[parts.index("-Command") + 1]
    if parts[0] in ("k3s", "microk8s") and len(parts) > 1:
        return parts[1]
    return parts[0].rsplit("/", 1)[-1]


def hints(command: str, kind: str, limit: int = 6) -> list[str]:
    """Allowed forms of the tool the model just reached for — shown on a denial."""
    cmd = command.strip()
    if cmd.startswith("sudo -n "):
        cmd = cmd[len("sudo -n "):]
    if not cmd:
        return []
    want = binary(cmd).lower()
    out: list[str] = []
    for c in CATALOG:
        if c.kind != kind:
            continue
        for ex in c.examples:
            if binary(ex).lower() == want and ex not in out:
                out.append(ex)
    return out[:limit]


def summary(plat: str = "all", disabled: frozenset | set = frozenset()) -> list[dict]:
    """Per-pack counts and the tools in each, for the CLI and the dashboard."""
    out = []
    for key, title in PACKS.items():
        row = {"pack": key, "title": title, "enabled": key not in disabled}
        for kind in ("diag", "fix"):
            es = entries(kind, plat, key)
            tools: list[str] = []
            for c in es:
                for ex in c.examples:
                    b = binary(ex)
                    if b not in tools:
                        tools.append(b)
            row[kind] = len(es)
            row[f"{kind}_tools"] = tools
        row["asks"] = sum(1 for c in entries("fix", plat, key) if c.ask)
        if row["diag"] or row["fix"]:
            out.append(row)
    return out


def counts(plat: str = "all") -> dict:
    return {"diag": len(entries("diag", plat)), "fix": len(entries("fix", plat)),
            "packs": len(summary(plat))}


_OS_LABEL = {"linux": "Linux", "macos": "macOS", "windows": "Windows", "unix": "Linux, macOS",
             "any": "all"}


def as_dict(c: Cmd) -> dict:
    return {"kind": c.kind, "pack": c.pack, "os": c.os, "label": c.label,
            "examples": list(c.examples), "asks_every_time": bool(c.ask), "timeout_s": c.timeout}


def markdown() -> str:
    """docs/commands.md — generated, so the docs can never drift from the code."""
    n = counts()
    lines = [
        "# Commands the agent may run",
        "",
        "<!-- generated by `wrench commands --markdown` — do not edit by hand -->",
        "",
        f"wrench's agent can run **{n['diag']} kinds of read-only diagnostic** and "
        f"**{n['fix']} kinds of fix**, in {n['packs']} packs, across Linux, macOS and Windows. "
        "It cannot run anything else: every command is matched whole against this catalog, "
        "with no shell, no pipes and no chaining.",
        "",
        "- **Look** — read-only. Runs at every policy tier.",
        "- **Fix** — changes the machine. Needs `wrench policy repair` (asks each time) or "
        "`autonomous` (runs unattended).",
        "- **Fix · always asks** — needs a person to say yes every time, even at `autonomous`. "
        "Unattended, it is refused.",
        "",
        "Each row shows example commands; the allowed flags for each are spelled out in "
        "`wrench/commands.py`. Check any command with `wrench commands --check \"<command>\"`. "
        "Add your own exact commands with `[policy] allow_diag` / `allow_fix`, or switch a "
        "pack off with `[policy] disabled_packs` — see "
        "[configuration](configuration.md#policy).",
        "",
    ]
    for key, title in PACKS.items():
        es = entries(pack=key)
        if not es:
            continue
        lines += [f"## {title}", "", f"Pack name: `{key}`", "",
                  "| | What | Where | Examples |", "|---|---|---|---|"]
        for c in es:
            kind = "Look" if c.kind == "diag" else ("Fix · always asks" if c.ask else "Fix")
            ex = "<br>".join(f"`{e.replace('|', chr(92) + '|')}`" for e in c.examples)
            lines.append(f"| {kind} | {c.label} | {_OS_LABEL[c.os]} | {ex} |")
        lines.append("")
    return "\n".join(lines)
