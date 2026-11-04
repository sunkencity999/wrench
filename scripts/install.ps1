# wrench installer — Windows (PowerShell)
#   irm https://raw.githubusercontent.com/sunkencity999/wrench/main/scripts/install.ps1 | iex
$ErrorActionPreference = "Stop"
$repo = "git+https://github.com/sunkencity999/wrench"

function Say($msg) { Write-Host "[wrench] $msg" -ForegroundColor Cyan }

# 1. find python >= 3.10
$py = $null
foreach ($cand in @("python", "python3", "py")) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) {
        $ok = & $cand -c "import sys; print(1 if sys.version_info >= (3,10) else 0)" 2>$null
        if ($ok -eq "1") { $py = $cand; break }
    }
}
if (-not $py) {
    Say "Python 3.10+ not found. Install it from https://www.python.org/downloads/ (check 'Add to PATH'), then re-run."
    exit 1
}
Say ("using " + (& $py --version))

# 2. prefer pipx, fall back to pip --user
$pipx = Get-Command pipx -ErrorAction SilentlyContinue
if ($pipx) {
    Say "installing with pipx..."
    pipx install --force $repo
} else {
    Say "pipx not found - installing with pip --user (consider 'pip install pipx' for cleaner installs)"
    & $py -m pip install --user --upgrade $repo
}

# 3. verify
$wrench = Get-Command wrench -ErrorAction SilentlyContinue
if ($wrench) {
    Say ("installed: " + (wrench version))
    if ([Environment]::UserInteractive -and -not $env:CI) {
        $reply = Read-Host "[wrench] set up now? Pick a provider - Meta (default, hosted) or fully local via Ollama [Y/n]"
        if ($reply -notmatch '^[Nn]') { wrench init }
        else { Say "later, then: wrench init ; wrench doctor ; wrench patrol" }
    } else {
        Say "next: wrench init ; wrench doctor ; wrench patrol"
        Say "(wrench init shows an interactive provider menu - Meta hosted by default, or local + private via Ollama)"
    }
} else {
    Say "installed, but 'wrench' is not on PATH yet."
    Say "open a NEW terminal (PATH refresh) or add your Python Scripts dir to PATH, then run: wrench init"
}
