"""Cross-platform tools + driftscan: run real on the host OS, mock the others."""


import pytest

from wrench import driftscan, platforms, sensors, tools
from wrench.store import Store


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


# ---------------- tools ----------------

def test_proc_top_is_psutil_native(store):
    out = tools.proc_top(store, "cpu", 5)
    lines = out.splitlines()
    assert lines[0].split() == ["PID", "CPU%", "MEM%", "USER", "NAME"]
    assert len(lines) <= 6


def test_net_listeners_psutil_fallback(store, monkeypatch):
    # force the non-Linux path even on Linux
    monkeypatch.setattr(platforms, "is_linux", lambda: False)
    out = tools.net_listeners(store)
    assert "proto" in out.splitlines()[0]


def test_disk_tree_python_fallback(store, tmp_path, monkeypatch):
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "f.bin").write_bytes(b"x" * 10000)
    (tmp_path / "small").mkdir()
    (tmp_path / "small" / "f.bin").write_bytes(b"x" * 10)
    monkeypatch.setattr(platforms, "has", lambda c: False)   # pretend du is missing
    out = tools.disk_tree(store, str(tmp_path), 1)
    assert "big" in out
    # biggest dir listed before smallest
    assert out.index("big") < out.index("small")


def test_read_logs_no_backend_degrades(store, monkeypatch):
    monkeypatch.setattr(platforms, "log_backend", lambda: None)
    out = tools.read_logs(store)
    assert "no system log reader" in out


def test_service_status_no_manager_degrades(store, monkeypatch):
    monkeypatch.setattr(platforms, "current_platform", lambda: "unknown")
    out = tools.service_status(store, "foo")
    assert "no service manager" in out


# ---------------- driftscan ----------------

def test_ports_psutil_collector_runs():
    ports = driftscan._ports_psutil()
    assert isinstance(ports, dict)
    for key in ports:
        proto, port = key.split("/")
        assert proto in ("tcp", "udp") and port.isdigit()


def test_collect_users_posix():
    if platforms.current_platform() not in ("linux", "macos"):
        pytest.skip("posix only")
    users = driftscan.collect_users()
    assert isinstance(users, dict) and len(users) >= 1
    assert any("shell=" in v for v in users.values())


def test_collect_packages_graceful_when_no_manager(monkeypatch):
    monkeypatch.setattr(platforms, "find_tool", lambda c: None)
    out = driftscan.collect_packages()
    if platforms.current_platform() == "windows":
        assert out["count"] == 0 and "digest" in out
    else:
        # a known manager that could not be run is "unknown" (skip the diff),
        # never "zero packages" (which would report everything as removed)
        assert out is None


def test_diff_engine_pure():
    old = {"tcp/22": "sshd"}
    new = {"tcp/22": "sshd", "tcp/8080": "python3"}
    changes = driftscan._diff_dicts("ports", old, new)
    assert changes == ["port opened: tcp/8080 (python3)"]
    changes = driftscan._diff_dicts("ports", new, old)
    assert changes == ["port closed: tcp/8080 (python3)"]


def test_scan_records_baseline_then_diffs(store, monkeypatch):
    fake = {"calls": 0}

    def collector():
        fake["calls"] += 1
        return {"tcp/1": "a"} if fake["calls"] == 1 else {"tcp/1": "a", "tcp/2": "b"}

    monkeypatch.setitem(driftscan.COLLECTORS, "ports", collector)
    assert driftscan.scan(store, kinds=("ports",)) == []          # baseline
    results = driftscan.scan(store, kinds=("ports",))             # diff
    assert results and results[0]["changes"] == ["port opened: tcp/2 (b)"]


# ---------------- sensors ----------------

def test_sample_os_core_fields(store):
    s = sensors.sample_os(store)
    for key in ("cpu_pct", "mem_pct", "disk_pct", "n_procs", "uptime_s", "disk_root_pct"):
        assert key in s
    assert s["n_procs"] > 0


def test_sample_os_survives_missing_loadavg(monkeypatch, store):
    import psutil

    def boom():
        raise OSError("no loadavg here")

    monkeypatch.setattr(psutil, "getloadavg", boom)
    s = sensors.sample_os(store)
    assert s["load_1m"] == 0.0
