"""webintel: OSV + endoflife.date with mocked HTTP; cache TTL; offline degradation;
fixxer cve_upgrade detector; security_intel tool."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import pytest
import requests

from wrench import webintel
from wrench.store import Store


@dataclass
class FakeCfg:
    raw: dict = field(default_factory=dict)
    db_path: str = ""


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "t.db")
    yield s
    s.close()


class FakeResp:
    def __init__(self, payload, status=200):
        self._p = payload
        self.status_code = status

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")


# ---------------- cache ----------------

def test_cache_roundtrip_and_ttl(store):
    store.cache_put("k", {"a": 1})
    assert store.cache_get("k", 60) == {"a": 1}
    assert store.cache_get("k", -1) is None          # expired
    assert store.cache_get("missing", 60) is None
    store.cache_put("k", {"a": 2})                    # upsert
    assert store.cache_get("k", 60) == {"a": 2}


# ---------------- inventory ----------------

def test_pip_packages_parses_json(monkeypatch):
    monkeypatch.setattr(webintel, "_run",
                        lambda argv, timeout=15: (0, '[{"name":"requests","version":"2.19.0"}]'))
    pkgs = webintel.pip_packages()
    assert pkgs == [{"name": "requests", "version": "2.19.0",
                     "ecosystem": "PyPI", "source": "pip"}]


def test_pip_packages_handles_failure(monkeypatch):
    monkeypatch.setattr(webintel, "_run", lambda argv, timeout=15: (1, ""))
    assert webintel.pip_packages() == []


def test_npm_packages(monkeypatch):
    monkeypatch.setattr(webintel.shutil, "which", lambda b: "/usr/bin/npm")
    monkeypatch.setattr(webintel, "_run",
                        lambda argv, timeout=15: (0, '{"dependencies":{"left-pad":{"version":"1.3.0"}}}'))
    pkgs = webintel.npm_packages()
    assert pkgs == [{"name": "left-pad", "version": "1.3.0",
                     "ecosystem": "npm", "source": "npm"}]


def test_distro_packages_watchlist_and_source_names(monkeypatch):
    monkeypatch.setattr(webintel.shutil, "which", lambda b: "/usr/bin/dpkg-query")
    monkeypatch.setattr(webintel, "_os_release",
                        lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"})
    out = ("openssh-client\topenssh\t1:9.6p1\n".replace("\topenssh\t", "\t")  # noqa
           )
    # dpkg -f '${source:Package}\t${Version}': source name + version
    monkeypatch.setattr(webintel, "_run", lambda argv, timeout=15: (
        0, "openssh\t1:9.6p1-3\nopenssl\t3.0.13-0ubuntu3\nnot-watched\t1.0\n"
           "openssh\t1:9.6p1-3\n"))  # dupe collapses
    pkgs = webintel.distro_packages()
    names = [(p["name"], p["ecosystem"]) for p in pkgs]
    assert ("openssh", "Ubuntu") in names and ("openssl", "Ubuntu") in names
    assert all(p["name"] != "not-watched" for p in pkgs)
    assert len([p for p in pkgs if p["name"] == "openssh"]) == 1


def test_distro_packages_non_debian(monkeypatch):
    monkeypatch.setattr(webintel.shutil, "which", lambda b: "/usr/bin/dpkg-query")
    monkeypatch.setattr(webintel, "_os_release", lambda: {"ID": "arch"})
    assert webintel.distro_packages() == []


# ---------------- OSV ----------------

def test_osv_querybatch_alignment(monkeypatch):
    pkgs = [{"name": "a", "version": "1", "ecosystem": "PyPI", "source": "pip"},
            {"name": "b", "version": "2", "ecosystem": "PyPI", "source": "pip"}]

    def fake_post(url, json=None, timeout=None):
        assert len(json["queries"]) == 2
        return FakeResp({"results": [{"vulns": [{"id": "GHSA-x"}]}, {}]})

    monkeypatch.setattr(webintel.requests, "post", fake_post)
    assert webintel.osv_querybatch(pkgs) == [["GHSA-x"], []]


def test_osv_vuln_detail_caches(monkeypatch, store):
    calls = []

    def fake_get(url, timeout=None):
        calls.append(url)
        return FakeResp({"id": "GHSA-x", "aliases": ["CVE-2024-1", "GHSA-x"],
                         "summary": "bad", "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                         "affected": [{"package": {"name": "a"},
                                       "ranges": [{"events": [{"introduced": "0"},
                                                              {"fixed": "1.5"}]}]}]})

    monkeypatch.setattr(webintel.requests, "get", fake_get)
    d1 = webintel.osv_vuln_detail(store, "GHSA-x", 3600)
    d2 = webintel.osv_vuln_detail(store, "GHSA-x", 3600)   # cache hit
    assert len(calls) == 1
    assert d1 == d2
    assert d1["aliases"] == ["CVE-2024-1"]
    assert webintel._fixed_of(d1, "a") == "1.5"
    assert d1["severity"] == "7.5"   # _severity_of already applied to the raw detail


# ---------------- EOL ----------------

def test_eol_check_flags_past_date(monkeypatch, store):
    monkeypatch.setattr(webintel, "_local_versions",
                        lambda: {"os": ("ubuntu", "20.04"), "python": ("python", "3.12")})

    def fake_get(url, timeout=None):
        if "ubuntu" in url:
            return FakeResp([{"cycle": "20.04", "eol": "2025-05-31"}])
        return FakeResp([{"cycle": "3.12", "eol": "2028-10-31"}])

    monkeypatch.setattr(webintel.requests, "get", fake_get)
    statuses = {s.product: s for s in webintel.eol_check(store, 3600)}
    assert statuses["os"].is_eol is True
    assert statuses["python"].is_eol is False
    # cached now
    monkeypatch.setattr(webintel.requests, "get",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no http")))
    assert len(webintel.eol_check(store, 3600)) == 2


# ---------------- scan: online, cache, offline ----------------

def _wire_happy_path(monkeypatch):
    monkeypatch.setattr(webintel, "inventory", lambda cfg=None: [
        {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI", "source": "pip"},
        {"name": "openssh", "version": "1:9.6p1", "ecosystem": "Ubuntu", "source": "distro"}])
    monkeypatch.setattr(webintel, "osv_querybatch",
                        lambda pkgs: [["GHSA-r"], ["UBUNTU-CVE-1"]])
    monkeypatch.setattr(webintel, "osv_vuln_detail", lambda store, vid, ttl: {
        "id": vid, "aliases": [f"CVE-{vid}"], "summary": "s", "severity": "7.5",
        "affected": []})
    monkeypatch.setattr(webintel, "eol_check", lambda store, ttl: [
        webintel.EolStatus("os", "20.04", "2025-05-31", True, "os 20.04: REACHED EOL 2025-05-31")])


def test_scan_happy_path_and_cache(monkeypatch, store):
    _wire_happy_path(monkeypatch)
    cfg = FakeCfg()
    res = webintel.scan(cfg, store, force=True)
    assert res["online"] and res["packages_checked"] == 2
    assert len(res["vulns"]) == 2
    assert res["vulns"][0]["aliases"] == ["CVE-GHSA-r"]
    assert res["eol"][0]["is_eol"]
    # second call: served from cache, no scan functions touched
    monkeypatch.setattr(webintel, "inventory",
                        lambda cfg=None: (_ for _ in ()).throw(AssertionError("no rescan")))
    res2 = webintel.scan(cfg, store, force=False)
    assert res2["vulns"] == res["vulns"]


def test_scan_offline_serves_stale_cache(monkeypatch, store):
    _wire_happy_path(monkeypatch)
    cfg = FakeCfg()
    webintel.scan(cfg, store, force=True)
    # make the cache "old" so force-refresh happens, then cut the network
    store.db.execute("UPDATE webintel_cache SET ts=? WHERE key='webintel_scan'",
                     (time.time() - 999999,))
    store.db.commit()

    def boom(pkgs):
        raise requests.ConnectionError("no internet")

    monkeypatch.setattr(webintel, "osv_querybatch", boom)
    res = webintel.scan(cfg, store, force=False)
    assert res["online"] is False
    assert len(res["vulns"]) == 2          # stale data still served
    assert any("cached" in e for e in res["errors"])


def test_scan_offline_no_cache(monkeypatch, store):
    monkeypatch.setattr(webintel, "inventory", lambda cfg=None: [
        {"name": "a", "version": "1", "ecosystem": "PyPI", "source": "pip"}])

    def boom(pkgs):
        raise requests.ConnectionError("no internet")

    monkeypatch.setattr(webintel, "osv_querybatch", boom)
    res = webintel.scan(FakeCfg(), store, force=True)
    assert res["online"] is False and res["vulns"] == []


def test_cached_or_refresh_respects_enable_knob(store):
    cfg = FakeCfg(raw={"webintel": {"enable": False}})
    assert webintel.cached_or_refresh(cfg, store) is None


def test_cadence_knob():
    cfg = FakeCfg(raw={"webintel": {"cadence_hours": 6}})
    assert webintel.ttl_s(cfg) == 6 * 3600


def test_summary_line_variants():
    assert "no known CVEs" in webintel.summary_line(
        {"online": True, "packages_checked": 9, "vulns": [], "eol": []})
    s = webintel.summary_line({"online": False, "packages_checked": 2, "vulns": [
        {"package": "openssh", "version": "1", "ecosystem": "Ubuntu", "source": "distro",
         "vuln_id": "X", "aliases": [], "summary": "", "severity": "", "fixed": ""}],
        "eol": [{"product": "os", "cycle": "20.04", "eol": "2025-05-31", "is_eol": True,
                 "label": "os 20.04: REACHED EOL 2025-05-31"}]})
    assert "openssh" in s and "EOL" in s and "offline" in s


# ---------------- fixxer integration ----------------

def test_fixxer_cve_upgrade_detector(monkeypatch, tmp_path):
    from wrench import fixxer as fx

    db = tmp_path / "w.db"
    s = Store(db)
    s.cache_put("webintel_scan", {
        "ts": time.time(), "online": True, "packages_checked": 3,
        "vulns": [{"package": "openssh", "version": "1:9.6p1", "ecosystem": "Ubuntu",
                   "source": "distro", "vuln_id": "UBUNTU-CVE-2024-1",
                   "aliases": ["CVE-2024-1"], "summary": "", "severity": "", "fixed": ""}],
        "eol": []})
    s.close()
    cfg = FakeCfg(db_path=db)
    ctx = {"pkg_manager": "apt", "platform": "linux", "cfg_fixxer": {}, "cfg": cfg}

    def fake_run(argv, timeout=300, env_extra=None):
        if argv[:2] == ["dpkg-query", "-W"]:
            return 0, "openssh-client\topenssh\nopenssh-server\topenssh\nvim\tvim\n"
        if argv[:4] == ["apt-get", "-s", "install", "--only-upgrade"]:
            return 0, "Inst openssh-client [old] (new)\nInst openssh-server [old] (new)\n"
        raise AssertionError(f"unexpected: {argv}")

    monkeypatch.setattr(fx, "_run", fake_run)
    f = fx._detect_cve_upgrade(ctx)
    assert f is not None and f.risk == "moderate" and f.needs_sudo
    assert "CVE-2024-1" in f.detail
    assert f.commands[0][:4] == ["apt-get", "install", "--only-upgrade", "-y"]
    assert "openssh-client" in f.commands[0] and "openssh-server" in f.commands[0]

    # verify: nothing left upgradable → verified
    def fake_run_clean(argv, timeout=300, env_extra=None):
        if argv[:2] == ["dpkg-query", "-W"]:
            return 0, "openssh-client\topenssh\n"
        return 0, "0 upgraded.\n"

    monkeypatch.setattr(fx, "_run", fake_run_clean)
    ok, note = fx._verify_cve_upgrade(ctx, f)
    assert ok


def test_fixxer_cve_upgrade_no_cache_no_finding(tmp_path):
    from wrench import fixxer as fx
    cfg = FakeCfg(db_path=tmp_path / "empty.db")
    ctx = {"pkg_manager": "apt", "platform": "linux", "cfg_fixxer": {}, "cfg": cfg}
    assert fx._detect_cve_upgrade(ctx) is None


def test_fixxer_cve_upgrade_no_fixed_builds(monkeypatch, tmp_path):
    """Vulns known but apt has no newer builds → advisory territory, no finding."""
    from wrench import fixxer as fx
    db = tmp_path / "w.db"
    s = Store(db)
    s.cache_put("webintel_scan", {"ts": time.time(), "online": True, "packages_checked": 1,
                                  "vulns": [{"package": "openssh", "version": "1",
                                             "ecosystem": "Ubuntu", "source": "distro",
                                             "vuln_id": "X", "aliases": ["CVE-1"],
                                             "summary": "", "severity": "", "fixed": ""}],
                                  "eol": []})
    s.close()
    ctx = {"pkg_manager": "apt", "platform": "linux", "cfg_fixxer": {},
           "cfg": FakeCfg(db_path=db)}

    def fake_run(argv, timeout=300, env_extra=None):
        if argv[:2] == ["dpkg-query", "-W"]:
            return 0, "openssh-client\topenssh\n"
        return 0, "0 upgraded, 0 newly installed.\n"   # no Inst lines

    monkeypatch.setattr(fx, "_run", fake_run)
    assert fx._detect_cve_upgrade(ctx) is None


# ---------------- security_intel tool ----------------

def test_security_intel_tool(store):
    from wrench import tools
    assert "No web-intel scan cached" in tools.security_intel(store)
    store.cache_put("webintel_scan", {
        "ts": time.time(), "online": True, "packages_checked": 5,
        "vulns": [{"package": "requests", "version": "2.19.0", "ecosystem": "PyPI",
                   "source": "pip", "vuln_id": "GHSA-x", "aliases": ["CVE-2018-18074"],
                   "summary": "credentials leak", "severity": "7.5", "fixed": "2.20.0"}],
        "eol": [{"product": "os", "cycle": "24.04", "eol": "2029-05-31", "is_eol": False,
                 "label": "os 24.04: supported until 2029-05-31"}]})
    out = tools.security_intel(store)
    assert "CVE-2018-18074" in out and "fixed in 2.20.0" in out and "24.04" in out


def test_eol_advisories_helper():
    res = {"eol": [{"label": "os 20.04: REACHED EOL", "is_eol": True},
                   {"label": "python 3.12: supported", "is_eol": False}]}
    assert webintel.eol_advisories(res) == ["os 20.04: REACHED EOL"]
    assert webintel.eol_advisories({}) == []
    assert webintel.distro_vuln_packages({}) == []
