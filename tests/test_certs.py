"""certwrench: x509 parsing (real openssl-generated fixtures), config scanning,
weak-TLS detection, expiry ladder, inventory de-dup."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from wrench import certs


HAVE_OPENSSL = shutil.which("openssl") is not None
requires_openssl = pytest.mark.skipif(not HAVE_OPENSSL, reason="openssl binary not on PATH")


# ---------------- fixture generation ----------------

def _gen_cert(dir_: Path, cn: str, days: int, *, keyspec="rsa:2048",
              sans=None, name="cert") -> tuple[Path, Path]:
    """Generate a self-signed cert/key with openssl. Returns (cert, key)."""
    cert = dir_ / f"{name}.pem"
    key = dir_ / f"{name}.key"
    args = ["openssl", "req", "-x509", "-nodes", "-newkey", keyspec,
            "-keyout", str(key), "-out", str(cert), "-days", str(abs(days)),
            "-subj", f"/CN={cn}"]
    if sans:
        args += ["-addext", "subjectAltName=" + ",".join(f"DNS:{s}" for s in sans)]
    subprocess.run(args, capture_output=True, check=True, timeout=30)
    return cert, key


@pytest.fixture(scope="module")
def good_cert(tmp_path_factory):
    if not HAVE_OPENSSL:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("good")
    cert, _ = _gen_cert(d, "good.example.com", 90,
                        sans=["good.example.com", "www.good.example.com"])
    return cert


@pytest.fixture(scope="module")
def weak_cert(tmp_path_factory):
    if not HAVE_OPENSSL:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("weak")
    cert, _ = _gen_cert(d, "weak.example.com", 90, keyspec="rsa:1024", name="weak")
    return cert


# ---------------- parse_cert ----------------

@requires_openssl
def test_parse_good_cert(good_cert):
    info = certs.parse_cert(str(good_cert))
    assert info.ok, info.error
    assert "good.example.com" in info.subject
    assert info.self_signed is True
    assert info.key_type == "RSA"
    assert info.key_bits == 2048
    assert not info.weak_key
    assert "good.example.com" in info.sans
    assert "www.good.example.com" in info.sans
    assert info.days_left is not None and 85 <= info.days_left <= 90
    assert info.fingerprint_sha256
    assert info.sig_algo
    assert info.common_name == "good.example.com"


@requires_openssl
def test_parse_weak_key_cert(weak_cert):
    info = certs.parse_cert(str(weak_cert))
    assert info.ok, info.error
    assert info.key_type == "RSA"
    assert info.key_bits == 1024
    assert info.weak_key is True


def test_parse_missing_file():
    info = certs.parse_cert("/nonexistent/nope.pem")
    assert not info.ok
    assert "not found" in info.error


def test_parse_bad_file(tmp_path):
    p = tmp_path / "junk.pem"
    p.write_text("this is not a certificate")
    info = certs.parse_cert(str(p))
    assert not info.ok
    assert "openssl parse failed" in info.error


# ---------------- openssl date parsing ----------------

def test_openssl_date_parsing():
    ts = certs._parse_openssl_date("Nov  5 10:00:00 2026 GMT")
    assert ts > 0
    # round-trips to the right year
    import datetime as dt
    assert dt.datetime.fromtimestamp(ts, dt.timezone.utc).year == 2026


# ---------------- expiry ladder ----------------

@pytest.mark.parametrize("days,sev", [
    (-1, "critical"), (0, "critical"), (3, "critical"), (7, "critical"),
    (8, "warning"), (14, "warning"),
    (15, "info"), (30, "info"),
    (31, None), (365, None), (None, None),
])
def test_expiry_severity_ladder(days, sev):
    c = certs.CertInfo(path="x", days_left=days)
    assert c.expiry_severity() == sev


# ---------------- weak-key property ----------------

@pytest.mark.parametrize("kt,bits,weak", [
    ("RSA", 2048, False), ("RSA", 4096, False), ("RSA", 1024, True),
    ("EC", 256, False), ("EC", 224, True), ("Ed25519", None, False),
])
def test_weak_key_property(kt, bits, weak):
    c = certs.CertInfo(path="x", key_type=kt, key_bits=bits)
    assert c.weak_key is weak


# ---------------- config scanning ----------------

def test_scan_nginx_config(tmp_path):
    root = tmp_path / "nginx"
    (root / "sites").mkdir(parents=True)
    (root / "sites" / "site.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_certificate /etc/ssl/site.pem;\n"
        "  ssl_certificate_key /etc/ssl/site.key;\n"
        "  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
        "}\n")
    refs, weak = certs.scan_config_certs([("nginx", root)])
    paths = [r[1] for r in refs]
    assert "/etc/ssl/site.pem" in paths
    # weak TLS detected
    assert any(w.kind == "tls_version" for w in weak)
    # HSTS missing flagged
    assert any(w.kind == "hsts_missing" for w in weak)


def test_scan_nginx_with_hsts_no_weakness(tmp_path):
    root = tmp_path / "nginx"
    root.mkdir()
    (root / "a.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_certificate /etc/ssl/a.pem;\n"
        "  ssl_protocols TLSv1.2 TLSv1.3;\n"
        '  add_header Strict-Transport-Security "max-age=63072000";\n'
        "}\n")
    refs, weak = certs.scan_config_certs([("nginx", root)])
    assert [r[1] for r in refs] == ["/etc/ssl/a.pem"]
    assert not any(w.kind == "tls_version" for w in weak)
    assert not any(w.kind == "hsts_missing" for w in weak)


def test_scan_apache_config(tmp_path):
    root = tmp_path / "apache2"
    root.mkdir()
    (root / "ssl.conf").write_text(
        "<VirtualHost *:443>\n"
        "  SSLEngine on\n"
        "  SSLCertificateFile /etc/pki/tls/certs/host.crt\n"
        "  SSLCertificateChainFile /etc/pki/tls/certs/chain.crt\n"
        "  SSLProtocol all -SSLv3\n"
        "</VirtualHost>\n")
    refs, weak = certs.scan_config_certs([("apache", root)])
    paths = [r[1] for r in refs]
    assert "/etc/pki/tls/certs/host.crt" in paths
    assert "/etc/pki/tls/certs/chain.crt" in paths


def test_scan_haproxy_config(tmp_path):
    root = tmp_path / "haproxy"
    root.mkdir()
    (root / "haproxy.cfg").write_text(
        "frontend fe\n"
        "  bind *:443 ssl crt /etc/haproxy/certs/bundle.pem\n")
    refs, _ = certs.scan_config_certs([("haproxy", root)])
    assert ("haproxy", "/etc/haproxy/certs/bundle.pem", str(root / "haproxy.cfg")) in refs


def test_scan_caddy_config(tmp_path):
    root = tmp_path / "caddy"
    root.mkdir()
    (root / "Caddyfile").write_text(
        "example.com {\n"
        "  tls /etc/caddy/cert.pem /etc/caddy/key.pem\n"
        "}\n")
    refs, _ = certs.scan_config_certs([("caddy", root)])
    assert any(r[1] == "/etc/caddy/cert.pem" for r in refs)


def test_weak_tls_versions_helper():
    assert certs._weak_tls_versions("TLSv1 TLSv1.1 TLSv1.2") == ["TLSv1.0", "TLSv1.1"]
    assert certs._weak_tls_versions("TLSv1.2 TLSv1.3") == []
    # tokens explicitly disabled with a leading '-' are not "enabled weak"
    assert certs._weak_tls_versions("all -SSLv3") == []
    assert certs._weak_tls_versions("+SSLv3") == ["SSLv3"]


def test_protocol_is_weak():
    assert certs.protocol_is_weak("TLSv1")
    assert certs.protocol_is_weak("TLSv1.1")
    assert not certs.protocol_is_weak("TLSv1.2")
    assert not certs.protocol_is_weak("TLSv1.3")


# ---------------- well-known discovery ----------------

def test_scan_wellknown_letsencrypt(tmp_path):
    live = tmp_path / "live"
    (live / "example.com").mkdir(parents=True)
    (live / "example.com" / "fullchain.pem").write_text("x")
    (live / "example.com" / "cert.pem").write_text("x")
    found = certs.scan_wellknown_certs([live])
    # prefers cert.pem over fullchain.pem
    assert str(live / "example.com" / "cert.pem") in found


def test_scan_wellknown_skips_ca_bundles(tmp_path):
    d = tmp_path / "certs"
    d.mkdir()
    (d / "ca-certificates.crt").write_text("x")
    (d / "mysite.pem").write_text("x")
    found = certs.scan_wellknown_certs([d])
    assert str(d / "mysite.pem") in found
    assert not any("ca-certificates" in f for f in found)


# ---------------- inventory integration ----------------

@requires_openssl
def test_inventory_dedup_and_weakness(tmp_path):
    certdir = tmp_path / "store"
    certdir.mkdir()
    good, _ = _gen_cert(certdir, "a.example.com", 90, name="a")
    weak, _ = _gen_cert(certdir, "b.example.com", 90, keyspec="rsa:1024", name="b")

    nginx = tmp_path / "nginx"
    nginx.mkdir()
    (nginx / "a.conf").write_text(
        f"server {{\n  listen 443 ssl;\n  ssl_certificate {good};\n"
        "  ssl_protocols TLSv1.2;\n}\n")

    found, weaknesses = certs.inventory(
        config_roots=[("nginx", nginx)],
        wellknown_dirs=[certdir])
    paths = {c.path for c in found}
    # both certs discovered, good one only once despite config+wellknown overlap
    assert str(good.resolve()) in paths
    assert str(weak.resolve()) in paths
    assert len(found) == 2
    # weak key surfaced as a weakness
    assert any(w.kind == "weak_key" for w in weaknesses)


# ---------------- store persistence ----------------

def test_store_upsert_and_read(tmp_path):
    from wrench.store import Store
    s = Store(tmp_path / "t.db")
    c = certs.CertInfo(path="/etc/ssl/a.pem", source="nginx:/etc/nginx/a.conf",
                       subject="CN=a.example.com", issuer="CN=R3",
                       not_after=time.time() + 5 * 86400, days_left=5,
                       sans=["a.example.com"], key_type="RSA", key_bits=2048,
                       self_signed=False, chain_complete=True,
                       fingerprint_sha256="AA:BB")
    s.upsert_cert(c.to_row())
    rows = s.recent_certs()
    assert len(rows) == 1
    assert rows[0]["path"] == "/etc/ssl/a.pem"
    assert rows[0]["days_left"] == 5
    assert rows[0]["sans"] == ["a.example.com"]
    assert rows[0]["chain_complete"] is True
    assert rows[0]["self_signed"] is False
    # upsert same path updates in place (no duplicate)
    c.days_left = 3
    s.upsert_cert(c.to_row())
    rows = s.recent_certs()
    assert len(rows) == 1 and rows[0]["days_left"] == 3
    s.close()


def test_store_recent_certs_sorted_by_expiry(tmp_path):
    from wrench.store import Store
    s = Store(tmp_path / "t.db")
    for path, days in [("/c.pem", 60), ("/a.pem", 2), ("/b.pem", 20), ("/d.pem", None)]:
        s.upsert_cert(certs.CertInfo(path=path, days_left=days).to_row())
    order = [r["path"] for r in s.recent_certs()]
    # ascending days_left, NULLs last
    assert order == ["/a.pem", "/b.pem", "/c.pem", "/d.pem"]
    s.close()


# ---------------- patrol integration (cached, ladder, merge) ----------------

class _CacheStore:
    """Minimal store exposing the cache + upsert surface certs uses."""
    def __init__(self):
        self._cache = {}
        self.certs = []

    def cache_get(self, key, max_age_s):
        v = self._cache.get(key)
        if not v:
            return None
        ts, payload = v
        if (time.time() - ts) > max_age_s:
            return None
        return payload

    def cache_put(self, key, payload):
        self._cache[key] = (time.time(), payload)

    def upsert_cert(self, row, ts=None):
        self.certs.append(row)


def test_cached_inventory_caches(monkeypatch):
    calls = {"n": 0}

    def fake_inventory(*a, **k):
        calls["n"] += 1
        c = certs.CertInfo(path="/x.pem", subject="CN=x", not_after=time.time() + 10 * 86400,
                           days_left=10, key_type="RSA", key_bits=2048)
        return [c], []

    monkeypatch.setattr(certs, "inventory", fake_inventory)
    store = _CacheStore()
    certs.cached_inventory(None, store, cadence_s=3600)
    certs.cached_inventory(None, store, cadence_s=3600)  # served from cache
    assert calls["n"] == 1
    assert store.certs  # persisted on the first (fresh) run


def test_patrol_findings_expiry_ladder(monkeypatch):
    def fake_inventory(*a, **k):
        now = time.time()
        certlist = [
            certs.CertInfo(path="/exp.pem", subject="CN=exp", not_after=now - 86400,
                           days_left=-1, key_type="RSA", key_bits=2048),
            certs.CertInfo(path="/soon.pem", subject="CN=soon", not_after=now + 5 * 86400,
                           days_left=5, key_type="RSA", key_bits=2048),
            certs.CertInfo(path="/warn.pem", subject="CN=warn", not_after=now + 12 * 86400,
                           days_left=12, key_type="RSA", key_bits=2048),
            certs.CertInfo(path="/info.pem", subject="CN=info", not_after=now + 25 * 86400,
                           days_left=25, key_type="RSA", key_bits=2048),
            certs.CertInfo(path="/fine.pem", subject="CN=fine", not_after=now + 200 * 86400,
                           days_left=200, key_type="RSA", key_bits=2048),
        ]
        weak = [certs.ConfigWeakness("tls_version", "warning", "TLS<1.2", "/etc/nginx/x.conf")]
        return certlist, weak

    monkeypatch.setattr(certs, "inventory", fake_inventory)
    store = _CacheStore()
    out = certs.patrol_findings(None, store)
    sevs = {f["text"].split()[1]: f["severity"] for f in out if f["text"].startswith("certificate")}
    assert sevs["exp"] == "critical"
    assert sevs["soon"] == "critical"
    assert sevs["warn"] == "warning"
    assert sevs["info"] == "info"
    assert "fine" not in sevs  # >30d: no finding
    assert any(f["severity"] == "warning" and "TLS<1.2" in f["text"] for f in out)


def test_merge_cert_findings_escalates_status():
    from wrench.agent import _merge_cert_findings
    # info never escalates
    s, f = _merge_cert_findings("ok", [], [{"severity": "info", "text": "30d"}])
    assert s == "ok" and len(f) == 1
    # warning -> attention
    s, f = _merge_cert_findings("ok", [], [{"severity": "warning", "text": "12d"}])
    assert s == "attention"
    # critical -> critical, even from attention
    s, f = _merge_cert_findings("attention", [], [{"severity": "critical", "text": "expired"}])
    assert s == "critical"
    # never downgrades
    s, f = _merge_cert_findings("critical", [], [{"severity": "info", "text": "x"}])
    assert s == "critical"


def test_patrol_severity_sees_cert_criticals():
    from wrench import notifications as notif
    p = {"status": "critical", "findings": [{"severity": "critical", "text": "cert expired"}]}
    assert notif.patrol_severity(p) == "critical"
    assert notif.should_notify(notif.patrol_severity(p), "attention")


# ---------------- renewal orchestration ----------------

def _cert(path="/etc/letsencrypt/live/example.com/cert.pem", cn="example.com"):
    return certs.CertInfo(path=path, subject=f"CN={cn}", sans=[cn])


def test_detect_renewer(monkeypatch):
    monkeypatch.setattr(certs.shutil, "which",
                        lambda b: "/usr/bin/certbot" if b == "certbot" else None)
    assert certs.detect_renewer() == "certbot"
    monkeypatch.setattr(certs.shutil, "which", lambda b: None)
    monkeypatch.setattr(certs.Path, "home", lambda: Path("/nonexistent-home"))
    assert certs.detect_renewer() is None


def test_certbot_lineage():
    assert certs.certbot_lineage("/etc/letsencrypt/live/foo.com/cert.pem") == "foo.com"
    assert certs.certbot_lineage("/etc/ssl/other.pem") is None


def test_renewer_commands_certbot():
    cmds = certs.renewer_commands("certbot", _cert())
    assert cmds["dry_run"] == ["certbot", "renew", "--cert-name", "example.com",
                               "--dry-run", "--non-interactive"]
    assert "--dry-run" not in cmds["renew"]
    assert cmds["dry_run_is_real"] is True


def test_renewer_commands_acme():
    cmds = certs.renewer_commands("acme.sh", _cert(cn="svc.local"))
    assert cmds["renew"] == ["acme.sh", "--renew", "-d", "svc.local", "--force"]
    assert cmds["dry_run"][0] == "acme.sh" and "--info" in cmds["dry_run"]


def test_validate_argv_rejects_non_allowlisted():
    assert certs._validate_argv(["certbot", "renew"]) is True
    assert certs._validate_argv(["rm", "-rf", "/"]) is False
    assert certs._validate_argv(["certbot", "renew; rm x"]) is False
    assert certs._validate_argv([]) is False


def test_orchestrate_dry_run_only_touches_nothing():
    calls = []

    def run(argv, timeout=30, **k):
        calls.append(argv)
        return 0, "simulated dry run OK"

    res = certs.orchestrate_renew(_cert(), "certbot", dry_run=True, run=run)
    assert res.ok and res.dry_run
    assert [s.name for s in res.steps] == ["dry_run"]
    # only the dry-run command ran; no renew/reload
    assert all("--dry-run" in " ".join(a) or a[0] == "certbot" for a in calls)
    assert len(calls) == 1


def test_orchestrate_dry_run_failure_stops():
    def run(argv, timeout=30, **k):
        return 1, "ACME challenge failed"
    res = certs.orchestrate_renew(_cert(), "certbot", dry_run=True, run=run)
    assert not res.ok
    assert "dry-run failed" in res.message
    assert len(res.steps) == 1


def test_orchestrate_full_success_with_reload():
    seq = []

    def run(argv, timeout=30, **k):
        seq.append(argv[0] + " " + (argv[1] if len(argv) > 1 else ""))
        return 0, "ok"

    def prober(host, port, timeout=5.0):
        return {"ok": True, "protocol": "TLSv1.3", "cipher": "X", "days_left": 89}

    monkeypatchverify = certs.verify_chain
    import wrench.certs as m
    m.verify_chain = lambda path, untrusted=None: (True, "chain ok")
    try:
        res = certs.orchestrate_renew(_cert(), "certbot", dry_run=False,
                                      reload_service="nginx", probe_host="localhost",
                                      run=run, prober=prober)
    finally:
        m.verify_chain = monkeypatchverify
    assert res.ok and not res.rolled_back
    names = [s.name for s in res.steps]
    assert names == ["dry_run", "renew", "validate_chain", "reload_test", "reload", "probe"]
    # nginx -t ran before the reload
    assert any(s.startswith("nginx -t") for s in seq)


def test_orchestrate_bad_chain_does_not_reload():
    def run(argv, timeout=30, **k):
        return 0, "ok"
    import wrench.certs as m
    saved = m.verify_chain
    m.verify_chain = lambda path, untrusted=None: (False, "missing issuer")
    try:
        res = certs.orchestrate_renew(_cert(), "certbot", dry_run=False,
                                      reload_service="nginx", run=run)
    finally:
        m.verify_chain = saved
    assert not res.ok and res.rolled_back
    assert "NOT reloading" in res.message
    assert [s.name for s in res.steps] == ["dry_run", "renew", "validate_chain"]


def test_orchestrate_reload_test_failure_leaves_service():
    def run(argv, timeout=30, **k):
        # nginx -t fails
        if argv[:2] == ["nginx", "-t"]:
            return 1, "config error"
        return 0, "ok"
    import wrench.certs as m
    saved = m.verify_chain
    m.verify_chain = lambda path, untrusted=None: (True, "ok")
    try:
        res = certs.orchestrate_renew(_cert(), "certbot", dry_run=False,
                                      reload_service="nginx", run=run)
    finally:
        m.verify_chain = saved
    assert not res.ok
    assert "config test failed" in res.message
    assert "reload" not in [s.name for s in res.steps][-1:]  # did not reach reload


# ---------------- renewal consent / policy gate ----------------

def test_renewal_permitted_tiers(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import wrench.config as wc
    monkeypatch.setattr(wc, "CONFIG_DIR", tmp_path)
    cfg_suggest = SimpleNamespace(policy_tier="suggest")
    ok, reason = certs.renewal_permitted(cfg_suggest)
    assert not ok and "suggest-only" in reason
    cfg_repair = SimpleNamespace(policy_tier="repair")
    ok, _ = certs.renewal_permitted(cfg_repair)
    assert ok
    # consent flips suggest to allowed
    certs.write_renew_consent(cfg_suggest)
    ok, reason = certs.renewal_permitted(cfg_suggest)
    assert ok and "consent" in reason
    assert certs.revoke_renew_consent(cfg_suggest)
    ok, _ = certs.renewal_permitted(cfg_suggest)
    assert not ok
