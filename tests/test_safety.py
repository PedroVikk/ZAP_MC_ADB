"""Testes das protecoes puras (sem ZAP no ar)."""
from zap_mcp.reports import group_alerts, risk_counts, risk_rank
from zap_mcp.safety import (
    ScanRegistry,
    is_allowed,
    normalize_allowlist,
)


def test_deny_by_default_empty_allowlist():
    assert is_allowed("http://localhost:3000", set()) is False


def test_exact_host_allowed():
    allow = normalize_allowlist(["localhost", "127.0.0.1"])
    assert is_allowed("http://localhost:3000/rest", allow) is True
    assert is_allowed("127.0.0.1", allow) is True


def test_subdomain_allowed():
    allow = normalize_allowlist(["example.com"])
    assert is_allowed("https://api.example.com/v3", allow) is True
    assert is_allowed("https://example.com", allow) is True


def test_unrelated_host_denied():
    allow = normalize_allowlist(["example.com"])
    assert is_allowed("https://evil.com", allow) is False
    # nao casa por sufixo enganoso
    assert is_allowed("https://notexample.com", allow) is False


def test_schemeless_target_resolves_host():
    allow = normalize_allowlist(["staging.local"])
    assert is_allowed("staging.local:8080", allow) is True


def test_group_alerts_counts_and_min_risk():
    alerts = [
        {"id": "1", "alert": "XSS", "risk": "High", "url": "u1"},
        {"id": "2", "alert": "XSS", "risk": "High", "url": "u2"},
        {"id": "3", "alert": "Cookie", "risk": "Low", "url": "u3"},
        {"id": "4", "alert": "Info leak", "risk": "Informational", "url": "u4"},
    ]
    grouped = group_alerts(alerts, min_risk="Low")
    # Informational fica de fora
    assert grouped["total"] == 3
    # agrupado por tipo: XSS com count 2 vem primeiro (risco maior)
    assert grouped["groups"][0]["name"] == "XSS"
    assert grouped["groups"][0]["count"] == 2
    assert grouped["by_risk"]["High"] == 2


def test_risk_rank_handles_suffix():
    assert risk_rank("High (Medium)") == 3
    assert risk_rank("informational") == 0


def test_risk_counts():
    counts = risk_counts([{"risk": "High"}, {"risk": "High"}, {"risk": "Low"}])
    assert counts == {"High": 2, "Medium": 0, "Low": 1, "Informational": 0}


def test_scan_registry_tracks_and_lists():
    reg = ScanRegistry()
    reg.add("5", "spider", "http://localhost")
    assert reg.get("5").kind == "spider"
    assert len(reg.all()) == 1
    assert reg.next_ajax_id() == "ajax-1"
    assert reg.next_ajax_id() == "ajax-2"
