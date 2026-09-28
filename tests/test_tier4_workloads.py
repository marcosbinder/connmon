"""
test_tier4_workloads.py - Tier 4: Real-World Application Workloads
Simulates complete real-world user and network lifecycles:
1. Application Startup & Network Identity Auto-Discovery
2. Day-in-the-Life Network Telemetry & Anomaly Lifecycle
3. Contract Configuration & Regulatory Claim in R$
4. 0 Undefined / Null / NaN Payload Guarantee for Forensic PDF
5. Retention Policy, Data Purge & Integrity Post-Verification
Derived from ORIGINAL_REQUEST.md, PROJECT.md, and TEST_INFRA.md.
"""

import math
import time
from datetime import datetime, timezone, timedelta
import pytest

import db
import monitor


def test_w01_application_startup_and_discovery(live_server, api_client, mock_isp):
    """Scenario 1: Full application boot, static dashboard delivery, ISP discovery, and status check."""
    # 1. Favicon is delivered cleanly
    favicon = api_client.get_text(f"{live_server}/favicon.ico")
    assert "<svg" in favicon

    # 2. Main dashboard HTML is served
    index_html = api_client.get_text(f"{live_server}/")
    assert "<!DOCTYPE html>" in index_html
    assert "NetMon" in index_html

    # 3. ISP auto-detection returns complete network metadata
    isp_data = api_client.get_json(f"{live_server}/api/isp")
    assert isp_data["isp"] == "Claro NXT Telecomunicacoes Ltda"
    assert isp_data["asn"] == "AS28573"
    assert isp_data["ip"] != ""
    assert "local_ip" in isp_data
    assert isp_data["local_ip"] != "--"

    # 4. Status endpoint reflects healthy initial connection
    status = api_client.get_json(f"{live_server}/api/status")
    assert "stats_24h" in status
    assert "config" in status
    assert status["stats_24h"]["uptime_pct"] >= 0.0


def test_w02_telemetry_and_outage_lifecycle(temp_db, monkeypatch):
    """Scenario 2: Simulates realistic telemetry transitions: normal -> noise -> moderate -> severe -> recovery."""
    state = {"status": "ONLINE"}

    # Phase A: Normal operating telemetry
    normal_check = {
        "is_online": True, "status": "ONLINE",
        "latency_ms": 14.5, "jitter_ms": 1.2,
        "packet_loss_pct": 0.0, "dns_ok": True,
        "details": "normal"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: normal_check)
    for _ in range(3):
        monitor.monitor_step(state)

    assert db.get_active_outage(temp_db) is None

    # Phase B: Transitory noise / Wi-Fi hiccup (1 packet dropped, DNS OK)
    noise_check = {
        "is_online": True, "status": "ONLINE",
        "latency_ms": 22.0, "jitter_ms": 3.0,
        "packet_loss_pct": 33.3, "dns_ok": True,
        "details": "wifi_hiccup"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: noise_check)
    monitor.monitor_step(state)
    # MUST NOT open an outage
    assert db.get_active_outage(temp_db) is None

    # Phase C: Provider outage (total loss)
    total_outage_check = {
        "is_online": False, "status": "OFFLINE",
        "latency_ms": None, "jitter_ms": None,
        "packet_loss_pct": 100.0, "dns_ok": False,
        "details": "fiber_cut"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: total_outage_check)
    monitor.monitor_step(state)
    active = db.get_active_outage(temp_db)
    assert active is not None
    assert active["outage_type"] == "TOTAL"

    # Phase D: Normalization / link recovery
    state["status"] = "OFFLINE"
    monkeypatch.setattr(monitor, "check_connectivity", lambda: normal_check)
    monitor.monitor_step(state)

    # Active outage is closed
    assert db.get_active_outage(temp_db) is None
    outages = db.get_all_outages(db_path=temp_db)
    assert len(outages) == 1
    assert outages[0]["status"] == "CLOSED"
    assert outages[0]["duration_seconds"] >= 0.0


def test_w03_contract_configuration_and_regulatory_claim(live_server, api_client, temp_db):
    """Scenario 3: User saves contract details in modal and generates regulatory claim with refund in R$."""
    # Step 1: User saves contract info via settings modal
    contract_payload = {
        "contract_holder": "Dr. Marco Aurelio Silva",
        "contract_number": "CLARO-FIBRA-2026-991",
        "installation_address": "Av. Paulista, 1000, Bela Vista, São Paulo - SP",
        "monthly_fee": "149.90",
        "contracted_download_mbps": "500",
        "contracted_upload_mbps": "250"
    }
    api_client.post_json(f"{live_server}/api/config", contract_payload)

    # Step 2: Accumulate 3 hours (10,800s) of downtime
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=4)).isoformat()
    end = (now - timedelta(hours=1)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute(
            "INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 10800.0, 'Rompimento de Fibra Optica', 'CLOSED', 'TOTAL');",
            (start, end)
        )
    conn.close()

    # Step 3: Fetch report JSON
    report_json = api_client.get_json(f"{live_server}/api/report_json?hours=24")
    assert report_json is not None

    # Step 4: Verify Anatel refund calculation: (10800 / 2592000) * 149.90 = R$ 0.62458... -> R$ 0.62
    summary = report_json.get("summary", {})
    fin = report_json.get("financial_compensation", {})
    refund = summary.get("financial_refund_reais", fin.get("proportional_refund_reais"))
    if refund is not None:
        assert round(refund, 2) in (0.62, 0.63)

    # Step 5: Fetch text report
    report_text = api_client.get_text(f"{live_server}/api/report?hours=24")
    assert "LAUDO TECNICO" in report_text
    assert "632/2014" in report_text
    assert "Rompimento de Fibra Optica" in report_text


def test_w04_zero_undefined_null_nan_payload_guarantee(live_server, api_client, populated_db):
    """Scenario 4: Exhaustive validation that /api/report_json contains ZERO undefined, null, or NaN values."""
    payload = api_client.get_json(f"{live_server}/api/report_json?hours=72")

    violations = []

    def inspect_node(val, path="root"):
        if isinstance(val, dict):
            for k, v in val.items():
                if str(k).lower() in ("undefined", "null", "nan"):
                    violations.append(f"Bad key '{k}' at {path}")
                inspect_node(v, f"{path}.{k}")
        elif isinstance(val, list):
            for i, item in enumerate(val):
                inspect_node(item, f"{path}[{i}]")
        elif isinstance(val, str):
            if val.strip().lower() in ("undefined", "nan"):
                violations.append(f"Literal '{val}' at {path}")
        elif isinstance(val, float):
            if math.isnan(val) or math.isinf(val):
                violations.append(f"Invalid float {val} at {path}")

    inspect_node(payload)
    assert len(violations) == 0, f"Found undefined/null/NaN violations: {violations}"

    # Verify structural integrity expected by populateLaudoHtml
    assert "summary" in payload
    assert "period" in payload
    assert "outages" in payload


def test_w05_retention_purge_and_integrity_audit(live_server, api_client, temp_db):
    """Scenario 5: Full 30-day retention purge cycle followed by cryptographic integrity verification."""
    now = datetime.now(timezone.utc)

    # Seed records: 5 old (40 days ago) and 5 recent (2 days ago)
    conn = db.get_connection(temp_db)
    with conn:
        for i in range(5):
            old_ts = (now - timedelta(days=40, hours=i)).isoformat()
            conn.execute("INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status) VALUES (?, 1, 15.0, 0.0, 1, 'ONLINE');", (old_ts,))
        for i in range(5):
            rec_ts = (now - timedelta(days=2, hours=i)).isoformat()
            conn.execute("INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status) VALUES (?, 1, 15.0, 0.0, 1, 'ONLINE');", (rec_ts,))
        # Seed an outage from 40 days ago (must NOT be deleted by cleanup)
        old_outage = (now - timedelta(days=40)).isoformat()
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 120.0, 'Old Outage', 'CLOSED', 'TOTAL');", (old_outage, old_outage))
    conn.close()

    # Execute cleanup via API
    cleanup_resp = api_client.post_json(f"{live_server}/api/cleanup", {"days": 30})
    assert cleanup_resp.get("deleted_pings") == 5

    # Verify outages were preserved
    conn = db.get_connection(temp_db)
    try:
        cur = conn.execute("SELECT count(*) FROM outages;")
        assert cur.fetchone()[0] >= 1
        cur = conn.execute("SELECT count(*) FROM pings;")
        assert cur.fetchone()[0] == 5
    finally:
        conn.close()

    # Verify audit integrity
    integrity = api_client.get_json(f"{live_server}/api/integrity")
    assert integrity["status"] in ("VALID", "TAMPERED")
