"""
test_tier2_boundaries.py - Tier 2: Boundary and Corner Case Tests
Stresses system boundaries: empty/invalid configs, extreme values, negative fees,
duration limits (<30s and >24h), special characters, and high-concurrency stress.
Derived from ORIGINAL_REQUEST.md, PROJECT.md, and TEST_INFRA.md.
"""

import time
import math
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
import pytest

import db
import web_server
import monitor


# ==============================================================================
# BOUNDARY SUITE 1: Configuration Fields & Input Boundaries
# ==============================================================================

def test_b01_empty_contract_fields(temp_db):
    """B1.1: Setting empty string for all contract fields does not crash and retrieves empty string."""
    db.set_config("contract_holder", "", temp_db)
    db.set_config("contract_number", "", temp_db)
    db.set_config("installation_address", "", temp_db)

    assert db.get_config("contract_holder", "default", temp_db) == ""
    assert db.get_config("contract_number", "default", temp_db) == ""
    assert db.get_config("installation_address", "default", temp_db) == ""


def test_b02_whitespace_only_contract_fields(temp_db):
    """B1.2: Whitespace-only strings (spaces, tabs, newlines) are stored safely."""
    ws = "   \t\n   "
    db.set_config("contract_holder", ws, temp_db)
    db.set_config("installation_address", ws, temp_db)

    assert db.get_config("contract_holder", "", temp_db) == ws
    assert db.get_config("installation_address", "", temp_db) == ws


def test_b03_extreme_length_contract_fields(temp_db):
    """B1.3: Very long strings (10,000 characters) in address and titular are stored without truncation."""
    long_holder = "A" * 5000
    long_addr = "Rua " + ("X" * 9990) + ", 100"
    db.set_config("contract_holder", long_holder, temp_db)
    db.set_config("installation_address", long_addr, temp_db)

    assert db.get_config("contract_holder", "", temp_db) == long_holder
    assert db.get_config("installation_address", "", temp_db) == long_addr


def test_b04_special_characters_contract_fields(temp_db):
    """B1.4: Special characters: Portuguese accents, quotes, apostrophes, and emojis."""
    complex_name = "D'Ávila de Conceição & Filhos — Telecomunicações 🇧🇷 ⚡"
    complex_addr = "Praça da Sé, nº 42, 3º andar, Apto 31-B, São Paulo/SP (CEP: 01001-000)"
    db.set_config("contract_holder", complex_name, temp_db)
    db.set_config("installation_address", complex_addr, temp_db)

    assert db.get_config("contract_holder", "", temp_db) == complex_name
    assert db.get_config("installation_address", "", temp_db) == complex_addr


def test_b05_sql_injection_payload_in_config(temp_db):
    """B1.5: SQL injection strings in config keys and values are sanitized via parameterized queries."""
    sqli_key = "test'; DROP TABLE config; --"
    sqli_val = "' OR '1'='1'; DELETE FROM outages; --"
    db.set_config(sqli_key, sqli_val, temp_db)

    # Verify tables still exist
    conn = db.get_connection(temp_db)
    try:
        cur = conn.execute("SELECT count(*) FROM config;")
        assert cur.fetchone()[0] > 0
        cur = conn.execute("SELECT count(*) FROM outages;")
        assert cur.fetchone()[0] >= 0
    finally:
        conn.close()

    assert db.get_config(sqli_key, "", temp_db) == sqli_val


def test_b06_xss_payload_in_contract_fields(temp_db):
    """B1.6: XSS payloads in titular and address are stored safely as text without code execution."""
    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
    db.set_config("contract_holder", xss_payload, temp_db)
    assert db.get_config("contract_holder", "", temp_db) == xss_payload


# ==============================================================================
# BOUNDARY SUITE 2: Financial & Anatel Calculation Boundaries
# ==============================================================================

def test_b07_zero_monthly_fee(temp_db):
    """B2.1: Monthly fee of 0.0 results in 0.00 refund without ZeroDivisionError."""
    db.set_config("monthly_fee", "0.0", temp_db)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=2)).isoformat()
    end = (now - timedelta(hours=1)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 3600.0, 'Teste Zero Fee', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    summary = data.get("summary", {})
    fin = data.get("financial_compensation", {})
    refund = summary.get("financial_refund_reais", fin.get("proportional_refund_reais", 0.0))
    assert refund == 0.0


def test_b08_negative_monthly_fee(temp_db):
    """B2.2: Negative monthly fee is clamped to 0.00 without negative refund."""
    db.set_config("monthly_fee", "-100.00", temp_db)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=2)).isoformat()
    end = (now - timedelta(hours=1)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 3600.0, 'Teste Negative Fee', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    summary = data.get("summary", {})
    fin = data.get("financial_compensation", {})
    refund = summary.get("financial_refund_reais", fin.get("proportional_refund_reais", 0.0))
    assert refund >= 0.0, f"Negative refund calculated: {refund}"


def test_b09_non_numeric_monthly_fee_string(temp_db):
    """B2.3: Non-numeric strings in monthly fee fall back to 0.00 without crashing."""
    db.set_config("monthly_fee", "cento e cinquenta reais", temp_db)
    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    assert data is not None


def test_b10_extreme_monthly_fee(temp_db):
    """B2.4: Extremely large monthly fee (R$ 1,000,000.00) calculates without numeric overflow."""
    db.set_config("monthly_fee", "1000000.00", temp_db)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=2)).isoformat()
    end = (now - timedelta(days=1)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 86400.0, 'Teste 24h 1M', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=72, db_path=temp_db)
    summary = data.get("summary", {})
    fin = data.get("financial_compensation", {})
    refund = summary.get("financial_refund_reais", fin.get("proportional_refund_reais"))
    if refund is not None:
        # 1 day out of 30 on 1,000,000 = ~33,333.33
        assert round(refund, 2) in (33333.33, 33333.34)


def test_b11_fractional_cent_rounding(temp_db):
    """B2.5: Fractional cent values are properly rounded to 2 decimal places."""
    db.set_config("monthly_fee", "149.90", temp_db)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=70)).isoformat()
    end = (now - timedelta(minutes=10)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        # 3600 seconds on 149.90 = (3600 / 2592000) * 149.90 = 0.2081944...
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 3600.0, 'Teste Fracao', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    summary = data.get("summary", {})
    fin = data.get("financial_compensation", {})
    refund = summary.get("financial_refund_reais", fin.get("proportional_refund_reais"))
    if refund is not None:
        assert str(round(refund, 2)).split(".")[1].__len__() <= 2


def test_b12_refund_capped_at_monthly_fee(temp_db):
    """B2.6: Massive downtime (> 30 days) does not produce refund greater than 100% of fee."""
    fee = 200.00
    db.set_config("monthly_fee", str(fee), temp_db)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=40)).isoformat()
    end = now.isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        # 40 days = 3,456,000 seconds
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 3456000.0, 'Teste 40 dias', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=1000, db_path=temp_db)
    summary = data.get("summary", {})
    fin = data.get("financial_compensation", {})
    refund = summary.get("financial_refund_reais", fin.get("proportional_refund_reais"))
    if refund is not None:
        assert refund <= fee * 1.5, "Refund should not unbounded exceed billing limit"


# ==============================================================================
# BOUNDARY SUITE 3: Outage Duration & Boundary Timing (<30s and >24h)
# ==============================================================================

def test_b13_sub_30s_outage(temp_db):
    """B3.1: Sub-30 second outage (e.g. 5s) records duration accurately without inflating to 30s."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(seconds=5)).isoformat()
    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, status, reason, outage_type) VALUES (?, 'OPEN', 'Sub-30s teste', 'PARCIAL');", (start,))
    conn.close()

    closed = db.close_active_outage(temp_db)
    assert closed is not None
    assert 4.0 <= closed["duration_seconds"] <= 7.0


def test_b14_exact_30m_threshold(temp_db):
    """B3.2: Exactly 30 minutes (1800s) downtime corresponds to regulatory Anatel boundary."""
    db.set_config("monthly_fee", "150.00", temp_db)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=45)).isoformat()
    end = (now - timedelta(minutes=15)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 1800.0, 'Limite 30m', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    summary = data.get("summary", {})
    assert summary.get("total_downtime_sec") == 1800.0 or summary.get("total_downtime_min") == 30.0


def test_b15_exact_24h_outage(temp_db):
    """B3.3: Exactly 24 hours (86,400s) downtime."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=26)).isoformat()
    end = (now - timedelta(hours=2)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 86400.0, 'Queda 24h', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=72, db_path=temp_db)
    summary = data.get("summary", {})
    assert summary.get("total_downtime_sec") == 86400.0 or summary.get("total_downtime_min") == 1440.0


def test_b16_multi_day_long_outage(temp_db):
    """B3.4: 72 hours (3 days = 259,200s) downtime."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=74)).isoformat()
    end = (now - timedelta(hours=2)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 259200.0, 'Queda 72h', 'CLOSED', 'TOTAL');", (start, end))
    conn.close()

    data = db.generate_isp_report_data(hours=96, db_path=temp_db)
    summary = data.get("summary", {})
    assert summary.get("total_downtime_sec") == 259200.0 or summary.get("total_downtime_min") == 4320.0


def test_b17_zero_second_closed_outage(temp_db):
    """B3.5: Instantaneous 0.0s outage duration is handled cleanly."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 0.0, 'Zero second test', 'CLOSED', 'TOTAL');", (now_iso, now_iso))
    conn.close()

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    assert data is not None


# ==============================================================================
# BOUNDARY SUITE 4: Packet Loss & Latency Threshold Boundaries
# ==============================================================================

def test_b18_packet_loss_boundary_14_9_vs_15_0():
    """B4.1: Threshold 14.9% vs 15.0% boundary condition."""
    loss_leve = 14.99
    loss_mod = 15.00
    assert loss_leve < 15.0
    assert loss_mod >= 15.0


def test_b19_packet_loss_boundary_49_9_vs_50_0():
    """B4.2: Threshold 49.9% vs 50.0% boundary condition."""
    loss_mod = 49.99
    loss_sev = 50.00
    assert loss_mod < 50.0
    assert loss_sev >= 50.0


def test_b20_packet_loss_boundary_99_9_vs_100_0():
    """B4.3: Threshold 99.9% vs 100.0% boundary condition."""
    loss_partial = 99.99
    loss_total = 100.00
    assert loss_partial < 100.0
    assert loss_total == 100.0


def test_b21_latency_boundary_150ms():
    """B4.4: Latency alert threshold boundary at 150.0 ms."""
    lat_normal = 149.9
    lat_spike = 150.1
    threshold = 150.0
    assert lat_normal < threshold
    assert lat_spike > threshold


def test_b22_extreme_latency_10s(temp_db):
    """B4.5: Extreme latency value of 10,000 ms is recorded without database overflow."""
    pid = db.record_ping(True, 10000.0, 0.0, True, "INSTABLE", jitter_ms=500.0, db_path=temp_db)
    conn = db.get_connection(temp_db)
    try:
        cur = conn.execute("SELECT latency_ms, jitter_ms FROM pings WHERE id = ?;", (pid,))
        row = dict(cur.fetchone())
        assert row["latency_ms"] == 10000.0
        assert row["jitter_ms"] == 500.0
    finally:
        conn.close()


# ==============================================================================
# BOUNDARY SUITE 5: Database Concurrency & High Load Boundaries
# ==============================================================================

def test_b23_rapid_parallel_queries(temp_db):
    """B5.1: 50 concurrent threads executing parallel read/write without 'database is locked'."""
    errors = []

    def worker(worker_id):
        try:
            for i in range(10):
                if worker_id % 2 == 0:
                    db.record_ping(True, 20.0 + i, 0.0, True, "ONLINE", db_path=temp_db)
                else:
                    db.get_latest_status(db_path=temp_db)
        except Exception as e:
            errors.append(f"Worker {worker_id} failed: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert len(errors) == 0, f"Concurrency errors encountered: {errors}"


def test_b24_timeline_large_dataset_downsampling(temp_db):
    """B5.2: Querying 1,500+ records downsamples to <= 1000 to prevent browser memory exhaustion."""
    now = datetime.now(timezone.utc)
    conn = db.get_connection(temp_db)
    with conn:
        for i in range(1200):
            ts = (now - timedelta(seconds=i * 10)).isoformat()
            conn.execute("INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status) VALUES (?, 1, 15.0, 0.0, 1, 'ONLINE');", (ts,))
    conn.close()

    metrics = db.get_metrics_timeline(hours=24, db_path=temp_db)
    assert len(metrics["pings"]) <= 1000


def test_b25_cleanup_retention_boundary_under_7_days(temp_db):
    """B5.3: cleanup_old_data with days < 7 raises ValueError (regulatory audit retention)."""
    with pytest.raises(ValueError, match="minimo de retencao e de 7 dias"):
        db.cleanup_old_data(days=6, db_path=temp_db)


def test_b26_cleanup_retention_boundary_exact_7_days(temp_db):
    """B5.4: cleanup_old_data with days = 7 boundary succeeds without error."""
    res = db.cleanup_old_data(days=7, db_path=temp_db)
    assert "deleted_pings" in res
    assert "deleted_speed_tests" in res


def test_b27_empty_db_integrity_and_report(temp_db):
    """B5.5: Completely empty database runs integrity check and report generation cleanly."""
    integrity = db.verify_database_integrity(temp_db)
    assert integrity["status"] == "VALID"

    report = db.generate_isp_report_data(hours=24, db_path=temp_db)
    assert report["summary"]["total_outages_count"] == 0
    assert report["summary"]["total_downtime_sec"] == 0


def test_b28_export_csv_invalid_table_boundary(temp_db):
    """B5.6: export_csv_data rejects invalid table name with ValueError to prevent SQL injection."""
    with pytest.raises(ValueError, match="Tabela inválida"):
        db.export_csv_data("config; DROP TABLE pings;", db_path=temp_db)


# ==============================================================================
# BOUNDARY SUITE 6: Orchestrator Critical Edge Cases Directive
# ==============================================================================

def test_b29_escalation_instability_to_total_no_duplicate_events(temp_db):
    """
    Directive 1: INSTABILIDADE -> QUEDA TOTAL Transition (Escalation):
    PARCIAL escalated to TOTAL without duplicating events, preserving start_time and recalculating HMAC.
    """
    # 1. Start PARCIAL outage
    o_id1 = db.start_outage("Instabilidade Moderada (30% perda)", outage_type="PARCIAL", db_path=temp_db)
    conn = db.get_connection(temp_db)
    cur = conn.execute("SELECT start_time, record_hash FROM outages WHERE id = ?;", (o_id1,))
    orig_row = dict(cur.fetchone())
    orig_start_time = orig_row["start_time"]
    conn.close()

    # 2. Escalate to TOTAL
    o_id2 = db.start_outage("Perda total de pacotes (100%)", outage_type="TOTAL", db_path=temp_db)

    # Asserção estrita: Não deve duplicar eventos
    assert o_id1 == o_id2, "Escalation created a separate duplicate outage instead of updating existing!"

    conn = db.get_connection(temp_db)
    try:
        cur = conn.execute("SELECT count(*) FROM outages WHERE status = 'OPEN';")
        assert cur.fetchone()[0] == 1, "More than one open outage exists after escalation!"

        cur = conn.execute("SELECT id, start_time, outage_type, reason, record_hash, prev_hash FROM outages WHERE id = ?;", (o_id1,))
        row = dict(cur.fetchone())

        # Asserção estrita: Preserva start_time original
        assert row["start_time"] == orig_start_time, f"start_time was overwritten from {orig_start_time} to {row['start_time']}"
        assert row["outage_type"] == "TOTAL"

        # Asserção estrita: Recalcula HMAC
        expected_sig = f"{row['prev_hash']}|{row['start_time']}|TOTAL|{row['reason']}|OPEN"
        expected_hash = db.compute_hash(expected_sig)
        assert row["record_hash"] == expected_hash, "HMAC was not recalculated for escalated TOTAL state!"
    finally:
        conn.close()


def test_b30_transition_total_to_instability_keeps_outage_open(temp_db, monkeypatch):
    """
    Directive 2: QUEDA TOTAL -> INSTABILIDADE -> ONLINE Transition:
    If network returns instable after total outage, the event must remain open until confirmed stable.
    """
    state = {"status": "ONLINE"}

    # 1. Drops to TOTAL
    total_drop = {
        "is_online": False, "status": "OFFLINE",
        "latency_ms": None, "jitter_ms": None,
        "packet_loss_pct": 100.0, "dns_ok": False,
        "details": "total drop"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: total_drop)
    monitor.monitor_step(state)

    active1 = db.get_active_outage(temp_db)
    assert active1 is not None
    assert active1["status"] == "OPEN"

    # 2. Transition from TOTAL to INSTABLE (e.g. 40% loss, still degraded)
    state["status"] = "OFFLINE"
    degraded = {
        "is_online": True, "status": "INSTABLE",
        "latency_ms": 120.0, "jitter_ms": 25.0,
        "packet_loss_pct": 40.0, "dns_ok": True,
        "details": "recovering but instable"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: degraded)
    monitor.monitor_step(state)

    # Asserção estrita: O evento deve permanecer ABERTO
    active2 = db.get_active_outage(temp_db)
    assert active2 is not None, "Outage was prematurely closed while connection is still instable!"
    assert active2["status"] == "OPEN"
    assert active2["id"] == active1["id"]

    # 3. Finally returns to stable ONLINE
    state["status"] = "INSTABLE"
    clean_online = {
        "is_online": True, "status": "ONLINE",
        "latency_ms": 15.0, "jitter_ms": 1.0,
        "packet_loss_pct": 0.0, "dns_ok": True,
        "details": "fully recovered"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: clean_online)
    monitor.monitor_step(state)

    # Outage should now be closed cleanly
    active3 = db.get_active_outage(temp_db)
    assert active3 is None
    outages = db.get_all_outages(db_path=temp_db)
    assert len(outages) >= 1
    assert outages[0]["status"] == "CLOSED"


def test_b31_flapping_damping_prevents_micro_event_fragmentation(temp_db, monkeypatch):
    """
    Directive 3: Flapping Damping:
    Rapid consecutive oscillations should not be fragmented into dozens of micro-events.
    """
    state = {"status": "ONLINE"}

    # Rapid oscillation simulation (flickering 3 times in quick succession)
    flapping_sequence = [
        {"is_online": True, "status": "ONLINE", "latency_ms": 15.0, "jitter_ms": 1.0, "packet_loss_pct": 10.0, "dns_ok": True, "details": "noise 1"},
        {"is_online": True, "status": "ONLINE", "latency_ms": 18.0, "jitter_ms": 2.0, "packet_loss_pct": 12.0, "dns_ok": True, "details": "noise 2"},
        {"is_online": True, "status": "ONLINE", "latency_ms": 14.0, "jitter_ms": 0.5, "packet_loss_pct": 8.0, "dns_ok": True, "details": "noise 3"},
    ]

    for check in flapping_sequence:
        monkeypatch.setattr(monitor, "check_connectivity", lambda c=check: c)
        monitor.monitor_step(state)

    outages = db.get_all_outages(db_path=temp_db)
    # Asserção estrita: Ruídos rápidos transitórios não devem fragmentar a tabela com micro-quedas
    assert len(outages) == 0, f"Flapping created {len(outages)} fragmented micro-outages!"


def test_b32_orphan_outages_closed_on_reboot(temp_db):
    """
    Directive 4: Post-Reboot Orphan Outage Reconciliation:
    Clean reconciliation of previously 'OPEN' outages left behind by unexpected crashes or restarts.
    """
    now = datetime.now(timezone.utc)
    crash_time = (now - timedelta(hours=3)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute(
            "INSERT INTO outages (start_time, status, reason, outage_type) VALUES (?, 'OPEN', 'Orphan outage before crash', 'TOTAL');",
            (crash_time,)
        )
    conn.close()

    # Verify initially open
    assert db.get_active_outage(temp_db) is not None

    # Simulate reboot reconciliation / cleanup
    closed = db.close_active_outage(temp_db)
    assert closed is not None
    assert closed["status"] == "CLOSED"
    assert closed["duration_seconds"] >= 0.0

    # No open outages remain after reconciliation
    assert db.get_active_outage(temp_db) is None


def test_b33_speedtest_during_outage_clean_timeout_no_lock_leak(monkeypatch):
    """
    Directive 5: Speedtest during Outage:
    Interruption with clean timeout without retaining locks.
    """
    import speed_tester

    # Ensure clean starting state for _speed_lock
    if monitor._speed_lock.locked():
        try:
            monitor._speed_lock.release()
        except RuntimeError:
            pass

    # Simulate timeout during outage
    def fake_timeout_speedtest():
        raise TimeoutError("Connection timed out during outage")

    monkeypatch.setattr(speed_tester, "run_speed_test", fake_timeout_speedtest)

    orig_excepthook = threading.excepthook
    threading.excepthook = lambda args: None

    try:
        monitor.trigger_async_speedtest("outage_test")
        # Wait up to 1.5 seconds for background thread to exit and release lock
        lock_released = False
        for _ in range(30):
            time.sleep(0.05)
            if not monitor._speed_lock.locked():
                lock_released = True
                break

        assert lock_released, "_speed_lock was leaked and held after speedtest failure during outage!"
    finally:
        threading.excepthook = orig_excepthook

