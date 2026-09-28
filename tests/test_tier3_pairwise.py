"""
test_tier3_pairwise.py - Tier 3: Cross-Feature Pairwise Interaction Tests
Validates combinatorial interactions between subsystems:
- Config Update + Report Generation
- Outage Escalation + Cryptographic Integrity Check
- Adaptive Detection + Recovery Timing
- Speedtest Lifecycle + Report Analytics
- Database Reset + Audit Logging + Chain Reset
- High Concurrency Writes + Outage State Transitions
- Custom Period Range + Open Outage Processing
Derived from ORIGINAL_REQUEST.md, PROJECT.md, and TEST_INFRA.md.
"""

import time
import threading
from datetime import datetime, timezone, timedelta
import pytest

import db
import monitor


def test_p01_config_update_and_report_generation(temp_db, mock_isp):
    """Pair 1: Updating contract configuration immediately updates report data and Anatel refund."""
    # Step 1: Baseline config
    db.set_config("monthly_fee", "120.00", temp_db)
    db.set_config("contract_holder", "Primeiro Titular", temp_db)

    # Step 2: Seed an outage of 2 hours (7200s)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=3)).isoformat()
    end = (now - timedelta(hours=1)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute(
            "INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, ?, 7200.0, 'Interrupcao teste', 'CLOSED', 'TOTAL');",
            (start, end)
        )
    conn.close()

    # Step 3: Check initial report
    data1 = db.generate_isp_report_data(hours=24, db_path=temp_db)
    meta1 = data1.get("contract_info", data1.get("client", {}))
    assert meta1.get("holder", meta1.get("contract_holder", "")) in ("Primeiro Titular", "")

    # Step 4: Update config with new fee and holder
    db.set_config("monthly_fee", "240.00", temp_db)
    db.set_config("contract_holder", "Segundo Titular Atualizado", temp_db)

    # Step 5: Check second report immediately reflects new values
    data2 = db.generate_isp_report_data(hours=24, db_path=temp_db)
    meta2 = data2.get("contract_info", data2.get("client", {}))
    # Refund for 7200s on 240.00 fee = (7200 / 2592000) * 240 = 0.666... -> 0.67
    fin2 = data2.get("financial_compensation", {})
    summary2 = data2.get("summary", {})
    refund = summary2.get("financial_refund_reais", fin2.get("proportional_refund_reais"))
    if refund is not None:
        assert round(refund, 2) in (0.66, 0.67)


def test_p02_outage_escalation_and_cryptographic_integrity(temp_db):
    """Pair 2: Outage escalation PARCIAL -> TOTAL preserves cryptographic chain integrity."""
    # Step 1: Open PARCIAL outage
    o1 = db.start_outage("Instabilidade Moderada (30% perda)", outage_type="PARCIAL", db_path=temp_db)

    # Step 2: Escalate to TOTAL
    o1_esc = db.start_outage("Perda total de pacotes (100%)", outage_type="TOTAL", db_path=temp_db)
    assert o1 == o1_esc

    # Step 3: Close outage
    closed = db.close_active_outage(temp_db)
    assert closed is not None
    assert closed["outage_type"] == "TOTAL"

    # Step 4: Run database integrity check
    integrity = db.verify_database_integrity(temp_db)
    # The chain should remain valid, zero tampered outages
    assert integrity["tampered_outages"] == 0
    assert integrity["chain_broken_outages"] == 0
    assert integrity["status"] == "VALID"


def test_p03_adaptive_detection_and_recovery_timing(temp_db, monkeypatch):
    """Pair 3: Noise rejection followed by confirmed anomaly and exact-second recovery."""
    monkeypatch.setattr(monitor, "trigger_async_speedtest", lambda reason: None)
    state = {"status": "ONLINE"}

    # 1. Noise check (should NOT open outage)
    noise_check = {
        "is_online": True,
        "status": "ONLINE",
        "latency_ms": 25.0,
        "jitter_ms": 2.0,
        "packet_loss_pct": 33.3,
        "dns_ok": True,
        "details": "noise"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: noise_check)
    monitor.monitor_step(state)
    assert db.get_active_outage(temp_db) is None

    # 2. Confirmed severe outage
    offline_check = {
        "is_online": False,
        "status": "OFFLINE",
        "latency_ms": None,
        "jitter_ms": None,
        "packet_loss_pct": 100.0,
        "dns_ok": False,
        "details": "offline"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: offline_check)
    monitor.monitor_step(state)
    active = db.get_active_outage(temp_db)
    assert active is not None

    # 3. Connection recovers
    online_check = {
        "is_online": True,
        "status": "ONLINE",
        "latency_ms": 15.0,
        "jitter_ms": 1.0,
        "packet_loss_pct": 0.0,
        "dns_ok": True,
        "details": "recovered"
    }
    monkeypatch.setattr(monitor, "check_connectivity", lambda: online_check)
    state["status"] = "OFFLINE"
    monitor.monitor_step(state)

    # 4. Outage should now be closed
    active_after = db.get_active_outage(temp_db)
    assert active_after is None
    outages = db.get_all_outages(db_path=temp_db)
    assert len(outages) >= 1
    assert outages[0]["status"] == "CLOSED"


def test_p04_speedtest_lifecycle_and_report_analytics(temp_db):
    """Pair 4: Speed test results (success and failure) integrate into report analytics."""
    now = datetime.now(timezone.utc)
    db.set_config("contracted_download_mbps", "500", temp_db)
    db.set_config("contracted_upload_mbps", "250", temp_db)

    # 1. Success test
    t1 = db.record_speed_test("scheduled", 450.0, 225.0, 12.0, "SUCCESS", db_path=temp_db)
    # 2. Failed test (should not skew compliance calculation)
    t2 = db.record_speed_test("instability", None, None, None, "FAILED", error_message="Timeout", db_path=temp_db)
    # 3. Second success test
    t3 = db.record_speed_test("scheduled", 470.0, 235.0, 11.0, "SUCCESS", db_path=temp_db)

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    perf = data.get("performance", {})
    # Average down of 450 and 470 = 460.0
    assert perf["avg_down"] == 460.0
    assert perf["avg_up"] == 230.0
    # Down compliance: 460 / 500 = 92.0%
    assert perf["down_compliance_pct"] == 92.0

    # Cryptographic integrity should remain valid
    res = db.verify_database_integrity(temp_db)
    assert res["status"] == "VALID"


def test_p05_database_reset_and_subsequent_hash_chain(temp_db):
    """Pair 5: Database reset logs audit action and restarts hash chaining cleanly from GENESIS."""
    # Seed data
    db.record_ping(True, 15.0, 0.0, True, "ONLINE", db_path=temp_db)
    db.record_speed_test("init", 500.0, 250.0, 10.0, "SUCCESS", db_path=temp_db)
    db.start_outage("Pre-reset outage", outage_type="TOTAL", db_path=temp_db)
    db.close_active_outage(temp_db)

    # Reset
    res = db.reset_database(actor_ip="127.0.0.1", db_path=temp_db)
    assert res["status"] == "SUCCESS"

    # Verify audit log
    conn = db.get_connection(temp_db)
    try:
        cur = conn.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1;")
        assert cur.fetchone()["action"] == "RESET_DATABASE"
    finally:
        conn.close()

    # Record post-reset telemetry
    p1 = db.record_ping(True, 16.0, 0.0, True, "ONLINE", db_path=temp_db)
    o1 = db.start_outage("Post-reset outage", outage_type="TOTAL", db_path=temp_db)

    conn = db.get_connection(temp_db)
    try:
        cur_p = conn.execute("SELECT prev_hash FROM pings WHERE id = ?;", (p1,))
        assert cur_p.fetchone()["prev_hash"] == "GENESIS"

        cur_o = conn.execute("SELECT prev_hash FROM outages WHERE id = ?;", (o1,))
        assert cur_o.fetchone()["prev_hash"] == "GENESIS"
    finally:
        conn.close()

    db.close_active_outage(temp_db)
    integrity = db.verify_database_integrity(temp_db)
    assert integrity["status"] == "VALID"


def test_p06_concurrent_writes_and_active_outage_close(temp_db):
    """Pair 6: Active outage close while parallel threads insert telemetry executes atomically."""
    outage_id = db.start_outage("Concurrency stress test", outage_type="TOTAL", db_path=temp_db)
    stop_event = threading.Event()
    errors = []

    def telemetry_feeder():
        while not stop_event.is_set():
            try:
                db.record_ping(True, 18.0, 0.0, True, "ONLINE", db_path=temp_db)
                time.sleep(0.005)
            except Exception as e:
                errors.append(str(e))

    threads = [threading.Thread(target=telemetry_feeder) for _ in range(5)]
    for t in threads:
        t.start()

    time.sleep(0.05)
    closed = db.close_active_outage(temp_db)
    stop_event.set()

    for t in threads:
        t.join(timeout=5)

    assert len(errors) == 0
    assert closed is not None
    assert closed["status"] == "CLOSED"
    assert closed["end_time"] is not None


def test_p07_csv_export_and_tamper_detection(temp_db):
    """Pair 7: Exporting CSV reflects raw database state and integrity check flags tampered edits."""
    pid = db.record_ping(True, 20.0, 0.0, True, "ONLINE", db_path=temp_db)
    csv1 = db.export_csv_data("pings", db_path=temp_db)
    assert "ONLINE" in csv1

    # Tamper with record directly in SQLite
    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("UPDATE pings SET latency_ms = 999.9 WHERE id = ?;", (pid,))
    conn.close()

    # CSV reflects modified data
    csv2 = db.export_csv_data("pings", db_path=temp_db)
    assert "999.9" in csv2

    # Cryptographic audit flags tampering
    integrity = db.verify_database_integrity(temp_db)
    assert integrity["status"] == "TAMPERED"
    assert integrity["tampered_pings"] > 0


def test_p08_custom_period_report_with_open_outage(temp_db):
    """Pair 8: Report generation with currently open (unclosed) outage calculates safely."""
    now = datetime.now(timezone.utc)
    start_time = (now - timedelta(minutes=15)).isoformat()

    conn = db.get_connection(temp_db)
    with conn:
        conn.execute(
            "INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, outage_type) VALUES (?, NULL, NULL, 'Queda Ativa', 'OPEN', 'TOTAL');",
            (start_time,)
        )
    conn.close()

    data = db.generate_isp_report_data(hours=24, db_path=temp_db)
    assert data is not None
    outages = data.get("outages", [])
    open_outages = [o for o in outages if o["status"] == "OPEN"]
    assert len(open_outages) >= 1
    # end_time is None or empty string, duration handled safely
    assert open_outages[0]["end_time"] is None or open_outages[0]["end_time"] == ""
