"""
conftest.py - Pytest fixtures and test harness for NetMon E2E testing suite.
Provides isolated SQLite test environments, mock services, and ephemeral HTTP test server.
"""

import os
import sys
import time
import json
import sqlite3
import threading
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
import pytest

# Ensure root claro directory is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import db
import web_server
import isp_detector
import rfc3161


ORIG_DB_PATH = db.DB_PATH


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """
    Creates an isolated temporary SQLite database for each test.
    Patches db.DB_PATH and db.get_connection so all operations are hermetic.
    """
    test_db_path = str(tmp_path / "test_netmon.db")
    monkeypatch.setattr(db, "_db_initialized", False)
    monkeypatch.setattr(db, "DB_PATH", test_db_path)

    # Initialize schema
    db.init_db(test_db_path)

    # Intercept get_connection so calls without arguments or with default paths route to test_db_path
    def patched_get_connection(db_path=None):
        if db_path is None or db_path == ORIG_DB_PATH or db_path == db.DB_PATH or db_path == test_db_path:
            target = test_db_path
        else:
            target = db_path
        conn = sqlite3.connect(target, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    monkeypatch.setattr(db, "get_connection", patched_get_connection)
    yield test_db_path


@pytest.fixture
def mock_isp_data():
    """Authoritative mock data for ISP identification."""
    return {
        "isp": "Claro NXT Telecomunicacoes Ltda",
        "org": "Claro NXT Telecomunicacoes Ltda",
        "asn": "AS28573",
        "ip": "189.120.45.67",
        "city": "São Paulo",
        "region": "São Paulo",
        "country": "Brazil",
        "local_ip": "192.168.1.100"
    }


@pytest.fixture
def mock_isp(monkeypatch, mock_isp_data):
    """Mocks isp_detector to return consistent deterministic data."""
    monkeypatch.setattr(isp_detector, "get_isp_info", lambda force_refresh=False: dict(mock_isp_data))
    monkeypatch.setattr(web_server, "get_local_ip", lambda: "192.168.1.100")
    return mock_isp_data


@pytest.fixture
def mock_rfc3161(monkeypatch):
    """Mocks RFC 3161 timestamping to avoid external network calls during test runs."""
    def fake_request(hash_val, timeout=4):
        return (f"mock_tsr_token_for_{hash_val[:8]}", "DigiCert SHA256 TimeStamp Responder")
    def fake_verify(tsr_token, hash_val):
        return True
    monkeypatch.setattr(rfc3161, "request_rfc3161_timestamp", fake_request)
    monkeypatch.setattr(rfc3161, "verify_tsr_token", fake_verify)


@pytest.fixture
def populated_db(temp_db, mock_isp_data):
    """Seeds the temporary database with a realistic baseline of telemetry and outages."""
    now = datetime.now(timezone.utc)

    # 1. Configs
    db.set_config("isp_name", mock_isp_data["isp"], temp_db)
    db.set_config("contract_holder", "Marco Aurelio Silva", temp_db)
    db.set_config("contract_number", "NET-SP-2026-88910", temp_db)
    db.set_config("installation_address", "Rua Augusta, 1500, Apto 82, Consolação, São Paulo - SP", temp_db)
    db.set_config("monthly_fee", "149.90", temp_db)
    db.set_config("contracted_download_mbps", "500", temp_db)
    db.set_config("contracted_upload_mbps", "250", temp_db)

    # 2. Sequential pings (last 10 checks)
    for i in range(10, 0, -1):
        ts = (now - timedelta(minutes=i * 2)).isoformat()
        is_online = 1 if i != 4 else 0
        loss = 0.0 if i != 4 else 100.0
        status = "ONLINE" if is_online else "OFFLINE"
        conn = db.get_connection(temp_db)
        with conn:
            cur = conn.execute("SELECT record_hash FROM pings ORDER BY id DESC LIMIT 1;")
            lr = cur.fetchone()
            prev_h = lr["record_hash"] if lr and lr["record_hash"] else "GENESIS"
            sig = f"{prev_h}|{ts}|{is_online}|18.5|{loss}|1|{status}|2.1"
            rec_h = db.compute_hash(sig)
            conn.execute(
                "INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status, jitter_ms, details, record_hash, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (ts, is_online, 18.5, loss, 1, status, 2.1, "test-ping", rec_h, prev_h)
            )
        conn.close()

    # 3. Successful speed tests
    for i in range(3, 0, -1):
        ts = (now - timedelta(hours=i * 2)).isoformat()
        conn = db.get_connection(temp_db)
        with conn:
            cur = conn.execute("SELECT record_hash FROM speed_tests ORDER BY id DESC LIMIT 1;")
            lr = cur.fetchone()
            prev_h = lr["record_hash"] if lr and lr["record_hash"] else "GENESIS"
            sig = f"{prev_h}|{ts}|scheduled_10min|485.5|245.2|16.0|SUCCESS"
            rec_h = db.compute_hash(sig)
            conn.execute(
                "INSERT INTO speed_tests (timestamp, trigger_reason, download_mbps, upload_mbps, ping_ms, status, error_message, record_hash, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (ts, "scheduled_10min", 485.5, 245.2, 16.0, "SUCCESS", None, rec_h, prev_h)
            )
        conn.close()

    # 4. Outage history (1 closed outage of 180 seconds)
    outage_start = (now - timedelta(hours=1)).isoformat()
    outage_end = (now - timedelta(hours=1) + timedelta(seconds=180)).isoformat()
    conn = db.get_connection(temp_db)
    with conn:
        sig = f"GENESIS|{outage_start}|{outage_end}|180.0|TOTAL|Perda total de pacotes (100.0%)|CLOSED"
        rec_h = db.compute_hash(sig)
        conn.execute(
            "INSERT INTO outages (start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, outage_type, tsa_authority) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (outage_start, outage_end, 180.0, "Perda total de pacotes (100.0%)", "CLOSED", rec_h, "GENESIS", "TOTAL", "DigiCert SHA256 TimeStamp Responder")
        )
    conn.close()

    return temp_db


@pytest.fixture
def live_server(temp_db, mock_isp):
    """
    Spins up an actual ThreadingHTTPServer on an ephemeral port (port 0).
    Allows true end-to-end HTTP requests with full client/server interactions.
    """
    server = web_server.ThreadingHTTPServer(("127.0.0.1", 0), web_server.NetworkMonitorHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    yield base_url

    server.shutdown()
    server.server_close()


class TestHttpClient:
    """Helper class for HTTP calls against the live server."""
    @staticmethod
    def get_json(url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": "NetMon-Pytest/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)

    @staticmethod
    def get_text(url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "NetMon-Pytest/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8")

    @staticmethod
    def post_json(url: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "NetMon-Pytest/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)


@pytest.fixture
def api_client():
    return TestHttpClient
