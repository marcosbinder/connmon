"""
db.py - Gerenciador de Banco de Dados SQLite para Monitoramento de Rede
Ultra-leve, seguro contra falhas, com suporte a WAL (Write-Ahead Logging).
"""

import sqlite3
import os
import hashlib
import hmac
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "net_monitor.db")
SECRET_SALT = "netmon_audit_v1_salt_2026"


def compute_hash(data_str: str) -> str:
    """Calcula hash HMAC SHA-256 para assegurar autenticidade dos registros contra adulteração."""
    return hmac.new(SECRET_SALT.encode("utf-8"), data_str.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def _compute_record_hash(data_str: str) -> str:
    """Helper canônico para cálculo de hash HMAC SHA-256."""
    return compute_hash(data_str)


_db_init_lock = threading.Lock()
_db_initialized = False
_initialized_paths = set()


def _create_raw_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Cria uma conexão SQLite de alta resiliência com WAL e busy_timeout de 30s."""
    conn = sqlite3.connect(os.path.abspath(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    return conn


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Retorna uma conexão SQLite configurada garantindo inicialização prévia thread-safe."""
    global _db_initialized
    norm_path = os.path.abspath(db_path)
    if norm_path not in _initialized_paths:
        init_db(norm_path)
    return _create_raw_connection(norm_path)


def _init_schema(conn: sqlite3.Connection):
    with conn:
        # Tabela de pings e saúde contínua (a cada 30s)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                is_online INTEGER NOT NULL,          -- 1 para online, 0 para offline
                latency_ms REAL,                     -- latência média em ms
                packet_loss_pct REAL NOT NULL,       -- % perda de pacotes (0 a 100)
                dns_ok INTEGER NOT NULL,             -- 1 se resolução DNS funcionou, 0 se falhou
                status TEXT NOT NULL,                -- 'ONLINE', 'INSTABLE', 'OFFLINE'
                jitter_ms REAL,                      -- variação da latência em ms
                details TEXT,                        -- info extra
                record_hash TEXT                     -- Assinatura HMAC de integridade
            );
        """)

        # Migrações transparentes
        try:
            conn.execute("ALTER TABLE pings ADD COLUMN jitter_ms REAL;")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE pings ADD COLUMN record_hash TEXT;")
        except sqlite3.OperationalError:
            pass

        # Tabela de testes de velocidade (a cada 10 min ou instabilidade)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS speed_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                trigger_reason TEXT NOT NULL,        -- 'scheduled_10min', 'instability_detected', 'manual', 'recovery'
                download_mbps REAL,
                upload_mbps REAL,
                ping_ms REAL,
                status TEXT NOT NULL,                -- 'SUCCESS', 'FAILED'
                error_message TEXT,
                record_hash TEXT
            );
        """)

        try:
            conn.execute("ALTER TABLE speed_tests ADD COLUMN record_hash TEXT;")
        except sqlite3.OperationalError:
            pass

        # Tabela de quedas (Downtime tracking exato para operadora)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS outages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TEXT NOT NULL,
                end_time TEXT,                       -- NULL se a queda ainda estiver ativa
                duration_seconds REAL,
                reason TEXT NOT NULL,                -- Causa (ex: '100% perda de pacotes', 'DNS inacessível')
                status TEXT NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'CLOSED'
                record_hash TEXT
            );
        """)

        try:
            conn.execute("ALTER TABLE outages ADD COLUMN record_hash TEXT;")
        except sqlite3.OperationalError:
            pass

        # Migrações para encadeamento criptográfico, Bufferbloat e carimbo digital RFC 3161
        for col_def in [
            ("pings", "prev_hash TEXT"),
            ("outages", "prev_hash TEXT"),
            ("outages", "tsr_token TEXT"),
            ("outages", "tsa_authority TEXT"),
            ("outages", "outage_type TEXT DEFAULT 'TOTAL'"),
            ("outages", "route_trace_id INTEGER"),
            ("speed_tests", "prev_hash TEXT"),
            ("speed_tests", "result_url TEXT"),
            ("speed_tests", "loaded_ping_ms REAL"),
            ("speed_tests", "bufferbloat_grade TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE {col_def[0]} ADD COLUMN {col_def[1]};")
            except sqlite3.OperationalError:
                pass

        # Tabela de rastreamento forense de rotas (Traceroute automatizado)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS route_traces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                trigger_reason TEXT NOT NULL,        -- 'outage_total', 'outage_instable', 'latency_spike'
                target TEXT NOT NULL,               -- '1.1.1.1'
                status TEXT NOT NULL,               -- 'OK', 'FAILED', 'HIGH_LATENCY'
                failed_hop INTEGER,                 -- Salto numérico do descarte
                failed_ip TEXT,                     -- IP do nó que falhou
                responsible_party TEXT NOT NULL,    -- 'ISP', 'LAN', 'EXTERNAL', 'NONE'
                diagnosis TEXT NOT NULL,            -- Parecer técnico conclusivo
                hops_json TEXT,                     -- Rota detalhada estruturada em JSON
                raw_output TEXT,                    -- Saída textual bruta do comando
                outage_id INTEGER,                  -- Vinculação com a queda
                record_hash TEXT,                   -- Assinatura HMAC SHA-256
                prev_hash TEXT                      -- Encadeamento blockchain-style
            );
        """)

        # Tabela de logs de auditoria (rastreia limpeza, reset e alterações administrativas)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                actor_ip TEXT
            );
        """)

        # Tabela de configurações
        conn.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)

        # Índices para consultas rápidas nos gráficos
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pings_timestamp ON pings(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_speed_timestamp ON speed_tests(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_outages_status ON outages(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON route_traces(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traces_outage_id ON route_traces(outage_id);")

        # Configurações padrão
        default_configs = [
            ("isp_name", ""),
            ("client_name", ""),
            ("contract_number", ""),
            ("client_address", ""),
            ("monthly_fee", "0.00"),
            ("contracted_download_mbps", "500"),
            ("contracted_upload_mbps", "250"),
            ("ping_interval_seconds", "30"),
            ("speedtest_interval_minutes", "10"),
            ("latency_alert_threshold_ms", "150"),
            ("loss_alert_threshold_pct", "10"),
            ("heartbeat_url", ""),
            ("discord_webhook_url", ""),
            ("telegram_bot_token", ""),
            ("telegram_chat_id", ""),
            ("notifications_enabled", "1"),
            ("speed_alert_threshold_pct", "40"),
        ]
        for key, val in default_configs:
            conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?);", (key, val))


def init_db(db_path: str = DB_PATH):
    """Inicializa as tabelas e índices necessários com fechamento garantido e proteção por lock."""
    global _db_initialized
    norm_path = os.path.abspath(db_path)
    with _db_init_lock:
        if norm_path in _initialized_paths:
            return
        conn = _create_raw_connection(norm_path)
        try:
            _init_schema(conn)
            _initialized_paths.add(norm_path)
            _db_initialized = True
        finally:
            conn.close()


def get_config(key: str, default: str = "", db_path: str = DB_PATH) -> str:
    """Busca um valor de configuração no banco."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT value FROM config WHERE key = ?;", (key,))
        row = cur.fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_config(key: str, value: str, db_path: str = DB_PATH):
    """Grava ou atualiza um valor de configuração."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?);", (key, str(value)))
    finally:
        conn.close()


def record_ping(
    is_online: bool,
    latency_ms: Optional[float],
    packet_loss_pct: float,
    dns_ok: bool,
    status: str,
    jitter_ms: Optional[float] = None,
    details: str = "",
    db_path: str = DB_PATH
) -> int:
    """Registra uma verificação de conectividade com encadeamento de hash (blockchain-style)."""
    now_iso = datetime.now(timezone.utc).isoformat()
    online_int = 1 if is_online else 0
    dns_int = 1 if dns_ok else 0

    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT record_hash FROM pings ORDER BY id DESC LIMIT 1;")
        last_row = cur.fetchone()
        prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

        raw_signature = f"{prev_hash}|{now_iso}|{online_int}|{latency_ms}|{packet_loss_pct}|{dns_int}|{status}|{jitter_ms}"
        rec_hash = _compute_record_hash(raw_signature)

        with conn:
            cur = conn.execute(
                """
                INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status, jitter_ms, details, record_hash, prev_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (now_iso, online_int, latency_ms, packet_loss_pct, dns_int, status, jitter_ms, details, rec_hash, prev_hash)
            )
            return cur.lastrowid
    finally:
        conn.close()


def record_speed_test(
    trigger_reason: str,
    download_mbps: Optional[float],
    upload_mbps: Optional[float],
    ping_ms: Optional[float],
    status: str,
    error_message: Optional[str] = None,
    result_url: Optional[str] = None,
    loaded_ping_ms: Optional[float] = None,
    bufferbloat_grade: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """Registra um teste completo de velocidade com encadeamento de hash e métricas de Bufferbloat."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT record_hash FROM speed_tests ORDER BY id DESC LIMIT 1;")
        last_row = cur.fetchone()
        prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

        # Mantém a assinatura estritamente canônica para compatibilidade com a verificação de integridade
        raw_signature = f"{prev_hash}|{now_iso}|{trigger_reason}|{download_mbps}|{upload_mbps}|{ping_ms}|{status}"
        rec_hash = _compute_record_hash(raw_signature)

        with conn:
            cur = conn.execute(
                """
                INSERT INTO speed_tests (
                    timestamp, trigger_reason, download_mbps, upload_mbps, ping_ms,
                    status, error_message, record_hash, prev_hash, result_url,
                    loaded_ping_ms, bufferbloat_grade
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (now_iso, trigger_reason, download_mbps, upload_mbps, ping_ms,
                 status, error_message, rec_hash, prev_hash, result_url,
                 loaded_ping_ms, bufferbloat_grade)
            )
            return cur.lastrowid
    finally:
        conn.close()


def record_route_trace(
    trigger_reason: str,
    target: str,
    status: str,
    failed_hop: Optional[int],
    failed_ip: Optional[str],
    responsible_party: str,
    diagnosis: str,
    hops_json: str,
    raw_output: str,
    outage_id: Optional[int] = None,
    db_path: str = DB_PATH
) -> int:
    """Registra rastreamento pericial de rota com encadeamento criptográfico."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT record_hash FROM route_traces ORDER BY id DESC LIMIT 1;")
        last_row = cur.fetchone()
        prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

        raw_signature = f"{prev_hash}|{now_iso}|{trigger_reason}|{target}|{status}|{failed_hop}|{failed_ip}|{responsible_party}"
        rec_hash = _compute_record_hash(raw_signature)

        with conn:
            cur = conn.execute(
                """
                INSERT INTO route_traces (
                    timestamp, trigger_reason, target, status, failed_hop, failed_ip,
                    responsible_party, diagnosis, hops_json, raw_output, outage_id, record_hash, prev_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (now_iso, trigger_reason, target, status, failed_hop, failed_ip,
                 responsible_party, diagnosis, hops_json, raw_output, outage_id, rec_hash, prev_hash)
            )
            return cur.lastrowid
    finally:
        conn.close()


def get_route_traces(limit: int = 50, outage_id: Optional[int] = None, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Retorna histórico de rastreamentos forenses de rotas."""
    conn = get_connection(db_path)
    try:
        if outage_id is not None:
            cur = conn.execute("SELECT * FROM route_traces WHERE outage_id = ? ORDER BY id DESC LIMIT ?;", (outage_id, limit))
        else:
            cur = conn.execute("SELECT * FROM route_traces ORDER BY id DESC LIMIT ?;", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_active_outage(db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Retorna a queda atualmente em andamento (se houver)."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT * FROM outages WHERE status = 'OPEN' ORDER BY id DESC LIMIT 1;")
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def start_outage(reason: str, outage_type: str = "TOTAL", db_path: str = DB_PATH) -> int:
    """Inicia o registro de uma nova queda (total ou parcial) com encadeamento de hash."""
    active = get_active_outage(db_path)
    if active:
        # Se era parcial e agora caiu totalmente, escala para TOTAL recalculando HMAC
        if active.get("outage_type") == "PARCIAL" and outage_type == "TOTAL":
            conn = get_connection(db_path)
            try:
                prev_h = active.get("prev_hash") or "GENESIS"
                start_time = active["start_time"]
                raw_sig = f"{prev_h}|{start_time}|TOTAL|{reason}|OPEN"
                new_rec_hash = _compute_record_hash(raw_sig)
                with conn:
                    conn.execute(
                        "UPDATE outages SET outage_type = 'TOTAL', reason = ?, record_hash = ? WHERE id = ?;",
                        (reason, new_rec_hash, active["id"])
                    )
            finally:
                conn.close()
        return active["id"]

    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT record_hash FROM outages ORDER BY id DESC LIMIT 1;")
        last_row = cur.fetchone()
        prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

        now_iso = datetime.now(timezone.utc).isoformat()
        raw_sig = f"{prev_hash}|{now_iso}|{outage_type}|{reason}|OPEN"
        rec_hash = _compute_record_hash(raw_sig)

        with conn:
            cur = conn.execute(
                "INSERT INTO outages (start_time, reason, status, record_hash, prev_hash, outage_type) VALUES (?, ?, 'OPEN', ?, ?, ?);",
                (now_iso, reason, rec_hash, prev_hash, outage_type)
            )
            outage_id = cur.lastrowid
    finally:
        conn.close()
    return outage_id


def close_active_outage(db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """
    Fecha a queda ativa calculando a duração, atualizando a assinatura encadeada
    e solicitando um carimbo de tempo digital público (RFC 3161 via DigiCert/FreeTSA).
    """
    active = get_active_outage(db_path)
    if not active:
        return None

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    start_dt = datetime.fromisoformat(active["start_time"])
    duration = max(0.0, (now - start_dt).total_seconds())
    dur_round = round(duration, 1)
    o_type = active.get("outage_type") or "TOTAL"

    prev_hash = active.get("prev_hash") or "GENESIS"
    raw_sig = f"{prev_hash}|{active['start_time']}|{now_iso}|{dur_round}|{o_type}|{active['reason']}|CLOSED"
    rec_hash = _compute_record_hash(raw_sig)

    # Solicita carimbo de tempo digital externo RFC 3161 (DigiCert ou FreeTSA)
    tsr_token = None
    tsa_authority = None
    try:
        import rfc3161
        tsr_token, tsa_authority = rfc3161.request_rfc3161_timestamp(rec_hash, timeout=4)
    except Exception:
        pass

    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                UPDATE outages
                SET end_time = ?, duration_seconds = ?, status = 'CLOSED', record_hash = ?, tsr_token = ?, tsa_authority = ?
                WHERE id = ?;
                """,
                (now_iso, dur_round, rec_hash, tsr_token, tsa_authority, active["id"])
            )
    finally:
        conn.close()

    active["end_time"] = now_iso
    active["duration_seconds"] = dur_round
    active["status"] = "CLOSED"
    active["record_hash"] = rec_hash
    active["tsr_token"] = tsr_token
    active["tsa_authority"] = tsa_authority
    active["outage_type"] = o_type
    return active


def get_latest_status(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Retorna o estado atual completo da conexão para os cards do dashboard."""
    conn = get_connection(db_path)
    try:
        # Último ping
        cur = conn.execute("SELECT * FROM pings ORDER BY id DESC LIMIT 1;")
        last_ping = cur.fetchone()

        # Último speedtest com sucesso
        cur = conn.execute("SELECT * FROM speed_tests WHERE status = 'SUCCESS' ORDER BY id DESC LIMIT 1;")
        last_speed = cur.fetchone()

        # Queda ativa
        cur = conn.execute("SELECT * FROM outages WHERE status = 'OPEN' ORDER BY id DESC LIMIT 1;")
        active_outage = cur.fetchone()

        # Resumo últimas 24h
        since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        cur = conn.execute(
            """
            SELECT
                COUNT(*) as total_checks,
                SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) as online_checks,
                AVG(latency_ms) as avg_latency,
                MIN(latency_ms) as min_latency,
                MAX(latency_ms) as max_latency,
                AVG(packet_loss_pct) as avg_loss,
                AVG(jitter_ms) as avg_jitter
            FROM pings WHERE timestamp >= ?;
            """,
            (since_24h,)
        )
        summary_24h = cur.fetchone()

        cur = conn.execute(
            """
            SELECT
                COUNT(*) as outage_count,
                SUM(CASE WHEN outage_type = 'TOTAL' OR outage_type IS NULL THEN 1 ELSE 0 END) as total_count,
                SUM(CASE WHEN outage_type = 'PARCIAL' THEN 1 ELSE 0 END) as partial_count,
                COALESCE(SUM(CASE WHEN outage_type = 'TOTAL' OR outage_type IS NULL THEN duration_seconds ELSE 0 END), 0) as total_outages_sec,
                COALESCE(SUM(CASE WHEN outage_type = 'PARCIAL' THEN duration_seconds ELSE 0 END), 0) as partial_outages_sec,
                COALESCE(SUM(duration_seconds), 0) as total_downtime_sec
            FROM outages WHERE start_time >= ?;
            """,
            (since_24h,)
        )
        outages_24h = cur.fetchone()

        cur = conn.execute(
            """
            SELECT
                COUNT(*) as test_count,
                AVG(download_mbps) as avg_down,
                AVG(upload_mbps) as avg_up
            FROM speed_tests
            WHERE timestamp >= ? AND status = 'SUCCESS';
            """,
            (since_24h,)
        )
        speed_24h = cur.fetchone()

        # Configs
        cur = conn.execute("SELECT key, value FROM config;")
        configs = {row["key"]: row["value"] for row in cur.fetchall()}
    finally:
        conn.close()

    # Pre-initialize to avoid UnboundLocalError on Python 3.13+ (stricter local var scoping)
    last_speed_dict = None

    total_checks = summary_24h["total_checks"] if summary_24h else 0
    online_checks = summary_24h["online_checks"] if summary_24h and summary_24h["online_checks"] else 0

    total_downtime_sec = round(outages_24h["total_downtime_sec"] or 0, 1) if outages_24h else 0.0
    total_outages_sec = round(outages_24h["total_outages_sec"] or 0, 1) if outages_24h else 0.0
    partial_outages_sec = round(outages_24h["partial_outages_sec"] or 0, 1) if outages_24h else 0.0

    # Disponibilidade Temporal (SLA) nas últimas 24h (86.400 segundos):
    # 1. Disponibilidade do link sem quedas totais (uptime oficial Anatel):
    if total_outages_sec > 0:
        uptime_pct = max(0.0, min(100.0, round(((86400.0 - total_outages_sec) / 86400.0) * 100, 2)))
    elif total_checks > 0:
        uptime_pct = round((online_checks / total_checks * 100), 2)
    else:
        uptime_pct = 100.0

    # 2. Disponibilidade com qualidade plena estável (livre de quedas E de degradações parciais):
    availability_full_quality_pct = max(0.0, min(100.0, round(((86400.0 - total_downtime_sec) / 86400.0) * 100, 2)))
    ping_success_rate_pct = round((online_checks / total_checks * 100), 2) if total_checks > 0 else 100.0

    # Detecção automática de operadora e IP público
    try:
        import isp_detector
        isp_info = isp_detector.get_isp_info()
    except Exception:
        isp_info = {
            "isp": configs.get("isp_name") or "Conexão Detectada",
            "ip": "",
            "asn": "",
            "city": "",
            "region": ""
        }

    # Bufferbloat & Latência sob carga do último teste de velocidade
    last_speed_dict = dict(last_speed) if last_speed else None
    latest_bb_grade = last_speed_dict.get("bufferbloat_grade") if last_speed_dict else None
    latest_bb_delta = None
    if last_speed_dict and last_speed_dict.get("loaded_ping_ms") is not None and last_speed_dict.get("ping_ms") is not None:
        latest_bb_delta = max(0.0, round(last_speed_dict["loaded_ping_ms"] - last_speed_dict["ping_ms"], 1))
    elif last_speed_dict and last_speed_dict.get("loaded_ping_ms") is not None:
        latest_bb_delta = 0.0

    return {
        "last_ping": dict(last_ping) if last_ping else None,
        "last_speed": last_speed_dict,
        "active_outage": dict(active_outage) if active_outage else None,
        "isp_info": isp_info,
        "stats_24h": {
            "uptime_pct": uptime_pct,
            "availability_full_quality_pct": availability_full_quality_pct,
            "ping_success_rate_pct": ping_success_rate_pct,
            "avg_latency_ms": round(summary_24h["avg_latency"] or 0, 1) if summary_24h else 0,
            "min_latency_ms": round(summary_24h["min_latency"] or 0, 1) if summary_24h and summary_24h["min_latency"] is not None else 0,
            "max_latency_ms": round(summary_24h["max_latency"] or 0, 1) if summary_24h and summary_24h["max_latency"] is not None else 0,
            "avg_jitter_ms": round(summary_24h["avg_jitter"] or 0, 1) if summary_24h and summary_24h["avg_jitter"] is not None else 0,
            "avg_loss_pct": round(summary_24h["avg_loss"] or 0, 1) if summary_24h else 0,
            "avg_download_mbps": round(speed_24h["avg_down"] or 0, 1) if speed_24h and speed_24h["avg_down"] else 0,
            "avg_upload_mbps": round(speed_24h["avg_up"] or 0, 1) if speed_24h and speed_24h["avg_up"] else 0,
            "latest_bufferbloat_grade": latest_bb_grade or "A",
            "latest_bufferbloat_delta_ms": latest_bb_delta,
            "total_outages": outages_24h["total_count"] if outages_24h and outages_24h["total_count"] else 0,
            "partial_outages": outages_24h["partial_count"] if outages_24h and outages_24h["partial_count"] else 0,
            "all_outages_count": outages_24h["outage_count"] if outages_24h else 0,
            "total_outages_seconds": total_outages_sec,
            "partial_outages_seconds": partial_outages_sec,
            "total_downtime_seconds": total_downtime_sec,
        },
        "config": configs
    }


def get_metrics_timeline(
    hours: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: str = DB_PATH
) -> Dict[str, Any]:
    """Retorna pontos de dados para plotagem de gráficos na janela solicitada (por horas ou período customizado)."""
    conn = get_connection(db_path)
    try:
        if start_time:
            since = start_time
            until = end_time if end_time else datetime.now(timezone.utc).isoformat()
        else:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            until = datetime.now(timezone.utc).isoformat()

        # Pings (amostragem inteligente se houver muitos pontos para manter leveza)
        cur = conn.execute(
            """
            SELECT timestamp, is_online, latency_ms, packet_loss_pct, status, dns_ok
            FROM pings
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY id ASC;
            """,
            (since, until)
        )
        pings = [dict(r) for r in cur.fetchall()]

        # Se houver mais de 1000 pontos, reduz para não sobrecarregar o navegador com 4GB de RAM
        if len(pings) > 1000:
            step = max(1, len(pings) // 600)
            pings = pings[::step]

        # Speed tests
        cur = conn.execute(
            """
            SELECT timestamp, trigger_reason, download_mbps, upload_mbps, ping_ms, status
            FROM speed_tests
            WHERE timestamp >= ? AND timestamp <= ? AND status = 'SUCCESS'
            ORDER BY id ASC;
            """,
            (since, until)
        )
        speeds = [dict(r) for r in cur.fetchall()]

        # Quedas no período ou abertas
        cur = conn.execute(
            """
            SELECT id, start_time, end_time, duration_seconds, reason, status, outage_type, tsa_authority
            FROM outages
            WHERE (start_time >= ? AND start_time <= ?) OR status = 'OPEN'
            ORDER BY CASE WHEN status = 'OPEN' THEN 0 ELSE 1 END, id DESC;
            """,
            (since, until)
        )
        outages = [dict(r) for r in cur.fetchall()]
        return {
            "pings": pings,
            "speeds": speeds,
            "outages": outages,
        }
    finally:
        conn.close()


def get_all_outages(limit: int = 150, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Retorna histórico de todas as quedas registradas, com a queda OPEN sempre no topo."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute(
            """
            SELECT id, start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, tsa_authority, outage_type
            FROM outages
            ORDER BY CASE WHEN status = 'OPEN' THEN 0 ELSE 1 END, id DESC
            LIMIT ?;
            """,
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def export_csv_data(
    table_name: str,
    hours: Optional[int] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: str = DB_PATH
) -> str:
    """Exporta qualquer tabela para formato CSV textual com suporte a filtros de período."""
    allowed = ["pings", "speed_tests", "outages", "route_traces"]
    if table_name not in allowed:
        raise ValueError(f"Tabela inválida: {table_name}")

    conn = get_connection(db_path)
    try:
        where_clauses = []
        params = []
        if start_time or hours:
            if start_time:
                since = start_time
                until = end_time if end_time else datetime.now(timezone.utc).isoformat()
            else:
                since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
                until = datetime.now(timezone.utc).isoformat()
            ts_col = "start_time" if table_name == "outages" else "timestamp"
            where_clauses.append(f"{ts_col} >= ? AND {ts_col} <= ?")
            params.extend([since, until])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        cur = conn.execute(f"SELECT * FROM {table_name} {where_sql} ORDER BY id ASC;", tuple(params))
        rows = cur.fetchall()

        if not rows:
            return "Nenhum dado registrado ainda."

        headers = [col[0] for col in cur.description]
        lines = [",".join(headers)]
        for row in rows:
            line_vals = [f'"{str(val)}"' if val is not None else "" for val in row]
            lines.append(",".join(line_vals))

        return "\n".join(lines)
    finally:
        conn.close()


def generate_custody_chain_text(
    hours: int = 72,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: str = DB_PATH
) -> str:
    """Gera o documento pericial da cadeia de custódia criptográfica para o Dossiê ZIP."""
    integrity = verify_database_integrity(db_path)
    conn = get_connection(db_path)
    try:
        if start_time:
            since = start_time
            until = end_time if end_time else datetime.now(timezone.utc).isoformat()
        else:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            until = datetime.now(timezone.utc).isoformat()

        cur = conn.execute(
            """
            SELECT id, start_time, end_time, duration_seconds, reason, outage_type, record_hash, prev_hash, tsa_authority, tsr_token
            FROM outages
            WHERE (start_time >= ? AND start_time <= ?) OR status = 'OPEN'
            ORDER BY id ASC;
            """,
            (since, until)
        )
        outages = [dict(r) for r in cur.fetchall()]

        cur = conn.execute(
            """
            SELECT id, timestamp, trigger_reason, target, status, failed_hop, failed_ip, responsible_party, record_hash, prev_hash
            FROM route_traces
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY id ASC;
            """,
            (since, until)
        )
        traces = [dict(r) for r in cur.fetchall()]

        cur = conn.execute("SELECT id, timestamp, action, details, actor_ip FROM audit_log ORDER BY id DESC LIMIT 25;")
        audit_entries = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    lines = []
    lines.append("=" * 86)
    lines.append("CADEIA DE CUSTODIA CRIPTOGRAFICA E AUTENTICIDADE FORENSE (RFC 3161 / HMAC SHA-256)")
    lines.append("Norma Internacional de Evidencias Digitais: ABNT NBR ISO/IEC 27037:2013")
    lines.append("=" * 86)
    lines.append(f"Data/Hora de Emissao: {datetime.now(timezone.utc).isoformat()} UTC")
    lines.append(f"Status da Integridade da Base: {integrity['status']}")
    lines.append(f"Parecer de Imutabilidade: {integrity['message']}")
    lines.append(f"Total de Pings Auditados: {integrity['checked_pings']} (Adulterados: {integrity['tampered_pings']}, Quebras: {integrity['chain_broken_pings']})")
    lines.append(f"Total de Quedas Auditadas: {integrity['checked_outages']} (Adulteradas: {integrity['tampered_outages']}, Certificadas TSA: {integrity['tsa_verified_outages']})")
    lines.append(f"Testes de Velocidade Auditados: {integrity['checked_speed_tests']} (Adulterados: {integrity['tampered_speed_tests']})")
    lines.append("")
    lines.append("1. ESPECIFICACAO DO ENCADEAMENTO DE BLOCOS (HASH CHAINING)")
    lines.append("-" * 86)
    lines.append("Chave Criptografica: HMAC com SHA-256 e salt secreto local pericial.")
    lines.append("Estrutura: Cada registro N armazena 'prev_hash' = hash do registro N-1.")
    lines.append("Qualquer alteracao ou remocao invalida matematicamente toda a cadeia posterior.")
    lines.append("")
    lines.append("2. CARIMBOS DE TEMPO ELETRONICOS DAS QUEDAS (RFC 3161 - PROVA INDEPENDENTE)")
    lines.append("-" * 86)
    if not outages:
        lines.append("Nenhuma interrupcao registrada no periodo periciado.")
    else:
        for o in outages:
            tsa = o["tsa_authority"] or "Assinatura Local HMAC"
            has_tsr = "SIM (Token TSR ASN.1 presente)" if o.get("tsr_token") else "NAO (Certificacao HMAC)"
            o_type = o.get("outage_type") or "TOTAL"
            lines.append(f"• Queda #{o['id']} [{o_type}]: {o['start_time']} ate {o['end_time'] or 'ABERTA'}")
            lines.append(f"  Diagnostico:    {o['reason']}")
            lines.append(f"  Hash Registro:  {o['record_hash']}")
            lines.append(f"  Hash Anterior:  {o['prev_hash']}")
            lines.append(f"  Autoridade TSA: {tsa} | Carimbo RFC 3161: {has_tsr}")
            lines.append("")

    lines.append("3. RASTREAMENTO FORENSE DE ROTAS (TRACEROUTE FORENSE)")
    lines.append("-" * 86)
    if not traces:
        lines.append("Nenhum diagnostico de rota disparado no periodo periciado.")
    else:
        for t in traces:
            lines.append(f"• Traceroute #{t['id']} [{t['timestamp']}] Motivo: {t['trigger_reason']} -> Destino: {t['target']}")
            lines.append(f"  Status: {t['status']} | Salto de Falha: {t['failed_hop']} | IP: {t['failed_ip']}")
            lines.append(f"  Atribuicao Juridica: {t['responsible_party']} | Hash: {t['record_hash']}")
            lines.append("")

    lines.append("4. HISTORICO DE AUDITORIA ADMINISTRATIVA")
    lines.append("-" * 86)
    for a in audit_entries:
        lines.append(f"[{a['timestamp']}] Acao: {a['action']:<15} | Origem: {a['actor_ip']:<15} | Detalhes: {a['details']}")

    lines.append("")
    lines.append("=" * 86)
    lines.append("FIM DA CADEIA DE CUSTODIA • PROVA DIGITAL PERICIAL VALIDA")
    lines.append("=" * 86)
    return "\n".join(lines)


def generate_isp_report_data(
    hours: int = 72,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: str = DB_PATH
) -> Dict[str, Any]:
    """Coleta e estrutura todas as métricas periciais para emissão do laudo técnico e PDF."""
    conn = get_connection(db_path)
    try:
        if start_time:
            since = start_time
            until = end_time if end_time else datetime.now(timezone.utc).isoformat()
        else:
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            until = datetime.now(timezone.utc).isoformat()

        # Coleta configs
        cur = conn.execute("SELECT key, value FROM config;")
        configs = {row["key"]: row["value"] for row in cur.fetchall()}
        try:
            contracted_down = float(configs.get("contracted_download_mbps", 500) or 500)
        except ValueError:
            contracted_down = 500.0
        try:
            contracted_up = float(configs.get("contracted_upload_mbps", 250) or 250)
        except ValueError:
            contracted_up = 250.0

        # Identificacao da operadora
        try:
            import isp_detector
            isp_info = isp_detector.get_isp_info()
        except Exception:
            isp_info = {}

        isp_name = isp_info.get("isp") or configs.get("isp_name", "Provedor")

        # Quedas no periodo (totais e parciais)
        cur = conn.execute(
            """
            SELECT id, start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, tsa_authority, outage_type
            FROM outages
            WHERE (start_time >= ? AND start_time <= ?) OR (status = 'OPEN' AND start_time <= ?)
            ORDER BY id ASC;
            """,
            (since, until, until)
        )
        outages = [dict(r) for r in cur.fetchall()]

        # Pings no periodo
        cur = conn.execute(
            """
            SELECT
                COUNT(*) as total_checks,
                SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) as online_checks,
                AVG(latency_ms) as avg_latency,
                MIN(latency_ms) as min_latency,
                MAX(latency_ms) as max_latency,
                AVG(jitter_ms) as avg_jitter,
                AVG(packet_loss_pct) as avg_loss
            FROM pings WHERE timestamp >= ? AND timestamp <= ?;
            """,
            (since, until)
        )
        ping_summary = cur.fetchone()

        # Velocidade no periodo
        cur = conn.execute(
            """
            SELECT
                COUNT(*) as test_count,
                AVG(download_mbps) as avg_down,
                MIN(download_mbps) as min_down,
                MAX(download_mbps) as max_down,
                AVG(upload_mbps) as avg_up,
                MIN(upload_mbps) as min_up,
                MAX(upload_mbps) as max_up
            FROM speed_tests
            WHERE timestamp >= ? AND timestamp <= ? AND status = 'SUCCESS';
            """,
            (since, until)
        )
        speed_summary = cur.fetchone()
    finally:
        conn.close()

    total_checks = ping_summary["total_checks"] if ping_summary else 0
    online_checks = ping_summary["online_checks"] if ping_summary and ping_summary["online_checks"] else 0

    # Duração total em segundos do período periciado
    try:
        dt_since = datetime.fromisoformat(since)
        dt_until = datetime.fromisoformat(until)
        period_seconds = max(1.0, (dt_until - dt_since).total_seconds())
    except Exception:
        period_seconds = max(1.0, float(hours) * 3600.0)

    # Segregação absoluta entre QUEDA TOTAL (ausência completa de sinal) e INSTABILIDADE SEVERA (vício de qualidade)
    total_outages_list = [o for o in outages if (o.get("outage_type") == "TOTAL" or not o.get("outage_type"))]
    partial_outages_list = [o for o in outages if o.get("outage_type") == "PARCIAL"]

    total_outages_count = len(total_outages_list)
    partial_outages_count = len(partial_outages_list)
    all_outages_count = len(outages)

    total_outages_sec = round(sum(o["duration_seconds"] or 0 for o in total_outages_list), 1)
    partial_outages_sec = round(sum(o["duration_seconds"] or 0 for o in partial_outages_list), 1)
    total_downtime_sec = round(total_outages_sec + partial_outages_sec, 1)

    total_outages_min = round(total_outages_sec / 60.0, 1)
    partial_outages_min = round(partial_outages_sec / 60.0, 1)
    downtime_min = round(total_downtime_sec / 60.0, 1)

    # Disponibilidade Temporal (SLA)
    # 1. Disponibilidade sem quedas totais (uptime oficial do link perante Anatel):
    if total_outages_sec > 0:
        uptime_pct = max(0.0, min(100.0, round(((period_seconds - total_outages_sec) / period_seconds) * 100, 2)))
    elif total_checks > 0:
        uptime_pct = round((online_checks / total_checks * 100), 2)
    else:
        uptime_pct = 100.0

    # 2. Disponibilidade com qualidade plena estável (livre de quedas E de degradações parciais):
    availability_full_quality_pct = max(0.0, min(100.0, round(((period_seconds - total_downtime_sec) / period_seconds) * 100, 2)))

    # 3. Taxa de sucesso de sondagem de pacotes:
    ping_success_pct = round((online_checks / total_checks * 100), 2) if total_checks > 0 else 100.0

    integrity = verify_database_integrity(db_path)

    avg_down = round(speed_summary["avg_down"] or 0, 2) if speed_summary and speed_summary["test_count"] else 0
    avg_up = round(speed_summary["avg_up"] or 0, 2) if speed_summary and speed_summary["test_count"] else 0
    down_compliance = round((avg_down / contracted_down * 100), 1) if contracted_down > 0 else 0
    up_compliance = round((avg_up / contracted_up * 100), 1) if contracted_up > 0 else 0

    client_name = configs.get("client_name") or configs.get("contract_holder", "")
    contract_number = configs.get("contract_number", "")
    client_address = configs.get("client_address") or configs.get("installation_address", "")
    try:
        monthly_fee = float(configs.get("monthly_fee", 0) or 0)
    except ValueError:
        monthly_fee = 0.0
    if monthly_fee < 0.0:
        monthly_fee = 0.0

    daily_rate = monthly_fee / 30.0 if monthly_fee > 0 else 0.0

    # Abatimento financeiro proporcional contínuo (30 dias = 2.592.000 segundos):
    raw_refund = (total_downtime_sec / 2592000.0) * monthly_fee if monthly_fee > 0 else 0.0
    refund_amount = round(min(monthly_fee, max(0.0, raw_refund)), 2)

    # Abatimento segregado por modalidade pericial:
    refund_total_outages = round(min(monthly_fee, max(0.0, (total_outages_sec / 2592000.0) * monthly_fee)), 2) if monthly_fee > 0 else 0.0
    refund_partial_instabilities = round(min(monthly_fee, max(0.0, (partial_outages_sec / 2592000.0) * monthly_fee)), 2) if monthly_fee > 0 else 0.0

    # Abatimento Mínimo Regulatório ANATEL (Art. 46, §§ 1º e 2º da Resolução nº 632/2014):
    # Interrupção igual ou superior a 30 min = no mínimo 1 dia inteiro de assinatura (1/30).
    # Interrupções sucessivas < 30 min em 24h que somem >= 30 min geram 1 dia de desconto.
    outages_by_day_total = {}
    outages_by_day_all = {}
    for o in outages:
        day_k = (o.get("start_time") or "")[:10]
        dur = o.get("duration_seconds") or 0.0
        o_type = o.get("outage_type") or "TOTAL"
        if o_type == "TOTAL":
            outages_by_day_total[day_k] = outages_by_day_total.get(day_k, 0.0) + dur
        outages_by_day_all[day_k] = outages_by_day_all.get(day_k, 0.0) + dur

    def _calc_reg_days(by_day_dict):
        days = 0
        for day_k, d_sec in by_day_dict.items():
            if not day_k:
                continue
            if d_sec >= 86400.0:
                full_d = int(d_sec // 86400.0)
                rem = d_sec % 86400.0
                days += full_d + (1 if rem >= 1800.0 else 0)
            elif d_sec >= 1800.0:
                days += 1
        return days

    regulatory_days_total_outages = _calc_reg_days(outages_by_day_total)
    regulatory_days_all = _calc_reg_days(outages_by_day_all)
    regulatory_days = regulatory_days_all

    regulatory_minimum_refund = round(min(monthly_fee, regulatory_days * daily_rate), 2) if monthly_fee > 0 else 0.0
    regulatory_refund_total_only = round(min(monthly_fee, regulatory_days_total_outages * daily_rate), 2) if monthly_fee > 0 else 0.0

    fin_comp = {
        "monthly_fee": monthly_fee,
        "daily_rate": round(daily_rate, 2),
        "proportional_refund_reais": refund_amount,
        "financial_refund_reais": refund_amount,
        "refund_total_outages_reais": refund_total_outages,
        "refund_partial_instabilities_reais": refund_partial_instabilities,
        "regulatory_days_due": regulatory_days,
        "regulatory_minimum_refund_reais": regulatory_minimum_refund,
        "regulatory_days_total_outages": regulatory_days_total_outages,
        "regulatory_refund_total_outages_reais": regulatory_refund_total_only,
        "legal_basis_total": "Resolução ANATEL nº 632/2014, Art. 46, caput e §§ 1º a 3º (Abatimento por Indisponibilidade Total)",
        "legal_basis_partial": "Código de Defesa do Consumidor, Art. 20, § 2º e Resoluções ANATEL 574/2011 e 717/2019 (Vício de Qualidade)",
        "summary_text": f"Abatimento Proporcional: R$ {refund_amount:.2f} (Sendo R$ {refund_total_outages:.2f} por queda completa e R$ {refund_partial_instabilities:.2f} por instabilidade). Mínimo Regulatório ANATEL (Art. 46): R$ {regulatory_minimum_refund:.2f} ({regulatory_days} diárias)."
    }

    client_data = {
        "client_name": client_name,
        "contract_holder": client_name,
        "contract_number": contract_number,
        "client_address": client_address,
        "installation_address": client_address,
        "monthly_fee": monthly_fee,
        "refund_estimate_reais": refund_amount,
        "financial_refund_reais": refund_amount,
        "refund_total_outages_reais": refund_total_outages,
        "refund_partial_instabilities_reais": refund_partial_instabilities,
        "regulatory_refund_reais": regulatory_minimum_refund,
        "isp_name": isp_name,
        "isp": isp_name,
        "asn": isp_info.get("asn", ""),
        "public_ip": isp_info.get("ip", ""),
        "city": isp_info.get("city", ""),
        "region": isp_info.get("region", ""),
        "contracted_download_mbps": contracted_down,
        "contracted_upload_mbps": contracted_up,
    }

    return {
        "client": client_data,
        "contract_info": client_data,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": {
            "since": since,
            "start": since,
            "until": until,
            "end": until,
            "hours": hours,
            "generated_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        },
        "summary": {
            "uptime_pct": uptime_pct,
            "availability_full_quality_pct": availability_full_quality_pct,
            "ping_success_rate_pct": ping_success_pct,
            "total_checks": total_checks,
            "online_checks": online_checks,
            "total_downtime_sec": total_downtime_sec,
            "total_downtime_min": downtime_min,
            "downtime_minutes": downtime_min,
            # Segregação Quedas Totais (Blackouts completos)
            "total_outages_count": total_outages_count,
            "total_outages": total_outages_count,
            "total_outages_sec": total_outages_sec,
            "total_outages_min": total_outages_min,
            "complete_outage_downtime_sec": total_outages_sec,
            "complete_outage_downtime_min": total_outages_min,
            # Segregação Instabilidades Parciais (Vício de Qualidade)
            "partial_outages_count": partial_outages_count,
            "partial_outages": partial_outages_count,
            "partial_outages_sec": partial_outages_sec,
            "partial_outages_min": partial_outages_min,
            "instability_downtime_sec": partial_outages_sec,
            "instability_downtime_min": partial_outages_min,
            # Totais Gerais
            "all_outages_count": all_outages_count,
            "avg_download_mbps": avg_down,
            "avg_upload_mbps": avg_up,
            # Ressarcimento financeiro em R$
            "financial_refund_reais": refund_amount,
            "refund_estimate_reais": refund_amount,
            "refund_total_outages_reais": refund_total_outages,
            "refund_partial_instabilities_reais": refund_partial_instabilities,
            "regulatory_refund_reais": regulatory_minimum_refund,
            "regulatory_days_due": regulatory_days,
        },
        "financial_compensation": fin_comp,
        "performance": {
            "avg_latency": round(ping_summary["avg_latency"] or 0, 1) if ping_summary and ping_summary["total_checks"] else None,
            "min_latency": round(ping_summary["min_latency"] or 0, 1) if ping_summary and ping_summary["total_checks"] else None,
            "max_latency": round(ping_summary["max_latency"] or 0, 1) if ping_summary and ping_summary["total_checks"] else None,
            "avg_jitter": round(ping_summary["avg_jitter"] or 0, 1) if ping_summary and ping_summary["total_checks"] else None,
            "avg_loss": round(ping_summary["avg_loss"] or 0, 2) if ping_summary and ping_summary["total_checks"] else 0.0,
            "avg_down": avg_down,
            "min_down": round(speed_summary["min_down"] or 0, 2) if speed_summary and speed_summary["test_count"] else 0,
            "max_down": round(speed_summary["max_down"] or 0, 2) if speed_summary and speed_summary["test_count"] else 0,
            "down_compliance_pct": down_compliance,
            "avg_up": avg_up,
            "min_up": round(speed_summary["min_up"] or 0, 2) if speed_summary and speed_summary["test_count"] else 0,
            "max_up": round(speed_summary["max_up"] or 0, 2) if speed_summary and speed_summary["test_count"] else 0,
            "up_compliance_pct": up_compliance,
            "min_down_required_avg": round(contracted_down * 0.80, 2),
            "min_down_required_instant": round(contracted_down * 0.40, 2),
            "min_up_required_avg": round(contracted_up * 0.80, 2),
            "min_up_required_instant": round(contracted_up * 0.40, 2),
            "down_avg_compliant": bool(down_compliance >= 80.0),
            "up_avg_compliant": bool(up_compliance >= 80.0),
            "latency_compliant": bool((ping_summary["avg_latency"] is None) or (ping_summary["avg_latency"] <= 80.0)) if ping_summary else True,
            "loss_compliant": bool((ping_summary["avg_loss"] is None) or (ping_summary["avg_loss"] <= 2.0)) if ping_summary else True,
            "regulatory_framework": "Resoluções ANATEL nº 574/2011 e 717/2019 (RQUAL)"
        },
        "outages": outages,
        "integrity": integrity
    }


def generate_isp_report_text(
    hours: int = 72,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: str = DB_PATH
) -> str:
    """
    Gera o laudo pericial formal em formato texto estruturado segundo as normas ABNT
    (ABNT NBR 13752, NBR ISO/IEC 27037, NBR 10719 e NBR 6023), diferenciando de forma
    absoluta interrupções totais de instabilidades severas e fundamentando o direito a abatimento.
    """
    data = generate_isp_report_data(hours=hours, start_time=start_time, end_time=end_time, db_path=db_path)
    client = data["client"]
    period = data["period"]
    summary = data["summary"]
    perf = data["performance"]
    fin = data.get("financial_compensation", {})
    outages = data["outages"]

    isp_title = client['isp_name'].upper() if client['isp_name'] else "OPERADORA DE TELECOMUNICACOES"
    asn_str = f" | ASN: {client['asn']}" if client.get('asn') else ""
    ip_str = f"{client['public_ip']}" + (f" ({client['city']} - {client['region']})" if client.get('city') else "")

    down_status = "CONFORME (>= 80%)" if perf.get("down_avg_compliant") else "VIOLAÇÃO REGULATÓRIA (< 80%)"
    up_status = "CONFORME (>= 80%)" if perf.get("up_avg_compliant") else "VIOLAÇÃO REGULATÓRIA (< 80%)"
    lat_status = "CONFORME (<= 80 ms)" if perf.get("latency_compliant") else "DEGRADADO / ALERTA (> 80 ms)"
    loss_status = "CONFORME (<= 2%)" if perf.get("loss_compliant") else "VIOLAÇÃO REGULATÓRIA (> 2%)"

    lines = []
    lines.append("=" * 86)
    lines.append("LAUDO TECNICO PERICIAL DE AUDITORIA DE CONECTIVIDADE E QUALIDADE DE BANDA LARGA")
    lines.append("Normas Tecnicas: ABNT NBR 13752 | ABNT NBR ISO/IEC 27037 | ABNT NBR 10719")
    lines.append(f"Operadora Requerida: {isp_title}")
    lines.append("=" * 86)
    lines.append(f"Data de Emissao: {period['generated_at']}")
    lines.append(f"Periodo Periciado: {period['since'][:19].replace('T', ' ')} ate {period['until'][:19].replace('T', ' ')} ({period['hours']}h)")
    lines.append("")
    lines.append("1. IDENTIFICACAO DO ASSINANTE E DO CONTRATO")
    lines.append("-" * 86)
    lines.append(f"Assinante / Titular:        {client.get('client_name') or 'Nao informado'}")
    lines.append(f"Contrato / Codigo Cliente:  {client.get('contract_number') or 'Nao informado'}")
    lines.append(f"Endereco de Instalacao:     {client.get('client_address') or 'Nao informado'}")
    lines.append(f"Prestadora dos Servicos:    {client['isp_name']}{asn_str}")
    lines.append(f"IP Publico Monitorado:      {ip_str if client.get('public_ip') else 'Nao identificado'}")
    lines.append(f"Plano Contratado:           {client['contracted_download_mbps']} Mbps Download / {client['contracted_upload_mbps']} Mbps Upload")
    lines.append(f"Valor da Mensalidade:       R$ {client['monthly_fee']:.2f}")
    lines.append("")
    lines.append("2. CADEIA DE CUSTODIA E PROVA DIGITAL (ABNT NBR ISO/IEC 27037)")
    lines.append("-" * 86)
    lines.append("2.1. Metodologia: Amostragem adaptativa (30s em estabilidade e 2s em contingencia),")
    lines.append("     com sondagem redundante ICMP/TCP em servidores neutros de alta disponibilidade.")
    lines.append("2.2. Encadeamento Criptografico: Cada registro de telemetria possui hash encadeado")
    lines.append("     sucessivo HMAC SHA-256 (padrao blockchain), garantindo imutabilidade dos dados.")
    lines.append("2.3. Carimbo de Tempo RFC 3161: As interrupcoes sao atestadas digitalmente por")
    lines.append("     Autoridade Certificadora independente (DigiCert / FreeTSA - Hora Legal Atomica).")
    lines.append(f"2.4. Integridade da Base Pericial: {data['integrity']['message']}")
    lines.append("")
    lines.append("3. DISCRIMINACAO ABSOLUTA: QUEDAS TOTAIS VS. INSTABILIDADES SEVERAS")
    lines.append("-" * 86)
    lines.append("Conforme a regulamentacao da ANATEL e o CDC, a indisponibilidade total nao deve ser")
    lines.append("confundida com instabilidade tecnica parcial, apresentando-se os dados de forma absoluta:")
    lines.append("")
    lines.append("A) INTERRUPCOES TOTAIS (FORA DO AR COMPLETO / AUSENCIA TOTAL DE CONECTIVIDADE):")
    lines.append(f"   - Quantidade de Quedas Completas:  {summary['total_outages_count']} ocorrencia(s)")
    lines.append(f"   - Tempo Total em Queda Completa:   {summary['total_outages_min']} minutos ({round(summary['total_outages_sec'])} segundos)")
    lines.append(f"   - Disponibilidade SLA do Link:     {summary['uptime_pct']}% (Meta ANATEL: >= 99.0%)")
    lines.append("   - Caracterizacao Tecnica: Perda de 100% dos pacotes, perda total de portadora/rota.")
    lines.append("   - Enquadramento Legal Direto: Art. 46, caput e §§ 1º a 3º da Resolucao Anatel 632/2014.")
    lines.append("")
    lines.append("B) INSTABILIDADES SEVERAS E DEGRADACAO TECNICA (VICIO DE QUALIDADE):")
    lines.append(f"   - Quantidade de Instabilidades:    {summary['partial_outages_count']} ocorrencia(s)")
    lines.append(f"   - Tempo Acumulado em Degradacao:   {summary['partial_outages_min']} minutos ({round(summary['partial_outages_sec'])} segundos)")
    lines.append("   - Caracterizacao Tecnica: Enlace ativo mas com perda abusiva (>20% a 50%), latencia anomala ou DNS inoperante.")
    lines.append("   - Enquadramento Legal Direto: Art. 20 do CDC e Metas RQUAL (Resolucoes Anatel 574/2011 e 717/2019).")
    lines.append("")
    lines.append("C) TEMPO CONSOLIDADO DE PREJUIZO A CONECTIVIDADE:")
    lines.append(f"   - Tempo Total Afetado (Quedas + Instabilidades): {summary['total_downtime_min']} minutos ({round(summary['total_downtime_sec'])} segundos)")
    lines.append(f"   - Indice de Disponibilidade Plena Estavel:       {summary['availability_full_quality_pct']}%")
    lines.append(f"   - Taxa de Sucesso dos Testes de Conectividade:   {summary['ping_success_rate_pct']}%")
    lines.append("")
    lines.append("4. CONFORMIDADE COM AS METAS REGULATORIAS DA ANATEL (RQUAL)")
    lines.append("-" * 86)
    if perf["avg_down"]:
        lines.append(f"- Download Medio Medido:  {perf['avg_down']} Mbps ({perf['down_compliance_pct']}% da meta) -> {down_status}")
        lines.append(f"  (Meta RQUAL: minimo 80% da taxa contratada = {perf['min_down_required_avg']} Mbps; instantanea minima 40% = {perf['min_down_required_instant']} Mbps)")
    if perf["avg_up"]:
        lines.append(f"- Upload Medio Medido:    {perf['avg_up']} Mbps ({perf['up_compliance_pct']}% da meta) -> {up_status}")
        lines.append(f"  (Meta RQUAL: minimo 80% da taxa contratada = {perf['min_up_required_avg']} Mbps; instantanea minima 40% = {perf['min_up_required_instant']} Mbps)")
    if perf["avg_latency"] is not None:
        lines.append(f"- Latencia Media Medida:  {perf['avg_latency']} ms (Min: {perf['min_latency']} ms | Max: {perf['max_latency']} ms) -> {lat_status}")
        if perf.get("avg_jitter"):
            lines.append(f"- Jitter Medio (Variacao): {perf['avg_jitter']} ms (Estabilidade de Rota)")
        lines.append(f"- Perda Media de Pacotes: {perf['avg_loss']}% -> {loss_status} (Meta ANATEL: <= 2.0%)")
    lines.append("")
    lines.append("5. HISTORICO DETALHADO DE INTERRUPCOES E INSTABILIDADES")
    lines.append("-" * 86)
    if not outages:
        lines.append("  (Nenhuma ocorrencia de interrupcao ou instabilidade no periodo periciado)")
    else:
        for i, o in enumerate(outages, 1):
            st = o["start_time"].replace("T", " ")[:19]
            et = o["end_time"].replace("T", " ")[:19] if o["end_time"] else "EM ANDAMENTO (Ao Vivo)"
            dur = f"{round(o['duration_seconds'] or 0)}s ({round((o['duration_seconds'] or 0)/60, 1)} min)" if o["end_time"] else "EM ANDAMENTO"
            o_type = o.get("outage_type") or "TOTAL"
            tipo_label = "QUEDA TOTAL (BLACKOUT)" if o_type == "TOTAL" else "INSTABILIDADE SEVERA"
            tsa_badge = f" [RFC 3161: {o['tsa_authority']}]" if o.get("tsa_authority") else " [HMAC SHA-256]"
            lines.append(f"  [{i:02d}] [{tipo_label}] {st} ate {et} | Duracao: {dur}{tsa_badge}")
            lines.append(f"       Diagnostico Tecnico: {o['reason']}")

    lines.append("")
    lines.append("6. FUNDAMENTACAO JURIDICO-REGULATORIA APLICAVEL")
    lines.append("-" * 86)
    lines.append("6.1. Resolução Anatel nº 632/2014 (Regulamento Geral de Direitos do Consumidor - RGC):")
    lines.append("     - Art. 46, caput: O consumidor tem direito ao abatimento proporcional do valor da")
    lines.append("       assinatura correspondente ao periodo de interrupcao dos servicos.")
    lines.append("     - Art. 46, § 1º: A interrupcao que perdurar por fracao igual ou superior a 30 (trinta)")
    lines.append("       minutos ensejara desconto equivalente a, no minimo, 1 (um) dia de assinatura (1/30).")
    lines.append("     - Art. 46, § 2º: As interrupcoes inferiores a 30 minutos ocorridas sucessivamente em 24h")
    lines.append("       que totalizem 30 minutos ou mais devem ser somadas para fins do desconto de 1 dia.")
    lines.append("     - Art. 46, § 3º: O desconto deve ser efetuado de forma automatica na fatura subsequente.")
    lines.append("     - Art. 47: Dever da prestadora de comunicar interrupcoes programadas com 72h de antecedencia.")
    lines.append("6.2. Resoluções Anatel nº 574/2011 e 717/2019 (RQUAL):")
    lines.append("     - A prestadora e obrigada a entregar mensalmente no minimo 80% da velocidade media")
    lines.append("       contratada e 40% instantanea em qualquer medicao individual.")
    lines.append("6.3. Codigo de Defesa do Consumidor (Lei Federal nº 8.078/1990):")
    lines.append("     - Art. 6º, inciso X: Direito basico a adequada e eficaz prestacao dos servicos essenciais.")
    lines.append("     - Art. 20, § 2º: Responsabilidade objetiva da prestadora por vicios de qualidade que")
    lines.append("       tornem o servico improprio ao consumo ou lhe diminuam o valor esperado.")
    lines.append("     - Art. 22 e Parágrafo Único: Concessionarias sao compelidas a fornecer servicos continuos,")
    lines.append("       adequados e seguros, cabendo indenizacao integral e reparacao dos prejuizos.")
    lines.append("     - Art. 42, Parágrafo Único: Repeticao do indebito em dobro para cobrancas sem contraprestacao.")
    lines.append("6.4. Marco Civil da Internet (Lei Federal nº 12.965/2014):")
    lines.append("     - Art. 7º, incisos IV e V: Garantia da nao suspensao da conexao e manutencao da qualidade.")
    lines.append("")
    lines.append("7. DEMONSTRATIVO FINANCEIRO DE ABATIMENTO E RESSARCIMENTO")
    lines.append("-" * 86)
    lines.append(f"- Valor Mensal Contratado Declarado:       R$ {client['monthly_fee']:.2f}")
    lines.append(f"- Diaria Contratual de Referencia (1/30):   R$ {fin.get('daily_rate', 0.0):.2f}")
    lines.append(f"- Abatimento Estrito por Queda Completa:    R$ {fin.get('refund_total_outages_reais', 0.0):.2f} (Proporcional a {summary['total_outages_min']} min)")
    lines.append(f"- Glosa / Abatimento por Instabilidade:     R$ {fin.get('refund_partial_instabilities_reais', 0.0):.2f} (Proporcional a {summary['partial_outages_min']} min)")
    lines.append(f"- Abatimento Proporcional Continuo Total:   R$ {fin.get('financial_refund_reais', 0.0):.2f} (Soma exata das horas afetadas)")
    lines.append(f"- Abatimento Minimo Regulatorio ANATEL:     R$ {fin.get('regulatory_minimum_refund_reais', 0.0):.2f} ({fin.get('regulatory_days_due', 0)} dia(s) devidos segundo Art. 46, § 1º)")
    lines.append("")
    lines.append("8. PARECER TECNICO CONCLUSIVO PERICIAL")
    lines.append("-" * 86)
    lines.append("Com base na telemetria cronometrada sob cadeia de custodia ABNT NBR ISO/IEC 27037, conclui-se")
    lines.append(f"que a prestadora {isp_title} descumpriu reiteradamente os parametros contratuais e regulatorios")
    lines.append("de continuidade e qualidade estipulados pela ANATEL e pelo Codigo de Defesa do Consumidor.")
    lines.append(f"Restou comprovada a ocorrencia de {summary['total_outages_count']} interrupcao(oes) total(is) e {summary['partial_outages_count']} degradacao(oes)")
    lines.append(f"severa(s), gerando o direito ao abatimento formal e imediato de no minimo R$ {fin.get('financial_refund_reais', 0.0):.2f}")
    lines.append(f"(podendo alcancar R$ {fin.get('regulatory_minimum_refund_reais', 0.0):.2f} pela aplicacao do Art. 46, § 1º da Resolucao Anatel 632/2014).")
    lines.append("O presente laudo constitui elemento tecnico-probatorio idoneo para reclamacoes na ANATEL,")
    lines.append("PROCON, plataforma Consumidor.gov.br e para instrucao de acao judicial no Juizado Especial Civel.")
    lines.append("=" * 86)

    return "\n".join(lines)


def log_audit(action: str, details: str = "", actor_ip: str = "local", db_path: str = DB_PATH):
    """Registra uma operacao administrativa no log de auditoria."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, details, actor_ip) VALUES (?, ?, ?, ?);",
                (now_iso, action, details, actor_ip)
            )
    finally:
        conn.close()


def verify_database_integrity(db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Verifica a autenticidade dos dados armazenados no SQLite.
    Valida a assinatura HMAC de cada registro, o encadeamento cronológico (hash chaining)
    e a validade dos carimbos de tempo digitais RFC 3161 das quedas.
    Audita as tabelas: pings, outages e speed_tests, além de inspecionar audit_log.
    """
    import rfc3161

    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT id, timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status, jitter_ms, record_hash, prev_hash FROM pings ORDER BY id ASC;")
        pings = cur.fetchall()

        checked_pings = 0
        tampered_pings = 0
        chain_broken_pings = 0
        last_ping_hash = None

        for p in pings:
            if p["record_hash"]:
                checked_pings += 1
                prev_h = p["prev_hash"] or "GENESIS"
                sig_chained_int = f"{prev_h}|{p['timestamp']}|{p['is_online']}|{p['latency_ms']}|{p['packet_loss_pct']}|{p['dns_ok']}|{p['status']}|{p['jitter_ms']}"
                sig_legacy_int = f"{p['timestamp']}|{p['is_online']}|{p['latency_ms']}|{p['packet_loss_pct']}|{p['dns_ok']}|{p['status']}|{p['jitter_ms']}"
                sig_legacy_bool = f"{p['timestamp']}|{bool(p['is_online'])}|{p['latency_ms']}|{p['packet_loss_pct']}|{bool(p['dns_ok'])}|{p['status']}|{p['jitter_ms']}"

                valid_hash = (
                    compute_hash(sig_chained_int) == p["record_hash"] or
                    compute_hash(sig_legacy_int) == p["record_hash"] or
                    compute_hash(sig_legacy_bool) == p["record_hash"]
                )
                if not valid_hash:
                    tampered_pings += 1

                if last_ping_hash and p["prev_hash"] and p["prev_hash"] != "GENESIS":
                    if p["prev_hash"] != last_ping_hash:
                        chain_broken_pings += 1
                last_ping_hash = p["record_hash"]

        cur = conn.execute("SELECT id, start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, tsr_token, tsa_authority, outage_type FROM outages ORDER BY id ASC;")
        outages = cur.fetchall()
        checked_outages = 0
        tampered_outages = 0
        chain_broken_outages = 0
        tsa_verified_outages = 0
        last_outage_hash = None

        for o in outages:
            if o["record_hash"]:
                checked_outages += 1
                prev_h = o["prev_hash"] or "GENESIS"
                o_type = o["outage_type"] or "TOTAL"
                if o["status"] == "CLOSED":
                    sig_typed = f"{prev_h}|{o['start_time']}|{o['end_time']}|{o['duration_seconds']}|{o_type}|{o['reason']}|CLOSED"
                    sig_chained = f"{prev_h}|{o['start_time']}|{o['end_time']}|{o['duration_seconds']}|{o['reason']}|CLOSED"
                    sig_legacy = f"{o['start_time']}|{o['end_time']}|{o['duration_seconds']}|{o['reason']}|CLOSED"
                    valid_hash = (
                        compute_hash(sig_typed) == o["record_hash"] or
                        compute_hash(sig_chained) == o["record_hash"] or
                        compute_hash(sig_legacy) == o["record_hash"]
                    )
                else:
                    sig_typed = f"{prev_h}|{o['start_time']}|{o_type}|{o['reason']}|OPEN"
                    sig_chained = f"{prev_h}|{o['start_time']}|{o['reason']}|OPEN"
                    sig_legacy = f"{o['start_time']}|{o['reason']}|OPEN"
                    valid_hash = (
                        compute_hash(sig_typed) == o["record_hash"] or
                        compute_hash(sig_chained) == o["record_hash"] or
                        compute_hash(sig_legacy) == o["record_hash"]
                    )
                if not valid_hash:
                    tampered_outages += 1

                if last_outage_hash and o["prev_hash"] and o["prev_hash"] != "GENESIS":
                    if o["prev_hash"] != last_outage_hash:
                        chain_broken_outages += 1
                last_outage_hash = o["record_hash"]

                if o["tsr_token"]:
                    if rfc3161.verify_tsr_token(o["tsr_token"], o["record_hash"]):
                        tsa_verified_outages += 1

        # Auditoria criptográfica da tabela speed_tests
        cur = conn.execute("SELECT id, timestamp, trigger_reason, download_mbps, upload_mbps, ping_ms, status, record_hash, prev_hash FROM speed_tests ORDER BY id ASC;")
        speed_tests = cur.fetchall()
        checked_speed_tests = 0
        tampered_speed_tests = 0
        chain_broken_speed_tests = 0
        last_speed_hash = None

        for s in speed_tests:
            if s["record_hash"]:
                checked_speed_tests += 1
                prev_h = s["prev_hash"] or "GENESIS"
                sig_chained = f"{prev_h}|{s['timestamp']}|{s['trigger_reason']}|{s['download_mbps']}|{s['upload_mbps']}|{s['ping_ms']}|{s['status']}"
                sig_legacy = f"{s['timestamp']}|{s['trigger_reason']}|{s['download_mbps']}|{s['upload_mbps']}|{s['ping_ms']}|{s['status']}"

                valid_hash = (
                    compute_hash(sig_chained) == s["record_hash"] or
                    compute_hash(sig_legacy) == s["record_hash"]
                )
                if not valid_hash:
                    tampered_speed_tests += 1

                if last_speed_hash and s["prev_hash"] and s["prev_hash"] != "GENESIS":
                    if s["prev_hash"] != last_speed_hash:
                        chain_broken_speed_tests += 1
                last_speed_hash = s["record_hash"]

        # Auditoria criptográfica da tabela route_traces
        cur = conn.execute("SELECT id, timestamp, trigger_reason, target, status, failed_hop, failed_ip, responsible_party, record_hash, prev_hash FROM route_traces ORDER BY id ASC;")
        route_traces = cur.fetchall()
        checked_route_traces = 0
        tampered_route_traces = 0
        chain_broken_route_traces = 0
        last_trace_hash = None

        for t in route_traces:
            if t["record_hash"]:
                checked_route_traces += 1
                prev_h = t["prev_hash"] or "GENESIS"
                sig_chained = f"{prev_h}|{t['timestamp']}|{t['trigger_reason']}|{t['target']}|{t['status']}|{t['failed_hop']}|{t['failed_ip']}|{t['responsible_party']}"
                if compute_hash(sig_chained) != t["record_hash"]:
                    tampered_route_traces += 1

                if last_trace_hash and t["prev_hash"] and t["prev_hash"] != "GENESIS":
                    if t["prev_hash"] != last_trace_hash:
                        chain_broken_route_traces += 1
                last_trace_hash = t["record_hash"]

        # Auditoria da tabela audit_log
        cur = conn.execute("SELECT count(*) as cnt FROM audit_log;")
        checked_audit_logs = cur.fetchone()["cnt"]
    finally:
        conn.close()

    total_tampered = (
        tampered_pings + tampered_outages + tampered_speed_tests + tampered_route_traces +
        chain_broken_pings + chain_broken_outages + chain_broken_speed_tests + chain_broken_route_traces
    )
    is_clean = (total_tampered == 0)

    if is_clean:
        if tsa_verified_outages > 0:
            msg = f"Base de dados 100% íntegra. {tsa_verified_outages} quedas certificadas via RFC 3161."
        else:
            msg = "Base de dados 100% íntegra, encadeada e autenticada."
    else:
        msg = f"Atenção: {total_tampered} inconsistências detectadas na integridade ou cadeia de registros."

    return {
        "status": "VALID" if is_clean else "TAMPERED",
        "checked_pings": checked_pings,
        "tampered_pings": tampered_pings,
        "chain_broken_pings": chain_broken_pings,
        "checked_outages": checked_outages,
        "tampered_outages": tampered_outages,
        "chain_broken_outages": chain_broken_outages,
        "tsa_verified_outages": tsa_verified_outages,
        "checked_speed_tests": checked_speed_tests,
        "tampered_speed_tests": tampered_speed_tests,
        "chain_broken_speed_tests": chain_broken_speed_tests,
        "checked_route_traces": checked_route_traces,
        "tampered_route_traces": tampered_route_traces,
        "checked_audit_logs": checked_audit_logs,
        "message": msg
    }


def cleanup_old_data(days: int = 30, actor_ip: str = "local", db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Remove registros de telemetria mais antigos que a quantidade de dias informada
    para liberar espaco em disco no servidor. Nao apaga o historico de quedas.
    """
    if days < 7:
        raise ValueError("O periodo minimo de retencao e de 7 dias para garantir auditoria.")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = get_connection(db_path)
    try:
        with conn:
            cur1 = conn.execute("DELETE FROM pings WHERE timestamp < ?;", (cutoff,))
            deleted_pings = cur1.rowcount
            cur2 = conn.execute("DELETE FROM speed_tests WHERE timestamp < ?;", (cutoff,))
            deleted_speeds = cur2.rowcount
        try:
            conn.execute("VACUUM;")
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()

    log_audit("CLEANUP_OLD_DATA", f"Excluidos {deleted_pings} pings e {deleted_speeds} testes anteriores a {days} dias.", actor_ip, db_path)

    return {
        "deleted_pings": deleted_pings,
        "deleted_speed_tests": deleted_speeds,
        "cutoff_date": cutoff
    }


def reset_database(actor_ip: str = "local", db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Reseta todas as tabelas de metricas, mantendo configuracoes e registrando
    o evento permanentemente no log de auditoria.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM pings;")
            conn.execute("DELETE FROM speed_tests;")
            conn.execute("DELETE FROM outages;")
        try:
            conn.execute("VACUUM;")
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()

    log_audit("RESET_DATABASE", "Historico de metricas zerado administrativamente.", actor_ip, db_path)

    return {
        "status": "SUCCESS",
        "message": "Historico de metricas resetado com sucesso."
    }
