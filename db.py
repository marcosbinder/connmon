"""
db.py - Gerenciador de Banco de Dados SQLite para Monitoramento de Rede
Ultra-leve, seguro contra falhas, com suporte a WAL (Write-Ahead Logging).
"""

import sqlite3
import os
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "net_monitor.db")
SECRET_SALT = "netmon_audit_v1_salt_2026"


def compute_hash(data_str: str) -> str:
    """Calcula hash HMAC SHA-256 para assegurar autenticidade dos registros contra adulteração."""
    return hmac.new(SECRET_SALT.encode("utf-8"), data_str.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


_db_initialized = False


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    global _db_initialized
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    # Ativa WAL mode para permitir leituras concorrentes do dashboard sem travar as escritas do monitor
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    if not _db_initialized:
        _db_initialized = True
        try:
            init_db(db_path)
        except Exception:
            pass
    return conn


def init_db(db_path: str = DB_PATH):
    """Inicializa as tabelas e índices necessários."""
    conn = get_connection(db_path)
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

        # Migrações para encadeamento criptográfico e carimbo digital RFC 3161
        for col_def in [
            ("pings", "prev_hash TEXT"),
            ("outages", "prev_hash TEXT"),
            ("outages", "tsr_token TEXT"),
            ("outages", "tsa_authority TEXT"),
            ("speed_tests", "prev_hash TEXT"),
            ("speed_tests", "result_url TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE {col_def[0]} ADD COLUMN {col_def[1]};")
            except sqlite3.OperationalError:
                pass

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

        # Configurações padrão
        default_configs = [
            ("isp_name", "Meu Provedor"),
            ("contracted_download_mbps", "500"),
            ("contracted_upload_mbps", "250"),
            ("ping_interval_seconds", "30"),
            ("speedtest_interval_minutes", "10"),
            ("latency_alert_threshold_ms", "150"),
            ("loss_alert_threshold_pct", "10"),
            ("heartbeat_url", ""),
        ]
        for key, val in default_configs:
            conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?);", (key, val))
    conn.close()


def get_config(key: str, default: str = "", db_path: str = DB_PATH) -> str:
    """Busca um valor de configuração no banco."""
    conn = get_connection(db_path)
    cur = conn.execute("SELECT value FROM config WHERE key = ?;", (key,))
    row = cur.fetchone()
    conn.close()
    return row["value"] if row else default


def set_config(key: str, value: str, db_path: str = DB_PATH):
    """Grava ou atualiza um valor de configuração."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?);", (key, str(value)))
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
    cur = conn.execute("SELECT record_hash FROM pings ORDER BY id DESC LIMIT 1;")
    last_row = cur.fetchone()
    prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

    raw_signature = f"{prev_hash}|{now_iso}|{online_int}|{latency_ms}|{packet_loss_pct}|{dns_int}|{status}|{jitter_ms}"
    rec_hash = compute_hash(raw_signature)

    with conn:
        cur = conn.execute(
            """
            INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status, jitter_ms, details, record_hash, prev_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (now_iso, online_int, latency_ms, packet_loss_pct, dns_int, status, jitter_ms, details, rec_hash, prev_hash)
        )
        ping_id = cur.lastrowid
    conn.close()
    return ping_id


def record_speed_test(
    trigger_reason: str,
    download_mbps: Optional[float],
    upload_mbps: Optional[float],
    ping_ms: Optional[float],
    status: str,
    error_message: Optional[str] = None,
    result_url: Optional[str] = None,
    db_path: str = DB_PATH
) -> int:
    """Registra um teste completo de velocidade com encadeamento de hash."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    cur = conn.execute("SELECT record_hash FROM speed_tests ORDER BY id DESC LIMIT 1;")
    last_row = cur.fetchone()
    prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

    raw_signature = f"{prev_hash}|{now_iso}|{trigger_reason}|{download_mbps}|{upload_mbps}|{ping_ms}|{status}"
    rec_hash = compute_hash(raw_signature)

    with conn:
        cur = conn.execute(
            """
            INSERT INTO speed_tests (timestamp, trigger_reason, download_mbps, upload_mbps, ping_ms, status, error_message, record_hash, prev_hash, result_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (now_iso, trigger_reason, download_mbps, upload_mbps, ping_ms, status, error_message, rec_hash, prev_hash, result_url)
        )
        test_id = cur.lastrowid
    conn.close()
    return test_id


def get_active_outage(db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Retorna a queda atualmente em andamento (se houver)."""
    conn = get_connection(db_path)
    cur = conn.execute("SELECT * FROM outages WHERE status = 'OPEN' ORDER BY id DESC LIMIT 1;")
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def start_outage(reason: str, db_path: str = DB_PATH) -> int:
    """Inicia o registro de uma nova queda com encadeamento de hash."""
    active = get_active_outage(db_path)
    if active:
        return active["id"]

    conn = get_connection(db_path)
    cur = conn.execute("SELECT record_hash FROM outages ORDER BY id DESC LIMIT 1;")
    last_row = cur.fetchone()
    prev_hash = last_row["record_hash"] if last_row and last_row["record_hash"] else "GENESIS"

    now_iso = datetime.now(timezone.utc).isoformat()
    raw_sig = f"{prev_hash}|{now_iso}|{reason}|OPEN"
    rec_hash = compute_hash(raw_sig)

    with conn:
        cur = conn.execute(
            "INSERT INTO outages (start_time, reason, status, record_hash, prev_hash) VALUES (?, ?, 'OPEN', ?, ?);",
            (now_iso, reason, rec_hash, prev_hash)
        )
        outage_id = cur.lastrowid
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

    prev_hash = active.get("prev_hash") or "GENESIS"
    raw_sig = f"{prev_hash}|{active['start_time']}|{now_iso}|{dur_round}|{active['reason']}|CLOSED"
    rec_hash = compute_hash(raw_sig)

    # Solicita carimbo de tempo digital externo RFC 3161 (DigiCert ou FreeTSA)
    tsr_token = None
    tsa_authority = None
    try:
        import rfc3161
        tsr_token, tsa_authority = rfc3161.request_rfc3161_timestamp(rec_hash, timeout=4)
    except Exception:
        pass

    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            UPDATE outages
            SET end_time = ?, duration_seconds = ?, status = 'CLOSED', record_hash = ?, tsr_token = ?, tsa_authority = ?
            WHERE id = ?;
            """,
            (now_iso, dur_round, rec_hash, tsr_token, tsa_authority, active["id"])
        )
    conn.close()
    active["end_time"] = now_iso
    active["duration_seconds"] = dur_round
    active["status"] = "CLOSED"
    active["record_hash"] = rec_hash
    active["tsr_token"] = tsr_token
    active["tsa_authority"] = tsa_authority
    return active


def get_latest_status(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Retorna o estado atual completo da conexão para os cards do dashboard."""
    conn = get_connection(db_path)

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
        SELECT COUNT(*) as outage_count, COALESCE(SUM(duration_seconds), 0) as total_downtime_sec
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

    conn.close()

    total_checks = summary_24h["total_checks"] if summary_24h else 0
    online_checks = summary_24h["online_checks"] if summary_24h and summary_24h["online_checks"] else 0
    uptime_pct = round((online_checks / total_checks * 100), 2) if total_checks > 0 else 100.0

    # Detecção automática de operadora e IP público
    try:
        import isp_detector
        isp_info = isp_detector.get_isp_info()
    except Exception:
        isp_info = {
            "isp": configs.get("isp_name", "Meu Provedor"),
            "ip": "",
            "asn": "",
            "city": "",
            "region": ""
        }

    return {
        "last_ping": dict(last_ping) if last_ping else None,
        "last_speed": dict(last_speed) if last_speed else None,
        "active_outage": dict(active_outage) if active_outage else None,
        "isp_info": isp_info,
        "stats_24h": {
            "uptime_pct": uptime_pct,
            "avg_latency_ms": round(summary_24h["avg_latency"] or 0, 1) if summary_24h else 0,
            "min_latency_ms": round(summary_24h["min_latency"] or 0, 1) if summary_24h and summary_24h["min_latency"] is not None else 0,
            "max_latency_ms": round(summary_24h["max_latency"] or 0, 1) if summary_24h and summary_24h["max_latency"] is not None else 0,
            "avg_jitter_ms": round(summary_24h["avg_jitter"] or 0, 1) if summary_24h and summary_24h["avg_jitter"] is not None else 0,
            "avg_loss_pct": round(summary_24h["avg_loss"] or 0, 1) if summary_24h else 0,
            "avg_download_mbps": round(speed_24h["avg_down"] or 0, 1) if speed_24h and speed_24h["avg_down"] else 0,
            "avg_upload_mbps": round(speed_24h["avg_up"] or 0, 1) if speed_24h and speed_24h["avg_up"] else 0,
            "total_outages": outages_24h["outage_count"] if outages_24h else 0,
            "total_downtime_seconds": round(outages_24h["total_downtime_sec"] or 0, 1) if outages_24h else 0,
        },
        "config": configs
    }


def get_metrics_timeline(hours: int = 24, db_path: str = DB_PATH) -> Dict[str, Any]:
    """Retorna pontos de dados para plotagem de gráficos na janela solicitada."""
    conn = get_connection(db_path)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # Pings (amostragem inteligente se houver muitos pontos para manter leveza)
    cur = conn.execute(
        """
        SELECT timestamp, is_online, latency_ms, packet_loss_pct, status
        FROM pings
        WHERE timestamp >= ?
        ORDER BY id ASC;
        """,
        (since,)
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
        WHERE timestamp >= ? AND status = 'SUCCESS'
        ORDER BY id ASC;
        """,
        (since,)
    )
    speeds = [dict(r) for r in cur.fetchall()]

    # Quedas
    cur = conn.execute(
        """
        SELECT id, start_time, end_time, duration_seconds, reason, status
        FROM outages
        WHERE start_time >= ? OR status = 'OPEN'
        ORDER BY id DESC;
        """,
        (since,)
    )
    outages = [dict(r) for r in cur.fetchall()]

    conn.close()
    return {
        "pings": pings,
        "speeds": speeds,
        "outages": outages,
    }


def get_all_outages(limit: int = 100, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Retorna histórico de todas as quedas registradas."""
    conn = get_connection(db_path)
    cur = conn.execute(
        """
        SELECT id, start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, tsa_authority
        FROM outages
        ORDER BY id DESC
        LIMIT ?;
        """,
        (limit,)
    )
    outages = [dict(r) for r in cur.fetchall()]
    conn.close()
    return outages


def export_csv_data(table_name: str, db_path: str = DB_PATH) -> str:
    """Exporta qualquer tabela para formato CSV textual."""
    allowed = ["pings", "speed_tests", "outages"]
    if table_name not in allowed:
        raise ValueError(f"Tabela inválida: {table_name}")

    conn = get_connection(db_path)
    cur = conn.execute(f"SELECT * FROM {table_name} ORDER BY id ASC;")
    rows = cur.fetchall()

    if not rows:
        conn.close()
        return "Nenhum dado registrado ainda."

    headers = [col[0] for col in cur.description]
    lines = [",".join(headers)]
    for row in rows:
        line_vals = [f'"{str(val)}"' if val is not None else "" for val in row]
        lines.append(",".join(line_vals))

    conn.close()
    return "\n".join(lines)


def generate_isp_report_text(hours: int = 72, db_path: str = DB_PATH) -> str:
    """
    Gera um relatorio tecnico estruturado com horarios de queda,
    medicoes de banda e base legal da Anatel para envio ao suporte.
    """
    conn = get_connection(db_path)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # Coleta configs
    cur = conn.execute("SELECT key, value FROM config;")
    configs = {row["key"]: row["value"] for row in cur.fetchall()}
    contracted_down = configs.get("contracted_download_mbps", "N/A")
    contracted_up = configs.get("contracted_upload_mbps", "N/A")

    # Identificacao da operadora
    try:
        import isp_detector
        isp_info = isp_detector.get_isp_info()
    except Exception:
        isp_info = {}

    isp_name = isp_info.get("isp") or configs.get("isp_name", "Provedor")
    public_ip = isp_info.get("ip", "Nao informado")
    asn = isp_info.get("asn", "")
    city = isp_info.get("city", "")

    # Quedas no periodo
    cur = conn.execute(
        """
        SELECT id, start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, tsa_authority
        FROM outages
        WHERE start_time >= ?
        ORDER BY id ASC;
        """,
        (since,)
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
        FROM pings WHERE timestamp >= ?;
        """,
        (since,)
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
        WHERE timestamp >= ? AND status = 'SUCCESS';
        """,
        (since,)
    )
    speed_summary = cur.fetchone()
    conn.close()

    total_checks = ping_summary["total_checks"] if ping_summary else 0
    online_checks = ping_summary["online_checks"] if ping_summary and ping_summary["online_checks"] else 0
    uptime_pct = round((online_checks / total_checks * 100), 2) if total_checks > 0 else 100.0

    total_downtime_sec = sum(o["duration_seconds"] or 0 for o in outages)
    downtime_min = round(total_downtime_sec / 60, 1)

    # Verificação de integridade dos registros para o laudo
    integrity = verify_database_integrity(db_path)

    lines = []
    lines.append("=" * 65)
    lines.append(f"RELATORIO TECNICO DE QUALIDADE DE CONEXAO ({isp_name.upper()})")
    lines.append("=" * 65)
    lines.append(f"Data de geracao: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lines.append(f"Periodo monitorado: Ultimas {hours} horas")
    lines.append(f"Operadora identificada: {isp_name}" + (f" ({asn})" if asn else ""))
    if public_ip and public_ip != "Nao informado":
        lines.append(f"IP Publico do cliente: {public_ip}" + (f" - {city}" if city else ""))
    lines.append(f"Plano contratado informado: {contracted_down} Mbps Download / {contracted_up} Mbps Upload")
    lines.append(f"Integridade criptografica: {integrity['message']}")
    lines.append("")
    lines.append("RESUMO DE CONECTIVIDADE E MEDIAS:")
    lines.append(f"- Disponibilidade do link: {uptime_pct}%")
    lines.append(f"- Interrupcoes de sinal registradas: {len(outages)}")
    lines.append(f"- Tempo acumulado sem conexao: {downtime_min} minutos ({round(total_downtime_sec)} segundos)")
    if ping_summary and ping_summary["total_checks"]:
        lines.append(f"- Latencia media: {round(ping_summary['avg_latency'] or 0, 1)} ms (Minima: {round(ping_summary['min_latency'] or 0, 1)} ms | Pico: {round(ping_summary['max_latency'] or 0, 1)} ms)")
        if ping_summary["avg_jitter"]:
            lines.append(f"- Jitter medio (variacao de rota): {round(ping_summary['avg_jitter'] or 0, 1)} ms")
        lines.append(f"- Perda media de pacotes: {round(ping_summary['avg_loss'] or 0, 2)}%")
    if speed_summary and speed_summary["test_count"]:
        lines.append(f"- Download medio medido: {round(speed_summary['avg_down'] or 0, 2)} Mbps (Minimo: {round(speed_summary['min_down'] or 0, 2)} Mbps | Maximo: {round(speed_summary['max_down'] or 0, 2)} Mbps)")
        lines.append(f"- Upload medio medido: {round(speed_summary['avg_up'] or 0, 2)} Mbps (Minimo: {round(speed_summary['min_up'] or 0, 2)} Mbps | Maximo: {round(speed_summary['max_up'] or 0, 2)} Mbps)")
    lines.append("")
    lines.append("HISTORICO DETALHADO DE INTERRUPCOES:")
    if not outages:
        lines.append("  (Nenhuma queda de conexao registrada no periodo selecionado)")
    else:
        for i, o in enumerate(outages, 1):
            st = o["start_time"].replace("T", " ")[:19]
            et = o["end_time"].replace("T", " ")[:19] if o["end_time"] else "EM ANDAMENTO"
            dur = f"{round(o['duration_seconds'] or 0)}s ({round((o['duration_seconds'] or 0)/60, 1)} min)" if o["end_time"] else "EM ABERTO"
            tsa_badge = f" [Carimbo Digital: {o['tsa_authority']} RFC 3161]" if o.get("tsa_authority") else ""
            lines.append(f"  [{i}] Inicio: {st} | Termino: {et} | Duracao: {dur}{tsa_badge}")
            lines.append(f"      Diagnostico: {o['reason']}")

    lines.append("")
    lines.append("REGULAMENTACAO APLICAVEL (ANATEL):")
    lines.append("Conforme resolucoes do Regulamento de Qualidade da Banda Larga (RQUAL) da Anatel:")
    lines.append("1. A prestadora deve entregar no minimo 80% da media mensal e 40% da taxa instantanea.")
    lines.append("2. Periodos de interrupcao geram direito a abatimento proporcional na cobranca.")
    lines.append("=" * 65)

    return "\n".join(lines)


def log_audit(action: str, details: str = "", actor_ip: str = "local", db_path: str = DB_PATH):
    """Registra uma operacao administrativa no log de auditoria."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details, actor_ip) VALUES (?, ?, ?, ?);",
            (now_iso, action, details, actor_ip)
        )
    conn.close()


def verify_database_integrity(db_path: str = DB_PATH) -> Dict[str, Any]:
    """
    Verifica a autenticidade dos dados armazenados no SQLite.
    Valida a assinatura HMAC de cada registro, o encadeamento cronológico (hash chaining)
    e a validade dos carimbos de tempo digitais RFC 3161 das quedas.
    """
    import rfc3161

    conn = get_connection(db_path)
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

    cur = conn.execute("SELECT id, start_time, end_time, duration_seconds, reason, status, record_hash, prev_hash, tsr_token, tsa_authority FROM outages ORDER BY id ASC;")
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
            if o["status"] == "CLOSED":
                sig_chained = f"{prev_h}|{o['start_time']}|{o['end_time']}|{o['duration_seconds']}|{o['reason']}|CLOSED"
                sig_legacy = f"{o['start_time']}|{o['end_time']}|{o['duration_seconds']}|{o['reason']}|CLOSED"
            else:
                sig_chained = f"{prev_h}|{o['start_time']}|{o['reason']}|OPEN"
                sig_legacy = f"{o['start_time']}|{o['reason']}|OPEN"

            valid_hash = (
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

    conn.close()

    total_tampered = tampered_pings + tampered_outages + chain_broken_pings + chain_broken_outages
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
    with conn:
        cur1 = conn.execute("DELETE FROM pings WHERE timestamp < ?;", (cutoff,))
        deleted_pings = cur1.rowcount
        cur2 = conn.execute("DELETE FROM speed_tests WHERE timestamp < ?;", (cutoff,))
        deleted_speeds = cur2.rowcount
    conn.execute("VACUUM;")
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
    with conn:
        conn.execute("DELETE FROM pings;")
        conn.execute("DELETE FROM speed_tests;")
        conn.execute("DELETE FROM outages;")
    conn.execute("VACUUM;")
    conn.close()

    log_audit("RESET_DATABASE", "Historico de metricas zerado administrativamente.", actor_ip, db_path)

    return {
        "status": "SUCCESS",
        "message": "Historico de metricas resetado com sucesso."
    }
