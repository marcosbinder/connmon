"""
db.py - Gerenciador de Banco de Dados SQLite para Monitoramento de Rede
Ultra-leve, seguro contra falhas, com suporte a WAL (Write-Ahead Logging).
"""

import sqlite3
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "net_monitor.db")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    # Ativa WAL mode para permitir leituras concorrentes do dashboard sem travar as escritas do monitor
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
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
                details TEXT                         -- info extra (ex: targets testados)
            );
        """)

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
                error_message TEXT
            );
        """)

        # Tabela de quedas (Downtime tracking exato para operadora)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS outages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TEXT NOT NULL,
                end_time TEXT,                       -- NULL se a queda ainda estiver ativa
                duration_seconds REAL,
                reason TEXT NOT NULL,                -- Causa (ex: '100% perda de pacotes', 'DNS inacessível')
                status TEXT NOT NULL DEFAULT 'OPEN'  -- 'OPEN', 'CLOSED'
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

        # Configurações padrão
        default_configs = [
            ("isp_name", "Meu Provedor"),
            ("contracted_download_mbps", "500"),
            ("contracted_upload_mbps", "250"),
            ("ping_interval_seconds", "30"),
            ("speedtest_interval_minutes", "10"),
            ("latency_alert_threshold_ms", "150"),
            ("loss_alert_threshold_pct", "10"),
        ]
        for key, val in default_configs:
            conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?);", (key, val))
    conn.close()


def record_ping(
    is_online: bool,
    latency_ms: Optional[float],
    packet_loss_pct: float,
    dns_ok: bool,
    status: str,
    details: str = "",
    db_path: str = DB_PATH
) -> int:
    """Registra uma verificação de conectividade de 30 segundos."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        cur = conn.execute(
            """
            INSERT INTO pings (timestamp, is_online, latency_ms, packet_loss_pct, dns_ok, status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (now_iso, 1 if is_online else 0, latency_ms, packet_loss_pct, 1 if dns_ok else 0, status, details)
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
    db_path: str = DB_PATH
) -> int:
    """Registra um teste completo de velocidade."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        cur = conn.execute(
            """
            INSERT INTO speed_tests (timestamp, trigger_reason, download_mbps, upload_mbps, ping_ms, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (now_iso, trigger_reason, download_mbps, upload_mbps, ping_ms, status, error_message)
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
    """Inicia o registro de uma nova queda."""
    # Se já existir uma queda aberta, não duplica
    active = get_active_outage(db_path)
    if active:
        return active["id"]

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection(db_path)
    with conn:
        cur = conn.execute(
            "INSERT INTO outages (start_time, reason, status) VALUES (?, ?, 'OPEN');",
            (now_iso, reason)
        )
        outage_id = cur.lastrowid
    conn.close()
    return outage_id


def close_active_outage(db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Fecha a queda ativa calculando a duração total em segundos."""
    active = get_active_outage(db_path)
    if not active:
        return None

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    start_dt = datetime.fromisoformat(active["start_time"])
    duration = max(0.0, (now - start_dt).total_seconds())

    conn = get_connection(db_path)
    with conn:
        conn.execute(
            """
            UPDATE outages
            SET end_time = ?, duration_seconds = ?, status = 'CLOSED'
            WHERE id = ?;
            """,
            (now_iso, round(duration, 1), active["id"])
        )
    conn.close()
    active["end_time"] = now_iso
    active["duration_seconds"] = round(duration, 1)
    active["status"] = "CLOSED"
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
            AVG(packet_loss_pct) as avg_loss
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

    # Configs
    cur = conn.execute("SELECT key, value FROM config;")
    configs = {row["key"]: row["value"] for row in cur.fetchall()}

    conn.close()

    total_checks = summary_24h["total_checks"] if summary_24h else 0
    online_checks = summary_24h["online_checks"] if summary_24h and summary_24h["online_checks"] else 0
    uptime_pct = round((online_checks / total_checks * 100), 2) if total_checks > 0 else 100.0

    return {
        "last_ping": dict(last_ping) if last_ping else None,
        "last_speed": dict(last_speed) if last_speed else None,
        "active_outage": dict(active_outage) if active_outage else None,
        "stats_24h": {
            "uptime_pct": uptime_pct,
            "avg_latency_ms": round(summary_24h["avg_latency"] or 0, 1) if summary_24h else 0,
            "avg_loss_pct": round(summary_24h["avg_loss"] or 0, 1) if summary_24h else 0,
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
        SELECT id, start_time, end_time, duration_seconds, reason, status
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
    Gera um relatório profissional pronto para colar no atendimento da Claro,
    no Procon ou na Anatel com horários, duração de quedas e médias de velocidade.
    """
    conn = get_connection(db_path)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # Coleta configs
    cur = conn.execute("SELECT key, value FROM config;")
    configs = {row["key"]: row["value"] for row in cur.fetchall()}
    isp_name = configs.get("isp_name", "Claro")
    contracted_down = configs.get("contracted_download_mbps", "N/A")
    contracted_up = configs.get("contracted_upload_mbps", "N/A")

    # Quedas no período
    cur = conn.execute(
        """
        SELECT id, start_time, end_time, duration_seconds, reason, status
        FROM outages
        WHERE start_time >= ?
        ORDER BY id ASC;
        """,
        (since,)
    )
    outages = [dict(r) for r in cur.fetchall()]

    # Pings no período
    cur = conn.execute(
        """
        SELECT 
            COUNT(*) as total_checks,
            SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) as online_checks,
            AVG(latency_ms) as avg_latency,
            MAX(latency_ms) as max_latency,
            AVG(packet_loss_pct) as avg_loss
        FROM pings WHERE timestamp >= ?;
        """,
        (since,)
    )
    ping_summary = cur.fetchone()

    # Velocidade no período
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

    lines = []
    lines.append("=" * 65)
    lines.append(f"RELATORIO TECNICO DE INSTABILIDADE DE CONEXAO ({isp_name.upper()})")
    lines.append("=" * 65)
    lines.append(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lines.append(f"Período analisado: Últimas {hours} horas")
    lines.append(f"Plano Contratado: {contracted_down} Mbps Download / {contracted_up} Mbps Upload")
    lines.append("")
    lines.append("RESUMO GERAL DE QUALIDADE:")
    lines.append(f"- Disponibilidade (Uptime): {uptime_pct}%")
    lines.append(f"- Total de interrupções/quedas registradas: {len(outages)}")
    lines.append(f"- Tempo total fora do ar: {downtime_min} minutos ({round(total_downtime_sec)} segundos)")
    if ping_summary:
        lines.append(f"- Latência Média: {round(ping_summary['avg_latency'] or 0, 1)} ms (Pico máximo: {round(ping_summary['max_latency'] or 0, 1)} ms)")
        lines.append(f"- Perda média de pacotes: {round(ping_summary['avg_loss'] or 0, 2)}%")
    if speed_summary and speed_summary["test_count"]:
        lines.append(f"- Download Médio medido: {round(speed_summary['avg_down'] or 0, 2)} Mbps (Mínimo registrado: {round(speed_summary['min_down'] or 0, 2)} Mbps)")
        lines.append(f"- Upload Médio medido: {round(speed_summary['avg_up'] or 0, 2)} Mbps (Mínimo registrado: {round(speed_summary['min_up'] or 0, 2)} Mbps)")
    lines.append("")
    lines.append("HISTÓRICO DETALHADO DE QUEDAS (DOWNTIME):")
    if not outages:
        lines.append("  (Nenhuma queda completa registrada no período selecionado)")
    else:
        for i, o in enumerate(outages, 1):
            st = o["start_time"].replace("T", " ")[:19]
            et = o["end_time"].replace("T", " ")[:19] if o["end_time"] else "EM ANDAMENTO"
            dur = f"{round(o['duration_seconds'] or 0)} segundos ({round((o['duration_seconds'] or 0)/60, 1)} min)" if o["end_time"] else "N/A"
            lines.append(f"  [{i}] Início: {st} | Fim: {et} | Duração: {dur}")
            lines.append(f"      Motivo detectado: {o['reason']}")

    lines.append("")
    lines.append("NOTA LEGAL / REGULAMENTAÇÃO ANATEL:")
    lines.append("Conforme Resoluções da Anatel (Regulamento de Qualidade da Banda Larga RQUAL):")
    lines.append("1. A prestadora deve entregar no mínimo 80% da taxa média contratada e 40% da taxa instantânea.")
    lines.append("2. Interrupções de serviço dão direito a abatimento proporcional na fatura mensal.")
    lines.append("=" * 65)

    return "\n".join(lines)
