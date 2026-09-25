"""
monitor.py - Motor de Monitoramento Contínuo de Conectividade e Saúde da Rede
Executa checagens a cada 30s, registra histórico, detecta quedas instantaneamente,
e dispara testes de velocidade periódicos (10 min) e em caso de instabilidade.
"""

import time
import subprocess
import platform
import re
import socket
import sys
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Garante codificação UTF-8 mesmo em terminais Windows legados (cp1252)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import db
import speed_tester

# Alvos confiáveis para ping redundante
PING_TARGETS = ["1.1.1.1", "8.8.8.8"]
DNS_CHECK_DOMAIN = "google.com"

# Controle de threads para testes de velocidade não bloquearem o loop de 30s
_speed_lock = threading.Lock()
_last_speed_test_time = 0.0
_is_running = True


def tcp_ping(host: str, port: int = 53, timeout: float = 1.2) -> Optional[float]:
    """Mede a latencia de handshake TCP como fallback caso ICMP ping falhe."""
    try:
        start = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        duration = (time.perf_counter() - start) * 1000.0
        s.close()
        return round(duration, 1)
    except Exception:
        return None


def ping_host(host: str, count: int = 2, timeout_ms: int = 1000) -> Dict[str, Any]:
    """Executa ping multiplataforma (Windows e Linux) para um host especifico."""
    is_win = platform.system().lower() == "windows"
    param = "-n" if is_win else "-c"
    timeout_param = "-w" if is_win else "-W"
    timeout_val = str(timeout_ms) if is_win else str(max(1, timeout_ms // 1000))
    cmd = ["ping", param, str(count), timeout_param, timeout_val, host]

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(3.0, (timeout_ms / 1000.0 * count) + 1.5)
        )
        
        # Extrai perda de pacotes (PT e EN)
        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet loss|loss|perda|de perda)", res.stdout, re.IGNORECASE)
        packet_loss = float(loss_match.group(1)) if loss_match else None

        # Extrai latência em ms (suporta 'time=14.2 ms' no Linux e 'tempo=15ms' no Windows)
        times = [float(x) for x in re.findall(r"(?:time|tempo)[=<](\d+(?:\.\d+)?)\s*ms", res.stdout, re.IGNORECASE)]
        avg_latency = round(sum(times) / len(times), 1) if times else None

        # Fallback 1: Linha de sumario do Linux (rtt min/avg/max/mdev = 14.2/15.1/...)
        if avg_latency is None:
            rtt_match = re.search(r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)/", res.stdout)
            if rtt_match:
                avg_latency = round(float(rtt_match.group(1)), 1)

        # Fallback 2: Linha de sumario do Windows (Media = 15ms / Average = 15ms)
        if avg_latency is None:
            win_match = re.search(r"(?:Média|Media|Average)\s*=\s*(\d+)ms", res.stdout, re.IGNORECASE)
            if win_match:
                avg_latency = float(win_match.group(1))

        if packet_loss is None:
            packet_loss = 0.0 if res.returncode == 0 else 100.0

        is_online = res.returncode == 0 and packet_loss < 100.0

        # Fallback 3: Se ping respondeu mas latencia nao foi parseada, usa TCP handshake
        if is_online and avg_latency is None:
            avg_latency = tcp_ping(host, 53)

        return {
            "online": is_online,
            "latency_ms": avg_latency,
            "loss_pct": packet_loss
        }
    except Exception:
        # Se o comando ping nao existir ou falhar por permissao, testa via TCP
        tcp_lat = tcp_ping(host, 53)
        if tcp_lat is not None:
            return {
                "online": True,
                "latency_ms": tcp_lat,
                "loss_pct": 0.0
            }
        return {
            "online": False,
            "latency_ms": None,
            "loss_pct": 100.0
        }


def check_dns(domain: str = DNS_CHECK_DOMAIN, timeout: float = 2.0) -> bool:
    """Verifica se a resolução DNS do provedor está respondendo."""
    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(orig_timeout)


def check_connectivity() -> Dict[str, Any]:
    """
    Executa a checagem completa de saúde:
    - Ping em múltiplos DNS públicos (1.1.1.1, 8.8.8.8)
    - Teste de resolução DNS
    - Classificação: ONLINE, INSTABLE ou OFFLINE
    """
    results = []
    for target in PING_TARGETS:
        results.append(ping_host(target))

    dns_ok = check_dns()

    # Métricas consolidadas
    valid_latencies = [r["latency_ms"] for r in results if r["latency_ms"] is not None]
    avg_latency = round(sum(valid_latencies) / len(valid_latencies), 1) if valid_latencies else None

    losses = [r["loss_pct"] for r in results]
    avg_loss = round(sum(losses) / len(losses), 1) if losses else 100.0

    online_targets = sum(1 for r in results if r["online"])
    is_online = online_targets > 0 or dns_ok

    # Determina status
    if not is_online or (avg_loss >= 100.0 and not dns_ok):
        status = "OFFLINE"
    elif avg_loss > 10.0 or (avg_latency and avg_latency > 150.0) or not dns_ok:
        status = "INSTABLE"
    else:
        status = "ONLINE"

    details = f"targets={len(PING_TARGETS)},online_targets={online_targets},dns={'OK' if dns_ok else 'FAIL'}"

    return {
        "is_online": is_online,
        "status": status,
        "latency_ms": avg_latency,
        "packet_loss_pct": avg_loss,
        "dns_ok": dns_ok,
        "details": details
    }


def trigger_async_speedtest(reason: str):
    """Dispara um teste de velocidade em segundo plano para não travar o loop de 30s."""
    global _last_speed_test_time

    def _worker():
        global _last_speed_test_time
        if not _speed_lock.acquire(blocking=False):
            return  # Já existe um teste em execução

        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [SPEED] Executando teste de velocidade ({reason})...")
            res = speed_tester.run_speed_test()
            db.record_speed_test(
                trigger_reason=reason,
                download_mbps=res["download_mbps"],
                upload_mbps=res["upload_mbps"],
                ping_ms=res["ping_ms"],
                status=res["status"],
                error_message=res["error_message"]
            )
            _last_speed_test_time = time.time()
            if res["status"] == "SUCCESS":
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SPEED-OK] Download: {res['download_mbps']} Mbps | Upload: {res['upload_mbps']} Mbps (Ping: {res['ping_ms']} ms)")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SPEED-ERRO] Falha no teste de velocidade: {res['error_message']}")
        finally:
            _speed_lock.release()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def monitor_step(last_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executa uma iteração única de monitoramento de 30 segundos.
    Atualiza banco e gerencia transição de quedas.
    """
    check = check_connectivity()

    # Grava medição no banco
    db.record_ping(
        is_online=check["is_online"],
        latency_ms=check["latency_ms"],
        packet_loss_pct=check["packet_loss_pct"],
        dns_ok=check["dns_ok"],
        status=check["status"],
        details=check["details"]
    )

    prev_status = last_state.get("status", "UNKNOWN")
    curr_status = check["status"]
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Transição: CONEXÃO CAIU (ONLINE/INSTABLE -> OFFLINE)
    if curr_status == "OFFLINE" and prev_status != "OFFLINE":
        reason = f"Perda total de pacotes ({check['packet_loss_pct']}%) e falha nos servidores DNS"
        outage_id = db.start_outage(reason)
        print(f"\n[{now_str}] [!] [QUEDA DETECTADA] Conexão caiu! Registrado no banco como Queda #{outage_id}")

    # Transição: CONEXÃO VOLTOU (OFFLINE -> ONLINE/INSTABLE)
    elif prev_status == "OFFLINE" and curr_status != "OFFLINE":
        closed = db.close_active_outage()
        if closed:
            dur = closed.get("duration_seconds", 0)
            print(f"\n[{now_str}] [+] [RECUPERADO] Conexão voltou após {dur}s ({round(dur/60, 1)} min) de queda!")
            # Agenda teste de velocidade imediato pós-recuperação
            trigger_async_speedtest(reason="recovery")

    # Formatação de log no console
    lat_str = f"{check['latency_ms']} ms" if check['latency_ms'] is not None else "-- ms"
    tag = "[OK]      " if curr_status == "ONLINE" else ("[ALERTA]  " if curr_status == "INSTABLE" else "[QUEDA]   ")
    print(f"[{now_str}] {tag} [{curr_status:<8}] Latência: {lat_str:<8} | Perda: {check['packet_loss_pct']:>4.1f}% | DNS: {'OK' if check['dns_ok'] else 'FALHA'}")

    # Disparo por instabilidade (se houver degradação e cooldown de 3 minutos respeitado)
    if curr_status == "INSTABLE":
        if (time.time() - _last_speed_test_time) > 180:
            print(f"[{now_str}] [!] Instabilidade detectada (Latência alta ou perda). Disparando teste de velocidade...")
            trigger_async_speedtest(reason="instability_detected")

    return check


def run_monitor_loop(ping_interval: int = 30, speed_interval_min: int = 10):
    """
    Loop principal do serviço de monitoramento.
    Roda continuamente a cada 30 segundos.
    """
    global _is_running
    db.init_db()

    print("=" * 65)
    print("📡 INICIANDO MONITOR DE CONEXÃO E SAÚDE DE REDE")
    print(f"⏱️  Intervalo de Ping: {ping_interval}s | Teste de Velocidade: {speed_interval_min}min")
    print("💾 Banco SQLite ativo: net_monitor.db (Modo WAL)")
    print("=" * 65)

    # Executa primeiro teste de velocidade inicial na largada
    trigger_async_speedtest(reason="startup")

    last_state = {"status": "UNKNOWN"}
    last_scheduled_speed = time.time()

    while _is_running:
        try:
            last_state = monitor_step(last_state)

            # Checa se passou o intervalo programado de 10 min de teste de velocidade
            if (time.time() - last_scheduled_speed) >= (speed_interval_min * 60):
                trigger_async_speedtest(reason=f"scheduled_{speed_interval_min}min")
                last_scheduled_speed = time.time()

        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Erro inesperado no ciclo de monitoramento: {e}")

        # Aguarda 30 segundos divididos em pequenos passos para responder rápido a Ctrl+C
        for _ in range(ping_interval):
            if not _is_running:
                break
            time.sleep(1)


def stop_monitor():
    """Sinaliza para parar o loop com segurança."""
    global _is_running
    _is_running = False


if __name__ == "__main__":
    try:
        run_monitor_loop(ping_interval=30, speed_interval_min=10)
    except KeyboardInterrupt:
        print("\nEncerrando monitor com segurança...")
        stop_monitor()
