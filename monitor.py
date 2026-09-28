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
import urllib.request
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
    """Mede a latencia de handshake TCP como fallback caso ICMP ping falhe com fechamento garantido."""
    s = None
    try:
        start = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        duration = (time.perf_counter() - start) * 1000.0
        return round(duration, 1)
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def ping_host(host: str, count: int = 3, timeout_ms: int = 1000) -> Dict[str, Any]:
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
            errors="replace",
            timeout=max(4.0, (timeout_ms / 1000.0 * count) + 1.5)
        )
        
        # Extrai perda de pacotes (PT e EN)
        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet loss|loss|perda|de perda)", res.stdout, re.IGNORECASE)
        packet_loss = float(loss_match.group(1)) if loss_match else None

        # Extrai latência em ms (suporta 'time=14.2 ms' no Linux e 'tempo=15ms' no Windows)
        times = [float(x) for x in re.findall(r"(?:time|tempo)[=<](\d+(?:\.\d+)?)\s*ms", res.stdout, re.IGNORECASE)]
        avg_latency = round(sum(times) / len(times), 1) if times else None

        # Jitter: variação média entre pacotes sucessivos
        jitter_ms = None
        if len(times) >= 2:
            diffs = [abs(times[i] - times[i - 1]) for i in range(1, len(times))]
            jitter_ms = round(sum(diffs) / len(diffs), 1)

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
            "jitter_ms": jitter_ms,
            "loss_pct": packet_loss
        }
    except Exception:
        # Se o comando ping nao existir ou falhar por permissao, testa via TCP
        tcp_lat = tcp_ping(host, 53)
        if tcp_lat is not None:
            return {
                "online": True,
                "latency_ms": tcp_lat,
                "jitter_ms": None,
                "loss_pct": 0.0
            }
        return {
            "online": False,
            "latency_ms": None,
            "jitter_ms": None,
            "loss_pct": 100.0
        }


def check_dns(domain: str = DNS_CHECK_DOMAIN, timeout: float = 2.0) -> bool:
    """
    Verifica se a resolução DNS do provedor está respondendo.
    Executa a resolução em thread dedicada sem alterar socket.setdefaulttimeout() globalmente,
    eliminando qualquer efeito colateral em conexões de outras threads (web server, speedtest).
    """
    resolved = [False]

    def _resolve():
        try:
            socket.gethostbyname(domain)
            resolved[0] = True
        except Exception:
            pass

    t = threading.Thread(target=_resolve, daemon=True, name="dns_probe")
    t.start()
    t.join(timeout=timeout)
    return resolved[0]


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

    valid_jitters = [r["jitter_ms"] for r in results if r.get("jitter_ms") is not None]
    avg_jitter = round(sum(valid_jitters) / len(valid_jitters), 1) if valid_jitters else None

    losses = [r["loss_pct"] for r in results]
    avg_loss = round(sum(losses) / len(losses), 1) if losses else 100.0

    online_targets = sum(1 for r in results if r["online"])

    # Determina status com calibração justa (evita falso alarme em perda leve passageira)
    if online_targets == 0 or avg_loss >= 100.0:
        is_online = False
        status = "OFFLINE"
    elif avg_loss >= 50.0 or (avg_loss > 20.0 and not dns_ok) or (avg_latency and avg_latency > 250.0) or not dns_ok:
        is_online = True
        status = "INSTABLE"
    else:
        is_online = True
        status = "ONLINE"

    details = f"targets={len(PING_TARGETS)},online_targets={online_targets},dns={'OK' if dns_ok else 'FAIL'}"

    return {
        "is_online": is_online,
        "status": status,
        "latency_ms": avg_latency,
        "jitter_ms": avg_jitter,
        "packet_loss_pct": avg_loss,
        "dns_ok": dns_ok,
        "details": details
    }


def trigger_async_speedtest(reason: str):
    """Dispara um teste de velocidade em segundo plano para não travar o loop de monitoramento."""
    global _last_speed_test_time

    def _worker():
        global _last_speed_test_time
        if not _speed_lock.acquire(blocking=False):
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [SPEED] Teste de velocidade ignorado: outro teste já está em execução.")
            return

        now_str = datetime.now().strftime('%H:%M:%S')
        res = None
        try:
            print(f"[{now_str}] [SPEED] Executando teste de velocidade ({reason})...")
            # Atualiza o timestamp imediatamente para evitar retentativas em tempestade
            _last_speed_test_time = time.time()

            try:
                res = speed_tester.run_speed_test()
            except Exception as test_err:
                print(f"[{now_str}] [SPEED-ERRO] Exceção crítica na execução do speedtest: {test_err}")
                res = {
                    "download_mbps": None,
                    "upload_mbps": None,
                    "ping_ms": None,
                    "status": "FAILED",
                    "error_message": f"Exceção no motor de teste: {test_err}",
                    "engine": "unknown"
                }
        finally:
            try:
                _speed_lock.release()
            except RuntimeError:
                pass

        # Persistência tolerante a falhas no banco de dados após liberação do lock de rede
        try:
            if res is None:
                res = {
                    "download_mbps": None,
                    "upload_mbps": None,
                    "ping_ms": None,
                    "status": "FAILED",
                    "error_message": "Resultado do speedtest indisponível",
                    "engine": "unknown"
                }

            db.record_speed_test(
                trigger_reason=reason,
                download_mbps=res.get("download_mbps"),
                upload_mbps=res.get("upload_mbps"),
                ping_ms=res.get("ping_ms"),
                status=res.get("status", "FAILED"),
                error_message=res.get("error_message")
            )

            if res.get("status") == "SUCCESS":
                print(f"[{now_str}] [SPEED-OK] Download: {res.get('download_mbps')} Mbps | Upload: {res.get('upload_mbps')} Mbps (Ping: {res.get('ping_ms')} ms)")
            else:
                print(f"[{now_str}] [SPEED-ERRO] Falha no teste de velocidade: {res.get('error_message')}")
        except Exception as db_err:
            print(f"[{now_str}] [SPEED-ERRO] Falha ao persistir resultado do teste no banco de dados: {db_err}")

    try:
        t = threading.Thread(target=_worker, daemon=True, name="speedtest_worker")
        t.start()
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [SPEED-ERRO] Não foi possível iniciar thread de velocidade: {e}")


def send_heartbeat_ping():
    """
    Envia ping HTTP silencioso para o serviço externo de monitoramento (ex: Healthchecks.io).
    Roda em thread separada com timeout curto de 3s para nunca atrasar o loop principal.
    """
    try:
        hb_url = db.get_config("heartbeat_url", "")
        if not hb_url or not hb_url.startswith("http"):
            return

        def _call():
            try:
                req = urllib.request.Request(hb_url, headers={"User-Agent": "NetMon-Heartbeat/1.0"})
                with urllib.request.urlopen(req, timeout=3):
                    pass
            except Exception:
                pass

        threading.Thread(target=_call, daemon=True).start()
    except Exception:
        pass


def monitor_step(last_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executa uma iteração única de monitoramento de 30 segundos.
    Atualiza banco e gerencia transição de quedas com isolamento de estágios.
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Estágio 1: Sondagem de conectividade
    try:
        check = check_connectivity()
    except Exception as e:
        print(f"[{now_str}] [ERRO] Falha crítica na checagem de conectividade: {e}")
        check = {
            "is_online": False,
            "status": "OFFLINE",
            "latency_ms": None,
            "jitter_ms": None,
            "packet_loss_pct": 100.0,
            "dns_ok": False,
            "details": f"exception={e}"
        }

    # Estágio 2: Persistência da telemetria de ping
    try:
        db.record_ping(
            is_online=check["is_online"],
            latency_ms=check["latency_ms"],
            packet_loss_pct=check["packet_loss_pct"],
            dns_ok=check["dns_ok"],
            status=check["status"],
            jitter_ms=check.get("jitter_ms"),
            details=check["details"]
        )
    except Exception as e:
        print(f"[{now_str}] [AVISO] Falha ao persistir ping no banco: {e}")

    # Estágio 3: Heartbeat externo
    if check["is_online"]:
        try:
            send_heartbeat_ping()
        except Exception:
            pass

    # Estágio 4: Máquina de estados de quedas (outages)
    prev_status = last_state.get("status", "UNKNOWN")
    curr_status = check["status"]

    # Confirmação imediata para filtrar soluços pontuais transitórios de 1 único ping
    if curr_status != "ONLINE" and prev_status == "ONLINE":
        time.sleep(1.5)
        recheck = check_connectivity()
        if recheck["status"] == "ONLINE":
            check = recheck
            curr_status = "ONLINE"

    try:
        if curr_status == "OFFLINE":
            reason = f"Perda total de pacotes ({check['packet_loss_pct']}%) e falha nos alvos DNS"
            outage_id = db.start_outage(reason, outage_type="TOTAL")
            if prev_status != "OFFLINE":
                print(f"\n[{now_str}] [!] [QUEDA TOTAL DETECTADA] Conexão caiu. Registrado como Queda #{outage_id}")

        elif curr_status == "INSTABLE":
            active = db.get_active_outage()
            if not active:
                reason = f"Degradação severa: perda {check['packet_loss_pct']}%, latência {check['latency_ms']}ms, DNS {'OK' if check['dns_ok'] else 'FALHA'}"
                outage_id = db.start_outage(reason, outage_type="PARCIAL")
                if prev_status == "ONLINE":
                    print(f"\n[{now_str}] [!] [INSTABILIDADE DETECTADA] Conexão degradada. Registrado como Interrupção Parcial #{outage_id}")
            if (time.time() - _last_speed_test_time) > 180:
                print(f"[{now_str}] [!] Instabilidade detectada. Disparando teste de velocidade investigativo...")
                trigger_async_speedtest(reason="instability_detected")

        elif curr_status == "ONLINE":
            active = db.get_active_outage()
            if active or prev_status in ("OFFLINE", "INSTABLE"):
                closed = db.close_active_outage()
                if closed:
                    dur = closed.get("duration_seconds", 0)
                    o_type = closed.get("outage_type", "TOTAL")
                    tipo_lbl = "Queda Total" if o_type == "TOTAL" else "Instabilidade Parcial"
                    print(f"\n[{now_str}] [+] [RECUPERADO] Conexão normalizada após {dur}s ({round(dur/60, 1)} min) de {tipo_lbl}.")
                    trigger_async_speedtest(reason="recovery")
    except Exception as e:
        print(f"[{now_str}] [AVISO] Falha ao atualizar transição de queda no banco: {e}")

    # Estágio 5: Console feedback
    lat_str = f"{check['latency_ms']} ms" if check['latency_ms'] is not None else "-- ms"
    jit_str = f" (Jitter: {check['jitter_ms']} ms)" if check.get("jitter_ms") is not None else ""
    tag = "[OK]      " if curr_status == "ONLINE" else ("[ALERTA]  " if curr_status == "INSTABLE" else "[QUEDA]   ")
    print(f"[{now_str}] {tag} [{curr_status:<8}] Latência: {lat_str:<7}{jit_str} | Perda: {check['packet_loss_pct']:>4.1f}% | DNS: {'OK' if check['dns_ok'] else 'FALHA'}")

    return check


def run_monitor_loop(ping_interval: int = 30, speed_interval_min: int = 10):
    """
    Loop principal do serviço de monitoramento com amostragem adaptativa de alta resolução.
    Em condições estáveis: checa a cada 30 segundos.
    Durante instabilidade ou queda: checa a cada 2 segundos para cravar duração exata.
    """
    global _is_running
    db.init_db()

    print("=" * 60)
    print("NetMon - Monitor de Conexao e Metricas de Rede")
    print(f"Checagem de Ping: {ping_interval}s | Teste de Velocidade: {speed_interval_min}min")
    try:
        import isp_detector
        isp_info = isp_detector.get_isp_info()
        if isp_info.get("isp"):
            print(f"Operadora: {isp_info['isp']} | IP Publico: {isp_info.get('ip', 'Nao identificado')}")
    except Exception:
        pass
    print("Banco SQLite: net_monitor.db (WAL)")
    print("=" * 60)

    # Fechamento seguro de quedas órfãs se a máquina/serviço reiniciou durante uma interrupção
    try:
        orphan = db.get_active_outage()
        if orphan:
            init_check = check_connectivity()
            if init_check.get("is_online"):
                closed = db.close_active_outage()
                if closed:
                    print(f"[*] Queda pendente #{orphan['id']} encerrada na inicialização do serviço ({closed.get('duration_seconds', 0)}s).")
    except Exception:
        pass

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

        # Amostragem adaptativa: se houver queda ou instabilidade ativa, verifica a cada 2 segundos!
        # Isso garante que a duração da interrupção seja cronometrada com precisão cirúrgica de segundos.
        try:
            active_outage = db.get_active_outage()
        except Exception:
            active_outage = None

        is_degraded = (last_state.get("status") != "ONLINE") or (active_outage is not None)
        current_sleep = 2 if is_degraded else ping_interval

        for _ in range(current_sleep):
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
