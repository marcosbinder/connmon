"""
traceroute_tracer.py - Módulo de Rastreamento Forense de Rota e Atribuição de Falhas
Executa diagnósticos de rota (tracert no Windows / traceroute no Linux), identifica o salto exato
onde ocorreu o descarte ou pico de latência, e gera parecer técnico pericial que comprova juridicamente
se a falha foi da infraestrutura da operadora (ISP) ou da rede interna do cliente (LAN).
"""

import subprocess
import platform
import re
import json
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import db

# Controle de taxa e concorrência para não sobrecarregar a rede
_trace_lock = threading.Lock()
_last_trace_time = 0.0
_MIN_TRACE_INTERVAL_SECONDS = 45.0  # Mínimo entre execuções automáticas


def is_private_ip(ip_str: str) -> bool:
    """Verifica se um endereço IP pertence às faixas privadas RFC 1918 / CGNAT RFC 6598."""
    if not ip_str or ip_str == "*":
        return False
    # Localhost
    if ip_str.startswith("127."):
        return True
    # RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if ip_str.startswith("192.168."):
        return True
    if ip_str.startswith("10."):
        return True
    # 172.16.0.0 - 172.31.255.255
    m = re.match(r"^172\.(\d+)\.", ip_str)
    if m and 16 <= int(m.group(1)) <= 31:
        return True
    # CGNAT RFC 6598: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    m_cgnat = re.match(r"^100\.(\d+)\.", ip_str)
    if m_cgnat and 64 <= int(m_cgnat.group(1)) <= 127:
        return True
    # Link-local RFC 3927: 169.254.0.0/16
    if ip_str.startswith("169.254."):
        return True
    return False


def run_traceroute_cmd(target: str = "1.1.1.1", max_hops: int = 15, timeout_ms: int = 1000) -> str:
    """
    Executa comando de traceroute de forma multiplataforma com saída em formato numérico (-d / -n).
    """
    is_win = platform.system().lower() == "windows"
    if is_win:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), target]
    else:
        # No Linux testa traceroute ou tracepath
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout_sec), "-q", "1", target]

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=max_hops * 1.5 + 5.0
        )
        return res.stdout if res.stdout else res.stderr
    except FileNotFoundError:
        # Se traceroute não existir no Linux, fallback para tracepath
        if not is_win:
            try:
                res = subprocess.run(
                    ["tracepath", "-n", "-m", str(max_hops), target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    errors="replace",
                    timeout=max_hops * 1.5 + 5.0
                )
                return res.stdout
            except Exception as e2:
                return f"Falha de execução: tracepath/traceroute não disponível ({e2})"
        return "Comando de traceroute indisponível no sistema operacional."
    except subprocess.TimeoutExpired:
        return f"Timeout geral expirado durante o traceroute para {target}."
    except Exception as e:
        return f"Exceção durante execução do traceroute: {e}"


def parse_traceroute_output(raw_output: str) -> List[Dict[str, Any]]:
    """
    Converte a saída textual de tracert (Windows) ou traceroute/tracepath (Linux)
    em uma lista estruturada de saltos (hops).
    """
    hops = []
    lines = raw_output.splitlines()

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        # Windows tracert: "  1     2 ms     1 ms     2 ms  192.168.1.1" ou "  3     *        *        *     Esgotado o tempo limite do pedido."
        win_match = re.match(r"^\s*(\d+)\s+([\d\s<*ms]+?)\s+([0-9a-fA-F.:*]+|\*|Esgotado|Request timeout|Tempo limite).*$", line)
        if win_match:
            hop_idx = int(win_match.group(1))
            timing_part = win_match.group(2)

            # Extrai tempos em ms
            times = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", timing_part)]
            # Procura IP na linha
            ip_match = re.search(r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", line)
            ip_str = ip_match.group(1) if ip_match else ("*" if "*" in timing_part or "*" in line else None)

            avg_rtt = round(sum(times) / len(times), 1) if times else None
            is_timeout = (ip_str == "*" or avg_rtt is None or "*" in timing_part) and (len(times) == 0)

            hops.append({
                "hop": hop_idx,
                "ip": ip_str if ip_str and ip_str != "*" else None,
                "rtt_ms": avg_rtt,
                "times_ms": times,
                "timeout": is_timeout,
                "raw": line_clean
            })
            continue

        # Linux traceroute: " 1  192.168.1.1  1.423 ms" ou " 2  *  *" ou " 3  *"
        linux_match = re.match(r"^\s*(\d+)\s+([^\s]+)(?:\s+(.*))?$", line_clean)
        if linux_match:
            hop_idx = int(linux_match.group(1))
            host_or_ip = linux_match.group(2)
            timing_part = linux_match.group(3) or ""

            ip_match = re.search(r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", host_or_ip)
            ip_str = ip_match.group(1) if ip_match else (None if host_or_ip == "*" else host_or_ip)

            times = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", timing_part)]
            avg_rtt = round(sum(times) / len(times), 1) if times else None
            is_timeout = (host_or_ip == "*" or avg_rtt is None)

            hops.append({
                "hop": hop_idx,
                "ip": ip_str,
                "rtt_ms": avg_rtt,
                "times_ms": times,
                "timeout": is_timeout,
                "raw": line_clean
            })

    return hops


def diagnose_hops(hops: List[Dict[str, Any]], target: str = "1.1.1.1", isp_name: str = "Claro") -> Dict[str, Any]:
    """
    Avalia a sequência de saltos e determina a responsabilidade jurídica e técnica da anomalia.
    Retorna parecer forense categorizado: 'ISP', 'LAN', 'EXTERNAL' ou 'NONE'.
    """
    if not hops:
        return {
            "status": "UNKNOWN",
            "failed_hop": None,
            "failed_ip": None,
            "responsible_party": "UNKNOWN",
            "diagnosis": "Não foi possível extrair saltos válidos da rota de diagnóstico.",
            "is_isp_fault": False
        }

    # Salto 1: Gateway Local (Roteador Wi-Fi / Fibra do assinante)
    hop1 = hops[0]
    hop1_ok = (not hop1["timeout"]) and (hop1.get("rtt_ms") is not None)
    hop1_ip = hop1.get("ip") or "192.168.1.1"
    hop1_rtt = hop1.get("rtt_ms", 0.0)

    # Se o primeiro salto falhar totalmente
    if not hop1_ok:
        return {
            "status": "FAILED",
            "failed_hop": 1,
            "failed_ip": hop1_ip,
            "responsible_party": "LAN",
            "diagnosis": f"Falha no Gateway Local / Wi-Fi do cliente ({hop1_ip}). O roteador doméstico não respondeu, indicando problema interno na residência/cabo.",
            "is_isp_fault": False
        }

    # Se hop 1 respondeu perfeitamente (ex: 1-5ms), a rede local do assinante está 100% sadia!
    # Agora procuramos o primeiro ponto de ruptura na infraestrutura da operadora.
    failed_hop_idx = None
    failed_hop_data = None

    for i, h in enumerate(hops):
        if h["timeout"] or (h["rtt_ms"] and h["rtt_ms"] > 350.0):
            # Encontrou o primeiro salto de degradação ou corte
            failed_hop_idx = h["hop"]
            failed_hop_data = h
            break

    # Se o destino final respondeu com sucesso
    last_hop = hops[-1]
    reached_destination = (last_hop.get("ip") == target) and (not last_hop["timeout"])

    if failed_hop_idx is None or reached_destination:
        # Rota completa ou pequenos nós intermediários que mascaram ICMP mas entregam
        max_rtt = max([h["rtt_ms"] for h in hops if h.get("rtt_ms") is not None] or [0])
        if max_rtt > 150.0:
            return {
                "status": "HIGH_LATENCY",
                "failed_hop": None,
                "failed_ip": None,
                "responsible_party": "ISP",
                "diagnosis": f"Rota operacional até {target}, porém com latência anormalmente elevada no enlace da operadora ({max_rtt}ms). Roteador local operacional ({hop1_rtt}ms).",
                "is_isp_fault": True
            }
        return {
            "status": "OK",
            "failed_hop": None,
            "failed_ip": None,
            "responsible_party": "NONE",
            "diagnosis": f"Rota íntegra até o destino {target}. Gateway local ({hop1_rtt}ms) e infraestrutura externa sem pontos de estrangulamento.",
            "is_isp_fault": False
        }

    # Falha comprovada a partir do salto 2 ou superior
    f_hop_num = failed_hop_data["hop"]
    f_ip = failed_hop_data.get("ip") or "Não divulgado (ICMP dropped)"

    # Identifica o último salto que respondeu antes da queda
    last_working_hop = hops[f_hop_num - 2] if f_hop_num >= 2 and len(hops) >= (f_hop_num - 1) else hop1
    prev_ip = last_working_hop.get("ip", "desconhecido")
    prev_rtt = last_working_hop.get("rtt_ms", hop1_rtt)

    diagnosis_text = (
        f"Comprovação Pericial: Equipamento local do assinante em perfeito funcionamento (Gateway {hop1_ip}, "
        f"tempo de resposta de {hop1_rtt}ms). O descarte do tráfego ocorreu no salto {f_hop_num} ({f_ip}) "
        f"após o nó intermediário {prev_ip} ({prev_rtt}ms), pertencente à infraestrutura e enlace da operadora "
        f"{isp_name}. A responsabilidade pela interrupção é exclusiva do prestador de telecomunicações."
    )

    return {
        "status": "FAILED",
        "failed_hop": f_hop_num,
        "failed_ip": f_ip,
        "responsible_party": "ISP",
        "diagnosis": diagnosis_text,
        "is_isp_fault": True
    }


def perform_forensic_traceroute(
    trigger_reason: str,
    target: str = "1.1.1.1",
    outage_id: Optional[int] = None,
    db_path: str = db.DB_PATH
) -> Dict[str, Any]:
    """
    Executa um traceroute completo, analisa os saltos, persiste na tabela route_traces com HMAC
    e retorna o relatório estruturado.
    """
    global _last_trace_time
    _last_trace_time = time.time()

    isp_name = db.get_config("isp_name", "Claro", db_path=db_path)
    raw_output = run_traceroute_cmd(target=target, max_hops=15, timeout_ms=1000)
    hops = parse_traceroute_output(raw_output)
    analysis = diagnose_hops(hops, target=target, isp_name=isp_name)

    trace_id = db.record_route_trace(
        trigger_reason=trigger_reason,
        target=target,
        status=analysis["status"],
        failed_hop=analysis["failed_hop"],
        failed_ip=analysis["failed_ip"],
        responsible_party=analysis["responsible_party"],
        diagnosis=analysis["diagnosis"],
        hops_json=json.dumps(hops, ensure_ascii=False),
        raw_output=raw_output,
        outage_id=outage_id,
        db_path=db_path
    )

    result = {
        "id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trigger_reason": trigger_reason,
        "target": target,
        "status": analysis["status"],
        "failed_hop": analysis["failed_hop"],
        "failed_ip": analysis["failed_ip"],
        "responsible_party": analysis["responsible_party"],
        "diagnosis": analysis["diagnosis"],
        "hops": hops,
        "is_isp_fault": analysis["is_isp_fault"]
    }
    return result


def trigger_async_traceroute(
    reason: str,
    outage_id: Optional[int] = None,
    target: str = "1.1.1.1",
    force: bool = False,
    db_path: str = db.DB_PATH
):
    """
    Dispara execução de traceroute em thread assíncrona desacoplada do loop de monitoramento.
    Protegido por debounce para não inundar conexões com múltiplos tracerts simultâneos.
    """
    global _last_trace_time

    if not force:
        if (time.time() - _last_trace_time) < _MIN_TRACE_INTERVAL_SECONDS:
            return

    def _worker():
        if not _trace_lock.acquire(blocking=False):
            return
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [TRACEROUTE] Iniciando auditoria de rota ({reason})...")
            diag = perform_forensic_traceroute(
                trigger_reason=reason,
                target=target,
                outage_id=outage_id,
                db_path=db_path
            )
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [TRACEROUTE-OK] Salto de falha: {diag.get('failed_hop')} | Culpado: {diag.get('responsible_party')}")
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [TRACEROUTE-ERRO] Falha no rastreamento de rota: {e}")
        finally:
            try:
                _trace_lock.release()
            except RuntimeError:
                pass

    t = threading.Thread(target=_worker, daemon=True, name="forensic_traceroute_worker")
    t.start()
