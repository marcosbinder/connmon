"""
speed_tester.py - Medidor de velocidade de rede ultra-leve e confiável.
Utiliza a CDN da Cloudflare como motor primário (sem dependências pesadas, sem consumo excessivo de RAM/CPU).
Suporta fallback opcional para speedtest-cli.
"""

import time
import threading
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

CLOUDFLARE_DOWN_URL = "https://speed.cloudflare.com/__down?bytes="
CLOUDFLARE_UP_URL = "https://speed.cloudflare.com/__up"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": "https://speed.cloudflare.com/",
    "Origin": "https://speed.cloudflare.com"
}


def measure_ping_http(timeout: float = 4.0) -> Optional[float]:
    """Mede a latência HTTP até a CDN de teste."""
    try:
        start = time.perf_counter()
        req = urllib.request.Request(
            "https://speed.cloudflare.com/__down?bytes=0",
            headers=HEADERS
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return round((time.perf_counter() - start) * 1000, 1)
    except Exception:
        return None


def run_cloudflare_download(bytes_to_fetch: int = 15_000_000, timeout: float = 12.0) -> float:
    """Mede velocidade de download via Cloudflare CDN (default: ~15MB)."""
    url = f"{CLOUDFLARE_DOWN_URL}{bytes_to_fetch}"
    req = urllib.request.Request(url, headers=HEADERS)

    start = time.perf_counter()
    total_bytes = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        # Lê em pedaços de 64KB para economizar RAM
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total_bytes += len(chunk)
            # Se já passaram mais de 10s medindo, encerra a leitura para não travar
            if time.perf_counter() - start > 10.0:
                break

    duration = time.perf_counter() - start
    if duration <= 0 or total_bytes == 0:
        return 0.0

    # Mbps = (bytes * 8) / (segundos * 10^6)
    mbps = (total_bytes * 8) / (duration * 1_000_000)
    return round(mbps, 2)


def run_cloudflare_upload(bytes_to_send: int = 4_000_000, timeout: float = 12.0) -> float:
    """Mede velocidade de upload via Cloudflare CDN (default: ~4MB)."""
    payload = b"0" * bytes_to_send
    up_headers = dict(HEADERS)
    up_headers["Content-Type"] = "application/octet-stream"

    req = urllib.request.Request(
        CLOUDFLARE_UP_URL,
        data=payload,
        headers=up_headers
    )

    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()
    duration = time.perf_counter() - start

    if duration <= 0:
        return 0.0

    mbps = (bytes_to_send * 8) / (duration * 1_000_000)
    return round(mbps, 2)


def run_speedtest_cli() -> Dict[str, Any]:
    """Fallback usando speedtest-cli se disponível."""
    try:
        import speedtest
        st = speedtest.Speedtest(timeout=10)
        st.get_best_server()
        down = round(st.download() / 1_000_000, 2)
        up = round(st.upload() / 1_000_000, 2)
        ping = round(st.results.ping, 1)
        return {
            "download_mbps": down,
            "upload_mbps": up,
            "ping_ms": ping,
            "status": "SUCCESS",
            "error_message": None,
            "engine": "speedtest-cli"
        }
    except Exception as e:
        return {
            "download_mbps": None,
            "upload_mbps": None,
            "ping_ms": None,
            "status": "FAILED",
            "error_message": str(e),
            "engine": "speedtest-cli"
        }


def calculate_bufferbloat_grade(delta_ms: Optional[float]) -> str:
    """Classifica o Bufferbloat conforme a escala internacional (RFC / DSLReports / Waveform)."""
    if delta_ms is None:
        return "A"
    if delta_ms <= 5.0:
        return "A+"
    elif delta_ms <= 30.0:
        return "A"
    elif delta_ms <= 60.0:
        return "B"
    elif delta_ms <= 120.0:
        return "C"
    elif delta_ms <= 200.0:
        return "D"
    else:
        return "F"


def measure_loaded_ping(timeout: float = 2.5) -> Optional[float]:
    """Mede a latência enquanto a conexão está sob carga ativa de transferência."""
    try:
        start = time.perf_counter()
        req = urllib.request.Request("https://speed.cloudflare.com/__down?bytes=0", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return round((time.perf_counter() - start) * 1000, 1)
    except Exception:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            st = time.perf_counter()
            s.connect(("1.1.1.1", 53))
            lat = (time.perf_counter() - st) * 1000.0
            s.close()
            return round(lat, 1)
        except Exception:
            return None


def run_speed_test(engine: str = "cloudflare") -> Dict[str, Any]:
    """
    Executa teste completo de velocidade com isolamento defensivo entre ping, download e upload.
    Mede a latência em repouso e sob carga para avaliação de Bufferbloat (RFC 3550 / RFC 4689).
    """
    if engine == "speedtest-cli":
        res = run_speedtest_cli()
        res["loaded_ping_ms"] = res.get("ping_ms")
        res["bufferbloat_delta_ms"] = 0.0
        res["bufferbloat_grade"] = "A"
        return res

    errors = []
    ping_ms = None
    try:
        ping_ms = measure_ping_http()
    except Exception as e:
        errors.append(f"ping: {e}")

    # Sondagem concorrente de latência sob carga durante o download
    loaded_latencies = []
    def _probe_loaded():
        time.sleep(0.5)
        lp = measure_loaded_ping(timeout=2.0)
        if lp is not None:
            loaded_latencies.append(lp)

    probe_th = threading.Thread(target=_probe_loaded, daemon=True, name="bufferbloat_probe")
    probe_th.start()

    down_mbps = None
    try:
        down_mbps = run_cloudflare_download()
    except Exception as e:
        errors.append(f"download: {e}")

    probe_th.join(timeout=0.8)

    up_mbps = None
    try:
        up_mbps = run_cloudflare_upload()
    except Exception as e:
        errors.append(f"upload: {e}")

    loaded_ping_ms = round(sum(loaded_latencies) / len(loaded_latencies), 1) if loaded_latencies else None
    if loaded_ping_ms is not None and ping_ms is not None:
        delta_ms = max(0.0, round(loaded_ping_ms - ping_ms, 1))
    elif loaded_ping_ms is not None:
        delta_ms = 0.0
    else:
        delta_ms = None
    bufferbloat_grade = calculate_bufferbloat_grade(delta_ms)

    # Se ao menos uma das métricas essenciais foi obtida, preservamos o resultado
    if down_mbps is not None or up_mbps is not None:
        return {
            "download_mbps": down_mbps,
            "upload_mbps": up_mbps,
            "ping_ms": ping_ms,
            "loaded_ping_ms": loaded_ping_ms,
            "bufferbloat_delta_ms": delta_ms,
            "bufferbloat_grade": bufferbloat_grade,
            "status": "SUCCESS" if (down_mbps is not None and up_mbps is not None) else "PARTIAL",
            "error_message": "; ".join(errors) if errors else None,
            "engine": "cloudflare"
        }

    # Se ambas as medições de banda falharam, tenta fallback para speedtest-cli
    primary_err = "; ".join(errors) if errors else "Falha completa na medição de banda Cloudflare"
    try:
        res = run_speedtest_cli()
        if res.get("status") == "SUCCESS":
            res["loaded_ping_ms"] = res.get("ping_ms")
            res["bufferbloat_delta_ms"] = 0.0
            res["bufferbloat_grade"] = "A"
            return res
    except Exception:
        pass

    return {
        "download_mbps": None,
        "upload_mbps": None,
        "ping_ms": ping_ms,
        "loaded_ping_ms": loaded_ping_ms,
        "bufferbloat_delta_ms": delta_ms,
        "bufferbloat_grade": bufferbloat_grade,
        "status": "FAILED",
        "error_message": primary_err,
        "engine": "cloudflare"
    }


if __name__ == "__main__":
    print("Iniciando teste de velocidade rápido...")
    result = run_speed_test()
    print("Resultado do teste:", result)
