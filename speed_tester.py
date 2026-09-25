"""
speed_tester.py - Medidor de velocidade de rede ultra-leve e confiável.
Utiliza a CDN da Cloudflare como motor primário (sem dependências pesadas, sem consumo excessivo de RAM/CPU).
Suporta fallback opcional para speedtest-cli.
"""

import time
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


def run_speed_test(engine: str = "cloudflare") -> Dict[str, Any]:
    """
    Executa teste completo de velocidade.
    Retorna dicionário com métricas ou status de erro em caso de falha total de conexão.
    """
    if engine == "speedtest-cli":
        return run_speedtest_cli()

    # Engine padrão: Cloudflare (super leve e rápida)
    try:
        ping_ms = measure_ping_http()
        down_mbps = run_cloudflare_download()
        up_mbps = run_cloudflare_upload()

        return {
            "download_mbps": down_mbps,
            "upload_mbps": up_mbps,
            "ping_ms": ping_ms,
            "status": "SUCCESS",
            "error_message": None,
            "engine": "cloudflare"
        }
    except Exception as e:
        # Se Cloudflare falhar por qualquer motivo e speedtest-cli estiver instalado, tenta fallback
        try:
            return run_speedtest_cli()
        except Exception:
            pass

        return {
            "download_mbps": None,
            "upload_mbps": None,
            "ping_ms": None,
            "status": "FAILED",
            "error_message": str(e),
            "engine": "cloudflare"
        }


if __name__ == "__main__":
    print("Iniciando teste de velocidade rápido...")
    result = run_speed_test()
    print("Resultado do teste:", result)
