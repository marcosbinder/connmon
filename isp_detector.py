"""
isp_detector.py - Identificador automatico de operadora e IP publico
Detecta provedor, ASN, IP externo e localizacao de forma leve e em cache.
"""

import urllib.request
import json
import time
from typing import Dict, Any, Optional

_cached_info: Optional[Dict[str, Any]] = None
_last_check_time: float = 0.0
CACHE_TTL_SECONDS = 21600  # 6 horas


def get_isp_info(force_refresh: bool = False) -> Dict[str, Any]:
    """Retorna dados da conexao publica (operadora, ASN e IP). Usa cache para evitar chamadas repetidas."""
    global _cached_info, _last_check_time

    now = time.time()
    if not force_refresh and _cached_info and (now - _last_check_time) < CACHE_TTL_SECONDS:
        return _cached_info

    # Tentativa 1: ip-api.com
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/?fields=status,country,regionName,city,isp,org,as,query",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                info = {
                    "isp": data.get("isp", "Desconhecido"),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    "ip": data.get("query", ""),
                    "city": data.get("city", ""),
                    "region": data.get("regionName", ""),
                    "country": data.get("country", "")
                }
                _cached_info = info
                _last_check_time = now
                return info
    except Exception:
        pass

    # Tentativa 2 (fallback): Cloudflare meta
    try:
        req = urllib.request.Request(
            "https://speed.cloudflare.com/meta",
            headers={
                "User-Agent": "Mozilla/5.0",
                "Referer": "https://speed.cloudflare.com/"
            }
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            asn_org = data.get("asnOrganization", "Desconhecido")
            asn_num = data.get("asn", "")
            info = {
                "isp": asn_org,
                "org": asn_org,
                "asn": f"AS{asn_num}" if asn_num else "",
                "ip": data.get("clientIp", ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country", "")
            }
            _cached_info = info
            _last_check_time = now
            return info
    except Exception:
        pass

    # Se estiver offline ou ambas as consultas falharem
    if _cached_info:
        return _cached_info

    return {
        "isp": "Nao identificado (offline)",
        "org": "",
        "asn": "",
        "ip": "",
        "city": "",
        "region": "",
        "country": ""
    }


if __name__ == "__main__":
    res = get_isp_info(force_refresh=True)
    print("Dados detectados:", json.dumps(res, indent=2, ensure_ascii=False))
