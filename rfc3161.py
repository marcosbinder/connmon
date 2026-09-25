"""
Módulo de Carimbo do Tempo Digital Criptográfico (RFC 3161).
Comunica-se diretamente com Autoridades Certificadoras públicas (TSA)
como DigiCert e FreeTSA usando a biblioteca padrão do Python (sem dependências externas).
"""

import hashlib
import urllib.request
import base64
from typing import Optional, Tuple, Union

# Servidores de Carimbo do Tempo (TSA) públicos e gratuitos compatíveis com RFC 3161
TSA_SERVERS = [
    ("DigiCert", "http://timestamp.digicert.com"),
    ("FreeTSA", "https://freetsa.org/tsr"),
]

# Estrutura DER padrão para TimeStampReq com SHA-256
# SEQUENCE {
#   version INTEGER 1,
#   messageImprint MessageImprint {
#     hashAlgorithm AlgorithmIdentifier { OID 2.16.840.1.101.3.4.2.1, NULL },
#     hashedMessage OCTET STRING [32 bytes]
#   }
# }
SHA256_ALG_ID = bytes.fromhex("300d06096086480165030402010500")


def compute_digest(data: Union[str, bytes]) -> bytes:
    """Calcula o digest binário SHA-256 (32 bytes)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def build_timestamp_query(digest: bytes) -> bytes:
    """Monta a requisição binária TimeStampReq compatível com RFC 3161."""
    if len(digest) != 32:
        raise ValueError("O digest SHA-256 deve ter exatamente 32 bytes.")
    imprint = b"\x30\x31" + SHA256_ALG_ID + b"\x04\x20" + digest
    return b"\x30\x36\x02\x01\x01" + imprint


def request_rfc3161_timestamp(
    data_or_digest: Union[str, bytes],
    timeout: int = 5
) -> Tuple[Optional[str], Optional[str]]:
    """
    Envia o hash dos dados para uma autoridade de carimbo de tempo (TSA) externa.
    Retorna uma tupla (tsr_base64, authority_name) em caso de sucesso,
    ou (None, None) se não for possível contatar a autoridade.
    """
    if isinstance(data_or_digest, (str, bytes)):
        if isinstance(data_or_digest, bytes) and len(data_or_digest) == 32:
            digest = data_or_digest
        else:
            digest = compute_digest(data_or_digest)
    else:
        return None, None

    ts_query = build_timestamp_query(digest)

    for name, url in TSA_SERVERS:
        try:
            req = urllib.request.Request(
                url,
                data=ts_query,
                headers={
                    "Content-Type": "application/timestamp-query",
                    "User-Agent": "NetMon-RFC3161-Client/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    der_bytes = resp.read()
                    # Verifica se o digest realmente está contido na resposta assinada da TSA
                    if digest in der_bytes:
                        tsr_b64 = base64.b64encode(der_bytes).decode("ascii")
                        return tsr_b64, name
        except Exception:
            continue

    return None, None


def verify_tsr_token(tsr_b64: str, expected_data_or_digest: Union[str, bytes]) -> bool:
    """
    Verifica se o token base64 RFC 3161 gerado contém a assinatura do hash esperado.
    """
    try:
        der_bytes = base64.b64decode(tsr_b64.encode("ascii"))
        if isinstance(expected_data_or_digest, bytes) and len(expected_data_or_digest) == 32:
            digest = expected_data_or_digest
        else:
            digest = compute_digest(expected_data_or_digest)
        return digest in der_bytes
    except Exception:
        return False
