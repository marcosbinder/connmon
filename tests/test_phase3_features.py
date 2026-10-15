"""
test_phase3_features.py - Suite de Testes Automatizados para a Fase 3 do NetMon:
1. Rastreamento Forense de Rota e Atribuição Jurídica de Falhas (Hop 1 LAN vs Hop 2+ ISP).
2. Avaliação de Bufferbloat (Notas A+ a F) e Latência sob Carga.
3. Pacote Dossiê Pericial (.ZIP) com os 5 componentes obrigatórios.
4. Encadeamento Criptográfico HMAC-SHA256 e Verificação de Integridade em route_traces.
5. Notificações e Webhooks em Tempo Real (Discord & Telegram) para Quedas e Velocidade.
"""

import io
import zipfile
import hashlib
import urllib.request
import pytest

import db
import traceroute_tracer
import speed_tester
import notifier


# ==============================================================================
# 1. TESTES DE PARSING E ATRIBUIÇÃO FORENSE DE TRACEROUTE
# ==============================================================================

def test_traceroute_parsing_windows_output():
    """Testa a extração e conversão de saída típica do comando tracert (Windows)."""
    raw_win = """
Rastreando a rota para 1.1.1.1 com no máximo 15 saltos:

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    12 ms    11 ms    13 ms  10.20.30.1
  3     *        *        *     Esgotado o tempo limite do pedido.
  4    18 ms    17 ms    19 ms  1.1.1.1

Rastreamento concluído.
"""
    hops = traceroute_tracer.parse_traceroute_output(raw_win)
    assert len(hops) == 4
    assert hops[0]["hop"] == 1
    assert hops[0]["ip"] == "192.168.1.1"
    assert hops[0]["rtt_ms"] == 1.0
    assert not hops[0]["timeout"]

    assert hops[2]["hop"] == 3
    assert hops[2]["timeout"] is True


def test_traceroute_parsing_linux_output():
    """Testa a extração e conversão de saída típica do comando traceroute (Linux)."""
    raw_linux = """
traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms
 2  100.64.0.1  8.450 ms
 3  *
 4  1.1.1.1  14.210 ms
"""
    hops = traceroute_tracer.parse_traceroute_output(raw_linux)
    assert len(hops) == 4
    assert hops[0]["ip"] == "192.168.1.1"
    assert hops[1]["ip"] == "100.64.0.1"
    assert hops[2]["timeout"] is True
    assert hops[3]["ip"] == "1.1.1.1"


def test_traceroute_hop1_failure_attributed_to_lan():
    """Se o primeiro salto (roteador doméstico) falhar, a responsabilidade é da LAN do cliente."""
    hops = [
        {"hop": 1, "ip": None, "rtt_ms": None, "times_ms": [], "timeout": True, "raw": "1 * * * Timeout"},
        {"hop": 2, "ip": None, "rtt_ms": None, "times_ms": [], "timeout": True, "raw": "2 * * * Timeout"},
    ]
    diag = traceroute_tracer.diagnose_hops(hops, target="1.1.1.1", isp_name="Claro")
    assert diag["responsible_party"] == "LAN"
    assert diag["is_isp_fault"] is False
    assert diag["failed_hop"] == 1
    assert "Gateway Local" in diag["diagnosis"] or "Wi-Fi" in diag["diagnosis"]


def test_traceroute_hop2_failure_attributed_to_isp():
    """Se o salto 1 responder com perfeição e o salto 2+ falhar, a culpa jurídica é comprovada da ISP."""
    hops = [
        {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.5, "times_ms": [1.5], "timeout": False, "raw": "1 192.168.1.1 1.5ms"},
        {"hop": 2, "ip": None, "rtt_ms": None, "times_ms": [], "timeout": True, "raw": "2 * * * Timeout"},
        {"hop": 3, "ip": None, "rtt_ms": None, "times_ms": [], "timeout": True, "raw": "3 * * * Timeout"},
    ]
    diag = traceroute_tracer.diagnose_hops(hops, target="1.1.1.1", isp_name="Claro")
    assert diag["responsible_party"] == "ISP"
    assert diag["is_isp_fault"] is True
    assert diag["failed_hop"] == 2
    assert "exclusiva do prestador de telecomunica" in diag["diagnosis"]
    assert "Claro" in diag["diagnosis"]


def test_traceroute_all_hops_healthy():
    """Quando todos os saltos respondem com latência normal e alcançam o destino."""
    hops = [
        {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.2, "times_ms": [1.2], "timeout": False, "raw": "1 192.168.1.1 1.2ms"},
        {"hop": 2, "ip": "10.0.0.1", "rtt_ms": 12.0, "times_ms": [12.0], "timeout": False, "raw": "2 10.0.0.1 12ms"},
        {"hop": 3, "ip": "1.1.1.1", "rtt_ms": 14.5, "times_ms": [14.5], "timeout": False, "raw": "3 1.1.1.1 14.5ms"},
    ]
    diag = traceroute_tracer.diagnose_hops(hops, target="1.1.1.1", isp_name="Claro")
    assert diag["responsible_party"] == "NONE"
    assert diag["is_isp_fault"] is False
    assert diag["status"] == "OK"


def test_traceroute_high_latency_isp_attribution():
    """Destino alcançado, porém com latência excessiva (> 150ms) na operadora."""
    hops = [
        {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.0, "times_ms": [1.0], "timeout": False, "raw": "1 192.168.1.1 1.0ms"},
        {"hop": 2, "ip": "10.0.0.1", "rtt_ms": 280.0, "times_ms": [280.0], "timeout": False, "raw": "2 10.0.0.1 280ms"},
        {"hop": 3, "ip": "1.1.1.1", "rtt_ms": 295.0, "times_ms": [295.0], "timeout": False, "raw": "3 1.1.1.1 295ms"},
    ]
    diag = traceroute_tracer.diagnose_hops(hops, target="1.1.1.1", isp_name="Claro")
    assert diag["status"] == "HIGH_LATENCY"
    assert diag["responsible_party"] == "ISP"
    assert diag["is_isp_fault"] is True


# ==============================================================================
# 2. TESTES DE BUFFERBLOAT E QUALIDADE DE BUFFER
# ==============================================================================

@pytest.mark.parametrize("delta,expected_grade", [
    (None, "A"),
    (0.0, "A+"),
    (4.9, "A+"),
    (5.0, "A+"),
    (5.1, "A"),
    (25.0, "A"),
    (30.0, "A"),
    (31.0, "B"),
    (55.0, "B"),
    (60.0, "B"),
    (61.0, "C"),
    (115.0, "C"),
    (120.0, "C"),
    (121.0, "D"),
    (195.0, "D"),
    (200.0, "D"),
    (201.0, "F"),
    (500.0, "F"),
])
def test_bufferbloat_grading_scale(delta, expected_grade):
    """Garante a precisão das notas A+ a F conforme delta de latência sob carga."""
    assert speed_tester.calculate_bufferbloat_grade(delta) == expected_grade


def test_bufferbloat_persistence_and_status_reporting(temp_db):
    """Testa armazenamento de campos de Bufferbloat no DB e recuperação no get_latest_status."""
    test_id = db.record_speed_test(
        trigger_reason="scheduled_test",
        download_mbps=450.0,
        upload_mbps=220.0,
        ping_ms=18.0,
        status="SUCCESS",
        loaded_ping_ms=45.0,
        bufferbloat_grade="A",
        db_path=temp_db
    )
    assert test_id > 0

    status = db.get_latest_status(temp_db)
    assert status["last_speed"]["loaded_ping_ms"] == 45.0
    assert status["last_speed"]["bufferbloat_grade"] == "A"
    assert status["stats_24h"]["latest_bufferbloat_grade"] == "A"
    assert status["stats_24h"]["latest_bufferbloat_delta_ms"] == 27.0  # 45.0 - 18.0


# ==============================================================================
# 3. TESTES DE CRIPTOGRAFIA FORENSE E INTEGRIDADE EM ROUTE_TRACES
# ==============================================================================

def test_route_trace_hmac_chaining_and_integrity_check(temp_db):
    """Valida o encadeamento HMAC-SHA256 em route_traces e a validação antifraude."""
    # 1. Base limpa deve ser VALID
    res1 = db.verify_database_integrity(temp_db)
    assert res1["status"] == "VALID"
    assert res1["checked_route_traces"] == 0

    # 2. Inserção de traces encadeados
    t1_id = db.record_route_trace(
        trigger_reason="anomaly_detected",
        target="1.1.1.1",
        status="FAILED",
        failed_hop=2,
        failed_ip="10.10.10.1",
        responsible_party="ISP",
        diagnosis="Falha no enlace da operadora",
        hops_json="[]",
        raw_output="raw 1",
        db_path=temp_db
    )
    t2_id = db.record_route_trace(
        trigger_reason="manual_audit",
        target="1.1.1.1",
        status="OK",
        failed_hop=None,
        failed_ip=None,
        responsible_party="NONE",
        diagnosis="Rota normalizada",
        hops_json="[]",
        raw_output="raw 2",
        db_path=temp_db
    )
    assert t1_id > 0
    assert t2_id > 0

    # 3. Verifica integridade após inserção
    res2 = db.verify_database_integrity(temp_db)
    assert res2["status"] == "VALID"
    assert res2["checked_route_traces"] == 2
    assert res2["tampered_route_traces"] == 0

    # 4. Simulação de adulteração fraudulenta direta no banco
    conn = db.get_connection(temp_db)
    with conn:
        conn.execute("UPDATE route_traces SET responsible_party = 'LAN' WHERE id = ?;", (t1_id,))
    conn.close()

    res3 = db.verify_database_integrity(temp_db)
    assert res3["status"] == "TAMPERED"
    assert res3["tampered_route_traces"] >= 1


# ==============================================================================
# 4. TESTES DO PACOTE DOSSIÊ PERICIAL (.ZIP)
# ==============================================================================

def test_export_dossier_zip_generation(live_server, api_client, populated_db):
    """
    Testa o endpoint GET /api/export_dossier:
    - Retorna status 200 e content-type application/zip.
    - Contém os 5 artefatos periciais canônicos.
    - Verifica assinaturas SHA-256 no arquivo Checksum_SHA256.sig.
    """
    url = f"{live_server}/api/export_dossier?hours=24"
    req = urllib.request.Request(url, headers={"User-Agent": "NetMon-Pytest/3.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        assert "application/zip" in resp.headers.get("Content-Type", "")
        zip_bytes = resp.read()

    assert len(zip_bytes) > 1000  # Deve ter tamanho real

    # Descompacta e valida conteúdo em memória
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    file_list = zf.namelist()

    expected_files = [
        "Laudo_Tecnico_Oficial.pdf",
        "Telemetria_Pings.csv",
        "Testes_Velocidade.csv",
        "Cadeia_Custodia_Hashes.txt",
        "Checksum_SHA256.sig"
    ]
    for ef in expected_files:
        assert ef in file_list, f"Arquivo {ef} ausente no Dossiê ZIP"

    # 1. Verifica PDF nativo 1.4
    pdf_content = zf.read("Laudo_Tecnico_Oficial.pdf")
    assert pdf_content.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_content

    # 2. Verifica CSVs
    pings_csv = zf.read("Telemetria_Pings.csv").decode("utf-8")
    assert "timestamp" in pings_csv
    assert "latency_ms" in pings_csv

    speed_csv = zf.read("Testes_Velocidade.csv").decode("utf-8")
    assert "download_mbps" in speed_csv

    # 3. Verifica Cadeia de Custódia
    custody_txt = zf.read("Cadeia_Custodia_Hashes.txt").decode("utf-8")
    assert "CADEIA DE CUSTODIA" in custody_txt
    assert "ABNT NBR ISO/IEC 27037" in custody_txt

    # 4. Verifica integridade dos Checksums
    sig_content = zf.read("Checksum_SHA256.sig").decode("utf-8")
    pdf_sha = hashlib.sha256(pdf_content).hexdigest()
    assert pdf_sha in sig_content


# ==============================================================================
# 5. TESTES DE WEBHOOKS E ALERTAS EM TEMPO REAL
# ==============================================================================

def test_discord_webhook_formatting(monkeypatch):
    """Verifica formatação correta de Embed para o Discord."""
    dispatched = []

    def mock_post(url, payload, timeout=4.0):
        dispatched.append((url, payload))
        return True, "HTTP 204"

    monkeypatch.setattr(notifier, "_http_post_json", mock_post)

    ok, msg = notifier.send_discord_webhook(
        webhook_url="https://discord.com/api/webhooks/test/123",
        title="Alerta de Teste",
        description="Descrição pericial",
        fields=[{"name": "Campo1", "value": "Valor1", "inline": True}]
    )
    assert ok is True
    assert len(dispatched) == 1
    url, body = dispatched[0]
    assert url == "https://discord.com/api/webhooks/test/123"
    assert body["embeds"][0]["title"] == "Alerta de Teste"
    assert body["embeds"][0]["fields"][0]["name"] == "Campo1"


def test_telegram_message_formatting(monkeypatch):
    """Verifica envio de mensagem formatada em HTML para o Telegram."""
    dispatched = []

    def mock_post(url, payload, timeout=4.0):
        dispatched.append((url, payload))
        return True, "HTTP 200"

    monkeypatch.setattr(notifier, "_http_post_json", mock_post)

    ok, msg = notifier.send_telegram_message(
        bot_token="123456:ABC-DEF",
        chat_id="987654321",
        text="<b>Alerta de Teste</b>"
    )
    assert ok is True
    assert len(dispatched) == 1
    url, body = dispatched[0]
    assert "123456:ABC-DEF" in url
    assert body["chat_id"] == "987654321"
    assert body["parse_mode"] == "HTML"


def test_notify_outage_started_and_ended(temp_db, monkeypatch):
    """Testa os despachantes notify_outage_started e notify_outage_ended com cálculo de ressarcimento."""
    # Configura webhook falso no DB de teste
    db.set_config("discord_webhook_url", "https://discord.com/api/webhooks/fake", temp_db)
    db.set_config("telegram_bot_token", "fake_token", temp_db)
    db.set_config("telegram_chat_id", "fake_chat", temp_db)
    db.set_config("notifications_enabled", "1", temp_db)

    calls = []

    def mock_discord(url, title, description, color=0x38BDF8, fields=None):
        calls.append(("discord", title, fields))
        return True, "OK"

    def mock_telegram(token, chat, text):
        calls.append(("telegram", text))
        return True, "OK"

    monkeypatch.setattr(notifier, "send_discord_webhook", mock_discord)
    monkeypatch.setattr(notifier, "send_telegram_message", mock_telegram)

    # Executa sincronicamente sem a thread para teste direto
    monkeypatch.setattr(notifier, "dispatch_async_notification", lambda fn: fn())

    notifier.notify_outage_started(
        outage_type="TOTAL",
        reason="Perda total de 100% dos pacotes",
        client_name="Marco Aurelio",
        isp_name="Claro",
        failed_hop=2,
        db_path=temp_db
    )
    assert any(c[0] == "discord" and "QUEDA TOTAL" in c[1] for c in calls)
    assert any(c[0] == "telegram" and "QUEDA TOTAL" in c[1] and "DETECTADA" in c[1] for c in calls)

    calls.clear()
    notifier.notify_outage_ended(
        outage_type="TOTAL",
        duration_seconds=3600.0,
        refund_reais=5.00,
        client_name="Marco Aurelio",
        isp_name="Claro",
        db_path=temp_db
    )
    assert any(c[0] == "discord" and "Conexão Restabelecida" in c[1] for c in calls)
    assert any(c[0] == "telegram" and "CONEXÃO RESTABELECIDA" in c[1] for c in calls)


# ==============================================================================
# 6. TESTES DOS ENDPOINTS REST DA FASE 3
# ==============================================================================

def test_api_traces_endpoint(live_server, api_client, temp_db):
    """Testa GET /api/traces."""
    db.record_route_trace(
        trigger_reason="test_api",
        target="1.1.1.1",
        status="OK",
        failed_hop=None,
        failed_ip=None,
        responsible_party="NONE",
        diagnosis="Rota OK",
        hops_json="[]",
        raw_output="out",
        db_path=temp_db
    )
    traces = api_client.get_json(f"{live_server}/api/traces")
    assert isinstance(traces, list)
    assert len(traces) >= 1
    assert traces[0]["target"] == "1.1.1.1"


def test_api_trigger_traceroute_endpoint(live_server, api_client):
    """Testa POST /api/trigger_traceroute."""
    resp = api_client.post_json(f"{live_server}/api/trigger_traceroute", {})
    assert resp.get("status") == "QUEUED"
