"""
notifier.py - Módulo de Notificações e Webhooks em Tempo Real (Discord & Telegram)
Envia alertas instantâneos para quedas de conexão, restabelecimento do sinal e
descumprimento flagrante das metas de velocidade RQUAL da ANATEL (< 40%).
Execução 100% assíncrona, tolerante a falhas e sem dependências externas.
"""

import json
import urllib.request
import urllib.error
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import db


def _http_post_json(url: str, payload: Dict[str, Any], timeout: float = 4.0) -> Tuple[bool, str]:
    """Helper seguro para requisições HTTP POST com JSON nativo e timeout curto."""
    try:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "NetMon-AlertService/3.0"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")[:200]
        return False, f"HTTP {e.code}: {err_msg}"
    except Exception as e:
        return False, str(e)


def send_discord_webhook(
    webhook_url: str,
    title: str,
    description: str,
    color: int = 0x38BDF8,
    fields: Optional[List[Dict[str, Any]]] = None
) -> Tuple[bool, str]:
    """Envia mensagem formatada com Embed no Discord."""
    if not webhook_url or not webhook_url.startswith("http"):
        return False, "URL de webhook do Discord não configurada."

    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {
            "text": "NetMon - Sistema de Auditoria Pericial de Telecomunicações"
        }
    }
    if fields:
        embed["fields"] = fields

    payload = {
        "username": "NetMon Auditor",
        "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/activity.svg",
        "embeds": [embed]
    }
    return _http_post_json(webhook_url, payload)


def send_telegram_message(
    bot_token: str,
    chat_id: str,
    text: str
) -> Tuple[bool, str]:
    """Envia notificação via Telegram Bot API com formatação HTML."""
    if not bot_token or not chat_id:
        return False, "Token do bot ou Chat ID do Telegram não configurados."

    url = f"https://api.telegram.org/bot{bot_token.strip()}/sendMessage"
    payload = {
        "chat_id": chat_id.strip(),
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    return _http_post_json(url, payload)


def dispatch_async_notification(task_fn, *args, **kwargs):
    """Executa o envio em thread daemon dedicada para nunca travar loops de monitoramento."""
    def _run():
        try:
            task_fn(*args, **kwargs)
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [NOTIFY-ERRO] {e}")

    threading.Thread(target=_run, daemon=True, name="webhook_dispatcher").start()


def notify_outage_started(
    outage_type: str,
    reason: str,
    client_name: str = "",
    isp_name: str = "",
    failed_hop: Optional[int] = None,
    db_path: str = db.DB_PATH
):
    """Dispara alerta em tempo real de início de queda ou instabilidade severa."""
    def _task():
        enabled = db.get_config("notifications_enabled", "1", db_path=db_path)
        if enabled != "1":
            return

        discord_url = db.get_config("discord_webhook_url", "", db_path=db_path)
        tg_token = db.get_config("telegram_bot_token", "", db_path=db_path)
        tg_chat = db.get_config("telegram_chat_id", "", db_path=db_path)

        now_str = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
        tipo_lbl = "🚨 QUEDA TOTAL (BLACKOUT)" if outage_type == "TOTAL" else "⚠️ INSTABILIDADE SEVERA"
        cor = 0xEF4444 if outage_type == "TOTAL" else 0xF59E0B

        hop_info = f"Salto {failed_hop} (Infraestrutura da Operadora)" if failed_hop else "Em análise forense via Traceroute..."

        # Discord
        if discord_url:
            fields = [
                {"name": "⏰ Horário de Início", "value": now_str, "inline": True},
                {"name": "🏢 Operadora", "value": isp_name or "Claro", "inline": True},
                {"name": "👤 Titular", "value": client_name or "Assinante", "inline": True},
                {"name": "🔍 Diagnóstico Técnico", "value": reason[:300], "inline": False},
                {"name": "🌐 Ponto de Ruptura (Traceroute)", "value": hop_info, "inline": False},
            ]
            send_discord_webhook(
                discord_url,
                title=f"{tipo_lbl} Detectada",
                description="O NetMon identificou interrupção de conectividade e iniciou a cronometragem pericial para fins de ressarcimento Anatel.",
                color=cor,
                fields=fields
            )

        # Telegram
        if tg_token and tg_chat:
            tg_text = (
                f"<b>{tipo_lbl} DETECTADA</b>\n\n"
                f"<b>Horário:</b> {now_str}\n"
                f"<b>Operadora:</b> {isp_name or 'Claro'}\n"
                f"<b>Titular:</b> {client_name or 'Assinante'}\n"
                f"<b>Diagnóstico:</b> {reason[:200]}\n"
                f"<b>Ruptura:</b> {hop_info}\n\n"
                f"<i>Cronometrando duração pericial exata (Art. 46 da Resolução Anatel nº 632/2014).</i>"
            )
            send_telegram_message(tg_token, tg_chat, tg_text)

    dispatch_async_notification(_task)


def notify_outage_ended(
    outage_type: str,
    duration_seconds: float,
    refund_reais: float = 0.0,
    client_name: str = "",
    isp_name: str = "",
    db_path: str = db.DB_PATH
):
    """Dispara alerta em tempo real de encerramento da interrupção com demonstrativo pericial."""
    def _task():
        enabled = db.get_config("notifications_enabled", "1", db_path=db_path)
        if enabled != "1":
            return

        discord_url = db.get_config("discord_webhook_url", "", db_path=db_path)
        tg_token = db.get_config("telegram_bot_token", "", db_path=db_path)
        tg_chat = db.get_config("telegram_chat_id", "", db_path=db_path)

        now_str = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
        tipo_lbl = "Queda Total" if outage_type == "TOTAL" else "Instabilidade Parcial"
        dur_min = round(duration_seconds / 60.0, 1)

        # Discord
        if discord_url:
            fields = [
                {"name": "⏰ Horário de Retorno", "value": now_str, "inline": True},
                {"name": "⏱️ Duração Total", "value": f"{round(duration_seconds)}s ({dur_min} min)", "inline": True},
                {"name": "💰 Abatimento Fatura", "value": f"R$ {refund_reais:.2f}", "inline": True},
                {"name": "🏢 Operadora", "value": isp_name or "Claro", "inline": True},
                {"name": "📜 Base Legal", "value": "Resolução ANATEL nº 632/2014 & CDC Art. 20", "inline": False},
            ]
            send_discord_webhook(
                discord_url,
                title="✅ Conexão Restabelecida",
                description=f"A interrupção de {tipo_lbl} foi concluída e o evento foi auditado com assinatura criptográfica no banco de dados.",
                color=0x22C55E,
                fields=fields
            )

        # Telegram
        if tg_token and tg_chat:
            tg_text = (
                f"<b>✅ CONEXÃO RESTABELECIDA</b>\n\n"
                f"<b>Tipo:</b> {tipo_lbl}\n"
                f"<b>Término:</b> {now_str}\n"
                f"<b>Duração:</b> {round(duration_seconds)}s ({dur_min} min)\n"
                f"<b>Abatimento Estimado:</b> R$ {refund_reais:.2f}\n"
                f"<b>Operadora:</b> {isp_name or 'Claro'}\n\n"
                f"<i>Evento auditado sob cadeia de custódia ABNT NBR ISO/IEC 27037.</i>"
            )
            send_telegram_message(tg_token, tg_chat, tg_text)

    dispatch_async_notification(_task)


def notify_speed_drop(
    delivered_down: float,
    contracted_down: float,
    delivered_up: float,
    contracted_up: float,
    bufferbloat_grade: str = "A",
    isp_name: str = "",
    db_path: str = db.DB_PATH
):
    """Dispara alerta em tempo real de descumprimento das metas de velocidade RQUAL (< 40%)."""
    def _task():
        enabled = db.get_config("notifications_enabled", "1", db_path=db_path)
        if enabled != "1":
            return

        discord_url = db.get_config("discord_webhook_url", "", db_path=db_path)
        tg_token = db.get_config("telegram_bot_token", "", db_path=db_path)
        tg_chat = db.get_config("telegram_chat_id", "", db_path=db_path)

        now_str = datetime.now().strftime("%d/%m/%Y às %H:%M:%S")
        down_pct = round((delivered_down / contracted_down * 100), 1) if contracted_down > 0 else 0

        # Discord
        if discord_url:
            fields = [
                {"name": "📉 Download Entregue", "value": f"{delivered_down:.1f} Mbps ({down_pct}% da meta)", "inline": True},
                {"name": "📋 Contratado", "value": f"{contracted_down:.0f} Mbps", "inline": True},
                {"name": "📶 Bufferbloat", "value": f"Nota {bufferbloat_grade}", "inline": True},
                {"name": "⚖️ Violação Regulatória", "value": "Abaixo de 40% da velocidade instantânea exigida pelo RQUAL (Resoluções ANATEL 574/2011 e 717/2019).", "inline": False},
            ]
            send_discord_webhook(
                discord_url,
                title="⚠️ Alerta de Lentidão Crítica (Violação ANATEL)",
                description="O teste de velocidade registrou entrega de banda muito abaixo da franquia mínima regulatória.",
                color=0xE11D48,
                fields=fields
            )

        # Telegram
        if tg_token and tg_chat:
            tg_text = (
                f"<b>⚠️ ALERTA DE LENTIDÃO CRÍTICA (VIOLAÇÃO ANATEL)</b>\n\n"
                f"<b>Horário:</b> {now_str}\n"
                f"<b>Download:</b> {delivered_down:.1f} Mbps (Contratado: {contracted_down:.0f} Mbps - {down_pct}%)\n"
                f"<b>Upload:</b> {delivered_up:.1f} Mbps (Contratado: {contracted_up:.0f} Mbps)\n"
                f"<b>Bufferbloat:</b> Nota {bufferbloat_grade}\n"
                f"<b>Operadora:</b> {isp_name or 'Claro'}\n\n"
                f"<i>Descumprimento flagrante da meta instantânea de 40% do RQUAL.</i>"
            )
            send_telegram_message(tg_token, tg_chat, tg_text)

    dispatch_async_notification(_task)


def test_notifications(db_path: str = db.DB_PATH) -> Dict[str, Any]:
    """Executa disparo de teste síncrono para validação das credenciais na aba de configurações."""
    discord_url = db.get_config("discord_webhook_url", "", db_path=db_path)
    tg_token = db.get_config("telegram_bot_token", "", db_path=db_path)
    tg_chat = db.get_config("telegram_chat_id", "", db_path=db_path)

    results = {}

    if discord_url:
        ok, msg = send_discord_webhook(
            discord_url,
            title="🔔 Teste de Notificação NetMon",
            description="Este é um envio de teste para confirmar que os alertas de queda e degradação estão funcionando perfeitamente.",
            color=0x38BDF8,
            fields=[
                {"name": "Status", "value": "Online e Operacional", "inline": True},
                {"name": "Hora do Teste", "value": datetime.now().strftime("%H:%M:%S"), "inline": True}
            ]
        )
        results["discord"] = {"ok": ok, "message": msg}
    else:
        results["discord"] = {"ok": False, "message": "URL do webhook não informada."}

    if tg_token and tg_chat:
        tg_text = (
            "<b>🔔 Teste de Notificação NetMon</b>\n\n"
            "Conexão com o bot do Telegram validada com sucesso!\n"
            f"Horário: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
        )
        ok, msg = send_telegram_message(tg_token, tg_chat, tg_text)
        results["telegram"] = {"ok": ok, "message": msg}
    else:
        results["telegram"] = {"ok": False, "message": "Bot Token ou Chat ID não informados."}

    return results
