/**
 * NetMon Cloudflare Worker - Testemunha Externa Gratuita
 * Roda 100% grátis no plano gratuito da Cloudflare (até 100.000 requisições/dia).
 * 
 * Funcionalidade:
 * 1. Recebe pings do seu monitor NetMon quando a internet está online (/ping)
 * 2. Permite verificar o último sinal recebido e status em tempo real (/status)
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const now = new Date().toISOString();

    // Rota: Recebe heartbeat do NetMon
    if (url.pathname === "/ping") {
      const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
      if (env.NETMON_KV) {
        await env.NETMON_KV.put("last_ping", JSON.stringify({
          timestamp: now,
          ip: clientIp,
          status: "ONLINE"
        }));
      }
      return new Response(JSON.stringify({ ok: true, received_at: now }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // Rota: Consulta pública de status
    if (url.pathname === "/status") {
      let lastData = null;
      if (env.NETMON_KV) {
        const raw = await env.NETMON_KV.get("last_ping");
        lastData = raw ? JSON.parse(raw) : null;
      }
      return new Response(JSON.stringify({
        probe: "NetMon Cloudflare Witness",
        time: now,
        last_heartbeat: lastData
      }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    return new Response("NetMon Probe Worker Ativo. Use /ping para enviar batimento ou /status para consultar.", {
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
};
