# Testemunha Externa Gratuita (Dual-Check / Anti-adulteração)

Este diretório contém alternativas para quem deseja uma **testemunha externa e neutra** para registrar que a sua conexão caiu, sem que ninguém (nem quem tem acesso root ao servidor) possa fraudar o histórico.

---

## Alternativa 1: Healthchecks.io (Recomendada, mais simples)

O **Healthchecks.io** é um serviço open-source consolidado com plano **100% gratuito**:

1. Acesse [healthchecks.io](https://healthchecks.io) e crie uma conta gratuita.
2. Crie um novo "Check" com intervalo de 1 minuto e período de tolerância de 1 minuto.
3. Copie a URL gerada (exemplo: `https://hc-ping.com/seu-codigo-uuid`).
4. No painel do NetMon, clique em **Configurações** e cole essa URL no campo **Testemunha Externa**.
5. Clique em **Salvar Configurações**.

**Como funciona a comprovação:**
- Enquanto a sua internet estiver funcionando, o NetMon avisa a nuvem do Healthchecks.io.
- Se a sua internet cair, o sinal cessa e o Healthchecks.io registra independentemente na nuvem dele: *"Downtime iniciado às HH:MM:SS"*.
- Você ganha uma página pública de status gerada por um terceiro neutro para anexar na ouvidoria ou Anatel.

---

## Alternativa 2: Cloudflare Worker (Serverless próprio)

Para quem prefere rodar sua própria probe na nuvem da Cloudflare (grátis até 100.000 requisições/dia):

1. Crie uma conta no [Cloudflare Dashboard](https://dash.cloudflare.com).
2. Vá em **Workers & Pages** -> **Create Application** -> **Create Worker**.
3. Cole o código do arquivo `worker.js`.
4. (Opcional) Crie um KV Namespace chamado `NETMON_KV` e faça o bind nas configurações do Worker.
5. Publique o worker e copie a URL (ex: `https://netmon-probe.seu-usuario.workers.dev/ping`).
6. Cole essa URL no NetMon em **Configurações** -> **Testemunha Externa**.
