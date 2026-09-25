# connmon

Monitor de conexao de internet em Python com registro de quedas e medicao periodica de velocidade. Inclui um dashboard web simples para acompanhar o historico de latencia, perda de pacotes e gerar relatorios para enviar ao suporte da operadora.

Construido para rodar direto no servidor ou em maquinas com poucos recursos (consome cerca de 13 MB de RAM). Nao exige dependencias externas obrigatorias; funciona com a biblioteca padrao do Python e SQLite local.

## O que ele faz

- Checagem a cada 30 segundos: envia pings para 1.1.1.1 e 8.8.8.8 e verifica a resolucao DNS.
- Registro de quedas: salva a hora exata em que o sinal caiu e a duracao total quando a conexao volta.
- Teste de velocidade: mede download e upload a cada 10 minutos (e tambem logo apos instabilidades ou retorno de queda).
- Dashboard no navegador: exibe graficos de latencia, velocidade e a tabela com o historico de paradas.
- Relatorio para suporte: gera um texto com datas, duracao de quedas e medias de banda para facilitar a abertura de chamados tecnicos ou solicitacao de desconto na fatura.

## Requisitos

- Python 3.9 ou superior (Windows ou Linux).

## Como rodar

### No Windows

De dois cliques em `start_windows.bat` ou execute no terminal:

```cmd
python run.py
```

### No Linux

```bash
python3 run.py
```

O dashboard estara acessivel no endereco: `http://localhost:8080` (ou pelo IP da maquina na rede local).

## Opcoes de terminal

O `run.py` inclui opcoes uteis para automacao e exportacao:

```bash
# Rodar em porta diferente
python run.py --port 9000

# Rodar apenas a checagem em segundo plano (sem o servidor web)
python run.py --monitor-only

# Rodar apenas o dashboard web
python run.py --web-only

# Imprimir no terminal o relatorio dos ultimos 3 dias
python run.py --report --hours 72

# Fazer um teste rapido de velocidade
python run.py --test-speed

# Exportar historico para CSV
python run.py --export outages > quedas.csv
python run.py --export pings > pings.csv
```

## Como os dados sao guardados

As metricas sao salvas em um arquivo SQLite local chamado `net_monitor.db`. O banco utiliza o modo WAL (Write-Ahead Logging), permitindo que o painel web consulte os dados enquanto o processo de monitoramento grava novas medicoes sem conflito de concorrencia.

## Estrutura dos arquivos

- `run.py`: ponto de entrada que sobe o monitor e o servidor web.
- `monitor.py`: checagem de ping e deteccao de mudanca de estado da rede.
- `speed_tester.py`: medicao de download e upload via CDN da Cloudflare.
- `db.py`: funcoes de persistencia e geracao de relatorios em SQLite.
- `web_server.py`: servidor HTTP simples sem frameworks externos.
- `static/index.html`: dashboard com graficos em Chart.js.

## Licenca

MIT
