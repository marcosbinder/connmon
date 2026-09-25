"""
web_server.py - Servidor Web HTTP leve e nativo em Python (sem frameworks pesados).
Consumo de RAM: ~15MB.
Fornece API REST JSON e entrega o Dashboard interativo em HTML/JS.
"""

import http.server
import socketserver
import json
import urllib.parse
import os
import sys
import threading
from typing import Any, Dict

import db
import monitor
import speed_tester

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class NetworkMonitorHandler(http.server.BaseHTTPRequestHandler):
    # Desativa logs barulhentos no console para cada request de polling
    def log_message(self, format, *args):
        # Apenas loga erros ou ações importantes
        if args and str(args[1]) in ["404", "500"]:
            sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, content_type: str = "text/plain; charset=utf-8", status: int = 200, filename: str = None):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filepath: str, content_type: str = "text/html; charset=utf-8"):
        if not os.path.exists(filepath):
            self.send_error(404, "Arquivo não encontrado")
            return
        with open(filepath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # Favicon embutido para evitar 404 nos logs
        if path == "/favicon.ico":
            svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="45" fill="#0f172a" stroke="#38bdf8" stroke-width="6"/><circle cx="50" cy="50" r="18" fill="#22c55e"/><path d="M25 50 A25 25 0 0 1 75 50" fill="none" stroke="#38bdf8" stroke-width="6" stroke-linecap="round"/><path d="M15 50 A35 35 0 0 1 85 50" fill="none" stroke="#38bdf8" stroke-width="6" stroke-linecap="round" opacity="0.5"/></svg>'
            self._send_text(svg, content_type="image/svg+xml")
            return

        # Rota principal (Dashboard)
        if path in ["/", "/index.html"]:
            dashboard_file = os.path.join(STATIC_DIR, "index.html")
            self._send_file(dashboard_file, "text/html; charset=utf-8")
            return

        # API: Status atual e KPIs
        if path == "/api/status":
            status_data = db.get_latest_status()
            self._send_json(status_data)
            return

        # API: Informacoes da operadora
        if path == "/api/isp":
            try:
                import isp_detector
                refresh = "refresh" in params and params["refresh"][0] == "1"
                info = isp_detector.get_isp_info(force_refresh=refresh)
                self._send_json(info)
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
            return

        # API: Linha do tempo de métricas para gráficos (pings e speed tests)
        if path == "/api/metrics":
            hours = 24
            if "hours" in params:
                try:
                    hours = max(1, min(720, int(params["hours"][0])))
                except ValueError:
                    pass
            metrics = db.get_metrics_timeline(hours=hours)
            self._send_json(metrics)
            return

        # API: Histórico completo de quedas
        if path == "/api/outages":
            limit = 100
            if "limit" in params:
                try:
                    limit = int(params["limit"][0])
                except ValueError:
                    pass
            outages = db.get_all_outages(limit=limit)
            self._send_json(outages)
            return

        # API: Relatório textual para a operadora (Claro / Anatel)
        if path == "/api/report":
            hours = 72
            if "hours" in params:
                try:
                    hours = int(params["hours"][0])
                except ValueError:
                    pass
            report_text = db.generate_isp_report_text(hours=hours)
            as_download = "download" in params and params["download"][0] == "1"
            filename = f"relatorio_instabilidade_{hours}h.txt" if as_download else None
            self._send_text(report_text, content_type="text/plain; charset=utf-8", filename=filename)
            return

        # API: Verificação de Integridade Criptográfica (antifraude)
        if path == "/api/integrity":
            result = db.verify_database_integrity()
            self._send_json(result)
            return

        # API: Histórico de Auditoria Administrativa
        if path == "/api/audit":
            conn = db.get_connection()
            cur = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50;")
            logs = [dict(r) for r in cur.fetchall()]
            conn.close()
            self._send_json(logs)
            return

        # API: Exportação de CSV
        if path == "/api/export":
            table = params.get("table", ["pings"])[0]
            try:
                csv_data = db.export_csv_data(table)
                filename = f"export_{table}.csv"
                self._send_text(csv_data, content_type="text/csv; charset=utf-8", filename=filename)
            except ValueError as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # Arquivos estáticos adicionais se houver
        if path.startswith("/static/"):
            rel_path = path[8:]
            file_path = os.path.join(STATIC_DIR, rel_path)
            content_type = "text/plain"
            if file_path.endswith(".css"):
                content_type = "text/css"
            elif file_path.endswith(".js"):
                content_type = "application/javascript"
            self._send_file(file_path, content_type)
            return

        self.send_error(404, "Endpoint não encontrado")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        client_ip = self.client_address[0] if self.client_address else "local"

        # Disparar teste manual de velocidade
        if path == "/api/trigger_speedtest":
            monitor.trigger_async_speedtest(reason="manual_web")
            self._send_json({
                "message": "Teste de velocidade disparado com sucesso em segundo plano.",
                "status": "QUEUED"
            })
            return

        # Atualizar configurações (ex: plano contratado) com auditoria
        if path == "/api/config":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8")
                payload = json.loads(body)

                conn = db.get_connection()
                with conn:
                    for k, v in payload.items():
                        conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?);", (str(k), str(v)))
                conn.close()

                db.log_audit("CONFIG_UPDATE", f"Plano atualizado: {payload}", client_ip)
                self._send_json({"message": "Configurações salvas com sucesso!", "saved": payload})
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # Limpeza de dados antigos (purga segura para servidores com pouco disco)
        if path == "/api/cleanup":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
                payload = json.loads(body) if body else {}
                days = int(payload.get("days", 30))
                res = db.cleanup_old_data(days=days, actor_ip=client_ip)
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # Reset completo de métricas com log de auditoria
        if path == "/api/reset":
            try:
                res = db.reset_database(actor_ip=client_ip)
                self._send_json(res)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        self.send_error(404, "Endpoint não encontrado")


def get_local_ip() -> str:
    """Detecta o IP da maquina na rede local."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def start_server(host: str = "0.0.0.0", port: int = 8080):
    """Inicia o servidor web HTTP leve."""
    db.init_db()
    server = ThreadingHTTPServer((host, port), NetworkMonitorHandler)
    local_ip = get_local_ip()
    print(f"Servidor Web ativo:")
    print(f"  Local:   http://localhost:{port}")
    if local_ip != "127.0.0.1":
        print(f"  Rede:    http://{local_ip}:{port} (qualquer aparelho no mesmo Wi-Fi/cabo)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    start_server()
