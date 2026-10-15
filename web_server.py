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
import zipfile
import io
import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

import db
import monitor

# Módulos opcionais — não disponíveis em todas as instalações
try:
    import pdf_generator
except ImportError:
    pdf_generator = None  # type: ignore

try:
    import traceroute_tracer
except ImportError:
    traceroute_tracer = None  # type: ignore

try:
    import notifier
except ImportError:
    notifier = None  # type: ignore

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

    def _send_bytes(self, data: bytes, content_type: str = "application/octet-stream", status: int = 200, filename: str = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

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
            start = params.get("start", [None])[0]
            end = params.get("end", [None])[0]
            if "hours" in params:
                try:
                    hours = max(1, min(720, int(params["hours"][0])))
                except ValueError:
                    pass
            metrics = db.get_metrics_timeline(hours=hours, start_time=start, end_time=end)
            self._send_json(metrics)
            return

        # API: Histórico completo de quedas
        if path == "/api/outages":
            limit = 150
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
            start = params.get("start", [None])[0]
            end = params.get("end", [None])[0]
            if "hours" in params:
                try:
                    hours = max(1, min(8760, int(params["hours"][0])))
                except ValueError:
                    pass
            report_text = db.generate_isp_report_text(hours=hours, start_time=start, end_time=end)
            as_download = "download" in params and params["download"][0] == "1"
            filename = f"laudo_tecnico_{hours}h.txt" if as_download else None
            self._send_text(report_text, content_type="text/plain; charset=utf-8", filename=filename)
            return

        # API: Dados periciais consolidados para Laudo Técnico e PDF
        if path == "/api/report_json":
            hours = 72
            start = params.get("start", [None])[0]
            end = params.get("end", [None])[0]
            if "hours" in params:
                try:
                    hours = max(1, min(8760, int(params["hours"][0])))
                except ValueError:
                    pass
            report_data = db.generate_isp_report_data(hours=hours, start_time=start, end_time=end)
            self._send_json(report_data)
            return

        # API: Verificação de Integridade Criptográfica (antifraude)
        if path == "/api/integrity":
            result = db.verify_database_integrity()
            self._send_json(result)
            return

        # API: Histórico de Auditoria Administrativa
        if path == "/api/audit":
            conn = db.get_connection()
            try:
                cur = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50;")
                logs = [dict(r) for r in cur.fetchall()]
            finally:
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

        # API: Dossiê Pericial Completo em Pacote ZIP
        if path == "/api/export_dossier":
            hours = 72
            start = params.get("start", [None])[0]
            end = params.get("end", [None])[0]
            if "hours" in params:
                try:
                    hours = max(1, min(8760, int(params["hours"][0])))
                except ValueError:
                    pass

            try:
                if pdf_generator is None:
                    self._send_json({"error": "Módulo pdf_generator não instalado neste servidor."}, status=501)
                    return
                # 1. Dados do laudo técnico e geração do PDF pericial oficial
                report_data = db.generate_isp_report_data(hours=hours, start_time=start, end_time=end)
                pdf_bytes = pdf_generator.generate_laudo_pdf(report_data)

                # 2. Telemetria em CSV do período selecionado
                pings_csv = db.export_csv_data("pings", hours=hours, start_time=start, end_time=end).encode("utf-8")
                speed_csv = db.export_csv_data("speed_tests", hours=hours, start_time=start, end_time=end).encode("utf-8")

                # 3. Cadeia de custódia e prova criptográfica ABNT NBR ISO/IEC 27037
                custody_txt = db.generate_custody_chain_text(hours=hours, start_time=start, end_time=end).encode("utf-8")

                # 4. Checksums SHA-256 dos artefatos periciais (não-repúdio)
                h_pdf = hashlib.sha256(pdf_bytes).hexdigest()
                h_pings = hashlib.sha256(pings_csv).hexdigest()
                h_speed = hashlib.sha256(speed_csv).hexdigest()
                h_custody = hashlib.sha256(custody_txt).hexdigest()

                now_utc = datetime.now(timezone.utc).isoformat()
                combined_hashes = f"{h_pdf}|{h_pings}|{h_speed}|{h_custody}"
                dossier_sig = db.compute_hash(combined_hashes)

                sig_content = (
                    "# ==============================================================================\n"
                    "# DOSSIÊ PERICIAL FORENSE NETMON - CHECKSUM SHA-256 E ASSINATURA DE NÃO-REPÚDIO\n"
                    "# Norma de Cadeia de Custódia Digital: ABNT NBR ISO/IEC 27037:2013\n"
                    f"# Data/Hora de Geração: {now_utc} UTC\n"
                    f"# Operadora Auditada: {report_data.get('client', {}).get('isp_name', 'Claro')}\n"
                    f"# Assinatura Digital do Dossiê (HMAC-SHA256): {dossier_sig}\n"
                    "# ==============================================================================\n\n"
                    f"{h_pdf}  Laudo_Tecnico_Oficial.pdf\n"
                    f"{h_pings}  Telemetria_Pings.csv\n"
                    f"{h_speed}  Testes_Velocidade.csv\n"
                    f"{h_custody}  Cadeia_Custodia_Hashes.txt\n"
                ).encode("utf-8")

                # 5. Empacotamento em ZIP seguro em memória
                zip_buf = io.BytesIO()
                with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("Laudo_Tecnico_Oficial.pdf", pdf_bytes)
                    zf.writestr("Telemetria_Pings.csv", pings_csv)
                    zf.writestr("Testes_Velocidade.csv", speed_csv)
                    zf.writestr("Cadeia_Custodia_Hashes.txt", custody_txt)
                    zf.writestr("Checksum_SHA256.sig", sig_content)

                zip_payload = zip_buf.getvalue()
                date_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"Dossie_Pericial_NetMon_{date_tag}.zip"
                self._send_bytes(zip_payload, content_type="application/zip", filename=filename)
            except Exception as e:
                self._send_json({"error": f"Falha na compilação do dossiê pericial: {e}"}, status=500)
            return

        # API: Diagnósticos de Rastreamento de Rota (Traceroute Forense)
        if path == "/api/traces":
            limit = 50
            if "limit" in params:
                try:
                    limit = int(params["limit"][0])
                except ValueError:
                    pass
            outage_id = None
            if "outage_id" in params:
                try:
                    outage_id = int(params["outage_id"][0])
                except ValueError:
                    pass
            traces = db.get_route_traces(limit=limit, outage_id=outage_id)
            self._send_json(traces)
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

        # Disparar rastreamento forense manual de rota (Traceroute)
        if path == "/api/trigger_traceroute":
            if traceroute_tracer is not None:
                traceroute_tracer.trigger_async_traceroute(reason="manual_web", force=True)
                self._send_json({
                    "message": "Auditoria pericial de rota disparada em segundo plano.",
                    "status": "QUEUED"
                })
            else:
                self._send_json({"error": "Módulo traceroute_tracer não instalado neste servidor."}, status=501)
            return

        # Testar webhook e alertas (Discord e Telegram)
        if path == "/api/test_notification":
            if notifier is not None:
                results = notifier.test_notifications()
                self._send_json(results)
            else:
                self._send_json({"error": "Módulo notifier não instalado neste servidor."}, status=501)
            return

        # Atualizar configurações (ex: plano contratado) com auditoria
        if path == "/api/config":
            try:
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len).decode("utf-8")
                payload = json.loads(body)

                conn = db.get_connection()
                try:
                    with conn:
                        for k, v in payload.items():
                            conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?);", (str(k), str(v)))
                finally:
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


_server_instance: Optional[ThreadingHTTPServer] = None


def stop_server():
    """Encerra o servidor web de forma graciosa e segura."""
    global _server_instance
    if _server_instance is not None:
        try:
            _server_instance.shutdown()
        except Exception:
            pass


def start_server(host: str = "0.0.0.0", port: int = 8080):
    """Inicia o servidor web HTTP leve com suporte a parada graciosa e tratamento de porta."""
    global _server_instance
    db.init_db()

    env_port = os.environ.get("NETMON_PORT") or os.environ.get("PORT")
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            pass

    try:
        server = ThreadingHTTPServer((host, port), NetworkMonitorHandler)
    except OSError as e:
        if getattr(e, "errno", None) in (98, 10048) or "already in use" in str(e).lower():
            print(f"[!] ERRO: A porta {port} já está em uso por outro processo (ex: outro NetMon ou Nginx).")
            print("    Para especificar outra porta, use: python run.py --port <nova_porta> ou defina NETMON_PORT=<porta>.")
            sys.exit(1)
        raise

    _server_instance = server
    local_ip = get_local_ip()
    print("Servidor Web ativo:")
    print(f"  Local:   http://localhost:{port}")
    if local_ip != "127.0.0.1":
        print(f"  Rede:    http://{local_ip}:{port} (qualquer aparelho no mesmo Wi-Fi/cabo)")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        try:
            server.server_close()
        except Exception:
            pass
        _server_instance = None


if __name__ == "__main__":
    start_server()
