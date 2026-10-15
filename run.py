"""
run.py - Ponto de entrada do NetMon
Executa o monitoramento de rede e o servidor web do dashboard.
"""

import argparse
import os
import sys
import threading
import time
import signal

# Assegura codificação correta para qualquer console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import db
import monitor
import web_server
import speed_tester


def parse_args():
    env_port_str = os.environ.get("NETMON_PORT") or os.environ.get("PORT") or "8080"
    try:
        default_port = int(env_port_str)
    except ValueError:
        default_port = 8080

    parser = argparse.ArgumentParser(
        description="NetMon: monitor de estabilidade e velocidade de internet"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"Porta para o Dashboard Web (padrão: {default_port})"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host para o Dashboard Web (padrão: 0.0.0.0 para acesso remoto)"
    )
    parser.add_argument(
        "--ping-interval",
        type=int,
        default=30,
        help="Intervalo de checagem de saúde/ping em segundos (padrão: 30s)"
    )
    parser.add_argument(
        "--speed-interval",
        type=int,
        default=5,
        help="Intervalo de teste completo de velocidade em minutos (padrão: 5 min)"
    )
    parser.add_argument(
        "--monitor-only",
        action="store_true",
        help="Executa apenas o monitor de rede em segundo plano (sem servidor web)"
    )
    parser.add_argument(
        "--web-only",
        action="store_true",
        help="Executa apenas o servidor web do Dashboard (sem motor de ping)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Gera e imprime no terminal o relatório técnico formatado para a operadora"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=72,
        help="Horas para o relatório com --report (padrão: 72h)"
    )
    parser.add_argument(
        "--test-speed",
        action="store_true",
        help="Executa um teste imediato de velocidade e exibe o resultado"
    )
    parser.add_argument(
        "--export",
        type=str,
        choices=["pings", "speed_tests", "outages"],
        help="Exporta a tabela informada para formato CSV e imprime no terminal"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    db.init_db()

    # Modo: Teste de velocidade avulso
    if args.test_speed:
        print("[*] Iniciando teste de velocidade imediato...")
        res = speed_tester.run_speed_test()
        print(f"Status: {res['status']}")
        if res["status"] == "SUCCESS":
            print(f"Download: {res['download_mbps']} Mbps")
            print(f"Upload:   {res['upload_mbps']} Mbps")
            print(f"Latência: {res['ping_ms']} ms")
        else:
            print(f"Erro: {res['error_message']}")
        return

    # Modo: Exportar CSV
    if args.export:
        print(db.export_csv_data(args.export))
        return

    # Modo: Gerar relatório para a operadora
    if args.report:
        report_text = db.generate_isp_report_text(hours=args.hours)
        print(report_text)
        return

    # Banner de Inicialização
    print("=" * 60)
    print("NetMon - Monitor de Conexao e Metricas de Rede")
    print("=" * 60)

    def handle_shutdown(signum=None, frame=None):
        print(f"\n[!] Encerrando monitor e servidor web com segurança (sinal {signum})...")
        monitor.stop_monitor()
        web_server.stop_server()
        time.sleep(0.5)
        print("[*] Encerrado com sucesso. Dados preservados em net_monitor.db.")
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, handle_shutdown)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, handle_shutdown)
    except Exception:
        pass

    # Modo apenas Web
    if args.web_only:
        print(f"[*] Modo: Apenas Dashboard Web (Porta {args.port})")
        web_server.start_server(host=args.host, port=args.port)
        return

    # Modo apenas Monitor
    if args.monitor_only:
        print(f"[*] Modo: Apenas Monitor (Checagem a cada {args.ping_interval}s)")
        try:
            monitor.run_monitor_loop(
                ping_interval=args.ping_interval,
                speed_interval_min=args.speed_interval
            )
        except (KeyboardInterrupt, SystemExit):
            handle_shutdown()
        return

    # Modo Padrão Completo: Monitor em Thread + Servidor Web
    local_ip = web_server.get_local_ip()
    print(f"[*] Painel web neste computador:   http://localhost:{args.port}")
    if local_ip != "127.0.0.1":
        print(f"[*] Painel web em outros aparelhos: http://{local_ip}:{args.port} (celular, notebook, etc)")
    print(f"[*] Checagem de conectividade: a cada {args.ping_interval} segundos")
    print(f"[*] Teste de velocidade completo: a cada {args.speed_interval} minutos (e na deteccao de instabilidade)")
    print("[*] Pressione CTRL+C ou envie SIGTERM (PM2) a qualquer momento para encerrar com seguranca.")
    print("-" * 60)

    monitor_thread = threading.Thread(
        target=monitor.run_monitor_loop,
        kwargs={
            "ping_interval": args.ping_interval,
            "speed_interval_min": args.speed_interval
        },
        daemon=True
    )
    monitor_thread.start()

    try:
        web_server.start_server(host=args.host, port=args.port)
    except (KeyboardInterrupt, SystemExit):
        handle_shutdown()


if __name__ == "__main__":
    main()
