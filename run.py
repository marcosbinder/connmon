"""
run.py - Ponto de entrada do NetMon
Executa o monitoramento de rede e o servidor web do dashboard.
"""

import argparse
import os
import sys
import threading
import time

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
    parser = argparse.ArgumentParser(
        description="NetMon: monitor de estabilidade e velocidade de internet"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Porta para o Dashboard Web (padrão: 8080)"
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
        default=10,
        help="Intervalo de teste completo de velocidade em minutos (padrão: 10 min)"
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
        except KeyboardInterrupt:
            print("\nEncerrando monitor...")
            monitor.stop_monitor()
        return

    # Modo Padrão Completo: Monitor em Thread + Servidor Web
    local_ip = web_server.get_local_ip()
    print(f"[*] Painel web neste computador:   http://localhost:{args.port}")
    if local_ip != "127.0.0.1":
        print(f"[*] Painel web em outros aparelhos: http://{local_ip}:{args.port} (celular, notebook, etc)")
    print(f"[*] Checagem de conectividade: a cada {args.ping_interval} segundos")
    print(f"[*] Teste de velocidade completo: a cada {args.speed_interval} minutos (e na deteccao de instabilidade)")
    print(f"[*] Pressione CTRL+C a qualquer momento para encerrar com seguranca.")
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
    except KeyboardInterrupt:
        print("\n[!] Encerrando monitor e servidor web...")
        monitor.stop_monitor()
        time.sleep(1)
        print("[*] Encerrado com sucesso. Dados preservados em net_monitor.db.")


if __name__ == "__main__":
    main()
