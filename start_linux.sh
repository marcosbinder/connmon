#!/usr/bin/env bash
# NetMon - Script de inicialização e gerenciamento via PM2 no Linux (VPS)

cd "$(dirname "$0")"

echo "=================================================="
echo "NetMon - Inicializador para Linux / VPS (PM2)"
echo "=================================================="

# Verifica se pm2 está instalado
if ! command -v pm2 &> /dev/null; then
    echo "[!] PM2 não encontrado no PATH. Iniciando diretamente com python3..."
    export PYTHONUNBUFFERED=1
    python3 run.py --host 0.0.0.0 --port 8080
    exit $?
fi

echo "[*] Iniciando / Reiniciando NetMon via PM2..."
pm2 startOrRestart ecosystem.config.cjs --update-env
pm2 save

echo ""
echo "[+] NetMon em execução com sucesso no PM2!"
echo "    Status:  pm2 status claro-mon"
echo "    Logs:    pm2 logs claro-mon"
echo "    Parar:   pm2 stop claro-mon"
echo "    Painel:  http://192.168.1.5:8080"
echo "=================================================="
