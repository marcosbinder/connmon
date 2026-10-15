module.exports = {
  apps: [
    {
      name: "claro-mon",
      script: "run.py",
      interpreter: "python3",
      args: "--host 0.0.0.0 --port 8080",
      env: {
        PYTHONUNBUFFERED: "1",
        NETMON_PORT: "8080"
      },
      kill_timeout: 6000,
      listen_timeout: 8000,
      autorestart: true,
      max_restarts: 10,
      restart_delay: 3000,
      watch: false
    }
  ]
};
