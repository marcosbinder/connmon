# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-14

### Added
- **Cryptographic Hash Chaining**: Blockchain-style sequential integrity linking (`prev_hash` + `record_hash` HMAC-SHA256) across pings, outages, speed tests, and route traces to guarantee non-repudiation.
- **RFC 3161 Digital Timestamping**: Direct communication with official public Time Stamping Authorities (TSA) such as DigiCert and FreeTSA using pure Python standard library for legal evidentiary admissibility.
- **Automated ISP & ASN Detection**: Lightweight, cached provider detection (`isp_detector.py`) identifying ISP name, ASN, external public IP, and geolocation via ip-api and Cloudflare meta fallbacks.
- **Forensic Route Traceroute & Fault Attribution**: Autonomous diagnostic engine (`traceroute_tracer.py`) running on latency spikes and outages to identify the failing hop and legally attribute responsibility (`ISP`, `LAN`, or `EXTERNAL`).
- **Forensic Dossier Export (ISO/IEC 27037)**: One-click export of an encrypted/signed `.zip` package containing:
  - Official Technical Expert Report in PDF 1.4 (`pdf_generator.py`), implemented 100% in pure Python without third-party dependencies.
  - Raw telemetry CSVs (`pings.csv`, `speed_tests.csv`).
  - Chain of custody verification manifest (`Cadeia_Custodia_Hashes.txt`).
  - SHA-256 non-repudiation checksums (`Checksum_SHA256.sig`).
- **Bufferbloat Measurement (RFC 3550 / RFC 4689)**: Concurrent loaded latency probe during speed tests, graded from `A+` to `F`.
- **Dual-Check External Witness**: Support for Cloudflare Worker probes (`cloudflare_probe/`) and Healthchecks.io heartbeats to prevent local tampering claims.
- **Real-Time Webhooks & Alerts**: Asynchronous notification dispatch (`notifier.py`) for Discord embeds and Telegram bots.
- **Adaptive Outage Sampling**: Polling rate dynamically accelerates to 2-second intervals during outages or instability for second-precise downtime logging.
- **Regulatory Compliance & Compensation Calculator**: Automated financial reimbursement calculation based on monthly fee and downtime, plus alerts for ANATEL RQUAL speed threshold violations (< 40% of contracted plan).
- **PEP 621 Packaging & Portability**: Modern `pyproject.toml` configuration, `connmon` console script entry point, and `.pyz` portable application bundle support.
- **GitHub Actions Workflows**: Automated CI test matrix (Ubuntu & Windows across Python 3.9, 3.11, 3.12) and automated semantic Release pipeline.

### Changed
- Refactored embedded HTTP web server with thread-safe connection pooling, RESTful JSON endpoints, and graceful SIGINT/SIGTERM shutdown.
- Upgraded SQLite storage engine to WAL (Write-Ahead Logging) mode with `NORMAL` synchronous pragma and 30-second busy timeout.
- Fully modernized vector-based web dashboard (`static/index.html`) featuring interactive latency timeline, outage severity badges, audit logs, and responsive layout.

---

## [0.1.0] - 2026-09-25

### Added
- Initial proof-of-concept release.
- Dual-target ICMP ping monitoring (1.1.1.1 and 8.8.8.8) with DNS resolution check.
- Periodic speed testing via Cloudflare CDN.
- Basic SQLite storage (`pings`, `speed_tests`, `outages`).
- Lightweight embedded HTTP server and web dashboard.
- CLI options for `--port`, `--host`, `--monitor-only`, `--web-only`, and CSV exports.
