# Realtime Certificate Transparency Log Streamer

**certdrip-go** is a real-time domain stream service powered by [Certificate Transparency Logs](https://certificate.transparency.dev/).  
It collects newly issued SSL/TLS certificates and streams extracted domain names over WebSocket, supporting use cases such as:

- Reconnaissance and bug bounty automation
- Threat intelligence pipelines
- OSINT domain monitoring
- Passive DNS & subdomain collection

<p align="center">
  <img src="/screenshots/demo.gif" alt="certdrip-go demo" width="700">
</p>

## Architecture Diagram

<p align="center">
  <img src="/screenshots/skema-proses.png" alt="certdrip-go process diagram" width="500">
</p>

---

## Features

- Fetches active CT logs dynamically from Chrome’s official log list
- Concurrent polling of multiple CT logs (via goroutines)
- Real-time WebSocket endpoint (`/ws`)
- Domain deduplication with time-based cache
- Rate reporting (domains per second)
- Filters out empty or intermediate certificates

---

## How It Works

1. Fetch usable CT logs from [log_list.json](https://www.gstatic.com/ct/log_list/v3/log_list.json)
2. Each log is polled in a dedicated goroutine
3. Parsed certificates yield Common Name or SAN domains
4. Results are sent to:
   - Console (`stdout`)
   - WebSocket (`ws://localhost:8080/ws`)
5. Duplicate domains are cached for 5 minutes (configurable)

---

## Requirements

- Go 1.20 or higher
- Docker (optional)

---

## Quick Start

```bash
git clone https://github.com/idhin/certdrip.git
cd certdrip

go mod tidy
go run main.go
```

Or run with Docker:

```bash
docker-compose up --build
```

Connect to WebSocket using:

```bash
npx wscat -c ws://localhost:8080/ws
```

---

## Contributing

Contributions are welcome.

You can help by:
- Adding support for new CT endpoints
- Building integrations (Redis, Discord, Kafka, etc)
- Optimizing performance and concurrency
- Improving logging, filtering, or output formatting

Just fork the repo, submit a pull request, or open an issue to get involved.

---

## Credits

Developed by:

**Khulafaur Rasyidin (@idhin)**  
[github.com/idhin](https://github.com/idhin)

---

## License

This project is licensed under the MIT License.  
Free to use, modify, and build upon—especially for defenders, researchers, and security engineers.