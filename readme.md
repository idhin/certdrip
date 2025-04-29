# 🔍 certstream-go (Realtime CT Log Hunter via WebSocket)

**certstream-go** is a real-time domain stream service based on [Certificate Transparency Logs](https://certificate.transparency.dev/).  
It aggregates all new SSL/TLS certificates issued publicly and pushes them via WebSocket for monitoring, threat intelligence, recon, and OSINT purposes.

<p align="center">
  <img src="/screenshots/demo.gif" alt="certstream-go demo" width="700">
</p>

---

## 🚀 Features

- ✅ Auto fetch **usable CT logs** from Chrome's [log list](https://www.gstatic.com/ct/log_list/v3/log_list.json)
- ✅ Poll **all logs concurrently** using goroutines
- ✅ Stream domain entries via WebSocket (`ws://localhost:8080/ws`)
- ✅ Deduplicate certs (avoid spam)
- ✅ Realtime `Domains/sec` rate monitor
- ✅ Filter intermediate / empty certs

---

## ⚙️ How It Works

1. We grab all **usable** CT logs from `log_list.json` (used by Chrome)
2. Each CT log is processed in its own goroutine using `GetSTH` → `GetEntries`
3. New X.509 certs are parsed, extracted, and pushed to:
   - `stdout`
   - WebSocket clients (`/ws`)
4. Domain deduplication is cached for 5 minutes (adjustable)

---

## 📦 Requirements

- Go 1.20+
- Docker (optional)

---

## 🧪 Quick Start (WS + Realtime Domain Stream)

bash
git clone https://github.com/idhin/certdrip.git
cd certstream-go

go mod tidy
go run main.go

## 👨‍💻 Contributing

We welcome contributions!

Just fork, code, and PR it.  
You can also open issues if you find a bug or want to suggest improvements.

Want to collaborate on advanced CT log use cases?  
Feel free to reach out — collaboration is open!

---

## ✨ Credits

Built with ❤️ by:

**Khulafaur Rasyidin (@idhin)**  
🔗 [github.com/idhin](https://github.com/idhin)  
☕ Powered by security research, caffeine, and open-source

---

## 📄 License

MIT — use it freely for your own research, red team automation, or even cyber countermeasures 😉
