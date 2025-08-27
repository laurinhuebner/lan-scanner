# 🔎 LAN-Scanner (Flask)

Kleines Webtool, das ein CIDR-Subnetz scannt, aktive Hosts findet, ein Set bekannter Ports prüft und die Ergebnisse in SQLite speichert. Ideal als Lern- und Admin-Tool – und später leicht ins Server-Dashboard integrierbar.

## ✨ Features
- Ping-Sweep eines Subnetzes (z. B. `192.168.1.0/24`)
- Port-Checks (Standard: `22,80,443,3000,5000,5050,8080`)
- Hostname-Auflösung (reverse DNS)
- Ergebnisse persistiert in `scanner.db` (SQLite)
- Einfache Web-UI (Flask), APIs: `/api/scan/<id>`
- Läuft standardmäßig auf Port **5051**

