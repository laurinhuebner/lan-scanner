import os, ipaddress, sqlite3, time, socket, subprocess, threading
from contextlib import closing
from dataclasses import dataclass, asdict
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort

DB_PATH = os.environ.get("DB_PATH", "scanner.db")
DEFAULT_PORTS = [22, 80, 443, 3000, 5000, 5050, 8080]
PING_CMD = ["ping", "-c", "1", "-W", "1"]  # Linux

app = Flask(__name__)

# --- DB helpers -----------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(db()) as conn, conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          cidr TEXT NOT NULL,
          started_at INTEGER NOT NULL,
          finished_at INTEGER
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id INTEGER NOT NULL,
          ip TEXT NOT NULL,
          hostname TEXT,
          open_ports TEXT,
          FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )""")

# --- Scan logic -----------------------------------------------------------------
def ping(ip: str) -> bool:
    try:
        out = subprocess.run(PING_CMD + [ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return out.returncode == 0
    except Exception:
        return False

def tcp_check(ip: str, port: int, timeout=0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def resolve_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

@dataclass
class HostResult:
    ip: str
    hostname: str | None
    open_ports: list[int]

def scan_subnet(cidr: str, ports: list[int]) -> list[HostResult]:
    net = ipaddress.ip_network(cidr, strict=False)
    results: list[HostResult] = []
    # simple concurrency
    from concurrent.futures import ThreadPoolExecutor, as_completed
    alive_ips = []

    def ping_task(ip):
        return (str(ip), ping(str(ip)))

    with ThreadPoolExecutor(max_workers=128) as ex:
        futs = [ex.submit(ping_task, ip) for ip in net.hosts()]
        for f in as_completed(futs):
            ip_str, is_up = f.result()
            if is_up:
                alive_ips.append(ip_str)

    def probe_task(ip):
        host = resolve_hostname(ip)
        openp = [p for p in ports if tcp_check(ip, p)]
        return HostResult(ip, host, openp)

    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = [ex.submit(probe_task, ip) for ip in alive_ips]
        for f in as_completed(futs):
            results.append(f.result())

    # stable sort by IP
    results.sort(key=lambda h: list(map(int, h.ip.split("."))))
    return results

# background scan runner
def run_scan_in_bg(scan_id: int, cidr: str, ports: list[int]):
    try:
        results = scan_subnet(cidr, ports)
        with closing(db()) as conn, conn:
            for r in results:
                conn.execute(
                    "INSERT INTO hosts (scan_id, ip, hostname, open_ports) VALUES (?,?,?,?)",
                    (scan_id, r.ip, r.hostname, ",".join(map(str, r.open_ports)))
                )
            conn.execute("UPDATE scans SET finished_at=? WHERE id=?", (int(time.time()), scan_id))
    except Exception:
        with closing(db()) as conn, conn:
            conn.execute("UPDATE scans SET finished_at=? WHERE id=?", (int(time.time()), scan_id))

# --- Routes ---------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    with closing(db()) as conn:
        scans = conn.execute(
            "SELECT id, cidr, started_at, finished_at FROM scans ORDER BY id DESC LIMIT 10"
        ).fetchall()
    return render_template("index.html", scans=scans, default_ports=",".join(map(str, DEFAULT_PORTS)))

@app.route("/scan", methods=["POST"])
def start_scan():
    cidr = request.form.get("cidr", "").strip()
    ports_str = request.form.get("ports", "").strip()
    if not cidr:
        abort(400, "CIDR fehlt (z.B. 192.168.1.0/24)")

    try:
        ipaddress.ip_network(cidr, strict=False)
    except Exception:
        abort(400, "Ungültiges CIDR")

    ports = DEFAULT_PORTS
    if ports_str:
        try:
            ports = [int(p) for p in ports_str.split(",") if p.strip()]
        except Exception:
            abort(400, "Ports ungültig (Kommagetrennte Zahlen)")

    with closing(db()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO scans (cidr, started_at, finished_at) VALUES (?,?,NULL)",
            (cidr, int(time.time()))
        )
        scan_id = cur.lastrowid

    t = threading.Thread(target=run_scan_in_bg, args=(scan_id, cidr, ports), daemon=True)
    t.start()

    return redirect(url_for("scan_detail", scan_id=scan_id))

@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id: int):
    with closing(db()) as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        hosts = conn.execute(
            "SELECT ip, hostname, open_ports FROM hosts WHERE scan_id=? ORDER BY ip", (scan_id,)
        ).fetchall()
    if not scan:
        abort(404)
    return render_template("index.html",
                           scans=[scan],
                           active_scan=scan,
                           hosts=hosts,
                           default_ports=",".join(map(str, DEFAULT_PORTS)))

# Simple APIs
@app.get("/api/scan/<int:scan_id>")
def api_scan(scan_id: int):
    with closing(db()) as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        hosts = conn.execute("SELECT ip, hostname, open_ports FROM hosts WHERE scan_id=? ORDER BY ip", (scan_id,)).fetchall()
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "scan": dict(scan),
        "hosts": [dict(h) for h in hosts]
    })

@app.get("/healthz")
def health():
    return "ok", 200

# --- main -----------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5051"))  # 5051, damit’s nicht mit 5050 kollidiert
    app.run(host="0.0.0.0", port=port, debug=True)
