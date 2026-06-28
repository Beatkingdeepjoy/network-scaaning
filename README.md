# NetSentry — Network Scanner Module

A standalone network host-discovery and port-scanning tool with a live
animated dashboard. Built to either run on its own or slot into the
larger NetSentry project as a module.

## What it does

- **Host discovery** — sweeps a CIDR range (e.g. `192.168.1.0/24`) to find live hosts
- **Port scanning** — checks common ports on each live host
- **Service fingerprinting** — identifies what's likely running on each open port (and version, when nmap is available)
- **Live dashboard** — animated radar-style console that updates in real time as hosts are found

## Two scan engines (automatic)

| Engine | Used when | Capability |
|---|---|---|
| `nmap` | `nmap` binary is installed and on PATH | Full scan, accurate service/version detection |
| `fallback` | `nmap` is not found | Pure-Python ping sweep + TCP connect scan, no dependencies beyond the standard library |

The app detects which is available at startup and uses it automatically — no config needed. This means it runs (and demos) even on a machine without nmap installed, which matters for grading/recruiter environments where you can't guarantee nmap is present.

## Setup

### 1. Install nmap (recommended, optional)

- **Linux:** `sudo apt install nmap`
- **macOS:** `brew install nmap`
- **Windows:** [download installer](https://nmap.org/download.html)

If you skip this, the app still works using the fallback engine — just with fewer details per port (no service version strings).

### 2. Backend

```bash
cd backend
pip install python-nmap flask flask-cors
python app.py
```

This starts the API on `http://localhost:5000` and creates `scans.db` (SQLite) to store scan history.

### 3. Frontend

Just open `frontend/index.html` directly in a browser — no build step needed, it's plain HTML/CSS/JS.

(If your browser blocks local API calls from a `file://` page, serve it instead: `cd frontend && python -m http.server 8000`, then visit `http://localhost:8000`.)

## Usage

1. Enter a CIDR range you own or have permission to scan (e.g. your home network: `192.168.1.0/24`)
2. Click **Run scan**
3. Watch the radar sweep and live feed populate as hosts are discovered
4. Click any host card to see full port/service details in the side drawer
5. Past scans are saved automatically and listed under "Recent Scans" — click one to reload those results

## API reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/status` | GET | Check which scan engine is active |
| `/api/scan` | POST | Run a scan. Body: `{"subnet": "192.168.1.0/24"}` |
| `/api/scans` | GET | List the last 20 scans |
| `/api/scans/<id>` | GET | Get full results for a past scan |

## Project structure

```
network-scanner/
├── backend/
│   ├── scanner.py   # core scanning logic (nmap + fallback engines)
│   └── app.py       # Flask API + SQLite persistence
├── frontend/
│   ├── index.html   # dashboard markup
│   ├── styles.css    # radar console design system
│   └── app.js        # API calls, radar animation, results rendering
└── README.md
```

## Notes for extending into NetSentry

- `scanner.py` has no Flask dependency — it's a clean module you can `import` directly into the larger NetSentry backend
- The SQLite schema in `app.py` is intentionally simple; when merging into NetSentry's existing DB, you'll likely want to add a foreign key from `scans` to a `cve_matches` table once you wire in NVD lookups
- Port/service results are already structured (`{"port": int, "service": str, "product": str, "version": str}`) so feeding them into a CVE-matching step (by product+version) is a small next step

## ⚠️ Legal / ethical use

Only scan networks and hosts you own or have explicit written authorization to test. Unauthorized scanning of networks you don't control may violate laws (e.g. the Computer Fraud and Abuse Act in the US, or equivalent laws elsewhere) even when no damage is done. This tool is built for home-lab and authorized-engagement use.
