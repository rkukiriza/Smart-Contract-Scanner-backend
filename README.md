# Smart Contract Vulnerability Scanner — Backend

This is the backend API for the Smart Contract Vulnerability Scanner, built with Python and FastAPI.  
It analyzes Ethereum smart contracts for vulnerabilities, produces dashboard-ready metrics, and supports comparative analysis for risk assessment.

Backend API and scanner for the Smart Contract Vulnerability Scanner.  
Built with FastAPI + Python. Scanning logic is implemented in `scanner.py`. The service is deployed on Railway.

# Live backend URL
- https://smart-contract-scanner-backend-production.up.railway.app

# Summary
- Scans Solidity contracts (address or `.sol` file) and returns dashboard-ready JSON: vulnerabilities, metrics, risk score, comparative data and recommendations.
- Produces and persists scan JSON files under `scan_results/` and maintains `scan_history.json`.
- Designed to be consumed by a React/Next.js frontend (example frontend: https://smart-contract-scanner-frontend-pxk.vercel.app).

# Features
- Automated Vulnerability Detection: Runs Slither detectors for multiple severity categories (critical, high, medium, low, informational).
- Aggregates scan metrics: total lines, vulnerable lines, severity breakdown, detectors run, scan duration.
- Dashboard metrics: normalized risk score, average lines per vulnerability, severity distribution.
- Comparative metrics: simulated rank, vulnerability density, riskiest contracts, networks and word cloud.
- History tracking:Saves scan results and maintains a history of recent scans,saves individual scan JSON and updates a scan history file.
- Extensible: Easily integrates with frontend dashboards(React/Next.js) and other tools.

# API Endpoints (example)
- `POST /api/scan` — scan a contract (address or uploaded `.sol`) and return results (JSON).
- `GET /api/history` — retrieve recent scan history.
- `GET /api/networks` — list supported networks.
- `GET /api/detectors` — list available detectors.
- `GET /health` — health check.

# Quickstart (local Windows)
1. Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install requirements:
   ```powershell
   pip install -r requirements.txt
   ```

3. Install Slither (required):
   - Slither requires additional system libraries (solc, graphviz, etc.). See Slither docs: https://github.com/crytic/slither
   ```powershell
   pip install slither-analyzer
   ```

4. Run the API (development):
   ```powershell
   uvicorn api:app --reload --host 0.0.0.0 --port 8000
   ```

# Example: scan using curl (POST JSON)
```sh
curl -X POST https://smart-contract-scanner-backend-production.up.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"address":"0xdAC17F958D2ee523a2206206994597C13D831ec7","network":"mainnet"}'
```

# Notes about scanner.py
- The scanner class (`ContractScanner`) orchestrates running Slither detectors, parsing results, computing metrics, and saving JSON output.
- Output files: `scan_results/scan_<contract>_<timestamp>.json` and `scan_results/scan_history.json`.
- Some code paths use simulated placeholders (randomized code insights, comparative placeholders). Full detection requires Slither to be installed and accessible on PATH.

# Railway deployment notes
- Ensure Python runtime and required system packages for Slither are available in Railway environment.
- Configure startup command (Railway web service) to run the API, for example:
  ```
  uvicorn api:app --host 0.0.0.0 --port $PORT
  ```
- Add any required environment variables/secrets in Railway project settings.
- Monitor service logs on Railway for detector runtime errors (Slither may need extra libs).

# Troubleshooting
- `{"detail":"Method Not Allowed"}` — you likely used GET; confirm `POST` for `/api/scan`.
- Pydantic validation errors — confirm request body matches expected model (use `address` field for scanning by address).
- If `slither` cannot be found, install Slither and required dependencies or ensure the build environment includes system packages Slither depends on.
- If you see raw JSON in your frontend, confirm the frontend is calling the backend API via the correct base URL (set `NEXT_PUBLIC_API_BASE` in frontend).

# Files of interest
- `api.py` — FastAPI endpoints and request/response handling.
- `scanner.py` — core scanning logic that uses Slither detectors and builds dashboard-ready JSON.
- `scan_results/` — directory where scan output JSON and history are stored.

# Sample scan result (abbreviated)
```json
{
  "contract": "contracts\\BoredApeYachtClub_0xbc4ca0.sol",
  "scan_timestamp": "2025-10-03T11:22:15.524730",
  "vulnerabilities": [],
  "metrics": {
    "total_lines": 1608,
    "vulnerable_lines": 0,
    "total_vulnerabilities": 0,
    "severity_breakdown": { "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0 },
    "detectors_run": 19,
    "scan_duration": 20.7
  },
  "detector_results": {}
}
```

# Security & limitations
- The scanner executes Slither (static analysis). Do not run untrusted code in environments with access to sensitive resources.
- Some comparative metrics and code-insights are simulated for demo/visualization; treat them as informative, not authoritative.

# License
- MIT

# Contact / Contributions
- Contributions and issues are welcome. Open a PR or issue in the repository.
