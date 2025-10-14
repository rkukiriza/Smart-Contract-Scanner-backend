"""
Smart Contract Vulnerability Scanner API (Production)
Compatible with investigative React dashboard
"""

from fastapi import FastAPI, HTTPException, UploadFile, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path
import uuid
import json
import os
import logging

# Assuming the ContractScanner class or function (from scanner.py) 
# would be imported here in a real, complete implementation.
# For this review, we focus on the data structure being returned.

logger = logging.getLogger("api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Smart Contract Vulnerability Scanner API")

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://*.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Data Paths ---
HISTORY_FILE = Path("scan_results/scan_history.json")
Path("scan_results").mkdir(parents=True, exist_ok=True)
Path("temp_contracts").mkdir(parents=True, exist_ok=True)


# ---------- Helpers ----------
def read_history() -> List[Dict[str, Any]]:
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def write_history(history: List[Dict[str, Any]]):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history[-200:], f, indent=2)


def make_dummy_scan_result(address: Optional[str], network: str):
    """Create a rich dummy scan result for demo or placeholder"""
    now = datetime.utcnow().isoformat()
    id_ = str(uuid.uuid4())

    vulnerabilities = [
        {"type": "Reentrancy", "severity": "critical", "description": "Reentrancy via withdraw()", "functions": ["withdraw"], "lines": [201]},
        {"type": "Integer Overflow", "severity": "high", "description": "Unchecked addition in mint()", "functions": ["mint"], "lines": [118]},
        {"type": "Unchecked Call", "severity": "medium", "description": "Low-level call return not checked in send()", "functions": ["send"], "lines": [75]},
        {"type": "Access Control", "severity": "low", "description": "Owner-only modifier missing in setAdmin()", "functions": ["setAdmin"], "lines": [150]},
        {"type": "Naming Convention", "severity": "informational", "description": "Variable names do not follow convention", "functions": []},
    ]

    severity_breakdown = {"critical": 1, "high": 1, "medium": 1, "low": 1, "informational": 1}
    total_vulns = sum(severity_breakdown.values())
    risk_score = round(min(10, (severity_breakdown["critical"] * 4 + severity_breakdown["high"] * 3 + severity_breakdown["medium"] * 2) * 1.5), 1) # Adjusted for 0-10 scale
    
    contract_lines = 880 # Total lines value
    vulnerable_lines = 4 # Count of vulnerabilities with line numbers

    result = {
        "id": id_,
        "contract": address or "(uploaded file)",
        "network": network,
        "timestamp": now,
        "risk_score": risk_score,
        "vulnerabilities": vulnerabilities, # Include full vulnerability list for the frontend display
        "metrics": {
            "severity_breakdown": severity_breakdown,
            "total_vulnerabilities": total_vulns,
            "total_lines": contract_lines,  # 🔥 FIXED: Renamed to total_lines
            "vulnerable_lines": vulnerable_lines, # Included vulnerable lines count
            "scan_duration": round(1.2, 2),
        },
        "code_insights": {
            "compiler_version": "v0.8.21+commit.d9974bed",
            "imports": ["@openzeppelin/contracts/token/ERC20.sol", "@openzeppelin/contracts/access/Ownable.sol"],
            "external_libraries": 2,
            "functions_analyzed": 40,
        },
        "comparative": {
            "rank": 5,
            "vulnerability_density": round(total_vulns / (contract_lines / 1000), 2),
            "riskiest_contracts": [
                {"name": "Vault.sol", "risk_score": 9.1}, # Adjusted scores for 0-10 scale
                {"name": "Exchange.sol", "risk_score": 8.4},
                {"name": "Router.sol", "risk_score": 8.0},
                {"name": "Bridge.sol", "risk_score": 7.3},
                {"name": "Token.sol", "risk_score": 7.0},
            ],
            "networks": [
                {"name": "Ethereum", "scans": 40},
                {"name": "BSC", "scans": 22},
                {"name": "Polygon", "scans": 16},
                {"name": "Arbitrum", "scans": 9},
            ],
            "word_cloud": [
                {"text": "Reentrancy", "value": 25},
                {"text": "Overflow", "value": 19},
                {"text": "AccessControl", "value": 15},
                {"text": "UncheckedCall", "value": 10},
                {"text": "DelegateCall", "value": 7},
            ]
        },
        "recommendations": [
            {"type": "Reentrancy", "advice": "Use ReentrancyGuard or CEI pattern."},
            {"type": "Integer Overflow", "advice": "Use SafeMath or compiler 0.8+."},
        ],
    }
    return result


def append_history(scan_result):
    history = read_history()
    history.append({
        "id": scan_result["id"],
        "timestamp": scan_result["timestamp"],
        "contract_path": scan_result["contract"], # 🔥 FIXED: Changed key to contract_path (matches HistoryRow)
        "network": scan_result["network"],
        "risk_score": scan_result["risk_score"],
        "vulnerabilities_found": scan_result["metrics"]["total_vulnerabilities"],
        "severity_breakdown": scan_result["metrics"]["severity_breakdown"],
        "scan_duration": scan_result["metrics"]["scan_duration"], # Correctly includes scan_duration
    })
    write_history(history)


# ---------- Endpoints ----------
@app.get("/")
def root():
    return {"service": "Smart Contract Vulnerability Scanner API", "version": "2.0.0"}


@app.get("/api/networks")
def get_networks():
    return {
        "networks": [
            {"id": "mainnet", "name": "Ethereum Mainnet"},
            {"id": "bsc", "name": "Binance Smart Chain"},
            {"id": "polygon", "name": "Polygon"},
            {"id": "arbitrum", "name": "Arbitrum"},
            {"id": "optimism", "name": "Optimism"},
            {"id": "avalanche", "name": "Avalanche"},
            {"id": "sepolia", "name": "Sepolia"},
        ]
    }


@app.post("/api/scan")
async def scan_contract(request: Request, background_tasks: BackgroundTasks):
    try:
        content_type = request.headers.get("content-type", "")
        address, network = None, "mainnet"

        # --- 1. Handle File Upload (Multipart) ---
        if "multipart/form-data" in content_type:
            form = await request.form()
            file = form.get("file")
            network = form.get("network", "mainnet")
            address = form.get("address")
            
            if file and file.filename:
                path = Path("temp_contracts") / f"{uuid.uuid4()}_{file.filename}"
                with open(path, "wb") as f:
                    f.write(await file.read())
                contract_path = str(path)
                
                # Placeholder for actual scanner integration
                # scanner = ContractScanner(...)
                # result = scanner.scan_contract(contract_path, ...)
                result = make_dummy_scan_result(address or path.name, network)
            else:
                # If address is present but file is not, fall through to address scan
                result = make_dummy_scan_result(address, network)

        # --- 2. Handle Address Scan (JSON) ---
        else:
            body = await request.json()
            address = body.get("address")
            network = body.get("network", "mainnet")
            
            # Placeholder for actual scanner integration
            # scanner = ContractScanner(...)
            # result = scanner.scan_contract(address, ...)
            result = make_dummy_scan_result(address, network)

        # --- 3. Return and Update History ---
        background_tasks.add_task(append_history, result)
        return JSONResponse({"success": True, "scan_result": result})

    except Exception as e:
        logger.exception("Scan failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/history")
def get_history(limit: int = 50, offset: int = 0):
    # Note: The frontend uses contract_path and scan_duration keys, which are now correctly saved by append_history
    history = sorted(read_history(), key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"total_scans": len(history), "scans": history[offset:offset + limit]}


@app.delete("/api/history")
def delete_history():
    write_history([])
    return {"success": True, "message": "History cleared"}


@app.get("/api/stats")
def stats():
    history = read_history()
    total_scans = len(history)
    total_vulns = sum(h.get("vulnerabilities_found", 0) for h in history)
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for s in history:
        for k, v in s.get("severity_breakdown", {}).items():
            if k in severity_totals:
                severity_totals[k] += v
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "avg_vulnerabilities": round(total_vulns / total_scans, 2) if total_scans else 0,
        "severity_breakdown": severity_totals,
    }


@app.exception_handler(404)
async def not_found(request, exc):
    return JSONResponse({"error": "Not Found"}, status_code=404)

@app.exception_handler(500)
async def server_error(request, exc):
    return JSONResponse({"error": "Internal Server Error"}, status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)