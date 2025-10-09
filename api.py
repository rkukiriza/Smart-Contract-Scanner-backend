# backend/api.py
"""
Simple, defensive FastAPI backend for Smart Contract Scanner.
- Handles JSON address scan or multipart file upload.
- Stores scan history to scan_results/scan_history.json.
- If your real scanner and etherscan_fetcher are available, it will use them;
  otherwise it will return a deterministic dummy scan result so the frontend can work.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime
import json
import os
import uuid
import logging

logger = logging.getLogger("api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Smart Contract Vulnerability Scanner API (dev)")

# CORS - allow localhost frontend ports for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://*.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        # you can add your deployed frontend origin here later
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ensure folders exist
Path("temp_contracts").mkdir(parents=True, exist_ok=True)
Path("scan_results").mkdir(parents=True, exist_ok=True)

HISTORY_FILE = Path("scan_results/scan_history.json")


# ---------- Pydantic models ----------
class ScanRequest(BaseModel):
    address: Optional[str] = Field(None, description="Contract address (0x...)")
    network: Optional[str] = Field("mainnet", description="Blockchain network")
    categories: Optional[List[str]] = None


# ---------- Helpers ----------
def read_history() -> List[Dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def write_history(history: List[Dict[str, Any]]):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def append_history_item(item: Dict[str, Any]):
    history = read_history()
    history.append(item)
    # keep only last 200
    history = history[-200:]
    write_history(history)


def make_dummy_scan_result(address: Optional[str], network: str):
    now = datetime.utcnow().isoformat()
    id_ = str(uuid.uuid4())
    vulnerabilities = [
        {"type": "reentrancy-eth", "severity": "critical", "description": "Dummy reentrancy issue", "locations": [{"file": "Dummy.sol", "lines": [10]}]},
        {"type": "naming-convention", "severity": "informational", "description": "Dummy naming note", "locations": [{"file": "Dummy.sol", "lines": [1]}]},
    ]
    metrics = {
        "total_lines": 200,
        "vulnerable_lines": 3,
        "total_vulnerabilities": len(vulnerabilities),
        "severity_breakdown": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 1},
        "scan_duration": 1.23
    }
    return {
        "id": id_,
        "contract": address or "(uploaded file)",
        "network": network,
        "timestamp": now,
        "vulnerabilities": vulnerabilities,
        "metrics": metrics
    }


# ---------- Endpoints ----------
@app.get("/")
def root():
    return {"service": "Smart Contract Vulnerability Scanner API (dev)", "version": "1.0.0"}


@app.get("/api/networks")
def get_networks():
    return {
        "networks": [
            {"id": "mainnet", "name": "Ethereum Mainnet", "chain_id": 1},
            {"id": "goerli", "name": "Goerli Testnet", "chain_id": 5},
            {"id": "sepolia", "name": "Sepolia Testnet", "chain_id": 11155111},
            {"id": "bsc", "name": "Binance Smart Chain", "chain_id": 56},
            {"id": "polygon", "name": "Polygon", "chain_id": 137},
        ]
    }


@app.get("/api/detectors")
def get_detectors():
    # Lightweight detectors list for UI
    return {
        "categories": {
            "critical": {"detectors": ["reentrancy-eth", "arbitrary-send-eth"], "count": 2},
            "high": {"detectors": ["uninitialized-state"], "count": 1},
            "medium": {"detectors": ["unchecked-lowlevel"], "count": 1},
            "low": {"detectors": ["shadowing-state"], "count": 1},
            "informational": {"detectors": ["pragma", "naming-convention"], "count": 2},
        }
    }


@app.post("/api/scan")
async def scan_contract(request: Request, background_tasks: BackgroundTasks):
    """
    Accepts either:
    - multipart/form-data with 'file' (UploadFile) and 'network' (form field)
    - or JSON body { address, network, categories }
    """
    content_type = request.headers.get("content-type", "")
    network = "mainnet"
    address = None

    try:
        # If multipart/form-data with file upload:
        if "multipart/form-data" in content_type:
            form = await request.form()
            network = form.get("network", "mainnet")
            address = form.get("address")  # optional
            file_obj = form.get("file")
            if file_obj and hasattr(file_obj, "filename"):
                # Save file to temp_contracts
                filename = file_obj.filename
                save_path = Path("temp_contracts") / f"{uuid.uuid4()}_{filename}"
                with open(save_path, "wb") as out:
                    out.write(await file_obj.read())
                logger.info(f"Saved uploaded file to {save_path}")
                # If you have a real scanner you could call it here
                result = make_dummy_scan_result(address or save_path.name, network)
            else:
                # no file: produce dummy result from address if present
                result = make_dummy_scan_result(address, network)

        else:
            # Expect JSON payload
            body = await request.json()
            address = body.get("address")
            network = body.get("network", "mainnet")
            # Ideally you'd validate address format here
            result = make_dummy_scan_result(address, network)

        # Save to history (background task)
        def save_history_task(scan_result):
            try:
                item = {
                    "id": scan_result.get("id"),
                    "timestamp": scan_result.get("timestamp"),
                    "contract": scan_result.get("contract"),
                    "contract_path": scan_result.get("contract"),
                    "vulnerabilities_found": scan_result.get("metrics", {}).get("total_vulnerabilities", 0),
                    "severity_breakdown": scan_result.get("metrics", {}).get("severity_breakdown", {}),
                    "scan_duration": scan_result.get("metrics", {}).get("scan_duration"),
                    "raw": scan_result
                }
                append_history_item(item)
                logger.info("Scan saved to history")
            except Exception as e:
                logger.exception("Failed to save history: %s", e)

        background_tasks.add_task(save_history_task, result)

        return JSONResponse({"success": True, "message": "Scan completed (dummy)", "scan_result": result})

    except Exception as e:
        logger.exception("Scan error")
        return JSONResponse({"success": False, "message": "Scan failed", "error": str(e)}, status_code=500)


@app.get("/api/history")
def get_history(limit: int = 50, offset: int = 0):
    history = read_history()
    # newest first
    history_sorted = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)
    paginated = history_sorted[offset:offset + limit]
    return {"total_scans": len(history_sorted), "scans": paginated}


@app.delete("/api/history")
async def delete_history(ids: Optional[List[str]] = None):
    try:
        history = read_history()
        if not ids:
            # clear all
            write_history([])
            return {"success": True, "message": "History cleared"}
        # keep those whose id is not in ids
        new_hist = [h for h in history if str(h.get("id") or h.get("timestamp")) not in ids]
        write_history(new_hist)
        return {"success": True, "message": "Deleted requested history entries", "remaining": len(new_hist)}
    except Exception as e:
        logger.exception("delete_history error")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats")
def stats():
    history = read_history()
    total_scans = len(history)
    total_vulns = sum(h.get("vulnerabilities_found", 0) for h in history)
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for s in history:
        for k, v in (s.get("severity_breakdown") or {}).items():
            if k in severity_totals:
                severity_totals[k] += v
    avg = round(total_vulns / total_scans, 2) if total_scans else 0
    return {"total_scans": total_scans, "total_vulnerabilities": total_vulns, "avg_vulnerabilities": avg, "severity_breakdown": severity_totals}


# --- Error handlers return proper JSONResponse (avoid middleware issues) ---
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse({"success": False, "error": "Endpoint not found", "message": str(exc)}, status_code=404)


@app.exception_handler(500)
async def internal_handler(request, exc):
    return JSONResponse({"success": False, "error": "Internal server error", "message": str(exc)}, status_code=500)


# Run with: uvicorn api:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
