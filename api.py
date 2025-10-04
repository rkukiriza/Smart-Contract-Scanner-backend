"""
Smart Contract Scanner - FastAPI Backend
Deploy on Railway, Render, or Heroku
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import os
import json
from pathlib import Path
from datetime import datetime
import logging

from etherscan_fetcher import EtherscanFetcher, ContractInfo
from scanner import ContractScanner

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Smart Contract Vulnerability Scanner API",
    description="API for scanning smart contracts for security vulnerabilities",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://*.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001",
        "*"  # Remove in production for security
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure directories exist
Path("temp_contracts").mkdir(exist_ok=True)
Path("scan_results").mkdir(exist_ok=True)


# Pydantic Models
class ScanRequest(BaseModel):
    address: str = Field(..., description="Contract address (0x...)")
    network: str = Field(default="mainnet", description="Blockchain network")
    categories: Optional[List[str]] = Field(
        default=None,
        description="Vulnerability categories to scan: critical, high, medium, low, informational"
    )

    class Config:
        schema_extra = {
            "example": {
                "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                "network": "mainnet",
                "categories": ["critical", "high"]
            }
        }


class ContractInfoResponse(BaseModel):
    address: str
    name: str
    compiler_version: str
    optimization_used: bool
    runs: int
    license_type: str
    proxy: bool
    implementation_address: Optional[str]


class ScanResponse(BaseModel):
    success: bool
    message: str
    contract_info: Optional[ContractInfoResponse] = None
    scan_result: Optional[Dict] = None
    error: Optional[str] = None


class HistoryResponse(BaseModel):
    total_scans: int
    scans: List[Dict]


# Root endpoint
@app.get("/")
def read_root():
    """API information"""
    return {
        "service": "Smart Contract Vulnerability Scanner API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "scan": "/api/scan (POST)",
            "history": "/api/history (GET)",
            "networks": "/api/networks (GET)",
            "detectors": "/api/detectors (GET)"
        }
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "scanner": "operational",
        "etherscan": "connected"
    }


@app.get("/api/networks")
def get_supported_networks():
    """Get list of supported blockchain networks"""
    return {
        "networks": [
            {"id": "mainnet", "name": "Ethereum Mainnet", "chain_id": 1},
            {"id": "goerli", "name": "Goerli Testnet", "chain_id": 5},
            {"id": "sepolia", "name": "Sepolia Testnet", "chain_id": 11155111},
            {"id": "bsc", "name": "Binance Smart Chain", "chain_id": 56},
            {"id": "polygon", "name": "Polygon", "chain_id": 137},
            {"id": "arbitrum", "name": "Arbitrum One", "chain_id": 42161},
            {"id": "optimism", "name": "Optimism", "chain_id": 10}
        ]
    }


@app.get("/api/detectors")
def get_detector_categories():
    """Get available vulnerability detector categories"""
    from scanner import DETECTORS
    
    return {
        "categories": {
            category: {
                "detectors": detectors,
                "count": len(detectors)
            }
            for category, detectors in DETECTORS.items()
        }
    }


@app.post("/api/scan", response_model=ScanResponse)
async def scan_contract(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Scan a smart contract for vulnerabilities
    
    - **address**: Contract address (0x...)
    - **network**: Blockchain network (mainnet, polygon, etc.)
    - **categories**: Optional list of vulnerability categories to scan
    """
    logger.info(f"Scan request received: {request.address} on {request.network}")
    
    try:
        # Validate address format
        if not request.address.startswith('0x') or len(request.address) != 42:
            raise HTTPException(
                status_code=400,
                detail="Invalid Ethereum address format. Must be 42 characters starting with 0x"
            )
        
        # Step 1: Fetch contract from blockchain
        logger.info(f"Fetching contract from {request.network}...")
        
        fetcher = EtherscanFetcher(network=request.network)
        
        # Check if verified
        if not fetcher.is_contract_verified(request.address):
            raise HTTPException(
                status_code=404,
                detail=f"Contract {request.address} is not verified on {request.network}. Only verified contracts can be scanned."
            )
        
        # Get contract source
        contract_info = fetcher.get_contract_source(request.address)
        contract_path = fetcher.save_contract(contract_info, "temp_contracts")
        
        logger.info(f"Contract fetched: {contract_info.name}")
        
        # Step 2: Scan contract
        logger.info("Starting vulnerability scan...")
        
        scanner = ContractScanner(output_dir="scan_results", verbose=False)
        scan_result = scanner.scan_contract(
            str(contract_path),
            categories=request.categories
        )
        
        logger.info(f"Scan complete: {scan_result.metrics.total_vulnerabilities} vulnerabilities found")
        
        # Step 3: Cleanup (in background)
        def cleanup():
            try:
                contract_path.unlink()
                metadata_file = contract_path.with_suffix('.json')
                if metadata_file.exists():
                    metadata_file.unlink()
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")
        
        background_tasks.add_task(cleanup)
        
        # Step 4: Prepare response
        contract_info_response = ContractInfoResponse(
            address=contract_info.address,
            name=contract_info.name,
            compiler_version=contract_info.compiler_version,
            optimization_used=contract_info.optimization_used,
            runs=contract_info.runs,
            license_type=contract_info.license_type,
            proxy=contract_info.proxy,
            implementation_address=contract_info.implementation_address
        )
        
        return ScanResponse(
            success=True,
            message=f"Successfully scanned {contract_info.name}",
            contract_info=contract_info_response,
            scan_result=scan_result.to_dict()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return ScanResponse(
            success=False,
            message="Scan failed",
            error=str(e)
        )


@app.get("/api/history", response_model=HistoryResponse)
async def get_scan_history(limit: int = 50, offset: int = 0):
    """
    Get scan history
    
    - **limit**: Maximum number of scans to return (default: 50)
    - **offset**: Number of scans to skip (default: 0)
    """
    history_file = Path("scan_results/scan_history.json")
    
    if not history_file.exists():
        return HistoryResponse(total_scans=0, scans=[])
    
    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        # Sort by timestamp (newest first)
        history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Apply pagination
        paginated = history[offset:offset + limit]
        
        return HistoryResponse(
            total_scans=len(history),
            scans=paginated
        )
        
    except Exception as e:
        logger.error(f"Error loading history: {e}")
        return HistoryResponse(total_scans=0, scans=[])


@app.delete("/api/history")
async def clear_history():
    """Clear scan history"""
    try:
        history_file = Path("scan_results/scan_history.json")
        if history_file.exists():
            history_file.unlink()
        
        return {"success": True, "message": "History cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats")
async def get_statistics():
    """Get overall statistics"""
    history_file = Path("scan_results/scan_history.json")
    
    if not history_file.exists():
        return {
            "total_scans": 0,
            "total_vulnerabilities": 0,
            "avg_vulnerabilities": 0,
            "severity_breakdown": {}
        }
    
    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
        
        total_scans = len(history)
        total_vulns = sum(scan.get('vulnerabilities_found', 0) for scan in history)
        
        # Aggregate severity breakdown
        severity_totals = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        for scan in history:
            breakdown = scan.get('severity_breakdown', {})
            for severity, count in breakdown.items():
                if severity in severity_totals:
                    severity_totals[severity] += count
        
        return {
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulns,
            "avg_vulnerabilities": round(total_vulns / total_scans, 2) if total_scans > 0 else 0,
            "severity_breakdown": severity_totals
        }
        
    except Exception as e:
        logger.error(f"Error calculating stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return {
        "success": False,
        "error": "Endpoint not found",
        "message": str(exc)
    }


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return {
        "success": False,
        "error": "Internal server error",
        "message": str(exc)
    }


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8000))
    
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )