"""
Enhanced Smart Contract Vulnerability Scanner v3.0
- Produces dashboard-ready metrics for risk, code, operation, and comparative analysis.
- Includes logic for Word Cloud and Comparative Metrics (Rank, Density).
"""

import json
import subprocess
import argparse
import sys
import random # Needed for simulating rank and other comparative data
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import logging

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# Detector categories by severity
DETECTORS = {
    "critical": [
        "arbitrary-send-eth",
        "controlled-delegatecall",
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "suicidal",
    ],
    "high": [
        "uninitialized-state",
        "uninitialized-storage",
        "unprotected-upgrade",
        "incorrect-equality",
        "locked-ether",
        "delegatecall-loop",
    ],
    "medium": [
        "unchecked-lowlevel",
        "unchecked-send",
        "divide-before-multiply",
        "reentrancy-events",
        "timestamp",
        "weak-prng",
        "missing-zero-check",
    ],
    "low": [
        "calls-loop",
        "shadowing-state",
        "shadowing-abstract",
        "shadowing-local",
        "unused-state",
        "tx-origin",
    ],
    "informational": [
        "solc-version",
        "pragma",
        "naming-convention",
        "assembly",
        "low-level-calls",
        "similar-names",
    ]
}

ALL_DETECTORS = [d for detectors in DETECTORS.values() for d in detectors]
SEVERITY_WEIGHTS = {"critical": 5, "high": 3, "medium": 2, "low": 1, "informational": 0}

# ------------------ DATA CLASSES ------------------

@dataclass
class VulnerabilityLocation:
    file: str
    lines: List[int]
    code: str
    element_type: str
    starting_column: Optional[int] = None
    ending_column: Optional[int] = None

@dataclass
class Vulnerability:
    vuln_type: str
    category: str
    severity: str
    confidence: str
    description: str
    locations: List[VulnerabilityLocation]
    markdown: str = ""
    first_markdown_element: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "locations": [asdict(loc) for loc in self.locations],
            "markdown": self.markdown,
            "first_markdown_element": self.first_markdown_element
        }

@dataclass
class ScanMetrics:
    total_lines: int
    vulnerable_lines: int
    vulnerable_line_percentage: float
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    detectors_run: int
    scan_duration: float

@dataclass
class DashboardMetrics:
    risk_score: float
    severity_distribution: Dict[str, int]
    total_lines: int
    vulnerable_lines: int
    vuln_line_percentage: float
    avg_lines_per_vuln: float
    scan_duration: float
    detectors_run: int

@dataclass
class ComparativeMetrics:
    rank: int
    vulnerability_density: float
    riskiest_contracts: List[Dict[str, Any]]
    networks: List[Dict[str, Any]]
    word_cloud: List[Dict[str, Any]]

@dataclass
class ScanResult:
    contract_path: str
    scan_timestamp: str
    vulnerabilities: List[Vulnerability]
    metrics: ScanMetrics
    dashboard_metrics: DashboardMetrics = None
    detector_results: Dict[str, List] = None
    comparative_metrics: ComparativeMetrics = None

    def to_dict(self) -> Dict:
        return {
            "contract": self.contract_path,
            "timestamp": self.scan_timestamp, # Renamed to timestamp for frontend history
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "metrics": {
                **asdict(self.metrics), 
                "severity_breakdown": self.metrics.severity_breakdown, # Ensure breakdown is at this level too
                "total_lines": self.metrics.total_lines, # Ensures total_lines is present at the required path
                "scan_duration": self.metrics.scan_duration
            },
            "risk_score": self.dashboard_metrics.risk_score if self.dashboard_metrics else 0.0,
            "code_insights": self.get_code_insights(),
            "comparative": asdict(self.comparative_metrics) if self.comparative_metrics else {},
            "recommendations": self.generate_recommendations(),
        }

    def get_code_insights(self) -> Dict[str, Any]:
        """Extracts simple code insights (simulated for now)."""
        return {
            "compiler_version": "v0.8.21+commit.d9974bed", # Placeholder
            "imports": ["@openzeppelin/contracts/token/ERC20.sol"], # Placeholder
            "external_libraries": random.randint(0, 3),
            "functions_analyzed": random.randint(20, 50),
        }

    def generate_recommendations(self):
        """Generates simple recommendations based on found vulnerabilities."""
        recommendations = []
        if any("reentrancy" in v.vuln_type.lower() for v in self.vulnerabilities):
            recommendations.append({"type": "Reentrancy", "advice": "Use ReentrancyGuard or the Checks-Effects-Interactions (CEI) pattern."})
        if any("unchecked" in v.vuln_type.lower() for v in self.vulnerabilities):
            recommendations.append({"type": "Unchecked Call", "advice": "Always check the return values of external low-level calls."})
        return recommendations

# ------------------ SCANNER CLASS ------------------

class ContractScanner:

    SEVERITY_COLORS = {
        "critical": Fore.RED,
        "high": Fore.MAGENTA,
        "medium": Fore.YELLOW,
        "low": Fore.CYAN,
        "informational": Fore.BLUE,
        "unknown": Fore.WHITE
    }

    SEVERITY_ICONS = {
        "critical": "🚨",
        "high": "🔴",
        "medium": "🟡",
        "low": "🔵",
        "informational": "ℹ️"
    }

    def __init__(self, output_dir: str = "scan_results", verbose: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        # Logger setup remains the same
        logger = logging.getLogger("ContractScanner")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        fh = logging.FileHandler(self.output_dir / "scanner.log")
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger

    # Verification, run_slither_detector, categorize_vulnerability, parse_vulnerability remain the same
    # ... (omitted for brevity, assume they are present)

    def verify_slither_installed(self) -> bool:
        try:
            result = subprocess.run(['slither', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def run_slither_detector(self, contract_path: str, detector_name: str) -> Optional[Dict]:
        try:
            cmd = ['slither', contract_path, '--detect', detector_name, '--json', '-', '--exclude-dependencies']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return None
            return None
        except Exception as e:
            self.logger.error(f"Detector {detector_name} failed: {e}")
            return None

    def categorize_vulnerability(self, detector_name: str) -> str:
        for category, detectors in DETECTORS.items():
            if detector_name in detectors:
                return category
        return "unknown"

    def parse_vulnerability(self, detection: Dict, detector_name: str, contract_path: Path) -> Optional[Vulnerability]:
        try:
            category = self.categorize_vulnerability(detector_name)
            locations = []
            elements = detection.get('elements', [])
            for element in elements:
                source_mapping = element.get('source_mapping', {})
                if source_mapping:
                    loc = VulnerabilityLocation(
                        file=source_mapping.get('filename_relative', str(contract_path)),
                        lines=source_mapping.get('lines', []),
                        code=element.get('name', ''),
                        element_type=element.get('type', ''),
                        starting_column=source_mapping.get('starting_column'),
                        ending_column=source_mapping.get('ending_column')
                    )
                    locations.append(loc)
            if not locations:
                return None
            return Vulnerability(
                vuln_type=detection.get('check', detector_name),
                category=category,
                severity=detection.get('impact', 'unknown'),
                confidence=detection.get('confidence', 'unknown'),
                description=detection.get('description', '').strip(),
                locations=locations,
                markdown=detection.get('markdown', ''),
                first_markdown_element=detection.get('first_markdown_element', '')
            )
        except Exception as e:
            self.logger.error(f"Parsing vulnerability failed: {e}")
            return None


    def count_contract_lines(self, contract_path: Path) -> int:
        try:
            # Handle deployed contracts (simulated by address format)
            if str(contract_path).startswith(("0x", "http")):
                return random.randint(300, 1500)
            
            with open(contract_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Count non-empty, non-comment lines
                return sum(1 for line in lines if line.strip() and not line.strip().startswith('//'))
        except Exception:
            return 0

    def compute_dashboard_metrics(self, vulnerabilities: List[Vulnerability], total_lines: int, vulnerable_lines: int, scan_duration: float, detectors_run: int) -> DashboardMetrics:
        # This function remains largely the same, but the risk score calculation is adjusted 
        # to ensure it returns the necessary DashboardMetrics object.
        severity_distribution = {k: 0 for k in DETECTORS.keys()}
        for v in vulnerabilities:
            if v.category in severity_distribution:
                severity_distribution[v.category] += 1
        
        # Calculate risk score based on weights
        risk_score_raw = sum(SEVERITY_WEIGHTS.get(v.category, 0) for v in vulnerabilities)
        
        # Normalize to a 0-10 scale (simple normalization for demo)
        # Using a fixed divisor for normalization might be better for consistent UI scale
        risk_score = round(min(10.0, risk_score_raw * 10 / 50), 1) if vulnerabilities else 0.0 
        
        avg_lines_per_vuln = (total_lines / len(vulnerabilities)) if vulnerabilities else 0
        vuln_line_percentage = (vulnerable_lines / total_lines * 100) if total_lines else 0

        return DashboardMetrics(
            risk_score=risk_score,
            severity_distribution=severity_distribution,
            total_lines=total_lines,
            vulnerable_lines=vulnerable_lines,
            vuln_line_percentage=round(vuln_line_percentage, 2),
            avg_lines_per_vuln=round(avg_lines_per_vuln, 2),
            scan_duration=round(scan_duration, 2),
            detectors_run=detectors_run
        )

    # ------------------ NEW COMPARATIVE LOGIC ------------------

    def generate_word_cloud_data(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
        """
        Analyzes vulnerability descriptions to create data for the Word Cloud.
        """
        keyword_counts: Dict[str, int] = {}
        # Core keywords to track (common vulnerability themes)
        keywords = ["reentrancy", "overflow", "underflow", "unchecked", "access control", "delegatecall", "timestamp", "tx.origin", "storage", "ERC20", "fallback"]
        
        for vuln in vulnerabilities:
            # Combine type and description for comprehensive analysis
            text = f"{vuln.vuln_type} {vuln.description}".lower()
            for keyword in keywords:
                if keyword in text:
                    # Increment count for each keyword found
                    keyword_counts[keyword.capitalize()] = keyword_counts.get(keyword.capitalize(), 0) + 1
        
        # Format the data for the frontend ('text' and 'value')
        # Multiply value by 10 to make them visually distinct on the chart
        word_cloud_data = [{"text": k, "value": v * 10} for k, v in keyword_counts.items() if v > 0]
        
        # Sort and return top 15
        word_cloud_data.sort(key=lambda x: x['value'], reverse=True)
        return word_cloud_data[:15]


    def compute_comparative_metrics(self, dashboard_metrics: DashboardMetrics) -> ComparativeMetrics:
        """
        Calculates Comparative Metrics, including Rank, Density, and placeholder data.
        """
        total_lines = dashboard_metrics.total_lines
        total_vulns = dashboard_metrics.severity_distribution.get("critical", 0) + dashboard_metrics.severity_distribution.get("high", 0)
        
        # 1. Density: High/Critical Vulns per 1000 lines of code
        vulnerability_density = round(total_vulns / (total_lines / 1000), 4) if total_lines > 0 else 0
        
        # 2. Rank: Simulating rank based on risk score (higher score = lower rank number)
        # Random rank between 1 and 1000, weighted by score
        rank_base = random.randint(1, 1000)
        rank_adjustment = int(dashboard_metrics.risk_score * 50)
        rank = max(1, rank_base - rank_adjustment)

        # 3. Simulating Placeholder Data
        riskiest_contracts = [
            {"name": "Vault.sol", "risk_score": 9.1},
            {"name": "Exchange.sol", "risk_score": 8.4},
            {"name": "Router.sol", "risk_score": 8.0},
            {"name": "Bridge.sol", "risk_score": 7.3},
            {"name": "Token.sol", "risk_score": 7.0},
        ]
        networks = [
            {"name": "Ethereum", "scans": 40},
            {"name": "BSC", "scans": 22},
            {"name": "Polygon", "scans": 16},
            {"name": "Arbitrum", "scans": 9},
        ]
        
        # Word Cloud will be populated in scan_contract
        return ComparativeMetrics(
            rank=rank,
            vulnerability_density=vulnerability_density,
            riskiest_contracts=riskiest_contracts,
            networks=networks,
            word_cloud=[]
        )

    # ------------------ END NEW COMPARATIVE LOGIC ------------------

    def scan_contract(self, contract_path: str, categories: List[str] = None) -> ScanResult:
        start_time = datetime.now()
        contract_path = Path(contract_path)
        detectors_to_run = ALL_DETECTORS if not categories else [d for c in categories for d in DETECTORS.get(c, [])]
        vulnerabilities = []
        vulnerable_lines = set()
        detector_results = {}
        
        # 1. Run Slither Detectors (Same logic)
        for detector_name in detectors_to_run:
            result = self.run_slither_detector(str(contract_path), detector_name)
            if result and 'results' in result:
                detections = result['results'].get('detectors', [])
                detector_results[detector_name] = detections
                for detection in detections:
                    vuln = self.parse_vulnerability(detection, detector_name, contract_path)
                    if vuln:
                        vulnerabilities.append(vuln)
                        for loc in vuln.locations:
                            vulnerable_lines.update(loc.lines)

        total_lines = self.count_contract_lines(contract_path)
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # 2. Compute Core Metrics (Same logic, now correctly using total_lines)
        metrics = ScanMetrics(
            total_lines=total_lines,
            vulnerable_lines=len(vulnerable_lines),
            vulnerable_line_percentage=round((len(vulnerable_lines)/total_lines*100) if total_lines else 0, 2),
            total_vulnerabilities=len(vulnerabilities),
            severity_breakdown={k: sum(1 for v in vulnerabilities if v.category==k) for k in DETECTORS.keys()},
            detectors_run=len(detectors_to_run),
            scan_duration=round(scan_duration, 2)
        )

        dashboard_metrics = self.compute_dashboard_metrics(vulnerabilities, total_lines, len(vulnerable_lines), scan_duration, len(detectors_to_run))
        
        # 3. Compute Comparative Metrics
        comparative_metrics = self.compute_comparative_metrics(dashboard_metrics)
        
        # 4. Compute Word Cloud and inject into comparative_metrics
        word_cloud_data = self.generate_word_cloud_data(vulnerabilities)
        comparative_metrics.word_cloud = word_cloud_data
        
        # 5. Final Assembly
        scan_result = ScanResult(
            contract_path=str(contract_path),
            scan_timestamp=datetime.now().isoformat(),
            vulnerabilities=vulnerabilities,
            metrics=metrics,
            dashboard_metrics=dashboard_metrics,
            detector_results=detector_results,
            comparative_metrics=comparative_metrics # Assign the new object
        )
        
        # 6. Save JSON and history
        self.save_results(scan_result, contract_path.stem)
        return scan_result

    def save_results(self, scan_result: ScanResult, contract_name: str):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = self.output_dir / f"scan_{contract_name}_{timestamp}.json"
        
        # Use the to_dict method from ScanResult
        json_output = scan_result.to_dict()
        
        json.dump(json_output, open(json_file, 'w', encoding='utf-8'), indent=2)
        self.update_scan_history(json_output) # Pass the dictionary, not the ScanResult object

    def update_scan_history(self, new_result_dict: Dict):
        history_file = self.output_dir / "scan_history.json"
        try:
            history = json.loads(history_file.read_text()) if history_file.exists() else []
        except Exception:
            history = []

        history.append(new_result_dict)
        history = history[-200:] # Keep the last 200 scans
        json.dump(history, open(history_file, 'w', encoding='utf-8'), indent=2)

# ------------------ MAIN ------------------

def main():
    parser = argparse.ArgumentParser(description="Enhanced Smart Contract Security Scanner v3.0")
    parser.add_argument("contract", help="Path to Solidity contract")
    parser.add_argument("--critical", action="store_true")
    parser.add_argument("--high", action="store_true")
    parser.add_argument("--medium", action="store_true")
    parser.add_argument("--low", action="store_true")
    parser.add_argument("--informational", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output", "-o", default="scan_results")
    args = parser.parse_args()

    categories = [c for c in ["critical","high","medium","low","informational"] if getattr(args, c)]
    categories = categories if categories else None

    scanner = ContractScanner(output_dir=args.output, verbose=args.verbose)
    # Check if Slither is installed before proceeding with the scan
    if not scanner.verify_slither_installed():
        scanner.logger.error("Slither not found. Please ensure it is installed and in your system PATH.")
        sys.exit(3)
        
    scan_result = scanner.scan_contract(args.contract, categories)

    # Exit codes: critical/high=2, others=1, clean=0
    critical_high = scan_result.metrics.severity_breakdown.get("critical",0)+scan_result.metrics.severity_breakdown.get("high",0)
    if critical_high>0: sys.exit(2)
    elif scan_result.metrics.total_vulnerabilities>0: sys.exit(1)
    else: sys.exit(0)

if __name__ == "__main__":
    main()