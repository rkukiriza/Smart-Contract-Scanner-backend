"""
Enhanced Smart Contract Vulnerability Scanner
Optimized for dashboard integration and better performance
"""

import json
import subprocess
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
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


@dataclass
class VulnerabilityLocation:
    """Represents a vulnerability location in code"""
    file: str
    lines: List[int]
    code: str
    element_type: str
    starting_column: Optional[int] = None
    ending_column: Optional[int] = None


@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    vuln_type: str
    category: str
    severity: str
    confidence: str
    description: str
    locations: List[VulnerabilityLocation]
    markdown: str = ""
    first_markdown_element: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
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
    """Scan metrics and statistics"""
    total_lines: int
    vulnerable_lines: int
    vulnerable_line_percentage: float
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    detectors_run: int
    scan_duration: float


@dataclass
class ScanResult:
    """Complete scan result"""
    contract_path: str
    scan_timestamp: str
    vulnerabilities: List[Vulnerability]
    metrics: ScanMetrics
    detector_results: Dict[str, List] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "contract": self.contract_path,
            "scan_timestamp": self.scan_timestamp,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "metrics": asdict(self.metrics),
            "detector_results": self.detector_results or {}
        }


class ContractScanner:
    """Enhanced smart contract vulnerability scanner"""
    
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
        """Initialize scanner"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("ContractScanner")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        log_file = self.output_dir / "scanner.log"
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def print_colored(self, text: str, color: str = Fore.WHITE, style: str = ""):
        """Print colored text if colorama available"""
        if COLORAMA_AVAILABLE:
            print(f"{style}{color}{text}{Style.RESET_ALL}")
        else:
            print(text)
    
    def print_banner(self):
        """Print scanner banner"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║     SMART CONTRACT VULNERABILITY SCANNER v2.0            ║
║     Enhanced Static Analysis Tool                        ║
╚══════════════════════════════════════════════════════════╝
        """
        self.print_colored(banner, Fore.CYAN, Style.BRIGHT)
    
    def verify_slither_installed(self) -> bool:
        """Check if Slither is installed"""
        try:
            result = subprocess.run(
                ['slither', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def run_slither_detector(self, contract_path: str, detector_name: str) -> Optional[Dict]:
        """Run a specific Slither detector with improved error handling"""
        try:
            cmd = [
                'slither',
                contract_path,
                '--detect', detector_name,
                '--json', '-',
                '--exclude-dependencies'
            ]
            
            if self.verbose:
                self.logger.debug(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return data
                except json.JSONDecodeError as e:
                    self.logger.warning(f"JSON decode error for {detector_name}: {e}")
                    return None
            
            if result.stderr:
                if "is not a detector" in result.stderr:
                    self.logger.warning(f"Invalid detector: {detector_name}")
                elif "Compilation failed" in result.stderr:
                    self.logger.error(f"Contract compilation failed")
            
            return None
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout: {detector_name} took too long")
            return None
        except Exception as e:
            self.logger.error(f"Error with {detector_name}: {e}")
            return None
    
    def get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        return self.SEVERITY_COLORS.get(severity.lower(), Fore.WHITE)
    
    def categorize_vulnerability(self, detector_name: str) -> str:
        """Categorize vulnerability by detector name"""
        for category, detectors in DETECTORS.items():
            if detector_name in detectors:
                return category
        return "unknown"
    
    def parse_vulnerability(self, detection: Dict, detector_name: str, contract_path: Path) -> Optional[Vulnerability]:
        """Parse a detection into a Vulnerability object"""
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
            self.logger.error(f"Error parsing vulnerability: {e}")
            return None
    
    def count_contract_lines(self, contract_path: Path) -> int:
        """Count total lines in contract"""
        try:
            with open(contract_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                return sum(1 for line in lines if line.strip() and not line.strip().startswith('//'))
        except Exception as e:
            self.logger.error(f"Error counting lines: {e}")
            return 0
    
    def scan_contract(self, contract_path: str, categories: List[str] = None) -> ScanResult:
        """Main scanning function"""
        start_time = datetime.now()
        
        self.print_banner()
        
        contract_path = Path(contract_path)
        if not contract_path.exists():
            raise FileNotFoundError(f"Contract file not found: {contract_path}")
        
        if not self.verify_slither_installed():
            raise RuntimeError("Slither is not installed. Install with: pip install slither-analyzer")
        
        detectors_to_run = self._get_detectors_to_run(categories)
        
        self.print_colored(f"📄 Scanning: {contract_path.name}", Fore.GREEN, Style.BRIGHT)
        self.print_colored(f"🔍 Running {len(detectors_to_run)} detectors...", Fore.CYAN)
        
        vulnerabilities = []
        vulnerable_lines = set()
        detector_results = {}
        
        for i, detector_name in enumerate(detectors_to_run):
            category = self.categorize_vulnerability(detector_name)
            color = self.get_severity_color(category)
            
            print(f"  [{i+1:2d}/{len(detectors_to_run)}] {color}{detector_name:<30}{Style.RESET_ALL}", end=" ")
            
            result = self.run_slither_detector(str(contract_path), detector_name)
            
            if result and 'results' in result:
                detections = result['results'].get('detectors', [])
                detector_results[detector_name] = detections
                
                if detections:
                    self.print_colored("FOUND", Fore.RED, Style.BRIGHT)
                    
                    for detection in detections:
                        vuln = self.parse_vulnerability(detection, detector_name, contract_path)
                        if vuln:
                            vulnerabilities.append(vuln)
                            for loc in vuln.locations:
                                vulnerable_lines.update(loc.lines)
                else:
                    self.print_colored("CLEAN", Fore.GREEN)
            else:
                self.print_colored("ERROR", Fore.YELLOW)
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        total_lines = self.count_contract_lines(contract_path)
        vuln_line_percentage = (len(vulnerable_lines) / total_lines * 100) if total_lines > 0 else 0
        
        severity_counts = {k: 0 for k in DETECTORS.keys()}
        for vuln in vulnerabilities:
            if vuln.category in severity_counts:
                severity_counts[vuln.category] += 1
        
        metrics = ScanMetrics(
            total_lines=total_lines,
            vulnerable_lines=len(vulnerable_lines),
            vulnerable_line_percentage=round(vuln_line_percentage, 2),
            total_vulnerabilities=len(vulnerabilities),
            severity_breakdown=severity_counts,
            detectors_run=len(detectors_to_run),
            scan_duration=round(scan_duration, 2)
        )
        
        scan_result = ScanResult(
            contract_path=str(contract_path),
            scan_timestamp=datetime.now().isoformat(),
            vulnerabilities=vulnerabilities,
            metrics=metrics,
            detector_results=detector_results
        )
        
        self.save_results(scan_result, contract_path.stem)
        self.print_summary(scan_result)
        
        return scan_result
    
    def _get_detectors_to_run(self, categories: List[str] = None) -> List[str]:
        """Get list of detectors to run based on categories"""
        if not categories:
            return ALL_DETECTORS
        
        detectors = []
        for category in categories:
            if category in DETECTORS:
                detectors.extend(DETECTORS[category])
        return detectors
    
    def save_results(self, scan_result: ScanResult, contract_name: str):
        """Save scan results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_file = self.output_dir / f"scan_{contract_name}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(scan_result.to_dict(), f, indent=2, ensure_ascii=False)
        
        if PANDAS_AVAILABLE:
            csv_file = self.output_dir / f"scan_{contract_name}_{timestamp}.csv"
            self.save_csv_summary(scan_result, csv_file)
        
        self.update_scan_history(scan_result)
        
        self.print_colored(f"📁 Results saved to: {json_file}", Fore.GREEN)
        self.logger.info(f"Scan results saved: {json_file}")
    
    def save_csv_summary(self, scan_result: ScanResult, csv_file: Path):
        """Save vulnerability summary to CSV"""
        if not scan_result.vulnerabilities:
            return
        
        csv_data = []
        for vuln in scan_result.vulnerabilities:
            csv_data.append({
                'Type': vuln.vuln_type,
                'Category': vuln.category,
                'Severity': vuln.severity,
                'Confidence': vuln.confidence,
                'Description': vuln.description[:100] + '...' if len(vuln.description) > 100 else vuln.description,
                'Lines': ', '.join(str(line) for loc in vuln.locations for line in loc.lines),
                'File': vuln.locations[0].file if vuln.locations else ''
            })
        
        df = pd.DataFrame(csv_data)
        df.to_csv(csv_file, index=False)
    
    def update_scan_history(self, scan_result: ScanResult):
        """Update scan history"""
        history_file = self.output_dir / "scan_history.json"
        history = []
        
        try:
            if history_file.exists():
                with open(history_file, 'r') as f:
                    history = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            history = []
        
        history.append({
            "timestamp": scan_result.scan_timestamp,
            "contract_path": scan_result.contract_path,
            "vulnerabilities_found": scan_result.metrics.total_vulnerabilities,
            "severity_breakdown": scan_result.metrics.severity_breakdown,
            "scan_duration": scan_result.metrics.scan_duration
        })
        
        history = history[-100:]
        
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def print_summary(self, scan_result: ScanResult):
        """Print comprehensive summary"""
        metrics = scan_result.metrics
        
        self.print_colored("\n" + "="*80, Fore.CYAN, Style.BRIGHT)
        self.print_colored("📊 SCAN RESULTS SUMMARY", Fore.CYAN, Style.BRIGHT)
        self.print_colored("="*80, Fore.CYAN, Style.BRIGHT)
        
        print(f"📄 Contract: {Fore.WHITE}{scan_result.contract_path}")
        print(f"⏱️  Scan Duration: {Fore.WHITE}{metrics.scan_duration}s")
        print(f"📏 Total Lines: {Fore.WHITE}{metrics.total_lines}")
        print(f"⚠️  Vulnerable Lines: {Fore.YELLOW}{metrics.vulnerable_lines}")
        print(f"📈 Vulnerability Coverage: {Fore.YELLOW}{metrics.vulnerable_line_percentage}%")
        print(f"🔍 Detectors Run: {Fore.WHITE}{metrics.detectors_run}")
        
        self.print_colored("\n🎯 SEVERITY BREAKDOWN:", Fore.CYAN, Style.BRIGHT)
        
        for severity, count in metrics.severity_breakdown.items():
            if count > 0:
                color = self.get_severity_color(severity)
                icon = self.SEVERITY_ICONS.get(severity, "⚪")
                print(f"  {icon} {severity.upper():<15}: {color}{count}{Style.RESET_ALL}")
        
        total_vulns = sum(metrics.severity_breakdown.values())
        
        if total_vulns == 0:
            self.print_colored("\n✅ CONGRATULATIONS! No vulnerabilities detected!", Fore.GREEN, Style.BRIGHT)
        else:
            self.print_colored(f"\n⚠️  TOTAL VULNERABILITIES: {total_vulns}", Fore.RED, Style.BRIGHT)
            
            critical_high = [v for v in scan_result.vulnerabilities if v.category in ['critical', 'high']]
            if critical_high:
                self.print_colored("\n🚨 CRITICAL/HIGH SEVERITY ISSUES:", Fore.RED, Style.BRIGHT)
                for i, vuln in enumerate(critical_high[:5], 1):
                    color = self.get_severity_color(vuln.category)
                    lines_str = ', '.join(str(line) for loc in vuln.locations[:1] for line in loc.lines[:3])
                    print(f"  {i}. {color}{vuln.vuln_type}{Style.RESET_ALL}")
                    print(f"     Lines: {lines_str}")
                    print(f"     {vuln.description[:80]}...")
        
        self.print_colored("="*80, Fore.CYAN, Style.BRIGHT)


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Smart Contract Security Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scanner.py contract.sol
  python scanner.py contract.sol --critical --high
  python scanner.py contract.sol -v
  python scanner.py contract.sol -o results/
        """
    )
    
    parser.add_argument("contract", help="Path to the Solidity contract file")
    parser.add_argument("--critical", action="store_true", help="Include critical detectors")
    parser.add_argument("--high", action="store_true", help="Include high severity detectors")
    parser.add_argument("--medium", action="store_true", help="Include medium severity detectors")
    parser.add_argument("--low", action="store_true", help="Include low severity detectors")
    parser.add_argument("--informational", action="store_true", help="Include informational detectors")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", default="scan_results", help="Output directory")
    
    args = parser.parse_args()
    
    categories = []
    if args.critical:
        categories.append("critical")
    if args.high:
        categories.append("high")
    if args.medium:
        categories.append("medium")
    if args.low:
        categories.append("low")
    if args.informational:
        categories.append("informational")
    
    if not categories:
        categories = None
    
    try:
        scanner = ContractScanner(output_dir=args.output, verbose=args.verbose)
        scan_result = scanner.scan_contract(args.contract, categories)
        
        critical_high = scan_result.metrics.severity_breakdown.get("critical", 0) + \
                       scan_result.metrics.severity_breakdown.get("high", 0)
        
        if critical_high > 0:
            sys.exit(2)
        elif scan_result.metrics.total_vulnerabilities > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except FileNotFoundError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(3)
    except RuntimeError as e:
        print(f"{Fore.RED}Runtime Error: {e}{Style.RESET_ALL}")
        sys.exit(3)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()