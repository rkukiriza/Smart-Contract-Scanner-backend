"""
Etherscan Contract Fetcher
Fetches verified Solidity contract source code from Etherscan
"""

import os
import requests
import time
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class ContractInfo:
    """Contract information from Etherscan"""
    address: str
    name: str
    compiler_version: str
    optimization_used: bool
    runs: int
    source_code: str
    abi: str
    constructor_arguments: str
    license_type: str
    proxy: bool = False
    implementation_address: Optional[str] = None


class EtherscanFetcher:
    """Fetches contract source code from Etherscan API"""
    
    BASE_URLS = {
        "mainnet": "https://api.etherscan.io/v2/api?chainid=1",
        "goerli": "https://api-goerli.etherscan.io/v2/api?chainid=5",
        "sepolia": "https://api-sepolia.etherscan.io/v2/api?chainid=11155111",
        "bsc": "https://api.bscscan.com/v2/api?chainid=56",
        "polygon": "https://api.polygonscan.com/v2/api?chainid=137",
        "arbitrum": "https://api.arbiscan.io/v2/api?chainid=42161",
        "optimism": "https://api-optimistic.etherscan.io/v2/api?chainid=10",
    }
    
    def __init__(self, api_key: Optional[str] = None, network: str = "mainnet"):
        """
        Initialize Etherscan fetcher
        
        Args:
            api_key: Etherscan API key (reads from .env if not provided)
            network: Network name (mainnet, goerli, sepolia, bsc, polygon, etc.)
        """
        self.api_key = api_key or os.getenv('ETHERSCAN_API_KEY')
        
        if not self.api_key:
            raise ValueError(
                "Etherscan API key not found. "
                "Set ETHERSCAN_API_KEY in .env file or pass as parameter"
            )
        
        self.network = network.lower()
        self.base_url = self.BASE_URLS.get(self.network)
        
        if not self.base_url:
            raise ValueError(
                f"Unsupported network: {network}. "
                f"Supported networks: {', '.join(self.BASE_URLS.keys())}"
            )
        
        self.session = requests.Session()
        self.rate_limit_delay = 0.2  # 5 requests per second max
    
    def _make_request(self, params: Dict) -> Dict:
        """
        Make API request with rate limiting and error handling
        
        Args:
            params: Request parameters
            
        Returns:
            API response as dictionary
        """
        params['apikey'] = self.api_key
        
        try:
            time.sleep(self.rate_limit_delay)
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') == '0':
                error_msg = data.get('result', 'Unknown error')
                if 'rate limit' in error_msg.lower():
                    raise Exception(f"Rate limit exceeded: {error_msg}")
                elif 'invalid api key' in error_msg.lower():
                    raise Exception(f"Invalid API key: {error_msg}")
                else:
                    raise Exception(f"API Error: {error_msg}")
            
            return data
            
        except requests.exceptions.Timeout:
            raise Exception("Request timeout - Etherscan API not responding")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {e}")
    
    def is_contract_verified(self, address: str) -> bool:
        """
        Check if contract is verified on Etherscan
        
        Args:
            address: Contract address
            
        Returns:
            True if verified, False otherwise
        """
        params = {
            'module': 'contract',
            'action': 'getabi',
            'address': address
        }
        
        try:
            data = self._make_request(params)
            return data.get('status') == '1'
        except:
            return False
    
    def get_contract_source(self, address: str) -> ContractInfo:
        """
        Fetch contract source code and metadata
        
        Args:
            address: Contract address (0x...)
            
        Returns:
            ContractInfo object with source code and metadata
        """
        # Validate address format
        if not address.startswith('0x') or len(address) != 42:
            raise ValueError(f"Invalid Ethereum address: {address}")
        
        # Check if contract is verified
        if not self.is_contract_verified(address):
            raise Exception(
                f"Contract {address} is not verified on {self.network}. "
                "Only verified contracts can be scanned."
            )
        
        # Fetch contract source
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }
        
        data = self._make_request(params)
        result = data.get('result', [{}])[0]
        
        if not result or result.get('SourceCode') == '':
            raise Exception(f"No source code found for {address}")
        
        # Parse source code (handle multi-file contracts)
        source_code = result.get('SourceCode', '')
        contract_name = result.get('ContractName', 'Unknown')
        
        # Check if it's a multi-file contract (wrapped in {{ }})
        if source_code.startswith('{{'):
            source_code = self._parse_multifile_source(source_code)
        elif source_code.startswith('{'):
            # Standard JSON input format
            try:
                source_json = json.loads(source_code)
                if 'sources' in source_json:
                    source_code = self._extract_main_contract(source_json, contract_name)
            except json.JSONDecodeError:
                pass  # Use as-is if not valid JSON
        
        # Check if contract is a proxy
        is_proxy = result.get('Proxy', '0') == '1'
        implementation = result.get('Implementation', None)
        
        contract_info = ContractInfo(
            address=address,
            name=contract_name,
            compiler_version=result.get('CompilerVersion', ''),
            optimization_used=result.get('OptimizationUsed', '0') == '1',
            runs=int(result.get('Runs', 0)),
            source_code=source_code,
            abi=result.get('ABI', ''),
            constructor_arguments=result.get('ConstructorArguments', ''),
            license_type=result.get('LicenseType', 'None'),
            proxy=is_proxy,
            implementation_address=implementation
        )
        
        return contract_info
    
    def _parse_multifile_source(self, source_code: str) -> str:
        """
        Parse multi-file contract source (Etherscan format)
        
        Args:
            source_code: Raw source code from Etherscan
            
        Returns:
            Concatenated source code
        """
        try:
            # Remove outer braces
            source_code = source_code[1:-1]
            source_json = json.loads(source_code)
            
            # Extract all .sol files
            sources = source_json.get('sources', {})
            combined = []
            
            for filepath, content in sources.items():
                if filepath.endswith('.sol'):
                    file_content = content.get('content', '')
                    combined.append(f"// File: {filepath}\n{file_content}\n")
            
            return '\n'.join(combined)
            
        except (json.JSONDecodeError, KeyError):
            # Return as-is if parsing fails
            return source_code
    
    def _extract_main_contract(self, source_json: Dict, contract_name: str) -> str:
        """
        Extract main contract from standard JSON input
        
        Args:
            source_json: Parsed JSON source
            contract_name: Name of the contract
            
        Returns:
            Main contract source code
        """
        sources = source_json.get('sources', {})
        
        # Try to find the main contract file
        for filepath, content in sources.items():
            if contract_name in filepath or filepath.endswith(f"{contract_name}.sol"):
                return content.get('content', '')
        
        # If not found, return the first contract
        if sources:
            first_file = list(sources.values())[0]
            return first_file.get('content', '')
        
        return str(source_json)
    
    def save_contract(self, contract_info: ContractInfo, output_dir: str = "contracts") -> Path:
        """
        Save contract source code to a file
        
        Args:
            contract_info: ContractInfo object
            output_dir: Directory to save contracts
            
        Returns:
            Path to saved contract file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Clean contract name for filename
        safe_name = "".join(c for c in contract_info.name if c.isalnum() or c in ('_', '-'))
        filename = f"{safe_name}_{contract_info.address[:8]}.sol"
        filepath = output_path / filename
        
        # Write source code
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"// Contract: {contract_info.name}\n")
            f.write(f"// Address: {contract_info.address}\n")
            f.write(f"// Network: {self.network}\n")
            f.write(f"// Compiler: {contract_info.compiler_version}\n")
            f.write(f"// Optimization: {contract_info.optimization_used} (Runs: {contract_info.runs})\n")
            f.write(f"// License: {contract_info.license_type}\n")
            if contract_info.proxy:
                f.write(f"// Proxy: Yes (Implementation: {contract_info.implementation_address})\n")
            f.write("\n")
            f.write(contract_info.source_code)
        
        # Save metadata
        metadata_file = output_path / f"{safe_name}_{contract_info.address[:8]}_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            metadata = {
                "address": contract_info.address,
                "name": contract_info.name,
                "network": self.network,
                "compiler_version": contract_info.compiler_version,
                "optimization_used": contract_info.optimization_used,
                "runs": contract_info.runs,
                "license_type": contract_info.license_type,
                "proxy": contract_info.proxy,
                "implementation_address": contract_info.implementation_address,
                "abi": json.loads(contract_info.abi) if contract_info.abi else []
            }
            json.dump(metadata, f, indent=2)
        
        return filepath
    
    def fetch_and_save(self, address: str, output_dir: str = "contracts") -> Path:
        """
        Convenience method to fetch and save contract in one step
        
        Args:
            address: Contract address
            output_dir: Output directory
            
        Returns:
            Path to saved contract file
        """
        print(f"🔍 Fetching contract {address} from {self.network}...")
        contract_info = self.get_contract_source(address)
        print(f"✅ Found: {contract_info.name}")
        
        if contract_info.proxy:
            print(f"⚠️  This is a proxy contract pointing to {contract_info.implementation_address}")
            print(f"   Consider scanning the implementation contract instead")
        
        filepath = self.save_contract(contract_info, output_dir)
        print(f"💾 Saved to: {filepath}")
        
        return filepath


def main():
    """CLI interface for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Fetch verified contract source from Etherscan"
    )
    parser.add_argument("address", help="Contract address (0x...)")
    parser.add_argument(
        "--network", "-n",
        default="mainnet",
        choices=list(EtherscanFetcher.BASE_URLS.keys()),
        help="Network name"
    )
    parser.add_argument(
        "--output", "-o",
        default="contracts",
        help="Output directory"
    )
    parser.add_argument(
        "--api-key", "-k",
        help="Etherscan API key (overrides .env)"
    )
    
    args = parser.parse_args()
    
    try:
        fetcher = EtherscanFetcher(api_key=args.api_key, network=args.network)
        filepath = fetcher.fetch_and_save(args.address, args.output)
        print(f"\n✅ Success! Contract saved to: {filepath}")
        print(f"\nTo scan this contract, run:")
        print(f"   python scanner.py {filepath}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())