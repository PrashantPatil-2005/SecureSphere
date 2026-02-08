"""
=============================================================================
SecuriSphere - Zeek Log Parser
=============================================================================

Parses Zeek log files (conn.log, http.log, dns.log, etc.) into structured
pandas DataFrames for analysis.

Supports both JSON and TSV formats from Zeek.
=============================================================================
"""

import json
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ZeekLogParser:
    """
    Parser for Zeek network monitor log files.
    
    Supports:
    - JSON format logs (modern Zeek default with json-logs policy)
    - TSV format logs (traditional Zeek format)
    
    Key log types:
    - conn.log: Connection records (flows)
    - http.log: HTTP requests/responses
    - dns.log: DNS queries
    - ssl.log: SSL/TLS connections
    - notice.log: Zeek notices/alerts
    """
    
    # Column definitions for TSV parsing (Zeek's traditional format)
    CONN_COLUMNS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
        'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'
    ]
    
    HTTP_COLUMNS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'trans_depth', 'method', 'host', 'uri', 'referrer', 'version',
        'user_agent', 'origin', 'request_body_len', 'response_body_len',
        'status_code', 'status_msg', 'info_code', 'info_msg', 'tags',
        'username', 'password', 'proxied', 'orig_fuids', 'orig_filenames',
        'orig_mime_types', 'resp_fuids', 'resp_filenames', 'resp_mime_types'
    ]
    
    DNS_COLUMNS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
        'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
        'RA', 'Z', 'answers', 'TTLs', 'rejected'
    ]
    
    def __init__(self, log_dir: str = "/logs"):
        """
        Initialize the parser.
        
        Args:
            log_dir: Directory containing Zeek log files
        """
        self.log_dir = Path(log_dir)
        logger.info(f"Initialized ZeekLogParser with log_dir: {self.log_dir}")
    
    def _detect_format(self, file_path: Path) -> str:
        """
        Detect if a log file is JSON or TSV format.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            'json' or 'tsv'
        """
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                
                # Skip comment lines in TSV format
                while first_line.startswith('#'):
                    first_line = f.readline().strip()
                
                if not first_line:
                    return 'tsv'  # Default to TSV for empty files
                
                # Try to parse as JSON
                try:
                    json.loads(first_line)
                    return 'json'
                except json.JSONDecodeError:
                    return 'tsv'
        except Exception as e:
            logger.warning(f"Error detecting format for {file_path}: {e}")
            return 'tsv'
    
    def _parse_json_log(self, file_path: Path) -> pd.DataFrame:
        """
        Parse a JSON-format Zeek log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            DataFrame with parsed log entries
        """
        records = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            record = json.loads(line)
                            records.append(record)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Error parsing JSON log {file_path}: {e}")
            return pd.DataFrame()
        
        if not records:
            return pd.DataFrame()
        
        df = pd.DataFrame(records)
        
        # Convert timestamp to datetime
        if 'ts' in df.columns:
            df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
        
        return df
    
    def _parse_tsv_log(self, file_path: Path, columns: List[str]) -> pd.DataFrame:
        """
        Parse a TSV-format Zeek log file.
        
        Args:
            file_path: Path to the log file
            columns: Expected column names
            
        Returns:
            DataFrame with parsed log entries
        """
        try:
            # Read the file, skipping comment lines
            df = pd.read_csv(
                file_path,
                sep='\t',
                comment='#',
                names=columns,
                na_values=['-', '(empty)'],
                low_memory=False
            )
            
            # Convert timestamp to datetime
            if 'ts' in df.columns:
                df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
            
            return df
        except Exception as e:
            logger.error(f"Error parsing TSV log {file_path}: {e}")
            return pd.DataFrame()
    
    def parse_conn_log(self, filename: str = "conn.log") -> pd.DataFrame:
        """
        Parse Zeek connection log (conn.log).
        
        Returns:
            DataFrame with connection records including:
            - Source/destination IP and port
            - Protocol and service
            - Duration and bytes transferred
            - Connection state
        """
        file_path = self.log_dir / filename
        
        if not file_path.exists():
            logger.warning(f"Connection log not found: {file_path}")
            return pd.DataFrame()
        
        log_format = self._detect_format(file_path)
        logger.info(f"Parsing {filename} ({log_format} format)")
        
        if log_format == 'json':
            df = self._parse_json_log(file_path)
        else:
            df = self._parse_tsv_log(file_path, self.CONN_COLUMNS)
        
        # Ensure numeric columns are properly typed
        numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 
                       'orig_pkts', 'resp_pkts', 'missed_bytes']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        logger.info(f"Parsed {len(df)} connection records")
        return df
    
    def parse_http_log(self, filename: str = "http.log") -> pd.DataFrame:
        """
        Parse Zeek HTTP log (http.log).
        
        Returns:
            DataFrame with HTTP request/response records including:
            - Request method, URI, host
            - User agent, status code
            - Request/response body lengths
        """
        file_path = self.log_dir / filename
        
        if not file_path.exists():
            logger.warning(f"HTTP log not found: {file_path}")
            return pd.DataFrame()
        
        log_format = self._detect_format(file_path)
        logger.info(f"Parsing {filename} ({log_format} format)")
        
        if log_format == 'json':
            df = self._parse_json_log(file_path)
        else:
            df = self._parse_tsv_log(file_path, self.HTTP_COLUMNS)
        
        # Ensure numeric columns are properly typed
        numeric_cols = ['status_code', 'request_body_len', 'response_body_len']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        logger.info(f"Parsed {len(df)} HTTP records")
        return df
    
    def parse_dns_log(self, filename: str = "dns.log") -> pd.DataFrame:
        """
        Parse Zeek DNS log (dns.log).
        
        Returns:
            DataFrame with DNS query records
        """
        file_path = self.log_dir / filename
        
        if not file_path.exists():
            logger.warning(f"DNS log not found: {file_path}")
            return pd.DataFrame()
        
        log_format = self._detect_format(file_path)
        logger.info(f"Parsing {filename} ({log_format} format)")
        
        if log_format == 'json':
            df = self._parse_json_log(file_path)
        else:
            df = self._parse_tsv_log(file_path, self.DNS_COLUMNS)
        
        logger.info(f"Parsed {len(df)} DNS records")
        return df
    
    def parse_all_logs(self) -> Dict[str, pd.DataFrame]:
        """
        Parse all available Zeek log files.
        
        Returns:
            Dictionary mapping log type to DataFrame
        """
        logs = {}
        
        # Parse each log type
        logs['conn'] = self.parse_conn_log()
        logs['http'] = self.parse_http_log()
        logs['dns'] = self.parse_dns_log()
        
        return logs
    
    def get_available_logs(self) -> List[str]:
        """
        List available log files in the log directory.
        
        Returns:
            List of log file names
        """
        if not self.log_dir.exists():
            return []
        
        return [f.name for f in self.log_dir.glob("*.log")]


# =============================================================================
# Convenience Functions
# =============================================================================

def parse_zeek_logs(log_dir: str = "/logs") -> Dict[str, pd.DataFrame]:
    """
    Convenience function to parse all Zeek logs in a directory.
    
    Args:
        log_dir: Directory containing Zeek log files
        
    Returns:
        Dictionary mapping log type to DataFrame
    """
    parser = ZeekLogParser(log_dir)
    return parser.parse_all_logs()


if __name__ == "__main__":
    # Example usage
    parser = ZeekLogParser("/logs")
    
    print("Available logs:", parser.get_available_logs())
    
    logs = parser.parse_all_logs()
    
    for log_type, df in logs.items():
        print(f"\n{log_type.upper()} Log: {len(df)} records")
        if not df.empty:
            print(df.head())
