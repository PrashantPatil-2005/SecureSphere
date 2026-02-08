"""
=============================================================================
SecuriSphere - Network Baseline Builder
=============================================================================

Builds statistical baselines from historical Zeek logs to enable
anomaly detection. Baselines capture normal behavior patterns for:

- Connection statistics (rate, duration, bytes)
- HTTP request patterns (endpoints, methods, status codes)
- Source/destination IP behavior
- Time-based patterns (hourly, daily)

=============================================================================
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
import logging

from .zeek_parser import ZeekLogParser

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ConnectionBaseline:
    """Baseline statistics for network connections."""
    
    # Connection rate statistics
    connections_per_minute_mean: float = 0.0
    connections_per_minute_std: float = 0.0
    connections_per_minute_max: float = 0.0
    
    # Duration statistics (in seconds)
    duration_mean: float = 0.0
    duration_std: float = 0.0
    duration_p95: float = 0.0
    duration_p99: float = 0.0
    
    # Bytes transferred statistics
    bytes_mean: float = 0.0
    bytes_std: float = 0.0
    bytes_p95: float = 0.0
    bytes_p99: float = 0.0
    
    # Unique source/destination counts
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    
    # Protocol distribution
    protocol_distribution: Dict[str, float] = None
    
    # Time window used for baseline
    baseline_start: str = ""
    baseline_end: str = ""
    total_connections: int = 0
    
    def __post_init__(self):
        if self.protocol_distribution is None:
            self.protocol_distribution = {}


@dataclass
class HTTPBaseline:
    """Baseline statistics for HTTP traffic."""
    
    # Request rate statistics
    requests_per_minute_mean: float = 0.0
    requests_per_minute_std: float = 0.0
    requests_per_minute_max: float = 0.0
    
    # Response size statistics
    response_size_mean: float = 0.0
    response_size_std: float = 0.0
    response_size_p95: float = 0.0
    
    # Status code distribution
    status_code_distribution: Dict[str, float] = None
    
    # Method distribution
    method_distribution: Dict[str, float] = None
    
    # Top endpoints (paths)
    top_endpoints: Dict[str, int] = None
    
    # Error rate (4xx, 5xx responses)
    error_rate: float = 0.0
    
    # Unique user agents
    unique_user_agents: int = 0
    
    # Time window
    baseline_start: str = ""
    baseline_end: str = ""
    total_requests: int = 0
    
    def __post_init__(self):
        if self.status_code_distribution is None:
            self.status_code_distribution = {}
        if self.method_distribution is None:
            self.method_distribution = {}
        if self.top_endpoints is None:
            self.top_endpoints = {}


class BaselineBuilder:
    """
    Builds network traffic baselines from Zeek logs.
    
    The baseline represents "normal" behavior and is used as a reference
    point for anomaly detection. It calculates statistical measures
    (mean, std, percentiles) for various traffic metrics.
    """
    
    def __init__(self, log_dir: str = "/logs"):
        """
        Initialize the baseline builder.
        
        Args:
            log_dir: Directory containing Zeek log files
        """
        self.log_dir = Path(log_dir)
        self.parser = ZeekLogParser(log_dir)
        logger.info(f"Initialized BaselineBuilder with log_dir: {log_dir}")
    
    def _calculate_rate_stats(
        self, 
        df: pd.DataFrame, 
        ts_column: str = 'ts',
        window: str = '1min'
    ) -> Tuple[float, float, float]:
        """
        Calculate per-minute rate statistics.
        
        Returns:
            Tuple of (mean, std, max) rate
        """
        if df.empty or ts_column not in df.columns:
            return 0.0, 0.0, 0.0
        
        # Resample to 1-minute windows and count
        df_with_ts = df.set_index(ts_column)
        rate_series = df_with_ts.resample(window).size()
        
        if len(rate_series) == 0:
            return 0.0, 0.0, 0.0
        
        return (
            float(rate_series.mean()),
            float(rate_series.std()) if len(rate_series) > 1 else 0.0,
            float(rate_series.max())
        )
    
    def build_connection_baseline(
        self, 
        conn_df: Optional[pd.DataFrame] = None
    ) -> ConnectionBaseline:
        """
        Build baseline statistics for network connections.
        
        Args:
            conn_df: Optional pre-parsed connection DataFrame.
                    If None, will parse conn.log from log_dir.
        
        Returns:
            ConnectionBaseline object with statistical measures
        """
        if conn_df is None:
            conn_df = self.parser.parse_conn_log()
        
        if conn_df.empty:
            logger.warning("No connection data available for baseline")
            return ConnectionBaseline()
        
        baseline = ConnectionBaseline()
        
        # Calculate connection rate
        rate_mean, rate_std, rate_max = self._calculate_rate_stats(conn_df)
        baseline.connections_per_minute_mean = rate_mean
        baseline.connections_per_minute_std = rate_std
        baseline.connections_per_minute_max = rate_max
        
        # Duration statistics
        if 'duration' in conn_df.columns:
            duration = conn_df['duration'].dropna()
            if len(duration) > 0:
                baseline.duration_mean = float(duration.mean())
                baseline.duration_std = float(duration.std()) if len(duration) > 1 else 0.0
                baseline.duration_p95 = float(duration.quantile(0.95))
                baseline.duration_p99 = float(duration.quantile(0.99))
        
        # Bytes statistics (combine orig + resp bytes)
        orig_bytes = conn_df.get('orig_bytes', pd.Series([0]))
        resp_bytes = conn_df.get('resp_bytes', pd.Series([0]))
        total_bytes = orig_bytes.fillna(0) + resp_bytes.fillna(0)
        
        if len(total_bytes) > 0:
            baseline.bytes_mean = float(total_bytes.mean())
            baseline.bytes_std = float(total_bytes.std()) if len(total_bytes) > 1 else 0.0
            baseline.bytes_p95 = float(total_bytes.quantile(0.95))
            baseline.bytes_p99 = float(total_bytes.quantile(0.99))
        
        # Unique counts
        if 'id.orig_h' in conn_df.columns:
            baseline.unique_src_ips = conn_df['id.orig_h'].nunique()
        if 'id.resp_h' in conn_df.columns:
            baseline.unique_dst_ips = conn_df['id.resp_h'].nunique()
        if 'id.resp_p' in conn_df.columns:
            baseline.unique_dst_ports = conn_df['id.resp_p'].nunique()
        
        # Protocol distribution
        if 'proto' in conn_df.columns:
            proto_counts = conn_df['proto'].value_counts(normalize=True)
            baseline.protocol_distribution = proto_counts.to_dict()
        
        # Time window
        if 'ts' in conn_df.columns:
            baseline.baseline_start = str(conn_df['ts'].min())
            baseline.baseline_end = str(conn_df['ts'].max())
        
        baseline.total_connections = len(conn_df)
        
        logger.info(f"Built connection baseline from {baseline.total_connections} records")
        return baseline
    
    def build_http_baseline(
        self, 
        http_df: Optional[pd.DataFrame] = None
    ) -> HTTPBaseline:
        """
        Build baseline statistics for HTTP traffic.
        
        Args:
            http_df: Optional pre-parsed HTTP DataFrame.
                    If None, will parse http.log from log_dir.
        
        Returns:
            HTTPBaseline object with statistical measures
        """
        if http_df is None:
            http_df = self.parser.parse_http_log()
        
        if http_df.empty:
            logger.warning("No HTTP data available for baseline")
            return HTTPBaseline()
        
        baseline = HTTPBaseline()
        
        # Calculate request rate
        rate_mean, rate_std, rate_max = self._calculate_rate_stats(http_df)
        baseline.requests_per_minute_mean = rate_mean
        baseline.requests_per_minute_std = rate_std
        baseline.requests_per_minute_max = rate_max
        
        # Response size statistics
        if 'response_body_len' in http_df.columns:
            resp_size = http_df['response_body_len'].dropna()
            if len(resp_size) > 0:
                baseline.response_size_mean = float(resp_size.mean())
                baseline.response_size_std = float(resp_size.std()) if len(resp_size) > 1 else 0.0
                baseline.response_size_p95 = float(resp_size.quantile(0.95))
        
        # Status code distribution
        if 'status_code' in http_df.columns:
            status_counts = http_df['status_code'].value_counts(normalize=True)
            baseline.status_code_distribution = {
                str(k): float(v) for k, v in status_counts.items()
            }
            
            # Calculate error rate (4xx and 5xx)
            error_codes = http_df['status_code'].dropna()
            error_mask = (error_codes >= 400) & (error_codes < 600)
            baseline.error_rate = float(error_mask.sum() / len(error_codes)) if len(error_codes) > 0 else 0.0
        
        # Method distribution
        if 'method' in http_df.columns:
            method_counts = http_df['method'].value_counts(normalize=True)
            baseline.method_distribution = method_counts.to_dict()
        
        # Top endpoints
        if 'uri' in http_df.columns:
            endpoint_counts = http_df['uri'].value_counts().head(20)
            baseline.top_endpoints = endpoint_counts.to_dict()
        
        # Unique user agents
        if 'user_agent' in http_df.columns:
            baseline.unique_user_agents = http_df['user_agent'].nunique()
        
        # Time window
        if 'ts' in http_df.columns:
            baseline.baseline_start = str(http_df['ts'].min())
            baseline.baseline_end = str(http_df['ts'].max())
        
        baseline.total_requests = len(http_df)
        
        logger.info(f"Built HTTP baseline from {baseline.total_requests} records")
        return baseline
    
    def build_full_baseline(self) -> Dict[str, Any]:
        """
        Build complete baseline from all available Zeek logs.
        
        Returns:
            Dictionary containing all baseline components
        """
        logger.info("Building full network baseline...")
        
        baseline = {
            'connection': asdict(self.build_connection_baseline()),
            'http': asdict(self.build_http_baseline()),
            'generated_at': datetime.now().isoformat(),
            'log_directory': str(self.log_dir)
        }
        
        return baseline
    
    def save_baseline(
        self, 
        baseline: Dict[str, Any], 
        output_path: str = "baseline.json"
    ) -> None:
        """
        Save baseline to a JSON file.
        
        Args:
            baseline: Baseline dictionary to save
            output_path: Path to output file
        """
        output = Path(output_path)
        
        with open(output, 'w') as f:
            json.dump(baseline, f, indent=2, default=str)
        
        logger.info(f"Saved baseline to {output}")
    
    def load_baseline(self, input_path: str = "baseline.json") -> Dict[str, Any]:
        """
        Load baseline from a JSON file.
        
        Args:
            input_path: Path to baseline file
            
        Returns:
            Baseline dictionary
        """
        with open(input_path, 'r') as f:
            baseline = json.load(f)
        
        logger.info(f"Loaded baseline from {input_path}")
        return baseline


if __name__ == "__main__":
    # Example usage
    builder = BaselineBuilder("/logs")
    
    # Build complete baseline
    baseline = builder.build_full_baseline()
    
    # Save to file
    builder.save_baseline(baseline)
    
    # Print summary
    print("\nBaseline Summary:")
    print(f"  Connections: {baseline['connection']['total_connections']}")
    print(f"  HTTP Requests: {baseline['http']['total_requests']}")
    print(f"  Generated: {baseline['generated_at']}")
