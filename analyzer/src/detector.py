"""
=============================================================================
SecuriSphere - Anomaly Detection Engine
=============================================================================

Detects network traffic anomalies by comparing current behavior against
established baselines. Uses multiple detection methods:

1. Statistical (Z-score) - Detects unusual values based on standard deviations
2. Rate-based - Detects sudden spikes or drops in traffic rates
3. Behavioral - Detects new IPs, ports, or unusual patterns
4. Threshold - Detects values exceeding predefined limits

Anomaly Types:
- HIGH_CONNECTION_RATE: Unusual number of connections (potential scan/DoS)
- LONG_DURATION: Abnormally long-lived connections
- HIGH_BYTES: Unusual data transfer volumes
- NEW_SOURCE_IP: Previously unseen source IP
- BRUTE_FORCE: Multiple failed authentications
- ENDPOINT_SCAN: Probing multiple endpoints rapidly
- ERROR_SPIKE: Unusual increase in error responses

=============================================================================
"""

import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
import logging
import json

from .zeek_parser import ZeekLogParser
from .baseline import BaselineBuilder, ConnectionBaseline, HTTPBaseline

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Types of network anomalies that can be detected."""
    
    HIGH_CONNECTION_RATE = "high_connection_rate"
    LOW_CONNECTION_RATE = "low_connection_rate"
    LONG_DURATION = "long_duration"
    HIGH_BYTES_TRANSFER = "high_bytes_transfer"
    NEW_SOURCE_IP = "new_source_ip"
    NEW_DESTINATION = "new_destination"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    ENDPOINT_SCAN = "endpoint_scan"
    ERROR_SPIKE = "error_spike"
    UNUSUAL_METHOD = "unusual_method"
    HIGH_REQUEST_RATE = "high_request_rate"
    LARGE_RESPONSE = "large_response"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"


class Severity(str, Enum):
    """Severity levels for detected anomalies."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Anomaly:
    """Represents a detected network anomaly."""
    
    anomaly_type: AnomalyType
    severity: Severity
    timestamp: str
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    baseline_value: float = 0.0
    observed_value: float = 0.0
    z_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert anomaly to dictionary."""
        data = asdict(self)
        data['anomaly_type'] = self.anomaly_type.value
        data['severity'] = self.severity.value
        return data


class AnomalyDetector:
    """
    Detects anomalies in network traffic by comparing against baselines.
    
    Uses statistical methods (z-scores, percentiles) and heuristic rules
    to identify suspicious patterns that deviate from normal behavior.
    """
    
    # Detection thresholds
    Z_SCORE_THRESHOLD = 3.0           # Standard deviations for anomaly
    RATE_SPIKE_MULTIPLIER = 5.0       # Multiplier for rate spike detection
    SCAN_THRESHOLD = 10               # Min ports/endpoints to flag as scan
    BRUTE_FORCE_THRESHOLD = 5         # Min failed attempts from same IP
    ERROR_RATE_THRESHOLD = 0.3        # 30% error rate threshold
    
    # SQL injection patterns
    SQL_PATTERNS = [
        "'", '"', ";", "--", "/*", "*/",
        "or 1=1", "or '1'='1", "or 1 = 1",
        "union", "select", "drop", "insert",
        "delete", "update", "exec", "execute"
    ]
    
    def __init__(
        self, 
        baseline: Dict[str, Any],
        log_dir: str = "/logs"
    ):
        """
        Initialize the anomaly detector.
        
        Args:
            baseline: Baseline dictionary (from BaselineBuilder)
            log_dir: Directory containing Zeek log files
        """
        self.baseline = baseline
        self.log_dir = Path(log_dir)
        self.parser = ZeekLogParser(log_dir)
        
        # Extract baseline components
        self.conn_baseline = baseline.get('connection', {})
        self.http_baseline = baseline.get('http', {})
        
        # Known IPs from baseline
        self.known_src_ips = set()
        self.known_dst_ips = set()
        self.known_endpoints = set(self.http_baseline.get('top_endpoints', {}).keys())
        
        logger.info("Initialized AnomalyDetector")
    
    def _calculate_z_score(
        self, 
        value: float, 
        mean: float, 
        std: float
    ) -> float:
        """
        Calculate z-score for a value.
        
        Args:
            value: Observed value
            mean: Baseline mean
            std: Baseline standard deviation
            
        Returns:
            Z-score (number of standard deviations from mean)
        """
        if std == 0:
            return 0.0 if value == mean else float('inf')
        return (value - mean) / std
    
    def _determine_severity(self, z_score: float) -> Severity:
        """
        Determine severity based on z-score.
        
        Args:
            z_score: Calculated z-score
            
        Returns:
            Severity level
        """
        z = abs(z_score)
        if z >= 5:
            return Severity.CRITICAL
        elif z >= 4:
            return Severity.HIGH
        elif z >= 3:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def detect_connection_anomalies(
        self, 
        conn_df: Optional[pd.DataFrame] = None,
        window_minutes: int = 1
    ) -> List[Anomaly]:
        """
        Detect anomalies in connection data.
        
        Args:
            conn_df: Connection DataFrame (or None to parse from logs)
            window_minutes: Time window for rate calculation
            
        Returns:
            List of detected anomalies
        """
        if conn_df is None:
            conn_df = self.parser.parse_conn_log()
        
        if conn_df.empty:
            logger.warning("No connection data for anomaly detection")
            return []
        
        anomalies = []
        
        # Get baseline values
        rate_mean = self.conn_baseline.get('connections_per_minute_mean', 0)
        rate_std = self.conn_baseline.get('connections_per_minute_std', 1)
        duration_mean = self.conn_baseline.get('duration_mean', 0)
        duration_std = self.conn_baseline.get('duration_std', 1)
        duration_p99 = self.conn_baseline.get('duration_p99', float('inf'))
        bytes_mean = self.conn_baseline.get('bytes_mean', 0)
        bytes_std = self.conn_baseline.get('bytes_std', 1)
        bytes_p99 = self.conn_baseline.get('bytes_p99', float('inf'))
        
        # ------------------------------------------------------------------
        # 1. CONNECTION RATE ANOMALY
        # ------------------------------------------------------------------
        if 'ts' in conn_df.columns:
            conn_df_ts = conn_df.set_index('ts')
            current_rate = conn_df_ts.resample(f'{window_minutes}min').size()
            
            for ts, count in current_rate.items():
                z_score = self._calculate_z_score(count, rate_mean, rate_std)
                
                if z_score > self.Z_SCORE_THRESHOLD:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.HIGH_CONNECTION_RATE,
                        severity=self._determine_severity(z_score),
                        timestamp=str(ts),
                        description=f"Connection rate {count:.0f}/min exceeds baseline ({rate_mean:.1f}±{rate_std:.1f})",
                        baseline_value=rate_mean,
                        observed_value=count,
                        z_score=z_score,
                        details={
                            'window_minutes': window_minutes,
                            'threshold': rate_mean + (self.Z_SCORE_THRESHOLD * rate_std)
                        }
                    ))
        
        # ------------------------------------------------------------------
        # 2. LONG DURATION CONNECTIONS
        # ------------------------------------------------------------------
        if 'duration' in conn_df.columns:
            long_conns = conn_df[conn_df['duration'] > duration_p99]
            
            for _, row in long_conns.iterrows():
                z_score = self._calculate_z_score(row['duration'], duration_mean, duration_std)
                
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.LONG_DURATION,
                    severity=self._determine_severity(z_score),
                    timestamp=str(row.get('ts', '')),
                    source_ip=str(row.get('id.orig_h', '')),
                    destination_ip=str(row.get('id.resp_h', '')),
                    destination_port=int(row.get('id.resp_p', 0)),
                    description=f"Connection duration {row['duration']:.1f}s exceeds p99 ({duration_p99:.1f}s)",
                    baseline_value=duration_mean,
                    observed_value=row['duration'],
                    z_score=z_score
                ))
        
        # ------------------------------------------------------------------
        # 3. HIGH BYTES TRANSFER
        # ------------------------------------------------------------------
        orig_bytes = conn_df.get('orig_bytes', pd.Series([0])).fillna(0)
        resp_bytes = conn_df.get('resp_bytes', pd.Series([0])).fillna(0)
        total_bytes = orig_bytes + resp_bytes
        conn_df = conn_df.copy()
        conn_df['total_bytes'] = total_bytes
        
        high_bytes = conn_df[conn_df['total_bytes'] > bytes_p99]
        
        for _, row in high_bytes.iterrows():
            z_score = self._calculate_z_score(row['total_bytes'], bytes_mean, bytes_std)
            
            anomalies.append(Anomaly(
                anomaly_type=AnomalyType.HIGH_BYTES_TRANSFER,
                severity=self._determine_severity(z_score),
                timestamp=str(row.get('ts', '')),
                source_ip=str(row.get('id.orig_h', '')),
                destination_ip=str(row.get('id.resp_h', '')),
                destination_port=int(row.get('id.resp_p', 0)),
                description=f"Data transfer {row['total_bytes']:.0f} bytes exceeds p99 ({bytes_p99:.0f})",
                baseline_value=bytes_mean,
                observed_value=row['total_bytes'],
                z_score=z_score
            ))
        
        # ------------------------------------------------------------------
        # 4. PORT SCAN DETECTION
        # ------------------------------------------------------------------
        if 'id.orig_h' in conn_df.columns and 'id.resp_p' in conn_df.columns:
            # Group by source IP and count unique destination ports
            port_counts = conn_df.groupby('id.orig_h')['id.resp_p'].nunique()
            scanners = port_counts[port_counts >= self.SCAN_THRESHOLD]
            
            for src_ip, port_count in scanners.items():
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.PORT_SCAN,
                    severity=Severity.HIGH,
                    timestamp=str(conn_df[conn_df['id.orig_h'] == src_ip]['ts'].min()),
                    source_ip=str(src_ip),
                    description=f"Source IP {src_ip} connected to {port_count} unique ports (potential port scan)",
                    observed_value=port_count,
                    details={
                        'unique_ports': port_count,
                        'threshold': self.SCAN_THRESHOLD
                    }
                ))
        
        logger.info(f"Detected {len(anomalies)} connection anomalies")
        return anomalies
    
    def detect_http_anomalies(
        self, 
        http_df: Optional[pd.DataFrame] = None,
        window_minutes: int = 1
    ) -> List[Anomaly]:
        """
        Detect anomalies in HTTP traffic.
        
        Args:
            http_df: HTTP DataFrame (or None to parse from logs)
            window_minutes: Time window for rate calculation
            
        Returns:
            List of detected anomalies
        """
        if http_df is None:
            http_df = self.parser.parse_http_log()
        
        if http_df.empty:
            logger.warning("No HTTP data for anomaly detection")
            return []
        
        anomalies = []
        
        # Get baseline values
        rate_mean = self.http_baseline.get('requests_per_minute_mean', 0)
        rate_std = self.http_baseline.get('requests_per_minute_std', 1)
        baseline_error_rate = self.http_baseline.get('error_rate', 0)
        response_p95 = self.http_baseline.get('response_size_p95', float('inf'))
        
        # ------------------------------------------------------------------
        # 1. REQUEST RATE ANOMALY
        # ------------------------------------------------------------------
        if 'ts' in http_df.columns:
            http_df_ts = http_df.set_index('ts')
            current_rate = http_df_ts.resample(f'{window_minutes}min').size()
            
            for ts, count in current_rate.items():
                z_score = self._calculate_z_score(count, rate_mean, rate_std)
                
                if z_score > self.Z_SCORE_THRESHOLD:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.HIGH_REQUEST_RATE,
                        severity=self._determine_severity(z_score),
                        timestamp=str(ts),
                        description=f"HTTP request rate {count:.0f}/min exceeds baseline ({rate_mean:.1f})",
                        baseline_value=rate_mean,
                        observed_value=count,
                        z_score=z_score
                    ))
        
        # ------------------------------------------------------------------
        # 2. BRUTE FORCE DETECTION (Failed login attempts)
        # ------------------------------------------------------------------
        if 'uri' in http_df.columns and 'status_code' in http_df.columns:
            # Look for failed login attempts (401/403 on /login endpoint)
            login_df = http_df[http_df['uri'].str.contains('/login', na=False)]
            failed_logins = login_df[login_df['status_code'].isin([401, 403])]
            
            if not failed_logins.empty and 'id.orig_h' in failed_logins.columns:
                failed_counts = failed_logins.groupby('id.orig_h').size()
                brute_forcers = failed_counts[failed_counts >= self.BRUTE_FORCE_THRESHOLD]
                
                for src_ip, fail_count in brute_forcers.items():
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.BRUTE_FORCE,
                        severity=Severity.HIGH,
                        timestamp=str(failed_logins[failed_logins['id.orig_h'] == src_ip]['ts'].min()),
                        source_ip=str(src_ip),
                        description=f"Potential brute force: {fail_count} failed login attempts from {src_ip}",
                        observed_value=fail_count,
                        details={
                            'failed_attempts': fail_count,
                            'threshold': self.BRUTE_FORCE_THRESHOLD
                        }
                    ))
        
        # ------------------------------------------------------------------
        # 3. ENDPOINT SCAN DETECTION
        # ------------------------------------------------------------------
        if 'id.orig_h' in http_df.columns and 'uri' in http_df.columns:
            endpoint_counts = http_df.groupby('id.orig_h')['uri'].nunique()
            scanners = endpoint_counts[endpoint_counts >= self.SCAN_THRESHOLD]
            
            for src_ip, endpoint_count in scanners.items():
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.ENDPOINT_SCAN,
                    severity=Severity.MEDIUM,
                    timestamp=str(http_df[http_df['id.orig_h'] == src_ip]['ts'].min()),
                    source_ip=str(src_ip),
                    description=f"Source IP {src_ip} accessed {endpoint_count} unique endpoints (potential enumeration)",
                    observed_value=endpoint_count,
                    details={
                        'unique_endpoints': endpoint_count,
                        'threshold': self.SCAN_THRESHOLD
                    }
                ))
        
        # ------------------------------------------------------------------
        # 4. SQL INJECTION ATTEMPTS
        # ------------------------------------------------------------------
        if 'uri' in http_df.columns:
            for _, row in http_df.iterrows():
                uri = str(row.get('uri', '')).lower()
                
                for pattern in self.SQL_PATTERNS:
                    if pattern in uri:
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.SQL_INJECTION_ATTEMPT,
                            severity=Severity.CRITICAL,
                            timestamp=str(row.get('ts', '')),
                            source_ip=str(row.get('id.orig_h', '')),
                            destination_ip=str(row.get('id.resp_h', '')),
                            description=f"Potential SQL injection attempt detected in URI",
                            details={
                                'uri': row.get('uri', ''),
                                'pattern_matched': pattern,
                                'method': row.get('method', '')
                            }
                        ))
                        break  # Only report once per request
        
        # ------------------------------------------------------------------
        # 5. ERROR RATE SPIKE
        # ------------------------------------------------------------------
        if 'status_code' in http_df.columns and 'ts' in http_df.columns:
            http_df_ts = http_df.set_index('ts')
            
            # Calculate error rate per minute
            for ts, group in http_df_ts.resample(f'{window_minutes}min'):
                if len(group) > 0:
                    error_mask = (group['status_code'] >= 400) & (group['status_code'] < 600)
                    current_error_rate = error_mask.sum() / len(group)
                    
                    if current_error_rate > self.ERROR_RATE_THRESHOLD and current_error_rate > baseline_error_rate * 2:
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.ERROR_SPIKE,
                            severity=Severity.MEDIUM,
                            timestamp=str(ts),
                            description=f"HTTP error rate {current_error_rate:.1%} exceeds baseline ({baseline_error_rate:.1%})",
                            baseline_value=baseline_error_rate,
                            observed_value=current_error_rate,
                            details={
                                'total_requests': len(group),
                                'error_requests': error_mask.sum()
                            }
                        ))
        
        logger.info(f"Detected {len(anomalies)} HTTP anomalies")
        return anomalies
    
    def detect_all_anomalies(self) -> List[Anomaly]:
        """
        Run all anomaly detection methods.
        
        Returns:
            Consolidated list of all detected anomalies
        """
        logger.info("Running comprehensive anomaly detection...")
        
        all_anomalies = []
        
        # Connection anomalies
        all_anomalies.extend(self.detect_connection_anomalies())
        
        # HTTP anomalies
        all_anomalies.extend(self.detect_http_anomalies())
        
        # Sort by timestamp
        all_anomalies.sort(key=lambda x: x.timestamp, reverse=True)
        
        logger.info(f"Total anomalies detected: {len(all_anomalies)}")
        return all_anomalies
    
    def generate_report(
        self, 
        anomalies: List[Anomaly],
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate an anomaly report.
        
        Args:
            anomalies: List of detected anomalies
            output_path: Optional path to save JSON report
            
        Returns:
            Report dictionary
        """
        # Group anomalies by type and severity
        by_type = {}
        by_severity = {s.value: 0 for s in Severity}
        
        for a in anomalies:
            type_key = a.anomaly_type.value
            by_type[type_key] = by_type.get(type_key, 0) + 1
            by_severity[a.severity.value] += 1
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_anomalies': len(anomalies),
            'by_severity': by_severity,
            'by_type': by_type,
            'anomalies': [a.to_dict() for a in anomalies]
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Report saved to {output_path}")
        
        return report


if __name__ == "__main__":
    # Example usage
    
    # First, build a baseline
    builder = BaselineBuilder("/logs")
    baseline = builder.build_full_baseline()
    
    # Then detect anomalies
    detector = AnomalyDetector(baseline, "/logs")
    anomalies = detector.detect_all_anomalies()
    
    # Generate report
    report = detector.generate_report(anomalies, "anomaly_report.json")
    
    print(f"\nDetected {report['total_anomalies']} anomalies")
    print(f"By severity: {report['by_severity']}")
    print(f"By type: {report['by_type']}")
