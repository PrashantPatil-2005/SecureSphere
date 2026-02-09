#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Network Anomaly Detector
# =============================================================================
"""
Network Traffic Anomaly Detection Module

Parses Zeek conn.log files and detects anomalies using:
- IsolationForest (trained on "normal" baseline data)
- Z-score fallback on total_bytes when model unavailable

Features:
- Zeek conn.log parsing (TSV format, skip # comment lines)
- Feature extraction: duration, orig_bytes, resp_bytes, proto, conn_state
- Baseline collection and saving (pickle/JSON)
- Anomaly detection with JSON alert output
- CLI interface with --log-path and --mode arguments

Usage:
    # Collect baseline from normal traffic
    python anomaly_detector.py --log-path /logs/conn.log --mode collect
    
    # Detect anomalies using trained model
    python anomaly_detector.py --log-path /logs/conn.log --mode detect
"""

import argparse
import json
import pickle
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Zeek conn.log standard column names
CONN_LOG_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"
]

# Features used for anomaly detection
DETECTION_FEATURES = ["duration", "orig_bytes", "resp_bytes", "proto_encoded", "conn_state_encoded"]

# Protocol and connection state mappings for encoding
PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2}
CONN_STATE_MAP = {
    "S0": 0, "S1": 1, "SF": 2, "REJ": 3, "S2": 4, "S3": 5,
    "RSTO": 6, "RSTR": 7, "RSTOS0": 8, "RSTRH": 9, "SH": 10,
    "SHR": 11, "OTH": 12
}

# Default baseline save path
DEFAULT_BASELINE_PATH = "network_baseline.pkl"
DEFAULT_BASELINE_JSON_PATH = "network_baseline.json"

# Z-score threshold for fallback detection
ZSCORE_THRESHOLD = 3.0

# Anomaly severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 4.0,  # z-score >= 4.0
    "high": 3.0,      # z-score >= 3.0
    "medium": 2.0,    # z-score >= 2.0
}


# =============================================================================
# Zeek Log Parser
# =============================================================================

class ZeekConnLogParser:
    """
    Parser for Zeek conn.log files.
    
    Handles TSV format with # comment lines (headers and metadata).
    """
    
    def __init__(self, log_path: str):
        """
        Initialize the parser.
        
        Args:
            log_path: Path to the Zeek conn.log file
        """
        self.log_path = Path(log_path)
        
    def parse(self) -> pd.DataFrame:
        """
        Parse the Zeek conn.log file.
        
        Returns:
            DataFrame with connection records
            
        Raises:
            FileNotFoundError: If log file doesn't exist
            ValueError: If parsing fails
        """
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")
            
        logger.info(f"Parsing Zeek conn.log: {self.log_path}")
        
        try:
            # Read file, skip lines starting with #
            df = pd.read_csv(
                self.log_path,
                sep="\t",
                comment="#",
                names=CONN_LOG_COLUMNS,
                na_values=["-", "(empty)"],
                low_memory=False
            )
            
            # Handle case where file has Zeek TSV header format
            # First line after #fields might contain actual column names
            if not df.empty and df.iloc[0]["ts"] == "ts":
                df = df.iloc[1:].reset_index(drop=True)
            
            logger.info(f"Parsed {len(df)} connection records")
            return df
            
        except Exception as e:
            logger.error(f"Failed to parse conn.log: {e}")
            raise ValueError(f"Failed to parse conn.log: {e}")


# =============================================================================
# Feature Extractor
# =============================================================================

class FeatureExtractor:
    """
    Extracts and preprocesses features from connection data for anomaly detection.
    """
    
    def __init__(self):
        """Initialize encoders for categorical features."""
        self.proto_encoder = LabelEncoder()
        self.state_encoder = LabelEncoder()
        self._proto_fitted = False
        self._state_fitted = False
        
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from connection DataFrame.
        
        Features:
        - duration: Connection duration (seconds)
        - orig_bytes: Bytes from originator
        - resp_bytes: Bytes from responder
        - proto_encoded: Protocol (tcp/udp/icmp) encoded as integer
        - conn_state_encoded: Connection state encoded as integer
        - total_bytes: orig_bytes + resp_bytes (for z-score fallback)
        
        Args:
            df: Raw connection DataFrame from parser
            
        Returns:
            DataFrame with extracted features
        """
        features = pd.DataFrame()
        
        # Numeric features - fill NaN with 0
        features["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
        features["orig_bytes"] = pd.to_numeric(df["orig_bytes"], errors="coerce").fillna(0)
        features["resp_bytes"] = pd.to_numeric(df["resp_bytes"], errors="coerce").fillna(0)
        features["total_bytes"] = features["orig_bytes"] + features["resp_bytes"]
        
        # Encode protocol
        proto = df["proto"].fillna("unknown").str.lower()
        features["proto_encoded"] = proto.map(lambda x: PROTO_MAP.get(x, 3))
        
        # Encode connection state
        conn_state = df["conn_state"].fillna("OTH")
        features["conn_state_encoded"] = conn_state.map(lambda x: CONN_STATE_MAP.get(x, 12))
        
        # Keep original connection info for alert generation
        features["ts"] = df["ts"]
        features["src_ip"] = df["id.orig_h"]
        features["src_port"] = df["id.orig_p"]
        features["dst_ip"] = df["id.resp_h"]
        features["dst_port"] = df["id.resp_p"]
        features["proto"] = df["proto"]
        features["conn_state"] = df["conn_state"]
        
        return features
    
    def get_model_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Get the feature matrix for model training/prediction.
        
        Args:
            df: DataFrame with extracted features
            
        Returns:
            NumPy array with detection features
        """
        return df[DETECTION_FEATURES].values


# =============================================================================
# Network Anomaly Detector
# =============================================================================

class NetworkAnomalyDetector:
    """
    Detects network traffic anomalies using IsolationForest.
    
    Supports two modes:
    - collect: Build and save baseline from normal traffic
    - detect: Load baseline and detect anomalies
    
    Uses z-score on total_bytes as fallback when model unavailable.
    """
    
    def __init__(
        self,
        baseline_path: str = DEFAULT_BASELINE_PATH,
        contamination: float = 0.01,
        n_estimators: int = 100,
        random_state: int = 42
    ):
        """
        Initialize the anomaly detector.
        
        Args:
            baseline_path: Path for saving/loading baseline model
            contamination: Expected proportion of outliers (for IsolationForest)
            n_estimators: Number of trees in IsolationForest
            random_state: Random seed for reproducibility
        """
        self.baseline_path = Path(baseline_path)
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        
        self.model: Optional[IsolationForest] = None
        self.feature_extractor = FeatureExtractor()
        self.baseline_stats: Dict[str, Any] = {}
        
    def collect_baseline(self, log_path: str, save_json: bool = True) -> Dict[str, Any]:
        """
        Collect baseline from normal traffic data.
        
        Parses conn.log, extracts features, trains IsolationForest,
        and calculates statistics for z-score fallback.
        
        Args:
            log_path: Path to Zeek conn.log file
            save_json: Whether to also save baseline stats as JSON
            
        Returns:
            Dictionary with baseline statistics
        """
        logger.info("Collecting baseline from normal traffic...")
        
        # Parse log file
        parser = ZeekConnLogParser(log_path)
        conn_df = parser.parse()
        
        if conn_df.empty:
            raise ValueError("No connection records found in log file")
        
        # Extract features
        features_df = self.feature_extractor.extract_features(conn_df)
        X = self.feature_extractor.get_model_features(features_df)
        
        # Train IsolationForest
        logger.info(f"Training IsolationForest on {len(X)} samples...")
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(X)
        
        # Calculate baseline statistics for z-score fallback
        self.baseline_stats = {
            "total_bytes_mean": float(features_df["total_bytes"].mean()),
            "total_bytes_std": float(features_df["total_bytes"].std()),
            "duration_mean": float(features_df["duration"].mean()),
            "duration_std": float(features_df["duration"].std()),
            "sample_count": len(features_df),
            "collected_at": datetime.utcnow().isoformat(),
            "features": DETECTION_FEATURES
        }
        
        # Save baseline (pickle for model, JSON for stats)
        self._save_baseline()
        
        if save_json:
            json_path = self.baseline_path.with_suffix(".json")
            with open(json_path, "w") as f:
                json.dump(self.baseline_stats, f, indent=2)
            logger.info(f"Baseline stats saved to: {json_path}")
        
        logger.info(f"Baseline collected: {self.baseline_stats['sample_count']} samples")
        return self.baseline_stats
    
    def _save_baseline(self) -> None:
        """Save the trained model and stats to pickle file."""
        baseline_data = {
            "model": self.model,
            "stats": self.baseline_stats,
            "version": "1.0"
        }
        
        with open(self.baseline_path, "wb") as f:
            pickle.dump(baseline_data, f)
        logger.info(f"Baseline model saved to: {self.baseline_path}")
    
    def _load_baseline(self) -> bool:
        """
        Load baseline from pickle file.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        if not self.baseline_path.exists():
            logger.warning(f"Baseline file not found: {self.baseline_path}")
            return False
        
        try:
            with open(self.baseline_path, "rb") as f:
                baseline_data = pickle.load(f)
            
            self.model = baseline_data.get("model")
            self.baseline_stats = baseline_data.get("stats", {})
            
            logger.info(f"Baseline loaded: {self.baseline_stats.get('sample_count', 0)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False
    
    def _calculate_zscore(self, value: float, mean: float, std: float) -> float:
        """Calculate z-score for a value."""
        if std == 0:
            return 0.0
        return abs((value - mean) / std)
    
    def _determine_severity(self, zscore: float, is_isolation_forest: bool = False) -> str:
        """
        Determine anomaly severity based on z-score.
        
        Args:
            zscore: Calculated z-score
            is_isolation_forest: Whether detection was by IsolationForest
            
        Returns:
            Severity level: "low", "medium", "high", or "critical"
        """
        if is_isolation_forest:
            # IsolationForest detections are at least medium severity
            if zscore >= SEVERITY_THRESHOLDS["critical"]:
                return "critical"
            elif zscore >= SEVERITY_THRESHOLDS["high"]:
                return "high"
            return "medium"
        
        if zscore >= SEVERITY_THRESHOLDS["critical"]:
            return "critical"
        elif zscore >= SEVERITY_THRESHOLDS["high"]:
            return "high"
        elif zscore >= SEVERITY_THRESHOLDS["medium"]:
            return "medium"
        return "low"
    
    def detect(self, log_path: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies in network traffic.
        
        Uses IsolationForest if model available, falls back to z-score
        on total_bytes otherwise.
        
        Args:
            log_path: Path to Zeek conn.log file
            
        Returns:
            List of anomaly alert dictionaries
        """
        logger.info("Starting anomaly detection...")
        
        # Load baseline
        has_model = self._load_baseline()
        
        # Parse log file
        parser = ZeekConnLogParser(log_path)
        conn_df = parser.parse()
        
        if conn_df.empty:
            logger.warning("No connection records to analyze")
            return []
        
        # Extract features
        features_df = self.feature_extractor.extract_features(conn_df)
        
        anomalies = []
        
        if has_model and self.model is not None:
            # Use IsolationForest for detection
            logger.info("Using IsolationForest for detection")
            anomalies = self._detect_with_isolation_forest(features_df)
        else:
            # Fallback to z-score method
            logger.warning("No trained model available, using z-score fallback")
            anomalies = self._detect_with_zscore(features_df)
        
        logger.info(f"Detected {len(anomalies)} anomalies")
        return anomalies
    
    def _detect_with_isolation_forest(self, features_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Detect anomalies using trained IsolationForest model.
        
        Args:
            features_df: DataFrame with extracted features
            
        Returns:
            List of anomaly alerts
        """
        X = self.feature_extractor.get_model_features(features_df)
        
        # Predict: -1 for anomalies, 1 for normal
        predictions = self.model.predict(X)
        scores = self.model.decision_function(X)
        
        anomalies = []
        anomaly_indices = np.where(predictions == -1)[0]
        
        for idx in anomaly_indices:
            row = features_df.iloc[idx]
            
            # Calculate z-score for severity
            total_bytes = row["total_bytes"]
            zscore = self._calculate_zscore(
                total_bytes,
                self.baseline_stats.get("total_bytes_mean", 0),
                self.baseline_stats.get("total_bytes_std", 1)
            )
            
            severity = self._determine_severity(zscore, is_isolation_forest=True)
            
            alert = self._create_alert(
                row=row,
                severity=severity,
                zscore=zscore,
                anomaly_score=float(scores[idx]),
                detection_method="isolation_forest"
            )
            anomalies.append(alert)
        
        return anomalies
    
    def _detect_with_zscore(self, features_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Detect anomalies using z-score on total_bytes (fallback method).
        
        Args:
            features_df: DataFrame with extracted features
            
        Returns:
            List of anomaly alerts
        """
        # Use baseline stats if available, otherwise calculate from current data
        if self.baseline_stats:
            mean = self.baseline_stats.get("total_bytes_mean", features_df["total_bytes"].mean())
            std = self.baseline_stats.get("total_bytes_std", features_df["total_bytes"].std())
        else:
            mean = features_df["total_bytes"].mean()
            std = features_df["total_bytes"].std()
        
        if std == 0:
            std = 1  # Prevent division by zero
        
        anomalies = []
        
        for idx, row in features_df.iterrows():
            total_bytes = row["total_bytes"]
            zscore = self._calculate_zscore(total_bytes, mean, std)
            
            if zscore >= ZSCORE_THRESHOLD:
                severity = self._determine_severity(zscore, is_isolation_forest=False)
                
                alert = self._create_alert(
                    row=row,
                    severity=severity,
                    zscore=zscore,
                    anomaly_score=None,
                    detection_method="zscore"
                )
                anomalies.append(alert)
        
        return anomalies
    
    def _create_alert(
        self,
        row: pd.Series,
        severity: str,
        zscore: float,
        anomaly_score: Optional[float],
        detection_method: str
    ) -> Dict[str, Any]:
        """
        Create a JSON alert dictionary for an anomaly.
        
        Args:
            row: Feature row for the anomaly
            severity: Severity level
            zscore: Z-score value
            anomaly_score: IsolationForest anomaly score (if applicable)
            detection_method: Method used for detection
            
        Returns:
            Alert dictionary
        """
        alert = {
            "module": "network",
            "type": "connection_anomaly",
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "detection_method": detection_method,
            "connection": {
                "timestamp": str(row.get("ts", "")),
                "src_ip": str(row.get("src_ip", "")),
                "src_port": int(row.get("src_port", 0)) if pd.notna(row.get("src_port")) else 0,
                "dst_ip": str(row.get("dst_ip", "")),
                "dst_port": int(row.get("dst_port", 0)) if pd.notna(row.get("dst_port")) else 0,
                "protocol": str(row.get("proto", "")),
                "conn_state": str(row.get("conn_state", ""))
            },
            "features": {
                "duration": float(row.get("duration", 0)),
                "orig_bytes": float(row.get("orig_bytes", 0)),
                "resp_bytes": float(row.get("resp_bytes", 0)),
                "total_bytes": float(row.get("total_bytes", 0))
            },
            "analysis": {
                "z_score": round(zscore, 3),
                "baseline_mean": round(self.baseline_stats.get("total_bytes_mean", 0), 2),
                "baseline_std": round(self.baseline_stats.get("total_bytes_std", 0), 2)
            }
        }
        
        if anomaly_score is not None:
            alert["analysis"]["isolation_forest_score"] = round(anomaly_score, 4)
        
        return alert


# =============================================================================
# CLI Interface
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for CLI."""
    parser = argparse.ArgumentParser(
        description="SecuriSphere Network Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect baseline from normal traffic
  python anomaly_detector.py --log-path /logs/conn.log --mode collect

  # Detect anomalies in traffic
  python anomaly_detector.py --log-path /logs/conn.log --mode detect

  # Specify custom baseline path
  python anomaly_detector.py --log-path /logs/conn.log --mode detect --baseline /path/to/baseline.pkl

  # Output alerts to file
  python anomaly_detector.py --log-path /logs/conn.log --mode detect --output alerts.json
        """
    )
    
    parser.add_argument(
        "--log-path",
        required=True,
        help="Path to Zeek conn.log file"
    )
    
    parser.add_argument(
        "--mode",
        required=True,
        choices=["collect", "detect"],
        help="Operation mode: 'collect' to build baseline, 'detect' to find anomalies"
    )
    
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE_PATH,
        help=f"Path to baseline file (default: {DEFAULT_BASELINE_PATH})"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for alerts (JSON format). If not specified, prints to stdout"
    )
    
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.01,
        help="Expected proportion of outliers for IsolationForest (default: 0.01)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser


def main():
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize detector
    detector = NetworkAnomalyDetector(
        baseline_path=args.baseline,
        contamination=args.contamination
    )
    
    try:
        if args.mode == "collect":
            # Collect baseline mode
            print(f"Collecting baseline from: {args.log_path}")
            stats = detector.collect_baseline(args.log_path)
            
            print("\n" + "=" * 60)
            print("BASELINE COLLECTION COMPLETE")
            print("=" * 60)
            print(f"  Samples collected: {stats['sample_count']}")
            print(f"  Total bytes mean:  {stats['total_bytes_mean']:.2f}")
            print(f"  Total bytes std:   {stats['total_bytes_std']:.2f}")
            print(f"  Baseline saved to: {args.baseline}")
            print("=" * 60)
            
        elif args.mode == "detect":
            # Detect anomalies mode
            print(f"Detecting anomalies in: {args.log_path}")
            anomalies = detector.detect(args.log_path)
            
            if not anomalies:
                print("\nNo anomalies detected.")
                return
            
            # Output results
            output_data = {
                "module": "network",
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "log_file": str(args.log_path),
                "total_anomalies": len(anomalies),
                "by_severity": {
                    "critical": sum(1 for a in anomalies if a["severity"] == "critical"),
                    "high": sum(1 for a in anomalies if a["severity"] == "high"),
                    "medium": sum(1 for a in anomalies if a["severity"] == "medium"),
                    "low": sum(1 for a in anomalies if a["severity"] == "low")
                },
                "alerts": anomalies
            }
            
            if args.output:
                # Write to file
                with open(args.output, "w") as f:
                    json.dump(output_data, f, indent=2)
                print(f"\nAlerts written to: {args.output}")
            else:
                # Print to stdout
                print("\n" + "=" * 60)
                print("ANOMALY DETECTION RESULTS")
                print("=" * 60)
                print(f"Total anomalies: {output_data['total_anomalies']}")
                print(f"By severity: {output_data['by_severity']}")
                print("=" * 60)
                print("\nAlerts:")
                print(json.dumps(anomalies, indent=2))
                
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.exception("Detection failed")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
