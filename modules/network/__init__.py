# =============================================================================
# SecuriSphere - Network Module
# =============================================================================
"""
Network traffic analysis and anomaly detection module.

This module provides functionality for:
- Parsing Zeek network logs (conn.log)
- Building baselines of normal network behavior
- Detecting anomalies using IsolationForest and z-score methods
- Generating JSON alerts for detected anomalies
"""

from .anomaly_detector import NetworkAnomalyDetector

__all__ = ["NetworkAnomalyDetector"]
