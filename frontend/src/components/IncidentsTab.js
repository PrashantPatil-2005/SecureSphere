import React from 'react';

const IncidentsTab = ({ incidents, getSeverityColor, formatTimestampFull }) => {

    // Count by severity
    const counts = {
        critical: incidents.filter(i => i.severity === 'critical').length,
        high: incidents.filter(i => i.severity === 'high').length,
        medium: incidents.filter(i => i.severity === 'medium').length,
        low: incidents.filter(i => i.severity === 'low').length,
        total: incidents.length
    };

    return (
        <div className="incidents-tab">

            {/* 1. Summary Bar (if incidents exist) */}
            {incidents.length > 0 && (
                <div className="section" style={{ display: 'flex', gap: '20px', alignItems: 'center', padding: '12px 20px', marginBottom: '16px' }}>
                    <div style={{ fontWeight: 600 }}>Total Incidents: {counts.total}</div>
                    <div style={{ width: '1px', height: '20px', background: 'var(--border-color)' }}></div>
                    <div style={{ color: 'var(--critical)' }}>Critical: {counts.critical}</div>
                    <div style={{ color: 'var(--high)' }}>High: {counts.high}</div>
                    <div style={{ color: 'var(--medium)' }}>Medium: {counts.medium}</div>
                </div>
            )}

            {/* 2. Incidents List */}
            {incidents.length > 0 ? (
                incidents.map(incident => (
                    <div
                        key={incident.incident_id}
                        className="incident-card"
                        style={{ borderLeftColor: getSeverityColor(incident.severity) }}
                    >
                        <div className="incident-header">
                            <div className="incident-title">{incident.title}</div>
                            <span
                                className="severity-badge"
                                style={{
                                    backgroundColor: `${getSeverityColor(incident.severity)}20`,
                                    color: getSeverityColor(incident.severity),
                                }}
                            >
                                {incident.severity}
                            </span>
                        </div>

                        <div className="incident-meta">
                            <div className="incident-meta-item">
                                <strong>Type:</strong> {incident.incident_type}
                            </div>
                            <div className="incident-meta-item">
                                <strong>Confidence:</strong> {incident.confidence * 100}%
                            </div>
                            <div className="incident-meta-item">
                                <strong>Time Span:</strong> {incident.time_span_seconds}s
                            </div>
                            <div className="incident-meta-item">
                                <strong>Detected:</strong> {formatTimestampFull(incident.timestamp)}
                            </div>
                        </div>

                        <div className="incident-description">
                            {incident.description}
                        </div>

                        <div className="incident-layers">
                            {incident.layers_involved?.map(layer => (
                                <span key={layer} className={`layer-badge layer-${layer}`}>
                                    {layer}
                                </span>
                            ))}
                        </div>

                        {incident.mitre_techniques?.length > 0 && (
                            <div className="mitre-tags">
                                {incident.mitre_techniques.map(tag => (
                                    <span key={tag} className="mitre-tag">{tag}</span>
                                ))}
                            </div>
                        )}

                        {incident.recommended_actions?.length > 0 && (
                            <div className="recommended-actions">
                                <h4>Recommended Actions</h4>
                                <ul>
                                    {incident.recommended_actions.map((action, idx) => (
                                        <li key={idx}>{action}</li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        <div style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-muted)' }}>
                            Correlated Events: {incident.correlated_events?.length || 0} • Risk Score Impact: {incident.risk_score_at_time}
                        </div>

                    </div>
                ))
            ) : (
                <div className="empty-state">
                    <div className="empty-state-icon">🔗</div>
                    <div className="empty-state-title">No Correlated Incidents Yet</div>
                    <div className="empty-state-message">
                        The Correlation Engine (Phase 6) will detect multi-layer attack patterns and display them here.
                        Incidents are created when security events from multiple layers (network, API, auth) are linked together.
                    </div>

                    <div className="section" style={{ maxWidth: '600px', margin: '30px auto', textAlign: 'left' }}>
                        <h4 className="section-title" style={{ fontSize: '14px', marginBottom: '10px' }}>What are Correlated Incidents?</h4>
                        <ul style={{ fontSize: '13px', color: 'var(--text-secondary)', paddingLeft: '20px' }}>
                            <li style={{ marginBottom: '8px' }}>When a port scan is followed by SQL injection from the same IP</li>
                            <li style={{ marginBottom: '8px' }}>When brute force is followed by a successful login</li>
                            <li style={{ marginBottom: '8px' }}>When attacks span all three monitoring layers</li>
                        </ul>
                    </div>
                </div>
            )}
        </div>
    );
};

export default IncidentsTab;
