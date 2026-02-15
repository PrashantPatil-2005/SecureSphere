import React from 'react';

const RiskTab = ({ riskScores, getThreatLevelColor, formatTimestampFull }) => {

    const scoresList = Object.entries(riskScores).map(([ip, data]) => ({ ip, ...data }));
    // Sort by score descending
    scoresList.sort((a, b) => b.current_score - a.current_score);

    const counts = {
        total: scoresList.length,
        critical: scoresList.filter(s => s.threat_level === 'critical').length,
        threatening: scoresList.filter(s => s.threat_level === 'threatening').length,
        suspicious: scoresList.filter(s => s.threat_level === 'suspicious').length,
        normal: scoresList.filter(s => s.threat_level === 'normal').length,
    };

    return (
        <div className="risk-tab">

            {/* 1. Summary Bar */}
            {scoresList.length > 0 && (
                <div className="section" style={{ display: 'flex', gap: '20px', alignItems: 'center', padding: '12px 20px', marginBottom: '16px' }}>
                    <div style={{ fontWeight: 600 }}>Total Entities: {counts.total}</div>
                    <div style={{ width: '1px', height: '20px', background: 'var(--border-color)' }}></div>
                    <div style={{ color: 'var(--critical)' }}>Critical: {counts.critical}</div>
                    <div style={{ color: 'var(--high)' }}>Threatening: {counts.threatening}</div>
                    <div style={{ color: 'var(--medium)' }}>Suspicious: {counts.suspicious}</div>
                    <div style={{ color: 'var(--low)' }}>Normal: {counts.normal}</div>
                </div>
            )}

            {/* 2. Risk Cards Grid */}
            {scoresList.length > 0 ? (
                <div className="risk-grid">
                    {scoresList.map(item => (
                        <div
                            key={item.ip}
                            className="risk-card"
                            style={{ borderLeftColor: getThreatLevelColor(item.threat_level) }}
                        >
                            <div className="risk-header">
                                <div className="risk-ip">{item.ip}</div>
                                <span
                                    className="risk-threat-level"
                                    style={{
                                        backgroundColor: `${getThreatLevelColor(item.threat_level)}20`,
                                        color: getThreatLevelColor(item.threat_level)
                                    }}
                                >
                                    {item.threat_level}
                                </span>
                            </div>

                            <div className="risk-score-number" style={{ color: getThreatLevelColor(item.threat_level) }}>
                                {item.current_score}
                            </div>

                            <div className="risk-score-bar">
                                <div
                                    className="risk-score-fill"
                                    style={{
                                        width: `${Math.min(item.current_score / 2, 100)}%`, // Score 200 = 100%
                                        backgroundColor: getThreatLevelColor(item.threat_level)
                                    }}
                                ></div>
                            </div>

                            <div className="risk-meta">
                                <div>Peak: {item.peak_score}</div>
                                <div>Events: {item.event_count}</div>
                            </div>

                            <div style={{ marginTop: '12px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                                {item.layers_involved?.map(layer => (
                                    <span key={layer} className={`layer-badge layer-${layer}`} style={{ fontSize: '10px' }}>
                                        {layer}
                                    </span>
                                ))}
                            </div>

                            <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--text-muted)' }}>
                                Last Update: {formatTimestampFull(item.last_update)}
                            </div>
                        </div>
                    ))}
                </div>
            ) : (
                <div className="empty-state">
                    <div className="empty-state-icon">⚡</div>
                    <div className="empty-state-title">No Risk Scores Yet</div>
                    <div className="empty-state-message">
                        The Correlation Engine (Phase 6) will calculate cumulative risk scores for each entity
                        (IP address) based on security events. Scores increase when threats are detected and decay over time.
                    </div>

                    <div className="section" style={{ maxWidth: '600px', margin: '30px auto', textAlign: 'left' }}>
                        <h4 className="section-title" style={{ fontSize: '14px', marginBottom: '10px' }}>How Risk Scoring Works:</h4>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                            <ul>
                                <li>Low Severity: +10 pts</li>
                                <li>Medium Severity: +25 pts</li>
                                <li>High Severity: +50 pts</li>
                                <li>Critical Severity: +100 pts</li>
                            </ul>
                            <ul>
                                <li>Cross-layer Bonus: ×1.5</li>
                                <li>Decay Rate: -5 pts/min</li>
                                <li>Threat Threshold: &gt;70 pts</li>
                                <li>Critical Threshold: &gt;150 pts</li>
                            </ul>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RiskTab;
