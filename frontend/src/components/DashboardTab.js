import React from 'react';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler
);

const DashboardTab = ({
    metrics,
    summary,
    events,
    incidents,
    riskScores,
    timeline,
    getSeverityColor,
    getLayerColor,
    getThreatLevelColor,
    formatTimestamp
}) => {

    // --- Helpers ---
    const totalEvents = metrics?.raw_events?.total || 0;
    const networkCount = metrics?.raw_events?.network || 0;
    const apiCount = metrics?.raw_events?.api || 0;
    const authCount = metrics?.raw_events?.auth || 0;

    const correlatedCount = metrics?.correlated_incidents || 0;
    const reductionPercent = metrics?.alert_reduction_percentage || 0;

    // Active threats (risk score threat level != normal)
    const activeThreats = Object.values(riskScores || {}).filter(
        score => score.threat_level !== 'normal'
    ).length;

    // --- Chart Data ---
    const chartData = {
        labels: timeline.map(t => new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })),
        datasets: [
            {
                label: 'Network',
                data: timeline.map(t => t.network),
                borderColor: '#3b82f6', // var(--network-color)
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.3,
                fill: true
            },
            {
                label: 'API',
                data: timeline.map(t => t.api),
                borderColor: '#a855f7', // var(--api-color)
                backgroundColor: 'rgba(168, 85, 247, 0.1)',
                tension: 0.3,
                fill: true
            },
            {
                label: 'Auth',
                data: timeline.map(t => t.auth),
                borderColor: '#06b6d4', // var(--auth-color)
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                tension: 0.3,
                fill: true
            }
        ]
    };

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: { color: '#94a3b8' } // var(--text-secondary)
            },
            tooltip: {
                mode: 'index',
                intersect: false,
            }
        },
        scales: {
            x: {
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                ticks: { color: '#64748b' }
            },
            y: {
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                ticks: { color: '#64748b' }
            }
        },
        interaction: {
            mode: 'nearest',
            axis: 'x',
            intersect: false
        }
    };

    return (
        <div className="dashboard-tab">

            {/* 1. Metric Cards */}
            <div className="metric-cards">
                <div className="metric-card">
                    <div className="metric-card-title">Raw Events</div>
                    <div className="metric-card-value">{totalEvents}</div>
                    <div className="metric-card-breakdown">
                        <span>🌐 {networkCount}</span>
                        <span>🔌 {apiCount}</span>
                        <span>🔐 {authCount}</span>
                    </div>
                </div>

                <div className={`metric-card ${correlatedCount > 0 ? 'highlight' : ''}`}>
                    <div className="metric-card-title">Correlated Incidents</div>
                    <div className="metric-card-value">{correlatedCount}</div>
                    <div className="metric-card-detail">Cross-layer threats detected</div>
                </div>

                <div className="metric-card">
                    <div className="metric-card-title">Alert Reduction</div>
                    <div className="metric-card-value">{reductionPercent}%</div>
                    <div className="metric-card-detail">Fewer alerts vs. uncorrelated</div>
                </div>

                <div className={`metric-card ${activeThreats > 0 ? 'critical-bg' : ''}`}>
                    <div className="metric-card-title">Active Threats</div>
                    <div className="metric-card-value">{activeThreats}</div>
                    <div className="metric-card-detail">Entities above normal threshold</div>
                </div>
            </div>

            <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>

                {/* Left Column (Layer Activity + Timeline) */}
                <div style={{ flex: '1 1 60%', minWidth: '300px' }}>

                    <div className="section">
                        <div className="section-header">
                            <div className="section-title">Layer Activity</div>
                        </div>

                        <div className="layer-bars">
                            {['network', 'api', 'auth'].map(layer => {
                                const count = layer === 'network' ? networkCount : (layer === 'api' ? apiCount : authCount);
                                const max = Math.max(totalEvents, 1); // Avoid div by zero
                                const percent = (count / max) * 100;

                                return (
                                    <div className="layer-bar-row" key={layer}>
                                        <div className="layer-bar-label">
                                            {layer === 'network' && '🌐 Network'}
                                            {layer === 'api' && '🔌 API'}
                                            {layer === 'auth' && '🔐 Auth'}
                                        </div>
                                        <div className="layer-bar-container">
                                            <div
                                                className={`layer-bar-fill ${layer}`}
                                                style={{ width: `${percent}%` }}
                                            ></div>
                                        </div>
                                        <div className="layer-bar-count">{count}</div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    <div className="section">
                        <div className="section-header">
                            <div className="section-title">Event Timeline</div>
                            <div className="section-subtitle">Last 30 Minutes</div>
                        </div>
                        <div className="chart-container">
                            {timeline.length > 0 ? (
                                <Line data={chartData} options={chartOptions} />
                            ) : (
                                <div className="empty-state">
                                    <div className="empty-state-message">Timeline data will appear as events are detected</div>
                                </div>
                            )}
                        </div>
                    </div>

                </div>

                {/* Right Column (Incidents + Risk) */}
                <div style={{ flex: '1 1 35%', minWidth: '300px' }}>

                    <div className="section">
                        <div className="section-header">
                            <div className="section-title">Recent Incidents</div>
                        </div>

                        {incidents && incidents.length > 0 ? (
                            incidents.slice(0, 5).map(incident => (
                                <div
                                    key={incident.incident_id}
                                    className="incident-card"
                                    style={{ borderLeftColor: getSeverityColor(incident.severity), padding: '12px' }}
                                >
                                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                        <div className="incident-title" style={{ fontSize: '14px' }}>{incident.title}</div>
                                        <span
                                            className="severity-badge"
                                            style={{
                                                backgroundColor: `${getSeverityColor(incident.severity)}20`,  // 20 is hex alpha approx 12%
                                                color: getSeverityColor(incident.severity)
                                            }}
                                        >
                                            {incident.severity}
                                        </span>
                                    </div>
                                    <div className="incident-description" style={{ fontSize: '12px', marginBottom: '8px' }}>
                                        {incident.description.substring(0, 100)}...
                                    </div>
                                    <div className="incident-layers">
                                        {incident.layers_involved.map(l => (
                                            <span key={l} className={`layer-badge layer-${l}`}>{l}</span>
                                        ))}
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div className="empty-state" style={{ padding: '20px' }}>
                                <div className="empty-state-title" style={{ fontSize: '14px' }}>🔗 No correlated incidents yet</div>
                                <div className="empty-state-message" style={{ fontSize: '12px' }}>
                                    Incidents will appear when the Correlation Engine detects multi-layer patterns
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="section">
                        <div className="section-header">
                            <div className="section-title">Top Risk Entities</div>
                        </div>

                        {Object.keys(riskScores).length > 0 ? (
                            Object.entries(riskScores)
                                .sort(([, a], [, b]) => b.current_score - a.current_score)
                                .slice(0, 5)
                                .map(([ip, scoreData]) => (
                                    <div key={ip} style={{ marginBottom: '12px', paddingBottom: '12px', borderBottom: '1px solid var(--border-color)' }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                                            <span style={{ fontFamily: 'monospace', fontWeight: 'bold' }}>{ip}</span>
                                            <span
                                                className="risk-threat-level"
                                                style={{ color: getThreatLevelColor(scoreData.threat_level) }}
                                            >
                                                {scoreData.threat_level}
                                            </span>
                                        </div>
                                        <div className="risk-score-bar">
                                            <div
                                                className="risk-score-fill"
                                                style={{
                                                    width: `${Math.min(scoreData.current_score / 2, 100)}%`,
                                                    backgroundColor: getThreatLevelColor(scoreData.threat_level)
                                                }}
                                            ></div>
                                        </div>
                                    </div>
                                ))
                        ) : (
                            <div className="empty-state" style={{ padding: '20px' }}>
                                <div className="empty-state-title" style={{ fontSize: '14px' }}>📊 No risk scores yet</div>
                                <div className="empty-state-message" style={{ fontSize: '12px' }}>
                                    Risk scores will appear when the Correlation Engine processes events
                                </div>
                            </div>
                        )}
                    </div>

                </div>
            </div>

            {/* Recent Events Section */}
            <div className="section">
                <div className="section-header">
                    <div className="section-title">Recent Events</div>
                </div>

                <div className="timeline-container" style={{ maxHeight: '300px' }}>
                    {events && events.length > 0 ? (
                        events.slice(0, 10).map((event) => (
                            <div key={event.event_id} className="timeline-item">
                                <div
                                    className="timeline-dot"
                                    style={{ backgroundColor: getSeverityColor(event.severity?.level || 'low') }}
                                ></div>
                                <div className="timeline-content">
                                    <div className="timeline-time">{formatTimestamp(event.timestamp)}</div>
                                    <span className={`layer-badge layer-${event.source_layer}`}>
                                        {event.source_layer}
                                    </span>
                                    <div className="timeline-type">{event.event_type}</div>
                                    <div className="timeline-source">{event.source_entity?.ip || 'Unknown'}</div>
                                    <div className="timeline-desc">
                                        {event.detection_details?.description?.substring(0, 80)}...
                                    </div>
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="empty-state">
                            <div className="empty-state-message">No events detected yet. Waiting for monitors...</div>
                        </div>
                    )}
                </div>
            </div>

        </div>
    );
};

export default DashboardTab;
