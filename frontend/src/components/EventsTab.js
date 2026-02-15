import React, { useState } from 'react';

const EventsTab = ({
    events,
    filters,
    onFilterChange,
    getSeverityColor,
    getLayerColor,
    formatTimestamp,
    formatTimestampFull
}) => {
    const [selectedEvent, setSelectedEvent] = useState(null);

    // Apply filters manually if needed (though backend does filtering too if configured)
    // Here we filter client-side for immediate responsiveness on the 'events' array we have
    const filteredEvents = events.filter(event => {
        if (filters.layer !== 'all' && event.source_layer !== filters.layer) return false;
        if (filters.severity !== 'all' && event.severity?.level !== filters.severity) return false;
        return true;
    });

    const handleFilterClick = (type, value) => {
        onFilterChange(prev => ({ ...prev, [type]: value }));
    };

    return (
        <div className="events-tab">

            {/* 1. Filter Bar */}
            <div className="section" style={{ marginBottom: '16px', padding: '12px' }}>
                <div className="filter-bar" style={{ marginBottom: 0 }}>

                    <div className="filter-group">
                        <span className="filter-label">Layer:</span>
                        {['all', 'network', 'api', 'auth'].map(layer => (
                            <button
                                key={layer}
                                className={`filter-btn ${filters.layer === layer ? 'active' : ''}`}
                                onClick={() => handleFilterClick('layer', layer)}
                            >
                                {layer.charAt(0).toUpperCase() + layer.slice(1)}
                            </button>
                        ))}
                    </div>

                    <div className="filter-group" style={{ marginLeft: '20px' }}>
                        <span className="filter-label">Severity:</span>
                        {['all', 'critical', 'high', 'medium', 'low'].map(severity => (
                            <button
                                key={severity}
                                className={`filter-btn ${filters.severity === severity ? 'active' : ''}`}
                                style={filters.severity === severity ? {
                                    backgroundColor: getSeverityColor(severity),
                                    borderColor: getSeverityColor(severity),
                                    color: '#fff'
                                } : {}}
                                onClick={() => handleFilterClick('severity', severity)}
                            >
                                {severity.charAt(0).toUpperCase() + severity.slice(1)}
                            </button>
                        ))}
                    </div>

                </div>
            </div>

            {/* 2. Events Table */}
            <div className="section" style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border-color)', fontSize: '12px', color: 'var(--text-muted)' }}>
                    Showing {filteredEvents.length} events
                </div>

                <div style={{ overflowX: 'auto' }}>
                    <table className="events-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Layer</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Source IP</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredEvents.length > 0 ? (
                                filteredEvents.map(event => (
                                    <tr key={event.event_id} onClick={() => setSelectedEvent(event)} style={{ cursor: 'pointer' }}>
                                        <td style={{ fontFamily: 'monospace' }}>{formatTimestamp(event.timestamp)}</td>
                                        <td>
                                            <span className={`layer-badge layer-${event.source_layer}`}>
                                                {event.source_layer}
                                            </span>
                                        </td>
                                        <td style={{ fontWeight: 500 }}>{event.event_type}</td>
                                        <td>
                                            <span
                                                className="severity-badge"
                                                style={{
                                                    backgroundColor: `${getSeverityColor(event.severity?.level)}20`,
                                                    color: getSeverityColor(event.severity?.level)
                                                }}
                                            >
                                                {event.severity?.level}
                                            </span>
                                        </td>
                                        <td style={{ fontFamily: 'monospace' }}>{event.source_entity?.ip}</td>
                                        <td>{event.detection_details?.description?.substring(0, 80)}...</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="6" style={{ textAlign: 'center', padding: '40px' }}>
                                        No events match current filters
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* 3. Event Detail Modal */}
            {selectedEvent && (
                <div className="modal-overlay" onClick={() => setSelectedEvent(null)}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <h2 className="section-title" style={{ fontSize: '20px' }}>{selectedEvent.event_type}</h2>
                                <span
                                    className="severity-badge"
                                    style={{
                                        backgroundColor: `${getSeverityColor(selectedEvent.severity?.level)}20`,
                                        color: getSeverityColor(selectedEvent.severity?.level),
                                        fontSize: '13px', padding: '4px 10px'
                                    }}
                                >
                                    {selectedEvent.severity?.level} ({selectedEvent.severity?.score})
                                </span>
                            </div>
                            <button className="modal-close" onClick={() => setSelectedEvent(null)}>&times;</button>
                        </div>

                        <div className="detail-grid">
                            <div className="detail-label">Event ID:</div>
                            <div className="detail-value">{selectedEvent.event_id}</div>

                            <div className="detail-label">Timestamp:</div>
                            <div className="detail-value">{formatTimestampFull(selectedEvent.timestamp)}</div>

                            <div className="detail-label">Source Layer:</div>
                            <div className="detail-value">
                                <span className={`layer-badge layer-${selectedEvent.source_layer}`}>
                                    {selectedEvent.source_layer}
                                </span>
                            </div>

                            <div className="detail-label">Monitor:</div>
                            <div className="detail-value">{selectedEvent.source_monitor}</div>

                            <div className="detail-label">Category:</div>
                            <div className="detail-value">{selectedEvent.event_category}</div>

                            <div className="detail-label">Source IP:</div>
                            <div className="detail-value" style={{ fontFamily: 'monospace' }}>{selectedEvent.source_entity?.ip}</div>

                            <div className="detail-label">Target:</div>
                            <div className="detail-value" style={{ fontFamily: 'monospace' }}>
                                {selectedEvent.target_entity?.ip || selectedEvent.target_entity?.endpoint || selectedEvent.target_entity?.username || 'N/A'}
                            </div>

                            <div className="detail-label">Confidence:</div>
                            <div className="detail-value">{selectedEvent.detection_details?.confidence * 100}%</div>

                            <div className="detail-label">Method:</div>
                            <div className="detail-value">{selectedEvent.detection_details?.method}</div>

                            <div className="detail-label">MITRE Technique:</div>
                            <div className="detail-value">{selectedEvent.mitre_technique || 'N/A'}</div>

                            <div className="detail-label">Correlation Tags:</div>
                            <div className="detail-value">
                                {selectedEvent.correlation_tags?.length > 0
                                    ? selectedEvent.correlation_tags.map(t => <span key={t} className="mitre-tag">{t}</span>)
                                    : 'None'}
                            </div>
                        </div>

                        <div style={{ marginTop: '20px' }}>
                            <h4 className="detail-label" style={{ marginBottom: '8px' }}>Description</h4>
                            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.5' }}>
                                {selectedEvent.detection_details?.description}
                            </p>
                        </div>

                        <div style={{ marginTop: '20px' }}>
                            <h4 className="detail-label" style={{ marginBottom: '8px' }}>Evidence</h4>
                            <div className="evidence-block">
                                {JSON.stringify(selectedEvent.detection_details?.evidence, null, 2)}
                            </div>
                        </div>

                    </div>
                </div>
            )}

        </div>
    );
};

export default EventsTab;
