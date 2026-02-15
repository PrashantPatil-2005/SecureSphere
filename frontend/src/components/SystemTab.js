import React from 'react';

const SystemTab = ({ systemStatus, onRefresh }) => {

    const redisConnected = systemStatus.redis?.connected;
    const metrics = systemStatus.metrics || {};

    // Helper to get status component
    const StatusCard = ({ title, active, detail, count, time }) => (
        <div className="status-card">
            <div className="status-card-header">
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
                <div className={`status-indicator ${active ? 'active' : 'inactive'}`}></div>
            </div>

            <div style={{ fontSize: '13px', color: active ? 'var(--success)' : 'var(--danger)', marginBottom: '8px' }}>
                {active ? 'Active' : 'Inactive'}
            </div>

            {detail && (
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    {detail}
                </div>
            )}

            {(count !== undefined) && (
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    Events Processed: {count}
                </div>
            )}

            {time && (
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '8px' }}>
                    Last Activity: {time ? new Date(time).toLocaleTimeString() : 'Never'}
                </div>
            )}
        </div>
    );

    return (
        <div className="system-tab">

            <div className="section-header">
                <div className="section-title">System Status</div>
                <button className="header-btn" onClick={onRefresh}>Refresh Status</button>
            </div>

            <div className="status-grid">

                {/* Redis */}
                <StatusCard
                    title="Redis Database"
                    active={redisConnected}
                    detail={redisConnected ? `Ping: ${systemStatus.redis?.ping || 'OK'}` : 'Connection Failed'}
                />

                {/* Backend */}
                <StatusCard
                    title="Backend API"
                    active={true} // Always true if we see this page
                    detail={`Uptime: ${metrics.system_uptime?.split('.')[0] || '-'}`}
                    count={metrics.raw_events?.total}
                />

                {/* Network Monitor */}
                <StatusCard
                    title="Network Monitor"
                    active={systemStatus.monitors?.network?.active}
                    count={systemStatus.monitors?.network?.event_count}
                    time={systemStatus.monitors?.network?.last_event}
                />

                {/* API Monitor */}
                <StatusCard
                    title="API Monitor"
                    active={systemStatus.monitors?.api?.active}
                    count={systemStatus.monitors?.api?.event_count}
                    time={systemStatus.monitors?.api?.last_event}
                />

                {/* Auth Monitor */}
                <StatusCard
                    title="Auth Monitor"
                    active={systemStatus.monitors?.auth?.active}
                    count={systemStatus.monitors?.auth?.event_count}
                    time={systemStatus.monitors?.auth?.last_event}
                />

                {/* Correlation Engine */}
                <StatusCard
                    title="Correlation Engine"
                    active={systemStatus.correlation_engine?.active}
                    detail="Phase 6 Integration Pending"
                    count={systemStatus.correlation_engine?.incidents}
                />

            </div>

            <div className="section" style={{ marginTop: '24px' }}>
                <div className="section-title">System Information</div>
                <div className="detail-grid" style={{ marginTop: '16px' }}>
                    <div className="detail-label">App Version:</div>
                    <div className="detail-value">1.0.0 (Phase 5)</div>

                    <div className="detail-label">Total Events:</div>
                    <div className="detail-value">{metrics.raw_events?.total || 0}</div>

                    <div className="detail-label">Active Monitors:</div>
                    <div className="detail-value">
                        {[
                            systemStatus.monitors?.network?.active,
                            systemStatus.monitors?.api?.active,
                            systemStatus.monitors?.auth?.active
                        ].filter(Boolean).length} / 3
                    </div>
                </div>
            </div>

        </div>
    );
};

export default SystemTab;
