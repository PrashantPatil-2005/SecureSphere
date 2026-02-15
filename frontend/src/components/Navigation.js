import React from 'react';

const Navigation = ({ selectedTab, onTabChange, eventCount, incidentCount }) => {
    return (
        <nav className="navigation">
            <button
                className={`nav-tab ${selectedTab === 'dashboard' ? 'active' : ''}`}
                onClick={() => onTabChange('dashboard')}
            >
                📊 Dashboard
            </button>

            <button
                className={`nav-tab ${selectedTab === 'events' ? 'active' : ''}`}
                onClick={() => onTabChange('events')}
            >
                🔔 Events
                {eventCount > 0 && <span className="nav-badge">{eventCount}</span>}
            </button>

            <button
                className={`nav-tab ${selectedTab === 'incidents' ? 'active' : ''}`}
                onClick={() => onTabChange('incidents')}
            >
                🚨 Incidents
                {incidentCount > 0 && <span className="nav-badge">{incidentCount}</span>}
            </button>

            <button
                className={`nav-tab ${selectedTab === 'risk' ? 'active' : ''}`}
                onClick={() => onTabChange('risk')}
            >
                ⚡ Risk Scores
            </button>

            <button
                className={`nav-tab ${selectedTab === 'system' ? 'active' : ''}`}
                onClick={() => onTabChange('system')}
            >
                ⚙️ System
            </button>
            <button
                className={`nav-tab ${selectedTab === 'pcap' ? 'active' : ''}`}
                onClick={() => onTabChange('pcap')}
            >
                📦 PCAP Analysis
            </button>
        </nav>
    );
};

export default Navigation;
