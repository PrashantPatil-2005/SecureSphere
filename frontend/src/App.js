import React, { useState, useEffect, useCallback } from 'react';
import io from 'socket.io-client';
import './App.css';

// Components
import Header from './components/Header';
import Navigation from './components/Navigation';
import DashboardTab from './components/DashboardTab';
import EventsTab from './components/EventsTab';
import IncidentsTab from './components/IncidentsTab';
import RiskTab from './components/RiskTab';
import SystemTab from './components/SystemTab';

// Constants
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000';

function App() {
    // State
    const [events, setEvents] = useState([]);
    const [incidents, setIncidents] = useState([]);
    const [riskScores, setRiskScores] = useState({});
    const [metrics, setMetrics] = useState({});
    const [summary, setSummary] = useState({});
    const [timeline, setTimeline] = useState([]);
    const [systemStatus, setSystemStatus] = useState({});
    const [selectedTab, setSelectedTab] = useState('dashboard');
    const [isConnected, setIsConnected] = useState(false);
    const [lastUpdate, setLastUpdate] = useState(null);

    // Filters
    const [eventFilters, setEventFilters] = useState({
        layer: 'all',
        severity: 'all',
        limit: 50
    });

    // Fetch initial data via REST
    const fetchData = useCallback(async () => {
        try {
            const endpoints = [
                { key: 'summary', url: `${BACKEND_URL}/api/dashboard/summary` },
                { key: 'events', url: `${BACKEND_URL}/api/events?limit=100` },
                { key: 'incidents', url: `${BACKEND_URL}/api/incidents?limit=50` },
                { key: 'risk_scores', url: `${BACKEND_URL}/api/risk-scores` },
                { key: 'timeline', url: `${BACKEND_URL}/api/metrics/timeline` },
                { key: 'status', url: `${BACKEND_URL}/api/system/status` }
            ];

            const results = await Promise.all(
                endpoints.map(ep =>
                    fetch(ep.url)
                        .then(res => res.json())
                        .then(data => ({ key: ep.key, data }))
                        .catch(err => console.error(`Fetch error for ${ep.key}:`, err))
                )
            );

            const dataMap = {};
            results.forEach(res => {
                if (res && res.data) {
                    dataMap[res.key] = res.data.data;
                }
            });

            if (dataMap.summary) {
                setSummary(dataMap.summary || {});
                setMetrics(dataMap.summary.metrics || {});
            }
            if (dataMap.events) setEvents(dataMap.events.events || []);
            if (dataMap.incidents) setIncidents(dataMap.incidents.incidents || []);
            if (dataMap.risk_scores) setRiskScores(dataMap.risk_scores.risk_scores || {});
            if (dataMap.timeline) setTimeline(dataMap.timeline.timeline || []);
            if (dataMap.status) setSystemStatus(dataMap.status || {});

            setLastUpdate(new Date().toISOString());
        } catch (error) {
            console.error("Error fetching initial data:", error);
        }
    }, []);

    // Socket.IO Connection
    useEffect(() => {
        const socket = io(BACKEND_URL);

        socket.on('connect', () => {
            console.log('Connected to WebSocket');
            setIsConnected(true);
        });

        socket.on('disconnect', () => {
            console.log('Disconnected from WebSocket');
            setIsConnected(false);
        });

        socket.on('initial_state', (data) => {
            if (data.summary) setSummary(data.summary);
            if (data.metrics) setMetrics(data.metrics);
            setLastUpdate(new Date().toISOString());
        });

        socket.on('new_event', (event) => {
            setEvents(prev => [event, ...prev].slice(0, 200));
            setLastUpdate(new Date().toISOString());
        });

        socket.on('new_incident', (incident) => {
            setIncidents(prev => [incident, ...prev].slice(0, 100));
            setLastUpdate(new Date().toISOString());
        });

        socket.on('risk_update', (data) => {
            setRiskScores(prev => ({
                ...prev,
                [data.ip]: data.score_data
            }));
            setLastUpdate(new Date().toISOString());
        });

        socket.on('summary_update', (data) => {
            setSummary(data);
            setLastUpdate(new Date().toISOString());
        });

        socket.on('metrics_update', (data) => {
            setMetrics(data);
            setLastUpdate(new Date().toISOString());
        });

        socket.on('timeline_update', (data) => {
            setTimeline(data.timeline || []);
            setLastUpdate(new Date().toISOString());
        });

        socket.on('full_refresh', (data) => {
            fetchData(); // Re-fetch everything
        });

        // Cleanup
        return () => {
            socket.disconnect();
        };
    }, [fetchData]);

    // Initial Rest Fetch
    useEffect(() => {
        fetchData();
    }, [fetchData]);

    // Periodic Refresh (every 15s)
    useEffect(() => {
        const interval = setInterval(() => {
            fetchData();
        }, 15000);
        return () => clearInterval(interval);
    }, [fetchData]);

    // Handlers
    const handleClearAll = async () => {
        if (!window.confirm("Are you sure you want to clear all data?")) return;

        try {
            await fetch(`${BACKEND_URL}/api/events/clear`, { method: 'POST' });
            setEvents([]);
            setIncidents([]);
            setRiskScores({});
            setMetrics({});
            setTimeline([]);

            // Force refresh
            setTimeout(fetchData, 500);
        } catch (error) {
            console.error("Error clearing data:", error);
        }
    };

    const handleRefresh = () => {
        fetchData();
    };

    // Helper Functions
    const getSeverityColor = (severity) => {
        switch (severity?.toLowerCase()) {
            case 'critical': return 'var(--critical)';
            case 'high': return 'var(--high)';
            case 'medium': return 'var(--medium)';
            case 'low': return 'var(--low)';
            default: return 'var(--text-muted)';
        }
    };

    const getLayerColor = (layer) => {
        switch (layer?.toLowerCase()) {
            case 'network': return 'var(--network-color)';
            case 'api': return 'var(--api-color)';
            case 'auth': return 'var(--auth-color)';
            default: return 'var(--text-muted)';
        }
    };

    const getThreatLevelColor = (level) => {
        switch (level?.toLowerCase()) {
            case 'critical': return 'var(--critical)';
            case 'threatening': return 'var(--high)';
            case 'suspicious': return 'var(--medium)';
            case 'normal': return 'var(--low)';
            default: return 'var(--low)';
        }
    };

    const formatTimestamp = (isoString) => {
        if (!isoString) return '-';
        return new Date(isoString).toLocaleTimeString();
    };

    const formatTimestampFull = (isoString) => {
        if (!isoString) return '-';
        return new Date(isoString).toLocaleString();
    };

    return (
        <div className="app">
            <Header
                isConnected={isConnected}
                lastUpdate={lastUpdate}
                onRefresh={handleRefresh}
                onClear={handleClearAll}
            />
            <Navigation
                selectedTab={selectedTab}
                onTabChange={setSelectedTab}
                eventCount={events.length}
                incidentCount={incidents.length}
            />
            <main className="main-content">
                {selectedTab === 'dashboard' && (
                    <DashboardTab
                        metrics={metrics}
                        summary={summary}
                        events={events}
                        incidents={incidents}
                        riskScores={riskScores}
                        timeline={timeline}
                        getSeverityColor={getSeverityColor}
                        getLayerColor={getLayerColor}
                        getThreatLevelColor={getThreatLevelColor}
                        formatTimestamp={formatTimestamp}
                    />
                )}
                {selectedTab === 'events' && (
                    <EventsTab
                        events={events}
                        filters={eventFilters}
                        onFilterChange={setEventFilters}
                        getSeverityColor={getSeverityColor}
                        getLayerColor={getLayerColor}
                        formatTimestamp={formatTimestamp}
                        formatTimestampFull={formatTimestampFull}
                    />
                )}
                {selectedTab === 'incidents' && (
                    <IncidentsTab
                        incidents={incidents}
                        getSeverityColor={getSeverityColor}
                        formatTimestampFull={formatTimestampFull}
                    />
                )}
                {selectedTab === 'risk' && (
                    <RiskTab
                        riskScores={riskScores}
                        getThreatLevelColor={getThreatLevelColor}
                        formatTimestampFull={formatTimestampFull}
                    />
                )}
                {selectedTab === 'system' && (
                    <SystemTab
                        systemStatus={systemStatus}
                        onRefresh={handleRefresh}
                    />
                )}
            </main>
        </div>
    );
}

export default App;
