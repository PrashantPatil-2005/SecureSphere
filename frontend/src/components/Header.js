import React, { useState, useEffect } from 'react';

const Header = ({ isConnected, lastUpdate, onRefresh, onClear }) => {
    const [currentTime, setCurrentTime] = useState(new Date());

    useEffect(() => {
        const timer = setInterval(() => setCurrentTime(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    return (
        <header className="header">
            <div className="header-left">
                <div className="header-logo">
                    🛡️ SecuriSphere
                </div>
                <div className="header-subtitle">
                    Multi-Layer Security Monitoring
                </div>
            </div>

            <div className="header-right">
                <div className="connection-status">
                    <span className={`status-dot ${isConnected ? 'connected' : 'disconnected'}`}></span>
                    {isConnected ? 'Connected' : 'Disconnected'}
                </div>

                <div className="header-time">
                    {currentTime.toLocaleTimeString()}
                </div>

                <button className="header-btn" onClick={onRefresh}>
                    Refresh
                </button>

                <button className="header-btn danger" onClick={onClear}>
                    Clear All
                </button>
            </div>
        </header>
    );
};

export default Header;
