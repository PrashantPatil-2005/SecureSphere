-- SecuriSphere Database Schema v1.0

CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    source_layer VARCHAR(20) NOT NULL,
    source_monitor VARCHAR(50) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity_level VARCHAR(20) NOT NULL,
    severity_score INTEGER NOT NULL,
    source_ip VARCHAR(45),
    source_container_id VARCHAR(64),
    source_container_name VARCHAR(100),
    target_ip VARCHAR(45),
    target_port INTEGER,
    target_service VARCHAR(100),
    detection_method VARCHAR(100),
    confidence FLOAT,
    description TEXT,
    evidence JSONB,
    correlation_tags TEXT[],
    mitre_technique VARCHAR(100),
    raw_data_reference TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS correlated_incidents (
    id SERIAL PRIMARY KEY,
    incident_id UUID NOT NULL UNIQUE,
    incident_type VARCHAR(50) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    confidence FLOAT,
    source_ip VARCHAR(45),
    target_username VARCHAR(100),
    correlated_event_ids UUID[],
    layers_involved TEXT[],
    event_types TEXT[],
    mitre_techniques TEXT[],
    recommended_actions TEXT[],
    risk_score_at_time INTEGER,
    time_span_seconds FLOAT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id SERIAL PRIMARY KEY,
    entity_ip VARCHAR(45) NOT NULL,
    current_score INTEGER DEFAULT 0,
    peak_score INTEGER DEFAULT 0,
    threat_level VARCHAR(20) DEFAULT 'normal',
    layers_involved TEXT[],
    event_count INTEGER DEFAULT 0,
    last_event_type VARCHAR(50),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS baseline_metrics (
    id SERIAL PRIMARY KEY,
    entity_ip VARCHAR(45) NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    metric_value FLOAT NOT NULL,
    rolling_mean FLOAT,
    rolling_stddev FLOAT,
    sample_count INTEGER DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE,
    window_end TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_events_source_ip ON security_events(source_ip);
CREATE INDEX idx_events_event_type ON security_events(event_type);
CREATE INDEX idx_events_source_layer ON security_events(source_layer);
CREATE INDEX idx_events_severity ON security_events(severity_level);

CREATE INDEX idx_incidents_timestamp ON correlated_incidents(created_at);
CREATE INDEX idx_incidents_severity ON correlated_incidents(severity);
CREATE INDEX idx_incidents_source_ip ON correlated_incidents(source_ip);

CREATE INDEX idx_risk_entity ON risk_scores(entity_ip);

CREATE INDEX idx_baseline_entity ON baseline_metrics(entity_ip, metric_name);
