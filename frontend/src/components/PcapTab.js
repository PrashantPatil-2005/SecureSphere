
import React, { useState, useEffect, useRef } from 'react';
import {
    Chart as ChartJS, ArcElement, Tooltip, Legend,
    CategoryScale, LinearScale, BarElement, Title
} from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale,
    LinearScale, BarElement, Title);

function PcapTab() {
    const [selectedFile, setSelectedFile] = useState(null);
    const [samples, setSamples] = useState([]);
    const [uploadStatus, setUploadStatus] = useState('idle'); // idle, uploading, processing, complete, error
    const [uploadProgress, setUploadProgress] = useState(0);
    const [processingProgress, setProcessingProgress] = useState(0);
    const [jobId, setJobId] = useState(null);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);

    const fileInputRef = useRef(null);
    const pollIntervalRef = useRef(null);

    // Fetch samples on mount
    useEffect(() => {
        fetchSamples();
        return () => stopPolling();
    }, []);

    const fetchSamples = async () => {
        try {
            const res = await fetch('http://localhost:8000/api/pcap/samples');
            const data = await res.json();
            if (data.status === 'success') {
                setSamples(data.data.samples);
            }
        } catch (err) {
            console.error("Failed to fetch samples:", err);
        }
    };

    const stopPolling = () => {
        if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
        }
    };

    const handleFileSelect = (e) => {
        if (e.target.files && e.target.files[0]) {
            setSelectedFile(e.target.files[0]);
            setUploadStatus('idle');
            setError(null);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setSelectedFile(e.dataTransfer.files[0]);
            setUploadStatus('idle');
            setError(null);
        }
    };

    const handleUpload = () => {
        if (!selectedFile) return;

        setUploadStatus('uploading');
        setUploadProgress(0);
        setError(null);

        const formData = new FormData();
        formData.append('file', selectedFile);

        const xhr = new XMLHttpRequest();

        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                setUploadProgress(percent);
            }
        };

        xhr.onload = () => {
            if (xhr.status === 202) {
                const response = JSON.parse(xhr.responseText);
                setJobId(response.data.job_id);
                setUploadStatus('processing');
                startPolling(response.data.job_id);
            } else {
                setUploadStatus('error');
                try {
                    const resp = JSON.parse(xhr.responseText);
                    setError(resp.message || 'Upload failed');
                } catch (e) {
                    setError('Upload failed');
                }
            }
        };

        xhr.onerror = () => {
            setUploadStatus('error');
            setError('Network error during upload');
        };

        xhr.open('POST', 'http://localhost:8000/api/pcap/upload');
        xhr.send(formData);
    };

    const handleAnalyzeSample = async (sampleName) => {
        setUploadStatus('processing');
        setError(null);
        setProcessingProgress(0);

        try {
            const res = await fetch('http://localhost:8000/api/pcap/analyze-sample', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sample_name: sampleName })
            });
            const data = await res.json();

            if (data.status === 'success') {
                setJobId(data.data.job_id);
                startPolling(data.data.job_id);
            } else {
                setUploadStatus('error');
                setError(data.message || 'Analysis failed');
            }
        } catch (err) {
            setUploadStatus('error');
            setError('Network error');
        }
    };

    const startPolling = (id) => {
        stopPolling();
        pollIntervalRef.current = setInterval(async () => {
            try {
                const res = await fetch(`http://localhost:8000/api/pcap/status/${id}`);
                const data = await res.json();

                if (data.status === 'success') {
                    const job = data.data;
                    setProcessingProgress(job.progress);

                    if (job.status === 'complete') {
                        setResults(job.results);
                        setUploadStatus('complete');
                        stopPolling();
                    } else if (job.status === 'error') {
                        setUploadStatus('error');
                        setError(job.error || 'Processing failed');
                        stopPolling();
                    }
                }
            } catch (err) {
                console.error("Polling error:", err);
            }
        }, 1000);
    };

    const handleNewAnalysis = () => {
        setSelectedFile(null);
        setUploadStatus('idle');
        setResults(null);
        setJobId(null);
        setError(null);
        setUploadProgress(0);
        setProcessingProgress(0);
    };

    const handleExportResults = () => {
        if (!results) return;
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(results, null, 2));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", `pcap_analysis_${new Date().toISOString()}.json`);
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    };

    const formatSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    // --- RENDER HELPERS ---

    const renderUploadSection = () => (
        <div className="pcap-upload-section">
            <div className="section">
                <div className="section-header">
                    <h2 className="section-title">📦 PCAP File Analysis</h2>
                    <span className="section-subtitle">
                        Upload a network capture file or select a sample
                    </span>
                </div>

                <div
                    className={`pcap-upload-area ${uploadStatus === 'idle' ? '' : 'disabled'}`}
                    onDragOver={handleDragOver}
                    onDrop={handleDrop}
                    onClick={() => uploadStatus === 'idle' && fileInputRef.current.click()}
                >
                    <input
                        type="file"
                        ref={fileInputRef}
                        accept=".pcap,.pcapng,.cap"
                        onChange={handleFileSelect}
                        style={{ display: 'none' }}
                    />

                    <div className="upload-icon">📁</div>
                    <div className="upload-text">
                        {selectedFile
                            ? `Selected: ${selectedFile.name} (${formatSize(selectedFile.size)})`
                            : 'Drag & drop a .pcap file here or click to browse'}
                    </div>
                    <div className="upload-hint">
                        Supported: .pcap, .pcapng, .cap (max 50MB)
                    </div>
                </div>

                {selectedFile && uploadStatus === 'idle' && (
                    <button className="pcap-analyze-btn" onClick={handleUpload}>
                        🔍 Analyze File
                    </button>
                )}

                <div className="pcap-divider">
                    <span>OR SELECT A SAMPLE</span>
                </div>

                <div className="pcap-samples-grid">
                    {samples.map((sample, idx) => (
                        <div key={idx}
                            className="pcap-sample-card"
                            onClick={() => handleAnalyzeSample(sample.name)}>
                            <div className="sample-icon">📄</div>
                            <div className="sample-name">{sample.name}</div>
                            <div className="sample-size">{sample.size_human}</div>
                            <button className="sample-analyze-btn">Analyze</button>
                        </div>
                    ))}
                    {samples.length === 0 && (
                        <div className="empty-state">
                            <div className="empty-state-message">
                                No sample files available. Generate them with: <code>make generate-pcap</code>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );

    const renderProcessingSection = () => (
        <div className="pcap-processing-section">
            <div className="section">
                <h2 className="section-title">
                    {uploadStatus === 'uploading' ? '📤 Uploading...' : '🔄 Processing...'}
                </h2>

                <div className="progress-bar-container">
                    <div className="progress-bar-fill"
                        style={{
                            width: `${uploadStatus === 'uploading' ? uploadProgress : processingProgress}%`,
                            backgroundColor: '#3b82f6'
                        }}>
                    </div>
                </div>
                <div className="progress-text">
                    {uploadStatus === 'uploading'
                        ? `Uploading: ${uploadProgress}%`
                        : `Processing packets: ${processingProgress}%`}
                </div>

                {uploadStatus === 'processing' && (
                    <div className="processing-info">
                        <p>Analyzing packets with SecuriSphere detection engine...</p>
                        <p>Events will appear on the Events tab automatically.</p>
                    </div>
                )}
            </div>
        </div>
    );

    const renderResultsSection = () => {
        if (!results) return null;

        return (
            <div className="pcap-results-section">
                {/* File Info Card */}
                <div className="section">
                    <h2 className="section-title">📋 File Information</h2>
                    <div className="pcap-info-grid">
                        <div className="info-item">
                            <span className="info-label">File Name</span>
                            <span className="info-value">{results.file_info.file_name}</span>
                        </div>
                        <div className="info-item">
                            <span className="info-label">File Size</span>
                            <span className="info-value">{results.file_info.file_size_human}</span>
                        </div>
                        <div className="info-item">
                            <span className="info-label">Total Packets</span>
                            <span className="info-value">{results.file_info.total_packets}</span>
                        </div>
                        <div className="info-item">
                            <span className="info-label">Duration</span>
                            <span className="info-value">
                                {results.file_info.time_range?.duration_seconds?.toFixed(1) || 'N/A'}s
                            </span>
                        </div>
                        <div className="info-item">
                            <span className="info-label">Unique IPs</span>
                            <span className="info-value">{results.file_info.unique_source_ips?.length || 0}</span>
                        </div>
                        <div className="info-item">
                            <span className="info-label">Unique Ports</span>
                            <span className="info-value">{results.file_info.total_unique_ports || 0}</span>
                        </div>
                    </div>
                </div>

                {/* Charts Row */}
                <div className="pcap-charts-row">
                    {/* Packet Type Distribution */}
                    <div className="section pcap-chart-card">
                        <h2 className="section-title">Packet Type Distribution</h2>
                        <div className="chart-container" style={{ height: '250px' }}>
                            <Pie
                                data={{
                                    labels: Object.keys(results.file_info.packet_type_distribution || {}),
                                    datasets: [{
                                        data: Object.values(results.file_info.packet_type_distribution || {}),
                                        backgroundColor: [
                                            'rgba(59, 130, 246, 0.8)',   // TCP - blue
                                            'rgba(168, 85, 247, 0.8)',   // UDP - purple
                                            'rgba(6, 182, 212, 0.8)',    // DNS - cyan
                                            'rgba(249, 115, 22, 0.8)',   // ICMP - orange
                                            'rgba(100, 116, 139, 0.8)',  // Other - gray
                                        ],
                                        borderWidth: 0
                                    }]
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    plugins: {
                                        legend: {
                                            position: 'bottom',
                                            labels: { color: '#94a3b8', font: { size: 12 } }
                                        }
                                    }
                                }}
                            />
                        </div>
                    </div>

                    {/* Source IP Distribution */}
                    <div className="section pcap-chart-card">
                        <h2 className="section-title">Top Source IPs</h2>
                        <div className="chart-container" style={{ height: '250px' }}>
                            <Bar
                                data={{
                                    labels: (results.source_ip_distribution || []).slice(0, 10).map(d => d.ip),
                                    datasets: [{
                                        label: 'Packets',
                                        data: (results.source_ip_distribution || []).slice(0, 10).map(d => d.count),
                                        backgroundColor: 'rgba(59, 130, 246, 0.6)',
                                        borderColor: 'rgba(59, 130, 246, 1)',
                                        borderWidth: 1
                                    }]
                                }}
                                options={{
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    indexAxis: 'y',
                                    plugins: {
                                        legend: { display: false }
                                    },
                                    scales: {
                                        x: {
                                            grid: { color: 'rgba(255,255,255,0.05)' },
                                            ticks: { color: '#94a3b8' }
                                        },
                                        y: {
                                            grid: { display: false },
                                            ticks: { color: '#94a3b8', font: { family: 'monospace' } }
                                        }
                                    }
                                }}
                            />
                        </div>
                    </div>
                </div>

                {/* Detection Results */}
                <div className="section">
                    <div className="section-header">
                        <h2 className="section-title">🔍 Detection Results</h2>
                        <span className="section-subtitle">
                            {results.events_detected || 0} security events detected
                        </span>
                    </div>

                    {results.events_detected > 0 ? (
                        <>
                            {/* Detection Summary Cards */}
                            <div className="metric-cards" style={{ marginBottom: '16px' }}>
                                <div className="metric-card">
                                    <div className="metric-card-title">Events Detected</div>
                                    <div className="metric-card-value">{results.events_detected}</div>
                                </div>
                                <div className="metric-card">
                                    <div className="metric-card-title">Packets Analyzed</div>
                                    <div className="metric-card-value">{results.file_info.total_packets}</div>
                                </div>
                                <div className="metric-card highlight">
                                    <div className="metric-card-title">Detection Rate</div>
                                    <div className="metric-card-value">
                                        {results.file_info.total_packets > 0
                                            ? ((results.events_detected / results.file_info.total_packets) * 100).toFixed(2)
                                            : 0}%
                                    </div>
                                </div>
                                <div className="metric-card">
                                    <div className="metric-card-title">Analysis Time</div>
                                    <div className="metric-card-value">
                                        {results.analysis_duration?.toFixed(1) || 'N/A'}s
                                    </div>
                                </div>
                            </div>

                            {/* Events List */}
                            <div className="pcap-events-list">
                                {(results.detected_events || []).map((event, idx) => (
                                    <div key={idx} className="pcap-event-item"
                                        style={{ borderLeft: `3px solid var(--${event.severity?.level || 'medium'})` }}>
                                        <div className="pcap-event-header">
                                            <span className={`severity-badge severity-${event.severity?.level}`}>
                                                {event.severity?.level?.toUpperCase()}
                                            </span>
                                            <span className="pcap-event-type">{event.event_type}</span>
                                            <span className="pcap-event-time">
                                                {new Date(event.timestamp).toLocaleTimeString()}
                                            </span>
                                        </div>
                                        <div className="pcap-event-desc">
                                            {event.detection_details?.description}
                                        </div>
                                        <div className="pcap-event-meta">
                                            <span>Source: {event.source_entity?.ip}</span>
                                            <span>Confidence: {(event.detection_details?.confidence * 100).toFixed(0)}%</span>
                                            {event.mitre_technique && (
                                                <span className="mitre-tag">{event.mitre_technique}</span>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="empty-state">
                            <div className="empty-state-icon">✅</div>
                            <div className="empty-state-title">No Threats Detected</div>
                            <div className="empty-state-message">
                                No security events were detected in this capture.
                                This may indicate normal network traffic.
                            </div>
                        </div>
                    )}
                </div>

                {/* Ports Scanned */}
                {results.file_info.unique_ports?.length > 10 && (
                    <div className="section">
                        <h2 className="section-title">🔌 Ports Observed</h2>
                        <div className="ports-grid">
                            {results.file_info.unique_ports.slice(0, 50).map((port, idx) => (
                                <span key={idx} className="port-badge">
                                    {port}
                                </span>
                            ))}
                            {results.file_info.total_unique_ports > 50 && (
                                <span className="port-badge port-more">
                                    +{results.file_info.total_unique_ports - 50} more
                                </span>
                            )}
                        </div>
                    </div>
                )}

                {/* Action Buttons */}
                <div className="pcap-actions">
                    <button className="header-btn" onClick={handleNewAnalysis}>
                        📦 Analyze Another File
                    </button>
                    <button className="header-btn" onClick={handleExportResults}>
                        📥 Export Results (JSON)
                    </button>
                </div>
            </div>
        );
    };

    const renderErrorSection = () => (
        <div className="pcap-error-section">
            <div className="section">
                <div className="empty-state">
                    <div className="empty-state-icon">❌</div>
                    <div className="empty-state-title">Analysis Failed</div>
                    <div className="empty-state-message">{error}</div>
                    <button className="header-btn" onClick={handleNewAnalysis}
                        style={{ marginTop: '16px' }}>
                        Try Again
                    </button>
                </div>
            </div>
        </div>
    );

    return (
        <div className="dashboard-content">
            {(uploadStatus === 'idle') && renderUploadSection()}
            {(uploadStatus === 'uploading' || uploadStatus === 'processing') && renderProcessingSection()}
            {uploadStatus === 'complete' && renderResultsSection()}
            {uploadStatus === 'error' && renderErrorSection()}
        </div>
    );
}

export default PcapTab;
