import os
import time
import json
import uuid
import threading
import logging
import redis
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from gevent import monkey
# Patch gevent
monkey.patch_all()

from pcap_handler import PcapProcessor

# ... (logging setup) ...

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("SecuriSphereBackend")
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Flask Setup
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# Redis Config
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
SERVER_START_TIME = datetime.utcnow()

# Redis Connection
redis_client = None
redis_available = False
pcap_processor = None

def connect_redis():
    global redis_client, redis_available
    for i in range(5):
        try:
            redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            if redis_client.ping():
                redis_available = True
                logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
                
                # Initialize PCAP Processor
                global pcap_processor
                pcap_processor = PcapProcessor(redis_client)
                
                return
        except redis.ConnectionError:
            logger.warning("Redis connection failed. Retrying...")
            time.sleep(3)
    logger.error("WARNING: Redis unavailable.")
    redis_available = False

# --- Helper Functions ---

def get_events_from_redis(list_name, start=0, count=50):
    if not redis_available: return []
    try:
        raw_events = redis_client.lrange(list_name, start, start + count - 1)
        return [json.loads(e) for e in raw_events]
    except Exception as e:
        logger.error(f"Error reading {list_name}: {e}")
        return []

def get_all_events(limit=100):
    if not redis_available: return []
    # Merge events from all layers
    network = get_events_from_redis("events:network", 0, limit)
    api = get_events_from_redis("events:api", 0, limit)
    auth = get_events_from_redis("events:auth", 0, limit)
    
    all_events = network + api + auth
    # Sort by timestamp descending
    all_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return all_events[:limit]

def get_incidents(limit=50):
    if not redis_available: return []
    try:
        raw = redis_client.lrange('incidents', 0, limit - 1)
        return [json.loads(i) for i in raw]
    except Exception as e:
        logger.error(f"Error reading incidents: {e}")
        return []

def get_risk_scores():
    if not redis_available: return {}
    try:
        raw = redis_client.hgetall('risk_scores_current')
        return {k: json.loads(v) for k, v in raw.items()}
    except Exception as e:
        logger.error(f"Error reading risk scores: {e}")
        return {}

def get_latest_summary():
    default_summary = {
        "total_events_in_window": 0,
        "events_by_layer": {"network": 0, "api": 0, "auth": 0},
        "events_by_type": {},
        "top_sources": {},
        "active_incidents": 0,
        "risk_scores": {},
        "timestamp": datetime.utcnow().isoformat()
    }
    if not redis_available: return default_summary
    try:
        raw = redis_client.get('latest_summary')
        return json.loads(raw) if raw else default_summary
    except:
        return default_summary

def calculate_metrics():
    metrics = {
        "raw_events": {"network": 0, "api": 0, "auth": 0, "total": 0},
        "correlated_incidents": 0,
        "alert_reduction_percentage": 0,
        "active_risk_entities": 0,
        "events_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "events_by_type": defaultdict(int),
        "system_uptime": str(datetime.utcnow() - SERVER_START_TIME),
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if not redis_available: return metrics
    
    try:
        # Counts
        metrics["raw_events"]["network"] = redis_client.llen('events:network')
        metrics["raw_events"]["api"] = redis_client.llen('events:api')
        metrics["raw_events"]["auth"] = redis_client.llen('events:auth')
        metrics["raw_events"]["total"] = sum(metrics["raw_events"].values())
        
        metrics["correlated_incidents"] = redis_client.llen('incidents')
        
        if metrics["raw_events"]["total"] > 0:
            metrics["alert_reduction_percentage"] = round(
                (1 - metrics["correlated_incidents"] / metrics["raw_events"]["total"]) * 100, 1
            )
            
        # Risk Entities
        risks = get_risk_scores()
        metrics["active_risk_entities"] = len([r for r in risks.values() if r.get('current_score', 0) > 30])
        
        # Severity & Types (Sample last 200 events)
        sample = get_all_events(200)
        for e in sample:
            sev = e.get('severity', {}).get('level', 'low')
            metrics["events_by_severity"][sev] += 1
            metrics["events_by_type"][e.get('event_type', 'unknown')] += 1
            
    except Exception as e:
        logger.error(f"Error calculating metrics: {e}")
        
    return metrics

def calculate_event_stats(events):
    stats = {
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_type": defaultdict(int),
        "unique_sources": set()
    }
    for e in events:
        sev = e.get('severity', {}).get('level', 'low')
        if sev in stats["by_severity"]:
            stats["by_severity"][sev] += 1
        stats["by_type"][e.get('event_type', 'unknown')] += 1
        stats["unique_sources"].add(e.get('source_entity', {}).get('ip'))
    
    stats["unique_sources"] = len(stats["unique_sources"])
    return stats

# --- Middleware ---

@app.before_request
def log_request():
    if request.path != '/api/health':
        pass # Too noisy

@app.after_request
def add_headers(response):
    response.headers['X-SecuriSphere-Version'] = '1.0.0'
    return response

# --- REST API Endpoints ---

@app.route('/api/health')
def health():
    return jsonify({
        "status": "healthy",
        "service": "securisphere-backend",
        "redis_connected": redis_available,
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    })

@app.route('/api/dashboard/summary')
def dashboard_summary():
    metrics = calculate_metrics()
    return jsonify({
        "status": "success",
        "data": {
            "summary": get_latest_summary(),
            "metrics": {
                "raw_events": metrics["raw_events"],
                "correlated_incidents": metrics["correlated_incidents"],
                "alert_reduction_percentage": metrics["alert_reduction_percentage"],
                "active_threats": metrics["active_risk_entities"],
                "critical_events": metrics["events_by_severity"]["critical"]
            },
            "recent_incidents": get_incidents(5),
            "risk_scores": get_risk_scores(),
            "events_by_layer": metrics["raw_events"], # simplified
            "timestamp": datetime.utcnow().isoformat()
        }
    })

@app.route('/api/events')
def get_events():
    layer = request.args.get('layer', 'all')
    limit = min(int(request.args.get('limit', 50)), 500)
    severity = request.args.get('severity', 'all')
    ev_type = request.args.get('event_type')
    
    if layer == 'all':
        events = get_all_events(limit) # This limits first, then filters. Might need optimization for deep filtering
        # Optimize: get more then filter? For now, fetch limit*2 to allow some filtering space
        if severity != 'all' or ev_type:
            events = get_all_events(limit * 5) 
    else:
        events = get_events_from_redis(f"events:{layer}", 0, limit * 5)
        
    # Filtering
    filtered = []
    for e in events:
        if severity != 'all' and e.get('severity', {}).get('level') != severity:
            continue
        if ev_type and e.get('event_type') != ev_type:
            continue
        filtered.append(e)
        
    # Apply limit after filtering
    final_events = filtered[:limit]
    
    return jsonify({
        "status": "success",
        "data": {
            "events": final_events,
            "count": len(final_events),
            "total_available": {
                "network": redis_client.llen("events:network") if redis_available else 0,
                "api": redis_client.llen("events:api") if redis_available else 0,
                "auth": redis_client.llen("events:auth") if redis_available else 0
            },
            "filters_applied": {
                "layer": layer,
                "severity": severity,
                "event_type": ev_type,
                "limit": limit
            },
            "stats": calculate_event_stats(final_events)
        }
    })

@app.route('/api/events/<event_id>')
def get_single_event(event_id):
    # Search in all lists (expensive but necessary without index)
    # Optimization: Search recent 1000 first
    all_ev = get_all_events(1000)
    for e in all_ev:
        if e.get('event_id') == event_id:
            return jsonify({"status": "success", "data": {"event": e}})
    return jsonify({"status": "error", "message": "Event not found"}), 404

@app.route('/api/incidents')
def list_incidents():
    limit = min(int(request.args.get('limit', 20)), 100)
    incidents = get_incidents(limit)
    return jsonify({
        "status": "success",
        "data": {
            "incidents": incidents,
            "count": len(incidents),
            "total_available": redis_client.llen("incidents") if redis_available else 0
        }
    })

@app.route('/api/incidents/<incident_id>')
def get_incident(incident_id):
    incidents = get_incidents(100)
    for i in incidents:
        if i.get('incident_id') == incident_id:
            return jsonify({"status": "success", "data": {"incident": i}})
    return jsonify({"status": "error", "message": "Incident not found"}), 404

@app.route('/api/risk-scores')
def list_risk_scores():
    risks = get_risk_scores()
    
    # Calculate summary
    summary = {
        "total_entities": len(risks),
        "critical_count": 0, 
        "threatening_count": 0,
        "suspicious_count": 0,
        "normal_count": 0
    }
    
    for r in risks.values():
        score = r.get('current_score', 0)
        if score >= 90: summary["critical_count"] += 1
        elif score >= 70: summary["threatening_count"] += 1
        elif score >= 30: summary["suspicious_count"] += 1
        else: summary["normal_count"] += 1
            
    return jsonify({
        "status": "success",
        "data": {
            "risk_scores": risks,
            "summary": summary
        }
    })

@app.route('/api/risk-scores/<ip>')
def get_ip_risk(ip):
    risks = get_risk_scores()
    if ip in risks:
        return jsonify({"status": "success", "data": risks[ip]})
    return jsonify({"status": "error", "message": "Risk score not found"}), 404

@app.route('/api/metrics')
def system_metrics():
    return jsonify({
        "status": "success", 
        "data": calculate_metrics()
    })

@app.route('/api/metrics/timeline')
def metrics_timeline():
    # Mocking timeline for now as we don't have time-series DB
    # In real impl, we would bucket recent events
    minutes = int(request.args.get('minutes', 30))
    events = get_all_events(500) # Get recent
    
    timeline = defaultdict(lambda: {"timestamp": "", "network": 0, "api": 0, "auth": 0, "total": 0})
    now = datetime.utcnow()
    
    # Init buckets
    for i in range(minutes):
        t = (now - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:00Z")
        timeline[t]["timestamp"] = t
        
    for e in events:
        ts_str = e.get('timestamp')
        if ts_str:
            try:
                # Truncate to minute
                ts = datetime.fromisoformat(ts_str.replace('Z', ''))
                key = ts.strftime("%Y-%m-%dT%H:%M:00Z")
                if key in timeline:
                    layer = e.get('source_layer', 'other')
                    timeline[key][layer] += 1
                    timeline[key]['total'] += 1
            except:
                pass
                
    return jsonify({
        "status": "success",
        "data": {
            "timeline": sorted([v for v in timeline.values()], key=lambda x: x['timestamp']),
            "time_range": {"minutes": minutes}
        }
    })

@app.route('/api/events/latest')
def latest_events():
    return jsonify({
        "status": "success",
        "data": {
            "latest": {
                "network": (get_events_from_redis("events:network", 0, 1) or [None])[0],
                "api": (get_events_from_redis("events:api", 0, 1) or [None])[0],
                "auth": (get_events_from_redis("events:auth", 0, 1) or [None])[0]
            }
        }
    })

@app.route('/api/events/clear', methods=['POST'])
def clear_events():
    if redis_available:
        redis_client.delete("events:network", "events:api", "events:auth", "incidents", "risk_scores_current", "latest_summary")
    return jsonify({
        "status": "success", 
        "message": "All events and incidents cleared",
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/api/system/status')
def system_status():
    status = {
        "redis": {"connected": redis_available},
        "monitors": {},
        "correlation_engine": {"active": False, "incidents": 0},
        "total_events": 0,
        "uptime_seconds": (datetime.utcnow() - SERVER_START_TIME).seconds
    }
    
    if redis_available:
        status["redis"]["ping"] = "PONG"
        
        # Check monitors
        monitors = ["network", "api", "auth"]
        for m in monitors:
            last = (get_events_from_redis(f"events:{m}", 0, 1) or [{}])[0]
            status["monitors"][m] = {
                "active": last is not None,
                "last_event": last.get('timestamp'),
                "event_count": redis_client.llen(f"events:{m}")
            }
            status["total_events"] += status["monitors"][m]["event_count"]
            
        status["correlation_engine"]["incidents"] = redis_client.llen("incidents")
        
    return jsonify({"status": "success", "data": status})

# --- PCAP Endpoints ---

@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    if not pcap_processor:
        return jsonify({"status": "error", "message": "PCAP Processor not initialized (Redis unavailable)"}), 503
        
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file provided"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"}), 400
        
    if not pcap_processor.validate_file(file.filename):
        return jsonify({"status": "error", "message": "Invalid file type. Allowed: .pcap, .pcapng, .cap"}), 400
        
    try:
        file_path = pcap_processor.save_uploaded_file(file)
        job_id = pcap_processor.start_processing(file_path)
        
        return jsonify({
            "status": "success",
            "message": "File uploaded and processing started",
            "data": {
                "job_id": job_id,
                "file_name": file.filename,
                "status": "queued"
            }
        }), 202
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 413
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/api/pcap/status/<job_id>')
def pcap_status(job_id):
    if not pcap_processor:
        return jsonify({"status": "error", "message": "Service unavailable"}), 503
        
    job = pcap_processor.get_job_status(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found"}), 404
        
    return jsonify({
        "status": "success",
        "data": {
            "job_id": job_id,
            "status": job["status"],
            "progress": job["progress"],
            "file": job["file"],
            "started_at": job["started_at"],
            "completed_at": job["completed_at"],
            "results": job["results"],
            "error": job["error"]
        }
    })

@app.route('/api/pcap/jobs')
def pcap_jobs():
    if not pcap_processor: return jsonify({"data": {"jobs": [], "count": 0}})
    
    jobs = pcap_processor.get_all_jobs()
    return jsonify({
        "status": "success",
        "data": {
            "jobs": jobs,
            "count": len(jobs)
        }
    })

@app.route('/api/pcap/samples')
def pcap_samples():
    if not pcap_processor: return jsonify({"data": {"samples": [], "count": 0}})
    
    samples = pcap_processor.get_sample_files()
    return jsonify({
        "status": "success",
        "data": {
            "samples": samples,
            "count": len(samples)
        }
    })

@app.route('/api/pcap/analyze-sample', methods=['POST'])
def analyze_sample():
    if not pcap_processor: return jsonify({"error": "Service unavailable"}), 503
    
    data = request.json
    sample_name = data.get('sample_name')
    if not sample_name:
        return jsonify({"status": "error", "message": "sample_name required"}), 400
        
    # Find sample path
    samples = pcap_processor.get_sample_files()
    sample_path = next((s['path'] for s in samples if s['name'] == sample_name), None)
    
    if not sample_path:
        return jsonify({"status": "error", "message": "Sample file not found"}), 404
        
    job_id = pcap_processor.start_processing(sample_path)
    return jsonify({
        "status": "success",
        "data": {"job_id": job_id, "status": "queued"}
    }), 202

@app.route('/api/pcap/info/<job_or_sample>')
def pcap_info(job_or_sample):
    if not pcap_processor: return jsonify({"error": "Service unavailable"}), 503
    
    file_path = None
    
    # Check if job
    job = pcap_processor.get_job_status(job_or_sample)
    if job:
        file_path = job['file_path']
    else:
        # Check if sample
        samples = pcap_processor.get_sample_files()
        file_path = next((s['path'] for s in samples if s['name'] == job_or_sample), None)
        
    if not file_path or not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "File not found"}), 404
        
    try:
        info = pcap_processor.get_pcap_info(file_path)
        return jsonify({"status": "success", "data": info})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Error Handling ---

@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Endpoint not found", "code": 404}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": "error", "message": "Internal server error", "code": 500}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {e}")
    return jsonify({"status": "error", "message": "Unexpected error", "code": 500}), 500

# --- WebSocket ---

@socketio.on('connect')
def ws_connect():
    logger.info(f"[WS] Client connected: {request.sid}")
    # Send initial state
    emit('initial_state', {
        "summary": get_latest_summary(),
        "metrics": calculate_metrics(),
        "recent_events": get_all_events(20),
        "recent_incidents": get_incidents(10),
        "risk_scores": get_risk_scores()
    })

@socketio.on('disconnect')
def ws_disconnect():
    logger.info(f"[WS] Client disconnected: {request.sid}")

@socketio.on('request_refresh')
def ws_refresh():
    emit('full_refresh', {
        "summary": get_latest_summary(),
        "metrics": calculate_metrics(),
        "recent_events": get_all_events(20),
        "recent_incidents": get_incidents(10),
        "risk_scores": get_risk_scores()
    })

# --- Background Threads ---

def redis_subscriber():
    # Separate connection for PubSub
    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            pubsub = r.pubsub()
            pubsub.subscribe("security_events", "correlated_incidents", "risk_scores", "correlation_summary")
            
            logger.info("[WS] Subscribed to Redis channels")
            
            for message in pubsub.listen():
                if message['type'] == 'message':
                    data = json.loads(message['data'])
                    channel = message['channel']
                    
                    if channel == "security_events":
                        socketio.emit('new_event', data)
                    elif channel == "correlated_incidents":
                        socketio.emit('new_incident', data)
                    elif channel == "risk_scores":
                        socketio.emit('risk_update', data)
                    elif channel == "correlation_summary":
                        socketio.emit('summary_update', data)
                        
        except Exception as e:
            logger.error(f"[WS] Redis subscriber error: {e}")
            time.sleep(5)

def periodic_metrics():
    while True:
        try:
            time.sleep(10)
            socketio.emit('metrics_update', calculate_metrics())
            
            if int(time.time()) % 30 == 0:
                # Re-use logic from endpoint (simplified)
                # Ideally refactor to shared func
                pass 
        except Exception as e:
            logger.error(f"Metrics thread error: {e}")

# --- Startup ---

if __name__ == '__main__':
    connect_redis()
    
    # Start threads
    t1 = threading.Thread(target=redis_subscriber)
    t1.daemon = True
    t1.start()
    
    t2 = threading.Thread(target=periodic_metrics)
    t2.daemon = True
    t2.start()
    
    print("========================================")
    print("  SecuriSphere Backend API v1.0.0")
    print("========================================")
    print("  REST API:   http://0.0.0.0:8000")
    print("  WebSocket:  ws://0.0.0.0:8000")
    print(f"  Redis:      {REDIS_HOST}:{REDIS_PORT}")
    print("========================================")
    
    socketio.run(app, host='0.0.0.0', port=8000, debug=False, allow_unsafe_werkzeug=True)
