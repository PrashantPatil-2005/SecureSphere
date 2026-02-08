# =============================================================================
# SecuriSphere - Zeek Local Configuration
# Network traffic analysis for baseline anomaly detection
# =============================================================================

# Load the standard Zeek scripts
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl

# Load policy scripts for additional context
@load policy/protocols/http/header-names
@load policy/protocols/http/software
@load policy/protocols/ssl/validate-certs
@load policy/misc/stats
@load policy/misc/scan

# Enable JSON output for easier parsing
@load policy/tuning/json-logs

# =============================================================================
# Logging Configuration
# =============================================================================

redef Log::default_rotation_interval = 1hr;
redef LogAscii::use_json = T;

# =============================================================================
# HTTP Analysis - Important for API security monitoring
# =============================================================================

# Log full HTTP headers for better analysis
redef HTTP::default_capture_password = T;

# =============================================================================
# Connection Analysis
# =============================================================================

# Track connection states for anomaly detection
redef Conn::analyze_state = T;

# =============================================================================
# Network Configuration
# =============================================================================

# Define our lab network as local
redef Site::local_nets += { 172.28.0.0/16 };

# =============================================================================
# Custom event handlers for SecuriSphere
# =============================================================================

event zeek_init()
{
    print "SecuriSphere Zeek monitor initialized";
    print fmt("Monitoring network: %s", Site::local_nets);
}

event connection_established(c: connection)
{
    # Log when connections are established to our victim
    if ( c$id$resp_h == 172.28.0.10 )
    {
        print fmt("Connection to victim from %s:%s", 
                  c$id$orig_h, c$id$orig_p);
    }
}

event http_request(c: connection, method: string, original_URI: string, 
                   unescaped_URI: string, version: string)
{
    # Log HTTP requests to the victim API
    if ( c$id$resp_h == 172.28.0.10 )
    {
        print fmt("HTTP %s %s from %s", 
                  method, original_URI, c$id$orig_h);
    }
}
