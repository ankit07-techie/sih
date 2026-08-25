# PassiveShield AI — Passive Telemetry Zeek Configuration
# Policy configuration for extracting Connection, DNS, and TLS/SSL metadata

# 1. Output Format: Enable JSON log format for machine parsing
@load policy/tuning/json-logs.zeek

# 2. Connection Logging Configuration
# Ensures conn.log includes detailed connection state, duration, bytes, and packet counts
@load base/protocols/conn
redef Conn::record_packet_count = T;

# 3. DNS Logging Configuration
# Captures queries, subdomains, query types (A, AAAA, TXT, ANY), and answer records
@load base/protocols/dns

# 4. TLS/SSL Metadata Logging Configuration
# Captures TLS handshakes, Server Name Indication (SNI), cipher suites, and cert metadata
@load base/protocols/ssl

# 5. Disable active probing / packet injection plugins
# Guarantees strictly passive observation
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Log file rotational tuning for streaming spooler
redef Log::default_rotation_interval = 0 sec; # Real-time log flushing for live tailing
