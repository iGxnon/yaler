##! detect-yaler.zeek — Behavioral detection of Yaler tunnel traffic
##!
##! Detects:
##!   1. WebSocket upgrades (especially to the /sw path)
##!   2. Long-lived TLS connections on port 443 with high byte counts (tunneling)
##!   3. TLS connections — logs cert + cipher info for offline JA3 comparison

module YalerDetect;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time      &log;
        uid:         string    &log;
        src:         addr      &log;
        dst:         addr      &log;
        dport:       port      &log;
        proto:       string    &log;
        detail:      string    &log;
        suspicious:  bool      &log;
        score:       count     &log &default=0;
    };
}

event zeek_init() {
    Log::create_stream(YalerDetect::LOG,
        [$columns=YalerDetect::Info, $path="yaler_detect"]);
    print "YalerDetect: detection module loaded";
}

# ── 1. WebSocket upgrade detection ────────────────────────────────────────────
# Header names in Zeek are normalized to uppercase.
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (!is_orig) return;
    if (name != "UPGRADE") return;
    if (/[Ww]eb[Ss]ocket/ !in value) return;

    local uri = "-";
    if (c?$http && c$http?$uri) uri = c$http$uri;

    local user_agent = "-";
    if (c?$http && c$http?$user_agent) user_agent = c$http$user_agent;

    # /sw is the default Yaler path; score higher for exact match
    local score = 1;
    if (uri == "/sw") score = 10;

    Log::write(YalerDetect::LOG, YalerDetect::Info(
        $ts         = network_time(),
        $uid        = c$uid,
        $src        = c$id$orig_h,
        $dst        = c$id$resp_h,
        $dport      = c$id$resp_p,
        $proto      = "websocket-upgrade",
        $detail     = fmt("uri=%s ua=%s", uri, user_agent),
        $suspicious = (score >= 10),
        $score      = score
    ));
}

# ── 2. Long-lived TLS tunnel detection ────────────────────────────────────────
event connection_state_remove(c: connection) {
    # Only care about TLS ports
    local p = c$id$resp_p;
    if (p != 443/tcp && p != 8443/tcp) return;

    if (!c?$duration) return;
    if (c$duration < 30 sec) return;

    local orig_bytes: count = 0;
    local resp_bytes: count = 0;
    if (c?$orig) orig_bytes = c$orig$size;
    if (c?$resp)  resp_bytes = c$resp$size;
    local total = orig_bytes + resp_bytes;

    # High-volume, long-lived TLS = likely tunnel
    local score = 0;
    if (c$duration > 60 sec)  score += 3;
    if (c$duration > 300 sec) score += 3;
    if (total > 100000)        score += 2;
    if (total > 1000000)       score += 2;

    Log::write(YalerDetect::LOG, YalerDetect::Info(
        $ts         = c$start_time,
        $uid        = c$uid,
        $src        = c$id$orig_h,
        $dst        = c$id$resp_h,
        $dport      = p,
        $proto      = "tls-long",
        $detail     = fmt("duration=%.1fs orig=%d resp=%d",
                          c$duration / 1sec, orig_bytes, resp_bytes),
        $suspicious = (score >= 5),
        $score      = score
    ));
}

# ── 3. TLS cipher / version fingerprinting ────────────────────────────────────
# Logs each TLS client hello's version, ciphers, and SNI for JA3 comparison.
# Actual JA3 hash computation is done offline by analyze.sh using tshark.
event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec) {
    local sni = "-";
    if (c?$ssl && c$ssl?$server_name) sni = c$ssl$server_name;

    local cipher_count = |ciphers|;

    # Chrome sends 15–17 ciphers with GREASE values; flag for manual review
    local detail = fmt("version=0x%x ciphers=%d sni=%s", version, cipher_count, sni);

    Log::write(YalerDetect::LOG, YalerDetect::Info(
        $ts         = network_time(),
        $uid        = c$uid,
        $src        = c$id$orig_h,
        $dst        = c$id$resp_h,
        $dport      = c$id$resp_p,
        $proto      = "tls-hello",
        $detail     = detail,
        $suspicious = F,
        $score      = 0
    ));
}
