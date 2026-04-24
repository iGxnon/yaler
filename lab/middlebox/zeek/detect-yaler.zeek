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
# Assembles the JA3 raw string across multiple SSL events:
#   Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
# GREASE values (RFC 8701) are stripped from all fields before logging.

type JA3State: record {
    version:   count     &default=0;
    ciphers:   index_vec &default=index_vec();
    ext_types: index_vec &default=index_vec();
    curves:    index_vec &default=index_vec();
    pf:        index_vec &default=index_vec();
};

global ja3_pending: table[string] of JA3State &read_expire=60sec;

# GREASE values (RFC 8701): both bytes equal, low nibble 0x0A
function is_grease(v: count): bool {
    return (v & 0xff) == ((v >> 8) & 0xff) && (v & 0x0f) == 10;
}

function vec_to_ja3_str(v: index_vec): string {
    local s = "";
    for (i in v) {
        if (is_grease(v[i])) next;
        if (s != "") s += "-";
        s += fmt("%d", v[i]);
    }
    return s;
}

event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec)
{
    local st: JA3State;
    st$version = version;
    st$ciphers = ciphers;
    ja3_pending[c$uid] = st;
}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
{
    if (!is_orig || c$uid !in ja3_pending) return;
    local st = ja3_pending[c$uid];
    st$ext_types[|st$ext_types|] = code;
    ja3_pending[c$uid] = st;
}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
{
    if (!is_orig || c$uid !in ja3_pending) return;
    ja3_pending[c$uid]$curves = curves;
}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec)
{
    if (!is_orig || c$uid !in ja3_pending) return;
    ja3_pending[c$uid]$pf = point_formats;
}

event ssl_established(c: connection)
{
    if (c$uid !in ja3_pending) return;
    local st = ja3_pending[c$uid];
    delete ja3_pending[c$uid];

    local sni = "-";
    if (c?$ssl && c$ssl?$server_name)
        sni = c$ssl$server_name;

    local ja3_raw = fmt("%d,%s,%s,%s,%s",
                        st$version,
                        vec_to_ja3_str(st$ciphers),
                        vec_to_ja3_str(st$ext_types),
                        vec_to_ja3_str(st$curves),
                        vec_to_ja3_str(st$pf));

    Log::write(YalerDetect::LOG, YalerDetect::Info(
        $ts         = network_time(),
        $uid        = c$uid,
        $src        = c$id$orig_h,
        $dst        = c$id$resp_h,
        $dport      = c$id$resp_p,
        $proto      = "tls-hello",
        $detail     = fmt("sni=%s ja3_raw=%s", sni, ja3_raw),
        $suspicious = F,
        $score      = 0
    ));
}
