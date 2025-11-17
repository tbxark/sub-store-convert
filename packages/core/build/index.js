// src/vendors/Sub-Store/backend/src/utils/index.js
var IPV4_REGEX = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$/;
var IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
function isIPv4(ip) {
  return IPV4_REGEX.test(ip);
}
function isIPv6(ip) {
  return IPV6_REGEX.test(ip);
}
function isNotBlank(str) {
  return typeof str === "string" && str.trim().length > 0;
}
function getIfNotBlank(str, defaultValue) {
  return isNotBlank(str) ? str : defaultValue;
}
function isPresent(obj) {
  return typeof obj !== "undefined" && obj !== null;
}
function getIfPresent(obj, defaultValue) {
  return isPresent(obj) ? obj : defaultValue;
}
function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function getRandomPort(portString) {
  let portParts = portString.split(/,|\//);
  let randomPart = portParts[Math.floor(Math.random() * portParts.length)];
  if (randomPart.includes("-")) {
    let [min, max] = randomPart.split("-").map(Number);
    return getRandomInt(min, max);
  } else {
    return Number(randomPart);
  }
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/peggy/surge.js
import * as peggy from "peggy";
var grammars = String.raw`
// global initializer
{{
    function $set(obj, path, value) {
      if (Object(obj) !== obj) return obj;
      if (!Array.isArray(path)) path = path.toString().match(/[^.[\]]+/g) || [];
      path
        .slice(0, -1)
        .reduce((a, c, i) => (Object(a[c]) === a[c] ? a[c] : (a[c] = Math.abs(path[i + 1]) >> 0 === +path[i + 1] ? [] : {})), obj)[
        path[path.length - 1]
      ] = value;
      return obj;
    }
}}

// per-parser initializer
{
    const proxy = {};
    const obfs = {};
    const $ = {};

    function handleWebsocket() {
        if (obfs.type === "ws") {
            proxy.network = "ws";
            $set(proxy, "ws-opts.path", obfs.path);
            $set(proxy, "ws-opts.headers", obfs['ws-headers']);
            if (proxy['ws-opts'] && proxy['ws-opts']['headers'] && proxy['ws-opts']['headers'].Host) {
                proxy['ws-opts']['headers'].Host = proxy['ws-opts']['headers'].Host.replace(/^"(.*)"$/, '$1')
            }
        }
    }
    function handleShadowTLS() {
        if (proxy['shadow-tls-password'] && !proxy['shadow-tls-version']) {
            proxy['shadow-tls-version'] = 2;
        }
    }
}

start = (shadowsocks/vmess/trojan/https/http/snell/socks5/socks5_tls/tuic/tuic_v5/wireguard/hysteria2/ssh/direct) {
    return proxy;
}

shadowsocks = tag equals "ss" address (method/passwordk/obfs/obfs_host/obfs_uri/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/udp_relay/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/udp_port/others)* {
    proxy.type = "ss";
    // handle obfs
    if (obfs.type == "http" || obfs.type === "tls") {
        proxy.plugin = "obfs";
        $set(proxy, "plugin-opts.mode", obfs.type);
        $set(proxy, "plugin-opts.host", obfs.host);
        $set(proxy, "plugin-opts.path", obfs.path);
    }
    handleShadowTLS();
}
vmess = tag equals "vmess" address (vmess_uuid/vmess_aead/ws/ws_path/ws_headers/method/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls/sni/tls_fingerprint/tls_verification/fast_open/tfo/udp_relay/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "vmess";
    proxy.cipher = proxy.cipher || "none";
    // Surfboard 与 Surge 默认不一致, 不管 Surfboard https://getsurfboard.com/docs/profile-format/proxy/external-proxy/vmess
    if (proxy.aead) {
        proxy.alterId = 0;
    } else {
        proxy.alterId = 1;
    }
    handleWebsocket();
    handleShadowTLS();
}
trojan = tag equals "trojan" address (passwordk/ws/ws_path/ws_headers/tls/sni/tls_fingerprint/tls_verification/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/udp_relay/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "trojan";
    handleWebsocket();
    handleShadowTLS();
}
https = tag equals "https" address (username password)? (usernamek passwordk)? (sni/tls_fingerprint/tls_verification/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "http";
    proxy.tls = true;
    handleShadowTLS();
}
http = tag equals "http" address (username password)? (usernamek passwordk)? (ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "http";
    handleShadowTLS();
}
ssh = tag equals "ssh" address (username password)? (usernamek passwordk)? (server_fingerprint/idle_timeout/private_key/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "ssh";
    handleShadowTLS();
}
snell = tag equals "snell" address (snell_version/snell_psk/obfs/obfs_host/obfs_uri/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/udp_relay/reuse/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "snell";
    // handle obfs
    if (obfs.type == "http" || obfs.type === "tls") {
        $set(proxy, "obfs-opts.mode", obfs.type);
        $set(proxy, "obfs-opts.host", obfs.host);
        $set(proxy, "obfs-opts.path", obfs.path);
    }
    handleShadowTLS();
}
tuic = tag equals "tuic" address (alpn/token/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls_fingerprint/tls_verification/sni/fast_open/tfo/ecn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/port_hopping_interval/others)* {
    proxy.type = "tuic";
    handleShadowTLS();
}
tuic_v5 = tag equals "tuic-v5" address (alpn/passwordk/uuidk/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls_fingerprint/tls_verification/sni/fast_open/tfo/ecn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/port_hopping_interval/others)* {
    proxy.type = "tuic";
    proxy.version = 5;
    handleShadowTLS();
}
wireguard = tag equals "wireguard" (section_name/no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "wireguard-surge";
    handleShadowTLS();
}
hysteria2 = tag equals "hysteria2" address (no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/sni/tls_verification/passwordk/tls_fingerprint/download_bandwidth/ecn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/port_hopping_interval/others)* {
    proxy.type = "hysteria2";
    handleShadowTLS();
}
socks5 = tag equals "socks5" address (username password)? (usernamek passwordk)? (udp_relay/no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "socks5";
    handleShadowTLS();
}
socks5_tls = tag equals "socks5-tls" address (username password)? (usernamek passwordk)? (udp_relay/no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/sni/tls_fingerprint/tls_verification/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "socks5";
    proxy.tls = true;
    handleShadowTLS();
}
direct = tag equals "direct" (udp_relay/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/block_quic/others)* {
    proxy.type = "direct";
}
address = comma server:server comma port:port {
    proxy.server = server;
    proxy.port = port;
}

server = ip/domain

ip = & {
    const start = peg$currPos;
    let j = start;
    while (j < input.length) {
        if (input[j] === ",") break;
        j++;
    }
    peg$currPos = j;
    $.ip = input.substring(start, j).trim();
    return true;
} { return $.ip; }

domain = match:[0-9a-zA-z-_.]+ { 
    const domain = match.join(""); 
    if (/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/.test(domain)) {
        return domain;
    }
}

port = digits:[0-9]+ { 
    const port = parseInt(digits.join(""), 10); 
    if (port >= 0 && port <= 65535) {
    	return port;
    }
}

port_hopping_interval = comma "port-hopping-interval" equals match:$[0-9]+ { proxy["hop-interval"] = parseInt(match.trim()); }

username = & {
    let j = peg$currPos; 
    let start, end;
    let first = true;
    while (j < input.length) {
        if (input[j] === ',') {
            if (first) {
                start = j + 1;
                first = false;
            } else {
                end = j;
                break;
            }
        }
        j++;
    }
    const match = input.substring(start, end);
    if (match.indexOf("=") === -1) {
        $.username = match;
        peg$currPos = end;
        return true;
    }
} { proxy.username = $.username.trim().replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
password = comma match:[^,]+ { proxy.password = match.join("").replace(/^"(.*)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }

tls = comma "tls" equals flag:bool { proxy.tls = flag; }
sni = comma "sni" equals sni:("off"/domain) { 
    if (sni === "off") {
        proxy["disable-sni"] = true;
    } else {
        proxy.sni = sni;
    }
}
tls_verification = comma "skip-cert-verify" equals flag:bool { proxy["skip-cert-verify"] = flag; }
tls_fingerprint = comma "server-cert-fingerprint-sha256" equals tls_fingerprint:$[^,]+ { proxy["tls-fingerprint"] = tls_fingerprint.trim(); }

snell_psk = comma "psk" equals match:[^,]+ { proxy.psk = match.join(""); }
snell_version = comma "version" equals match:$[0-9]+ { proxy.version = parseInt(match.trim()); }

usernamek = comma "username" equals match:[^,]+ { proxy.username = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
passwordk = comma "password" equals match:[^,]+ { proxy.password = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
vmess_uuid = comma "username" equals match:[^,]+ { proxy.uuid = match.join(""); }
vmess_aead = comma "vmess-aead" equals flag:bool { proxy.aead = flag; }

method = comma "encrypt-method" equals cipher:cipher {
    proxy.cipher = cipher;
}
cipher = ("aes-128-cfb"/"aes-128-ctr"/"aes-128-gcm"/"aes-192-cfb"/"aes-192-ctr"/"aes-192-gcm"/"aes-256-cfb"/"aes-256-ctr"/"aes-256-gcm"/"bf-cfb"/"camellia-128-cfb"/"camellia-192-cfb"/"camellia-256-cfb"/"cast5-cfb"/"chacha20-ietf-poly1305"/"chacha20-ietf"/"chacha20-poly1305"/"chacha20"/"des-cfb"/"idea-cfb"/"none"/"rc2-cfb"/"rc4-md5"/"rc4"/"salsa20"/"seed-cfb"/"xchacha20-ietf-poly1305"/"2022-blake3-aes-128-gcm"/"2022-blake3-aes-256-gcm");

ws = comma "ws" equals flag:bool { obfs.type = "ws"; }
ws_headers = comma "ws-headers" equals headers:$[^,]+ {
    const pairs = headers.split("|");
    const result = {};
    pairs.forEach(pair => {
        const [key, value] = pair.trim().split(":");
        result[key.trim()] = value.trim().replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1');
    })
    obfs["ws-headers"] = result;
}
ws_path = comma "ws-path" equals path:uri { obfs.path = path.trim().replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }

obfs = comma "obfs" equals type:("http"/"tls") { obfs.type = type; }
obfs_host = comma "obfs-host" equals host:domain { obfs.host = host; };
obfs_uri = comma "obfs-uri" equals path:uri { obfs.path = path }
uri = $[^,]+

udp_relay = comma "udp-relay" equals flag:bool { proxy.udp = flag; }
fast_open = comma "fast-open" equals flag:bool { proxy.tfo = flag; }
reuse = comma "reuse" equals flag:bool { proxy.reuse = flag; }
ecn = comma "ecn" equals flag:bool { proxy.ecn = flag; }
tfo = comma "tfo" equals flag:bool { proxy.tfo = flag; }
ip_version = comma "ip-version" equals match:[^,]+ { proxy["ip-version"] = match.join(""); }
section_name = comma "section-name" equals match:[^,]+ { proxy["section-name"] = match.join(""); }
no_error_alert = comma "no-error-alert" equals match:[^,]+ { proxy["no-error-alert"] = match.join(""); }
underlying_proxy = comma "underlying-proxy" equals match:[^,]+ { proxy["underlying-proxy"] = match.join(""); }
download_bandwidth = comma "download-bandwidth" equals match:[^,]+ { proxy.down = match.join(""); }
test_url = comma "test-url" equals match:[^,]+ { proxy["test-url"] = match.join(""); }
test_udp = comma "test-udp" equals match:[^,]+ { proxy["test-udp"] = match.join(""); }
test_timeout = comma "test-timeout" equals match:$[0-9]+ { proxy["test-timeout"] = parseInt(match.trim()); }
tos = comma "tos" equals match:$[0-9]+ { proxy.tos = parseInt(match.trim()); }
interface = comma "interface" equals match:[^,]+ { proxy.interface = match.join(""); }
allow_other_interface = comma "allow-other-interface" equals flag:bool { proxy["allow-other-interface"] = flag; }
hybrid = comma "hybrid" equals flag:bool { proxy.hybrid = flag; }
idle_timeout = comma "idle-timeout" equals match:$[0-9]+ { proxy["idle-timeout"] = parseInt(match.trim()); }
private_key = comma "private-key" equals match:[^,]+ { proxy["keystore-private-key"] = match.join("").replace(/^"(.*)"$/, '$1'); }
server_fingerprint = comma "server-fingerprint" equals match:[^,]+ { proxy["server-fingerprint"] = match.join("").replace(/^"(.*)"$/, '$1'); }
block_quic = comma "block-quic" equals match:[^,]+ { proxy["block-quic"] = match.join(""); }
udp_port = comma "udp-port" equals match:$[0-9]+ { proxy["udp-port"] = parseInt(match.trim()); }
shadow_tls_version = comma "shadow-tls-version" equals match:$[0-9]+ { proxy["shadow-tls-version"] = parseInt(match.trim()); }
shadow_tls_sni = comma "shadow-tls-sni" equals match:[^,]+ { proxy["shadow-tls-sni"] = match.join(""); }
shadow_tls_password = comma "shadow-tls-password" equals match:[^,]+ { proxy["shadow-tls-password"] = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
token = comma "token" equals match:[^,]+ { proxy.token = match.join(""); }
alpn = comma "alpn" equals match:[^,]+ { proxy.alpn = match.join(""); }
uuidk = comma "uuid" equals match:[^,]+ { proxy.uuid = match.join(""); }

tag = match:[^=,]* { proxy.name = match.join("").trim(); }
comma = _ "," _
equals = _ "=" _
_ = [ \r\t]*
bool = b:("true"/"false") { return b === "true" }
others = comma [^=,]+ equals [^=,]+
`;
var parser;
function getParser() {
  if (!parser) {
    parser = peggy.generate(grammars);
  }
  return parser;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/peggy/loon.js
import * as peggy2 from "peggy";
var grammars2 = String.raw`
// global initializer
{{
    function $set(obj, path, value) {
      if (Object(obj) !== obj) return obj;
      if (!Array.isArray(path)) path = path.toString().match(/[^.[\]]+/g) || [];
      path
        .slice(0, -1)
        .reduce((a, c, i) => (Object(a[c]) === a[c] ? a[c] : (a[c] = Math.abs(path[i + 1]) >> 0 === +path[i + 1] ? [] : {})), obj)[
        path[path.length - 1]
      ] = value;
      return obj;
    }
}}

// per-parser initializer
{
    const proxy = {};
    const obfs = {};
    const transport = {};
    const $ = {};

    function handleTransport() {
        if (transport.type === "tcp") { /* do nothing */ }
        else if (transport.type === "ws") {
            proxy.network = "ws";
            $set(proxy, "ws-opts.path", transport.path);
            $set(proxy, "ws-opts.headers.Host", transport.host);
        } else if (transport.type === "http") {
            proxy.network = "http";
            $set(proxy, "http-opts.path", transport.path);
            $set(proxy, "http-opts.headers.Host", transport.host);
        }
    }
}

start = (shadowsocksr/shadowsocks/vmess/vless/trojan/https/http/socks5/hysteria2) {
    return proxy;
}

shadowsocksr = tag equals "shadowsocksr"i address method password (ssr_protocol/ssr_protocol_param/obfs_ssr/obfs_ssr_param/obfs_host/obfs_uri/fast_open/udp_relay/udp_port/shadow_tls_version/shadow_tls_sni/shadow_tls_password/ip_mode/block_quic/others)*{
    proxy.type = "ssr";
    // handle ssr obfs
    proxy.obfs = obfs.type;
}
shadowsocks = tag equals "shadowsocks"i address method password (obfs_typev obfs_hostv)? (obfs_ss/obfs_host/obfs_uri/fast_open/udp_relay/udp_port/shadow_tls_version/shadow_tls_sni/shadow_tls_password/ip_mode/block_quic/others)* {
    proxy.type = "ss";
    // handle ss obfs
    if (obfs.type == "http" || obfs.type === "tls") {
        proxy.plugin = "obfs";
        $set(proxy, "plugin-opts.mode", obfs.type);
        $set(proxy, "plugin-opts.host", obfs.host);
        $set(proxy, "plugin-opts.path", obfs.path);
    }
}
vmess = tag equals "vmess"i address method uuid (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/vmess_alterId/fast_open/udp_relay/ip_mode/public_key/short_id/block_quic/others)* {
    proxy.type = "vmess";
    proxy.cipher = proxy.cipher || "none";
    proxy.alterId = proxy.alterId || 0;
    handleTransport();
}
vless = tag equals "vless"i address uuid (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/fast_open/udp_relay/ip_mode/flow/public_key/short_id/block_quic/others)* {
    proxy.type = "vless";
    handleTransport();
}
trojan = tag equals "trojan"i address password (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/fast_open/udp_relay/ip_mode/block_quic/others)* {
    proxy.type = "trojan";
    handleTransport();
}
hysteria2 = tag equals "hysteria2"i address password (tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/udp_relay/fast_open/download_bandwidth/salamander_password/ecn/ip_mode/block_quic/others)* {
    proxy.type = "hysteria2";
}
https = tag equals "https"i address (username password)? (tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/fast_open/udp_relay/ip_mode/block_quic/others)* {
    proxy.type = "http";
    proxy.tls = true;
}
http = tag equals "http"i address (username password)? (fast_open/udp_relay/ip_mode/block_quic/others)* {
    proxy.type = "http";
}
socks5 = tag equals "socks5"i address (username password)? (over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/fast_open/udp_relay/ip_mode/block_quic/others)* {
    proxy.type = "socks5";
}

address = comma server:server comma port:port {
    proxy.server = server;
    proxy.port = port;
}

server = ip/domain

ip = & {
    const start = peg$currPos;
    let j = start;
    while (j < input.length) {
        if (input[j] === ",") break;
        j++;
    }
    peg$currPos = j;
    $.ip = input.substring(start, j).trim();
    return true;
} { return $.ip; }

domain = match:[0-9a-zA-z-_.]+ { 
    const domain = match.join(""); 
    if (/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/.test(domain)) {
        return domain;
    }
    throw new Error("Invalid domain: " + domain);
}

port = digits:[0-9]+ { 
    const port = parseInt(digits.join(""), 10); 
    if (port >= 0 && port <= 65535) {
    	return port;
    }
    throw new Error("Invalid port number: " + port);
}

method = comma cipher:cipher { 
    proxy.cipher = cipher;
}
cipher = ("aes-128-cfb"/"aes-128-ctr"/"aes-128-gcm"/"aes-192-cfb"/"aes-192-ctr"/"aes-192-gcm"/"aes-256-cfb"/"aes-256-ctr"/"aes-256-gcm"/"auto"/"bf-cfb"/"camellia-128-cfb"/"camellia-192-cfb"/"camellia-256-cfb"/"chacha20-ietf-poly1305"/"chacha20-ietf"/"chacha20-poly1305"/"chacha20"/"none"/"rc4-md5"/"rc4"/"salsa20"/"xchacha20-ietf-poly1305"/"2022-blake3-aes-128-gcm"/"2022-blake3-aes-256-gcm");

username = & {
    let j = peg$currPos; 
    let start, end;
    let first = true;
    while (j < input.length) {
        if (input[j] === ',') {
            if (first) {
                start = j + 1;
                first = false;
            } else {
                end = j;
                break;
            }
        }
        j++;
    }
    const match = input.substring(start, end);
    if (match.indexOf("=") === -1) {
        $.username = match;
        peg$currPos = end;
        return true;
    }
} { proxy.username = $.username; }
password = comma '"' match:[^"]* '"' { proxy.password = match.join(""); }
uuid = comma '"' match:[^"]+ '"' { proxy.uuid = match.join(""); }

obfs_typev = comma type:("http"/"tls") { obfs.type = type; }
obfs_hostv = comma match:[^,]+ { obfs.host = match.join(""); }

obfs_ss = comma "obfs-name" equals type:("http"/"tls") { obfs.type = type; }

obfs_ssr = comma "obfs" equals type:("plain"/"http_simple"/"http_post"/"random_head"/"tls1.2_ticket_auth"/"tls1.2_ticket_fastauth") { obfs.type = type; }
obfs_ssr_param = comma "obfs-param" equals match:$[^,]+ { proxy["obfs-param"] = match; }

obfs_host = comma "obfs-host" equals host:domain { obfs.host = host; }
obfs_uri = comma "obfs-uri" equals uri:uri { obfs.path = uri; }
uri = $[^,]+

transport = comma "transport" equals type:("tcp"/"ws"/"http") { transport.type = type; }
transport_host = comma "host" equals host:domain { transport.host = host; }
transport_path = comma "path" equals path:uri { transport.path = path; }

ssr_protocol = comma "protocol" equals protocol:("origin"/"auth_sha1_v4"/"auth_aes128_md5"/"auth_aes128_sha1"/"auth_chain_a"/"auth_chain_b") { proxy.protocol = protocol; }
ssr_protocol_param = comma "protocol-param" equals param:$[^=,]+ { proxy["protocol-param"] = param; }

vmess_alterId = comma "alterId" equals alterId:$[0-9]+ { proxy.alterId = parseInt(alterId); } 

udp_port = comma "udp-port" equals match:$[0-9]+ { proxy["udp-port"] = parseInt(match.trim()); }
shadow_tls_version = comma "shadow-tls-version" equals match:$[0-9]+ { proxy["shadow-tls-version"] = parseInt(match.trim()); }
shadow_tls_sni = comma "shadow-tls-sni" equals match:[^,]+ { proxy["shadow-tls-sni"] = match.join(""); }
shadow_tls_password = comma "shadow-tls-password" equals match:[^,]+ { proxy["shadow-tls-password"] = match.join(""); }

over_tls = comma "over-tls" equals flag:bool { proxy.tls = flag; }
tls_name = comma sni:("tls-name") equals host:domain { proxy.sni = host; }
sni = comma sni:("sni") equals host:domain { proxy.sni = host; }
tls_verification = comma "skip-cert-verify" equals flag:bool { proxy["skip-cert-verify"] = flag; }
tls_cert_sha256 = comma "tls-cert-sha256" equals match:[^,]+ { proxy["tls-fingerprint"] = match.join("").replace(/^"(.*)"$/, '$1'); }
tls_pubkey_sha256 = comma "tls-pubkey-sha256" equals match:[^,]+ { proxy["tls-pubkey-sha256"] = match.join("").replace(/^"(.*)"$/, '$1'); }

flow = comma "flow" equals match:[^,]+ { proxy["flow"] = match.join("").replace(/^"(.*)"$/, '$1'); }
public_key = comma "public-key" equals match:[^,]+ { proxy["reality-opts"] = proxy["reality-opts"] || {}; proxy["reality-opts"]["public-key"] = match.join("").replace(/^"(.*)"$/, '$1'); }
short_id = comma "short-id" equals match:[^,]+ { proxy["reality-opts"] = proxy["reality-opts"] || {}; proxy["reality-opts"]["short-id"] = match.join("").replace(/^"(.*)"$/, '$1'); }

fast_open = comma "fast-open" equals flag:bool { proxy.tfo = flag; }
udp_relay = comma "udp" equals flag:bool { proxy.udp = flag; }
ip_mode = comma "ip-mode" equals match:[^,]+ { proxy["ip-version"] = match.join(""); }

ecn = comma "ecn" equals flag:bool { proxy.ecn = flag; }
download_bandwidth = comma "download-bandwidth" equals match:[^,]+ { proxy.down = match.join(""); }
salamander_password = comma "salamander-password" equals match:[^,]+ { proxy['obfs-password'] = match.join(""); proxy.obfs = 'salamander'; }

block_quic = comma "block-quic" equals flag:bool { if(flag) proxy["block-quic"] = "on"; else proxy["block-quic"] = "off"; }

tag = match:[^=,]* { proxy.name = match.join("").trim(); }
comma = _ "," _
equals = _ "=" _
_ = [ \r\t]*
bool = b:("true"/"false") { return b === "true" }
others = comma [^=,]+ equals [^=,]+
`;
var parser2;
function getParser2() {
  if (!parser2) {
    parser2 = peggy2.generate(grammars2);
  }
  return parser2;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/peggy/qx.js
import * as peggy3 from "peggy";
var grammars3 = String.raw`
// global initializer
{{
    function $set(obj, path, value) {
      if (Object(obj) !== obj) return obj;
      if (!Array.isArray(path)) path = path.toString().match(/[^.[\]]+/g) || [];
      path
        .slice(0, -1)
        .reduce((a, c, i) => (Object(a[c]) === a[c] ? a[c] : (a[c] = Math.abs(path[i + 1]) >> 0 === +path[i + 1] ? [] : {})), obj)[
        path[path.length - 1]
      ] = value;
      return obj;
    }
}}

// per-parse initializer
{
	const proxy = {};
    const obfs = {};
    const $ = {};

    function handleObfs() {
        if (obfs.type === "ws" || obfs.type === "wss") {
            proxy.network = "ws";
            if (obfs.type === 'wss') {
                proxy.tls = true;
            }
            $set(proxy, "ws-opts.path", obfs.path);
            $set(proxy, "ws-opts.headers.Host", obfs.host);
        } else if (obfs.type === "over-tls") {
            proxy.tls = true;
        } else if (obfs.type === "http") {
            proxy.network = "http";
            $set(proxy, "http-opts.path", obfs.path);
            $set(proxy, "http-opts.headers.Host", obfs.host);
        }
    }
}

start = (trojan/shadowsocks/vmess/vless/http/socks5) {
    return proxy
}

trojan = "trojan" equals address
    (password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/obfs/obfs_host/obfs_uri/tag/udp_relay/udp_over_tcp/fast_open/server_check_url/others)* {
    proxy.type = "trojan";
    handleObfs();
}

shadowsocks = "shadowsocks" equals address
    (password/method/obfs_ssr/obfs_ss/obfs_host/obfs_uri/ssr_protocol/ssr_protocol_param/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/udp_relay/udp_over_tcp_new/fast_open/tag/server_check_url/others)* {
    if (proxy.protocol || proxy.type === "ssr") {
        proxy.type = "ssr";
        if (!proxy.protocol) {
            proxy.protocol = "origin";
        }
        // handle ssr obfs
        if (obfs.host) proxy["obfs-param"] = obfs.host;
        if (obfs.type) proxy.obfs = obfs.type;
    } else {
        proxy.type = "ss";
        // handle ss obfs
        if (obfs.type == "http" || obfs.type === "tls") {
            proxy.plugin = "obfs";
            $set(proxy, "plugin-opts", {
                mode: obfs.type
            });
        } else if (obfs.type === "ws" || obfs.type === "wss") {
            proxy.plugin = "v2ray-plugin";
            $set(proxy, "plugin-opts.mode", "websocket");
            if (obfs.type === "wss") {
                $set(proxy, "plugin-opts.tls", true);
            }
        } else if (obfs.type === 'over-tls') {
            throw new Error('ss over-tls is not supported');
        }
        if (obfs.type) {
            $set(proxy, "plugin-opts.host", obfs.host);
            $set(proxy, "plugin-opts.path", obfs.path);
        }
    }
}

vmess = "vmess" equals address
    (uuid/method/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/obfs/obfs_host/obfs_uri/udp_relay/udp_over_tcp/fast_open/aead/server_check_url/others)* {
    proxy.type = "vmess";
    proxy.cipher = proxy.cipher || "none";
    if (proxy.aead === false) {
        proxy.alterId = 1;
    } else {
        proxy.alterId = 0;
    }
    handleObfs();
}

vless = "vless" equals address
    (uuid/method/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/obfs/obfs_host/obfs_uri/udp_relay/udp_over_tcp/fast_open/aead/server_check_url/others)* {
    proxy.type = "vless";
    proxy.cipher = proxy.cipher || "none";
    handleObfs();
}

http = "http" equals address 
    (username/password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/fast_open/udp_relay/udp_over_tcp/server_check_url/others)*{
    proxy.type = "http";
}

socks5 = "socks5" equals address
    (username/password/password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/fast_open/udp_relay/udp_over_tcp/server_check_url/others)* {
    proxy.type = "socks5";
}
    
address = server:server ":" port:port {
    proxy.server = server;
    proxy.port = port;
}
server = ip/domain

domain = match:[0-9a-zA-z-_.]+ { 
    const domain = match.join(""); 
    if (/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/.test(domain)) {
        return domain;
    }
}

ip = & {
    const start = peg$currPos;
    let end;
    let j = start;
    while (j < input.length) {
        if (input[j] === ",") break;
        if (input[j] === ":") end = j;
        j++;
    }
    peg$currPos = end || j;
    $.ip = input.substring(start, end).trim();
    return true;
} { return $.ip; }

port = digits:[0-9]+ { 
    const port = parseInt(digits.join(""), 10); 
    if (port >= 0 && port <= 65535) {
    	return port;
    }
}

username = comma "username" equals username:[^,]+ { proxy.username = username.join("").trim(); }
password = comma "password" equals password:[^,]+ { proxy.password = password.join("").trim(); }
uuid = comma "password" equals uuid:[^,]+ { proxy.uuid = uuid.join("").trim(); }

method = comma "method" equals cipher:cipher { 
    proxy.cipher = cipher;
};
cipher = ("aes-128-cfb"/"aes-128-ctr"/"aes-128-gcm"/"aes-192-cfb"/"aes-192-ctr"/"aes-192-gcm"/"aes-256-cfb"/"aes-256-ctr"/"aes-256-gcm"/"bf-cfb"/"cast5-cfb"/"chacha20-ietf-poly1305"/"chacha20-ietf"/"chacha20-poly1305"/"chacha20"/"des-cfb"/"none"/"rc2-cfb"/"rc4-md5-6"/"rc4-md5"/"salsa20"/"xchacha20-ietf-poly1305"/"2022-blake3-aes-128-gcm"/"2022-blake3-aes-256-gcm");
aead = comma "aead" equals flag:bool { proxy.aead = flag; }

udp_relay = comma "udp-relay" equals flag:bool { proxy.udp = flag; }
udp_over_tcp = comma "udp-over-tcp" equals flag:bool { throw new Error("UDP over TCP is not supported"); }
udp_over_tcp_new = comma "udp-over-tcp" equals param:$[^=,]+ { if (param === "sp.v1") { proxy["udp-over-tcp"] = true; proxy["udp-over-tcp-version"] = 1; } else if (param === "sp.v2") { proxy["udp-over-tcp"] = true; proxy["udp-over-tcp-version"] = 2; } else if (param === "true") { proxy["_ssr_python_uot"] = true; } else { throw new Error("Invalid value for udp-over-tcp"); } }

fast_open = comma "fast-open" equals flag:bool { proxy.tfo = flag; }

over_tls = comma "over-tls" equals flag:bool { proxy.tls = flag; }
tls_host = comma "tls-host" equals sni:domain { proxy.sni = sni; }
tls_verification = comma "tls-verification" equals flag:bool { 
    proxy["skip-cert-verify"] = !flag;
}
tls_fingerprint = comma "tls-cert-sha256" equals tls_fingerprint:$[^,]+ { proxy["tls-fingerprint"] = tls_fingerprint.trim(); }
tls_pubkey_sha256 = comma "tls-pubkey-sha256" equals param:$[^=,]+ { proxy["tls-pubkey-sha256"] = param; }
tls_alpn = comma "tls-alpn" equals param:$[^=,]+ { proxy["tls-alpn"] = param; }
tls_no_session_ticket = comma "tls-no-session-ticket" equals flag:bool { 
    proxy["tls-no-session-ticket"] = flag;
}
tls_no_session_reuse = comma "tls-no-session-reuse" equals flag:bool { 
    proxy["tls-no-session-reuse"] = flag;
}

obfs_ss = comma "obfs" equals type:("http"/"tls"/"wss"/"ws"/"over-tls") { obfs.type = type; return type; }
obfs_ssr = comma "obfs" equals type:("plain"/"http_simple"/"http_post"/"random_head"/"tls1.2_ticket_auth"/"tls1.2_ticket_fastauth") { proxy.type = "ssr"; obfs.type = type; return type; }
obfs = comma "obfs" equals type:("wss"/"ws"/"over-tls"/"http") { obfs.type = type; return type; };

obfs_host = comma "obfs-host" equals host:domain { obfs.host = host; }
obfs_uri = comma "obfs-uri" equals uri:uri { obfs.path = uri; }

ssr_protocol = comma "ssr-protocol" equals protocol:("origin"/"auth_sha1_v4"/"auth_aes128_md5"/"auth_aes128_sha1"/"auth_chain_a"/"auth_chain_b") { proxy.protocol = protocol; return protocol; }
ssr_protocol_param = comma "ssr-protocol-param" equals param:$[^=,]+ { proxy["protocol-param"] = param; }

server_check_url = comma "server_check_url" equals param:$[^=,]+ { proxy["test-url"] = param; }

uri = $[^,]+

tag = comma "tag" equals tag:[^=,]+ { proxy.name = tag.join(""); }
others = comma [^=,]+ equals [^=,]+
comma = _ "," _
equals = _ "=" _
_ = [ \r\t]*
bool = b:("true"/"false") { return b === "true" }
`;
var parser3;
function getParser3() {
  if (!parser3) {
    parser3 = peggy3.generate(grammars3);
  }
  return parser3;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/peggy/trojan-uri.js
import * as peggy4 from "peggy";
var grammars4 = String.raw`
// global initializer
{{
  function $set(obj, path, value) {
    if (Object(obj) !== obj) return obj;
    if (!Array.isArray(path)) path = path.toString().match(/[^.[\]]+/g) || [];
    path
      .slice(0, -1)
      .reduce((a, c, i) => (Object(a[c]) === a[c] ? a[c] : (a[c] = Math.abs(path[i + 1]) >> 0 === +path[i + 1] ? [] : {})), obj)[
      path[path.length - 1]
    ] = value;
    return obj;
  }

  function toBool(str) {
    if (typeof str === 'undefined' || str === null) return undefined;
    return /(TRUE)|1/i.test(str);
  }
}}

{
  const proxy = {};
  const obfs = {};
  const $ = {};
  const params = {};
}

start = (trojan) {
  return proxy
}

trojan = "trojan://" password:password "@" server:server ":" port:port "/"? params? name:name?{
  proxy.type = "trojan";
  proxy.password = password;
  proxy.server = server;
  proxy.port = port;
  proxy.name = name;

  // name may be empty
  if (!proxy.name) {
    proxy.name = server + ":" + port;
  }
};

password = match:$[^@]+ {
  return decodeURIComponent(match);
};

server = ip/domain;

domain = match:[0-9a-zA-z-_.]+ { 
  const domain = match.join(""); 
  if (/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/.test(domain)) {
    return domain;
  }
}

ip = & {
  const start = peg$currPos;
  let end;
  let j = start;
  while (j < input.length) {
    if (input[j] === ",") break;
    if (input[j] === ":") end = j;
    j++;
  }
  peg$currPos = end || j;
  $.ip = input.substring(start, end).trim();
  return true;
} { return $.ip; }

port = digits:[0-9]+ { 
  const port = parseInt(digits.join(""), 10); 
  if (port >= 0 && port <= 65535) {
    return port;
  } else {
    throw new Error("Invalid port: " + port);
  }
}

params = "?" head:param tail:("&"@param)* {
  for (const [key, value] of Object.entries(params)) {
    params[key] = decodeURIComponent(value);
  }
  proxy["skip-cert-verify"] = toBool(params["allowInsecure"]);
  proxy.sni = params["sni"] || params["peer"];
  proxy['client-fingerprint'] = params.fp;
  proxy.alpn = params.alpn ? decodeURIComponent(params.alpn).split(',') : undefined;

  if (toBool(params["ws"])) {
    proxy.network = "ws";
    $set(proxy, "ws-opts.path", params["wspath"]);
  }
  
  if (params["type"]) {
    let httpupgrade
    proxy.network = params["type"]
    if(proxy.network === 'httpupgrade') {
      proxy.network = 'ws'
      httpupgrade = true
    }
    if (['grpc'].includes(proxy.network)) {
        proxy[proxy.network + '-opts'] = {
            'grpc-service-name': params["serviceName"],
            '_grpc-type': params["mode"],
            '_grpc-authority': params["authority"],
        };
    } else {
      if (params["path"]) {
        $set(proxy, proxy.network+"-opts.path", decodeURIComponent(params["path"]));  
      }
      if (params["host"]) {
        $set(proxy, proxy.network+"-opts.headers.Host", decodeURIComponent(params["host"])); 
      }
      if (httpupgrade) {
        $set(proxy, proxy.network+"-opts.v2ray-http-upgrade", true); 
        $set(proxy, proxy.network+"-opts.v2ray-http-upgrade-fast-open", true); 
      }
    }
    if (['reality'].includes(params.security)) {
      const opts = {};
      if (params.pbk) {
        opts['public-key'] = params.pbk;
      }
      if (params.sid) {
        opts['short-id'] = params.sid;
      }
      if (params.spx) {
        opts['_spider-x'] = params.spx;
      }
      if (params.mode) {
        proxy._mode = params.mode;
      }
      if (params.extra) {
        proxy._extra = params.extra;
      }
      if (Object.keys(opts).length > 0) {
        $set(proxy, params.security+"-opts", opts); 
      }
    }
  }

  proxy.udp = toBool(params["udp"]);
  proxy.tfo = toBool(params["tfo"]);
}

param = kv/single;

kv = key:$[a-z]i+ "=" value:$[^&#]i* {
  params[key] = value;
}

single = key:$[a-z]i+ {
  params[key] = true;
};

name = "#" + match:$.* {
  return decodeURIComponent(match);
}
`;
var parser4;
function getParser4() {
  if (!parser4) {
    parser4 = peggy4.generate(grammars4);
  }
  return parser4;
}

// src/core/app/index.js
var app_default = new Proxy(console, {
  get: function(target, prop) {
    if (prop in target) {
      return target[prop];
    }
    return function() {
      return void 0;
    };
  }
});

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/index.js
import JSON5 from "json5";

// src/vendors/Sub-Store/backend/src/utils/yaml.js
import YAML from "static-js-yaml";
function retry(fn, content, ...args) {
  try {
    return fn(content, ...args);
  } catch (e) {
    return fn(
      dump(
        fn(
          content.replace(/!<str>\s*/g, "__SubStoreJSYAMLString__"),
          ...args
        )
      ).replace(/__SubStoreJSYAMLString__/g, ""),
      ...args
    );
  }
}
function safeLoad(content, ...args) {
  return retry(YAML.safeLoad, JSON.parse(JSON.stringify(content)), ...args);
}
function load(content, ...args) {
  return retry(YAML.load, JSON.parse(JSON.stringify(content)), ...args);
}
function safeDump(content, ...args) {
  return YAML.safeDump(JSON.parse(JSON.stringify(content)), ...args);
}
function dump(content, ...args) {
  return YAML.dump(JSON.parse(JSON.stringify(content)), ...args);
}
var yaml_default = {
  safeLoad,
  load,
  safeDump,
  dump,
  parse: safeLoad,
  stringify: safeDump
};

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/index.js
import { Base64 } from "js-base64";
function surge_port_hopping(raw) {
  const [parts, port_hopping] = raw.match(
    /,\s*?port-hopping\s*?=\s*?["']?\s*?((\d+(-\d+)?)([,;]\d+(-\d+)?)*)\s*?["']?\s*?/
  ) || [];
  return {
    port_hopping: port_hopping ? port_hopping.replace(/;/g, ",") : void 0,
    line: parts ? raw.replace(parts, "") : raw
  };
}
function URI_PROXY() {
  const name = "URI PROXY Parser";
  const test = (line) => {
    return /^(socks5\+tls|socks5|http|https):\/\//.test(line);
  };
  const parse = (line) => {
    let [__, type, tls, username, password, server, port, query, name2] = line.match(
      /^(socks5|http|http)(\+tls|s)?:\/\/(?:(.*?):(.*?)@)?(.*?)(?::(\d+?))?\/?(\?.*?)?(?:#(.*?))?$/
    );
    if (port) {
      port = parseInt(port, 10);
    } else {
      if (tls) {
        port = 443;
      } else if (type === "http") {
        port = 80;
      } else {
        app_default.error(`port is not present in line: ${line}`);
        throw new Error(`port is not present in line: ${line}`);
      }
      app_default.info(`port is not present in line: ${line}, set to ${port}`);
    }
    const proxy = {
      name: name2 != null ? decodeURIComponent(name2) : `${type} ${server}:${port}`,
      type,
      tls: tls ? true : false,
      server,
      port,
      username: username != null ? decodeURIComponent(username) : void 0,
      password: password != null ? decodeURIComponent(password) : void 0
    };
    return proxy;
  };
  return { name, test, parse };
}
function URI_SOCKS() {
  const name = "URI SOCKS Parser";
  const test = (line) => {
    return /^socks:\/\//.test(line);
  };
  const parse = (line) => {
    let [__, type, auth, server, port, query, name2] = line.match(
      /^(socks)?:\/\/(?:(.*)@)?(.*?)(?::(\d+?))?(\?.*?)?(?:#(.*?))?$/
    );
    if (port) {
      port = parseInt(port, 10);
    } else {
      app_default.error(`port is not present in line: ${line}`);
      throw new Error(`port is not present in line: ${line}`);
    }
    let username, password;
    if (auth) {
      const parsed = Base64.decode(decodeURIComponent(auth)).split(":");
      username = parsed[0];
      password = parsed[1];
    }
    const proxy = {
      name: name2 != null ? decodeURIComponent(name2) : `${type} ${server}:${port}`,
      type: "socks5",
      server,
      port,
      username,
      password
    };
    return proxy;
  };
  return { name, test, parse };
}
function URI_SS() {
  const name = "URI SS Parser";
  const test = (line) => {
    return /^ss:\/\//.test(line);
  };
  const parse = (line) => {
    let content = line.split("ss://")[1];
    let name2 = line.split("#")[1];
    const proxy = {
      type: "ss"
    };
    content = content.split("#")[0];
    let serverAndPortArray = content.match(/@([^/?]*)(\/|\?|$)/);
    let rawUserInfoStr = decodeURIComponent(content.split("@")[0]);
    let userInfoStr;
    if (rawUserInfoStr?.startsWith("2022-blake3-")) {
      userInfoStr = rawUserInfoStr;
    } else {
      userInfoStr = Base64.decode(rawUserInfoStr);
    }
    let query = "";
    if (!serverAndPortArray) {
      if (content.includes("?")) {
        const parsed = content.match(/^(.*)(\?.*)$/);
        content = parsed[1];
        query = parsed[2];
      }
      content = Base64.decode(content);
      if (query) {
        if (/(&|\?)v2ray-plugin=/.test(query)) {
          const parsed = query.match(/(&|\?)v2ray-plugin=(.*?)(&|$)/);
          let v2rayPlugin = parsed[2];
          if (v2rayPlugin) {
            proxy.plugin = "v2ray-plugin";
            proxy["plugin-opts"] = JSON.parse(
              Base64.decode(v2rayPlugin)
            );
          }
        }
        content = `${content}${query}`;
      }
      userInfoStr = content.match(/(^.*)@/)?.[1];
      serverAndPortArray = content.match(/@([^/@]*)(\/|$)/);
    } else if (content.includes("?")) {
      const parsed = content.match(/(\?.*)$/);
      query = parsed[1];
    }
    const serverAndPort = serverAndPortArray[1];
    const portIdx = serverAndPort.lastIndexOf(":");
    proxy.server = serverAndPort.substring(0, portIdx);
    proxy.port = `${serverAndPort.substring(portIdx + 1)}`.match(
      /\d+/
    )?.[0];
    let userInfo = userInfoStr.match(/(^.*?):(.*$)/);
    proxy.cipher = userInfo?.[1];
    proxy.password = userInfo?.[2];
    const pluginMatch = content.match(/[?&]plugin=([^&]+)/);
    const shadowTlsMatch = content.match(/[?&]shadow-tls=([^&]+)/);
    if (pluginMatch) {
      const pluginInfo = ("plugin=" + decodeURIComponent(pluginMatch[1])).split(";");
      const params = {};
      for (const item of pluginInfo) {
        const [key, val] = item.split("=");
        if (key) params[key] = val || true;
      }
      switch (params.plugin) {
        case "obfs-local":
        case "simple-obfs":
          proxy.plugin = "obfs";
          proxy["plugin-opts"] = {
            mode: params.obfs,
            host: getIfNotBlank(params["obfs-host"])
          };
          break;
        case "v2ray-plugin":
          proxy.plugin = "v2ray-plugin";
          proxy["plugin-opts"] = {
            mode: "websocket",
            host: getIfNotBlank(params["obfs-host"]),
            path: getIfNotBlank(params.path),
            tls: getIfPresent(params.tls)
          };
          break;
        case "shadow-tls": {
          proxy.plugin = "shadow-tls";
          const version = getIfNotBlank(params["version"]);
          proxy["plugin-opts"] = {
            host: getIfNotBlank(params["host"]),
            password: getIfNotBlank(params["password"]),
            version: version ? parseInt(version, 10) : void 0
          };
          break;
        }
        default:
          throw new Error(
            `Unsupported plugin option: ${params.plugin}`
          );
      }
    }
    if (shadowTlsMatch) {
      const params = JSON.parse(Base64.decode(shadowTlsMatch[1]));
      const version = getIfNotBlank(params["version"]);
      const address = getIfNotBlank(params["address"]);
      const port = getIfNotBlank(params["port"]);
      proxy.plugin = "shadow-tls";
      proxy["plugin-opts"] = {
        host: getIfNotBlank(params["host"]),
        password: getIfNotBlank(params["password"]),
        version: version ? parseInt(version, 10) : void 0
      };
      if (address) {
        proxy.server = address;
      }
      if (port) {
        proxy.port = parseInt(port, 10);
      }
    }
    if (/(&|\?)uot=(1|true)/i.test(query)) {
      proxy["udp-over-tcp"] = true;
    }
    if (/(&|\?)tfo=(1|true)/i.test(query)) {
      proxy.tfo = true;
    }
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    proxy.name = name2 ?? `SS ${proxy.server}:${proxy.port}`;
    return proxy;
  };
  return { name, test, parse };
}
function URI_SSR() {
  const name = "URI SSR Parser";
  const test = (line) => {
    return /^ssr:\/\//.test(line);
  };
  const parse = (line) => {
    line = Base64.decode(line.split("ssr://")[1]);
    let splitIdx = line.indexOf(":origin");
    if (splitIdx === -1) {
      splitIdx = line.indexOf(":auth_");
    }
    const serverAndPort = line.substring(0, splitIdx);
    const server = serverAndPort.substring(
      0,
      serverAndPort.lastIndexOf(":")
    );
    const port = serverAndPort.substring(
      serverAndPort.lastIndexOf(":") + 1
    );
    let params = line.substring(splitIdx + 1).split("/?")[0].split(":");
    let proxy = {
      type: "ssr",
      server,
      port,
      protocol: params[0],
      cipher: params[1],
      obfs: params[2],
      password: Base64.decode(params[3])
    };
    const other_params = {};
    line = line.split("/?")[1].split("&");
    if (line.length > 1) {
      for (const item of line) {
        let [key, val] = item.split("=");
        val = val.trim();
        if (val.length > 0 && val !== "(null)") {
          other_params[key] = val;
        }
      }
    }
    proxy = {
      ...proxy,
      name: other_params.remarks ? Base64.decode(other_params.remarks) : proxy.server,
      "protocol-param": getIfNotBlank(
        Base64.decode(other_params.protoparam || "").replace(/\s/g, "")
      ),
      "obfs-param": getIfNotBlank(
        Base64.decode(other_params.obfsparam || "").replace(/\s/g, "")
      )
    };
    return proxy;
  };
  return { name, test, parse };
}
function URI_VMess() {
  const name = "URI VMess Parser";
  const test = (line) => {
    return /^vmess:\/\//.test(line);
  };
  const parse = (line) => {
    line = line.split("vmess://")[1];
    let content = Base64.decode(line.replace(/\?.*?$/, ""));
    if (/=\s*vmess/.test(content)) {
      const partitions = content.split(",").map((p) => p.trim());
      const params = {};
      for (const part of partitions) {
        if (part.indexOf("=") !== -1) {
          const [key, val] = part.split("=");
          params[key.trim()] = val.trim();
        }
      }
      const proxy = {
        name: partitions[0].split("=")[0].trim(),
        type: "vmess",
        server: partitions[1],
        port: partitions[2],
        cipher: getIfNotBlank(partitions[3], "auto"),
        uuid: partitions[4].match(/^"(.*)"$/)[1],
        tls: params.obfs === "wss",
        udp: getIfPresent(params["udp-relay"]),
        tfo: getIfPresent(params["fast-open"]),
        "skip-cert-verify": isPresent(params["tls-verification"]) ? !params["tls-verification"] : void 0
      };
      if (isPresent(params.obfs)) {
        if (params.obfs === "ws" || params.obfs === "wss") {
          proxy.network = "ws";
          proxy["ws-opts"].path = (getIfNotBlank(params["obfs-path"]) || '"/"').match(/^"(.*)"$/)[1];
          let obfs_host = params["obfs-header"];
          if (obfs_host && obfs_host.indexOf("Host") !== -1) {
            obfs_host = obfs_host.match(
              /Host:\s*([a-zA-Z0-9-.]*)/
            )[1];
          }
          if (isNotBlank(obfs_host)) {
            proxy["ws-opts"].headers = {
              Host: obfs_host
            };
          }
        } else {
          throw new Error(`Unsupported obfs: ${params.obfs}`);
        }
      }
      return proxy;
    } else {
      let params = {};
      try {
        params = JSON.parse(content);
      } catch (e) {
        let [__, base64Line, qs] = /(^[^?]+?)\/?\?(.*)$/.exec(line);
        content = Base64.decode(base64Line);
        for (const addon of qs.split("&")) {
          const [key, valueRaw] = addon.split("=");
          let value = valueRaw;
          value = decodeURIComponent(valueRaw);
          if (value.indexOf(",") === -1) {
            params[key] = value;
          } else {
            params[key] = value.split(",");
          }
        }
        let [___, cipher, uuid2, server2, port2] = /(^[^:]+?):([^:]+?)@(.*):(\d+)$/.exec(content);
        params.scy = cipher;
        params.id = uuid2;
        params.port = port2;
        params.add = server2;
      }
      const server = params.add;
      const port = parseInt(getIfPresent(params.port), 10);
      const proxy = {
        name: params.ps ?? params.remarks ?? params.remark ?? `VMess ${server}:${port}`,
        type: "vmess",
        server,
        port,
        // https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link
        // https://github.com/XTLS/Xray-core/issues/91
        cipher: [
          "auto",
          "aes-128-gcm",
          "chacha20-poly1305",
          "none"
        ].includes(params.scy) ? params.scy : "auto",
        uuid: params.id,
        alterId: parseInt(
          getIfPresent(params.aid ?? params.alterId, 0),
          10
        ),
        tls: ["tls", true, 1, "1"].includes(params.tls),
        "skip-cert-verify": isPresent(params.verify_cert) ? !params.verify_cert : void 0
      };
      if (!proxy["skip-cert-verify"] && isPresent(params.allowInsecure)) {
        proxy["skip-cert-verify"] = /(TRUE)|1/i.test(
          params.allowInsecure
        );
      }
      if (proxy.tls) {
        if (params.sni && params.sni !== "") {
          proxy.sni = params.sni;
        } else if (params.peer && params.peer !== "") {
          proxy.sni = params.peer;
        }
      }
      let httpupgrade = false;
      if (params.net === "ws" || params.obfs === "websocket") {
        proxy.network = "ws";
      } else if (["http"].includes(params.net) || ["http"].includes(params.obfs) || ["http"].includes(params.type)) {
        proxy.network = "http";
      } else if (["grpc", "kcp", "quic"].includes(params.net)) {
        proxy.network = params.net;
      } else if (params.net === "httpupgrade" || proxy.network === "httpupgrade") {
        proxy.network = "ws";
        httpupgrade = true;
      } else if (params.net === "h2" || proxy.network === "h2") {
        proxy.network = "h2";
      }
      if (proxy.network) {
        let transportHost = params.host ?? params.obfsParam;
        try {
          const parsedObfs = JSON.parse(transportHost);
          const parsedHost = parsedObfs?.Host;
          if (parsedHost) {
            transportHost = parsedHost;
          }
        } catch (e) {
        }
        let transportPath = params.path;
        if (["ws"].includes(proxy.network)) {
          transportPath = transportPath || "/";
        }
        if (proxy.network === "http") {
          if (transportHost) {
            transportHost = transportHost.split(",").map((i) => i.trim());
            transportHost = Array.isArray(transportHost) ? transportHost[0] : transportHost;
          }
          if (transportPath) {
            transportPath = Array.isArray(transportPath) ? transportPath[0] : transportPath;
          } else {
            transportPath = "/";
          }
        }
        if (transportPath || transportHost || ["kcp", "quic"].includes(proxy.network)) {
          if (["grpc"].includes(proxy.network)) {
            proxy[`${proxy.network}-opts`] = {
              "grpc-service-name": getIfNotBlank(transportPath),
              "_grpc-type": getIfNotBlank(params.type),
              "_grpc-authority": getIfNotBlank(params.authority)
            };
          } else if (["kcp", "quic"].includes(proxy.network)) {
            proxy[`${proxy.network}-opts`] = {
              [`_${proxy.network}-type`]: getIfNotBlank(
                params.type
              ),
              [`_${proxy.network}-host`]: getIfNotBlank(
                getIfNotBlank(transportHost)
              ),
              [`_${proxy.network}-path`]: getIfNotBlank(transportPath)
            };
          } else {
            const opts = {
              path: getIfNotBlank(transportPath),
              headers: { Host: getIfNotBlank(transportHost) }
            };
            if (httpupgrade) {
              opts["v2ray-http-upgrade"] = true;
              opts["v2ray-http-upgrade-fast-open"] = true;
            }
            proxy[`${proxy.network}-opts`] = opts;
          }
        } else {
          delete proxy.network;
        }
      }
      proxy["client-fingerprint"] = params.fp;
      proxy.alpn = params.alpn ? params.alpn.split(",") : void 0;
      return proxy;
    }
  };
  return { name, test, parse };
}
function URI_VLESS() {
  const name = "URI VLESS Parser";
  const test = (line) => {
    return /^vless:\/\//.test(line);
  };
  const parse = (line) => {
    line = line.split("vless://")[1];
    let isShadowrocket;
    let parsed = /^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
    if (!parsed) {
      let [_2, base64, other] = /^(.*?)(\?.*?$)/.exec(line);
      line = `${Base64.decode(base64)}${other}`;
      parsed = /^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
      isShadowrocket = true;
    }
    let [__, uuid2, server, port, ___, addons = "", name2] = parsed;
    if (isShadowrocket) {
      uuid2 = uuid2.replace(/^.*?:/g, "");
    }
    port = parseInt(`${port}`, 10);
    uuid2 = decodeURIComponent(uuid2);
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    const proxy = {
      type: "vless",
      name: name2,
      server,
      port,
      uuid: uuid2
    };
    const params = {};
    for (const addon of addons.split("&")) {
      if (addon) {
        const [key, valueRaw] = addon.split("=");
        let value = valueRaw;
        value = decodeURIComponent(valueRaw);
        params[key] = value;
      }
    }
    proxy.name = name2 ?? params.remarks ?? params.remark ?? `VLESS ${server}:${port}`;
    proxy.tls = params.security && params.security !== "none";
    if (isShadowrocket && /TRUE|1/i.test(params.tls)) {
      proxy.tls = true;
      params.security = params.security ?? "reality";
    }
    proxy.sni = params.sni || params.peer;
    proxy.flow = params.flow;
    if (!proxy.flow && isShadowrocket && params.xtls) {
      const flow = [void 0, "xtls-rprx-direct", "xtls-rprx-vision"][params.xtls];
      if (flow) {
        proxy.flow = flow;
      }
    }
    proxy["client-fingerprint"] = params.fp;
    proxy.alpn = params.alpn ? params.alpn.split(",") : void 0;
    proxy["skip-cert-verify"] = /(TRUE)|1/i.test(params.allowInsecure);
    if (["reality"].includes(params.security)) {
      const opts = {};
      if (params.pbk) {
        opts["public-key"] = params.pbk;
      }
      if (params.sid) {
        opts["short-id"] = params.sid;
      }
      if (params.spx) {
        opts["_spider-x"] = params.spx;
      }
      if (Object.keys(opts).length > 0) {
        proxy[`${params.security}-opts`] = opts;
      }
    }
    let httpupgrade = false;
    proxy.network = params.type;
    if (proxy.network === "tcp" && params.headerType === "http") {
      proxy.network = "http";
    } else if (proxy.network === "httpupgrade") {
      proxy.network = "ws";
      httpupgrade = true;
    }
    if (!proxy.network && isShadowrocket && params.obfs) {
      proxy.network = params.obfs;
      if (["none"].includes(proxy.network)) {
        proxy.network = "tcp";
      }
    }
    if (["websocket"].includes(proxy.network)) {
      proxy.network = "ws";
    }
    if (proxy.network && !["tcp", "none"].includes(proxy.network)) {
      const opts = {};
      const host = params.host ?? params.obfsParam;
      if (host) {
        if (params.obfsParam) {
          try {
            const parsed2 = JSON.parse(host);
            opts.headers = parsed2;
          } catch (e) {
            opts.headers = { Host: host };
          }
        } else {
          opts.headers = { Host: host };
        }
      }
      if (params.serviceName) {
        opts[`${proxy.network}-service-name`] = params.serviceName;
        if (["grpc"].includes(proxy.network) && params.authority) {
          opts["_grpc-authority"] = params.authority;
        }
      } else if (isShadowrocket && params.path) {
        if (!["ws", "http", "h2"].includes(proxy.network)) {
          opts[`${proxy.network}-service-name`] = params.path;
          delete params.path;
        }
      }
      if (params.path) {
        opts.path = params.path;
      }
      if (["grpc"].includes(proxy.network)) {
        opts["_grpc-type"] = params.mode || "gun";
      }
      if (httpupgrade) {
        opts["v2ray-http-upgrade"] = true;
        opts["v2ray-http-upgrade-fast-open"] = true;
      }
      if (Object.keys(opts).length > 0) {
        proxy[`${proxy.network}-opts`] = opts;
      }
      if (proxy.network === "kcp") {
        if (params.seed) {
          proxy.seed = params.seed;
        }
        proxy.headerType = params.headerType || "none";
      }
      if (params.mode) {
        proxy._mode = params.mode;
      }
      if (params.extra) {
        proxy._extra = params.extra;
      }
    }
    if (params.encryption) {
      proxy.encryption = params.encryption;
    }
    if (params.pqv) {
      proxy._pqv = params.pqv;
    }
    return proxy;
  };
  return { name, test, parse };
}
function URI_AnyTLS() {
  const name = "URI AnyTLS Parser";
  const test = (line) => {
    return /^anytls:\/\//.test(line);
  };
  const parse = (line) => {
    const parsed = URI_VLESS().parse(line.replace("anytls", "vless"));
    line = line.split(/anytls:\/\//)[1];
    let [__, password, server, port, addons = "", name2] = /^(.*?)@(.*?)(?::(\d+))?\/?(?:\?(.*?))?(?:#(.*?))?$/.exec(line);
    password = decodeURIComponent(password);
    port = parseInt(`${port}`, 10);
    if (isNaN(port)) {
      port = 443;
    }
    password = decodeURIComponent(password);
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    name2 = name2 ?? `AnyTLS ${server}:${port}`;
    const proxy = {
      ...parsed,
      uuid: void 0,
      type: "anytls",
      name: name2,
      server,
      port,
      password
    };
    for (const addon of addons.split("&")) {
      if (addon) {
        let [key, value] = addon.split("=");
        key = key.replace(/_/g, "-");
        value = decodeURIComponent(value);
        if (["alpn"].includes(key)) {
          proxy[key] = value ? value.split(",") : void 0;
        } else if (["insecure"].includes(key)) {
          proxy["skip-cert-verify"] = /(TRUE)|1/i.test(value);
        } else if (["udp"].includes(key)) {
          proxy[key] = /(TRUE)|1/i.test(value);
        } else if (!Object.keys(proxy).includes(key)) {
          proxy[key] = value;
        }
      }
    }
    if (["tcp"].includes(proxy.network) && !proxy["reality-opts"]) {
      delete proxy.network;
      delete proxy.security;
    }
    return proxy;
  };
  return { name, test, parse };
}
function URI_Hysteria2() {
  const name = "URI Hysteria2 Parser";
  const test = (line) => {
    return /^(hysteria2|hy2):\/\//.test(line);
  };
  const parse = (line) => {
    line = line.split(/(hysteria2|hy2):\/\//)[2];
    let ports;
    let [
      __,
      password,
      server,
      ___,
      port,
      ____,
      _____,
      ______,
      _______,
      ________,
      addons = "",
      name2
    ] = /^(.*?)@(.*?)(:((\d+(-\d+)?)([,;]\d+(-\d+)?)*))?\/?(\?(.*?))?(?:#(.*?))?$/.exec(
      line
    );
    if (/^\d+$/.test(port)) {
      port = parseInt(`${port}`, 10);
      if (isNaN(port)) {
        port = 443;
      }
    } else if (port) {
      ports = port;
      port = getRandomPort(ports);
    } else {
      port = 443;
    }
    password = decodeURIComponent(password);
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    name2 = name2 ?? `Hysteria2 ${server}:${port}`;
    const proxy = {
      type: "hysteria2",
      name: name2,
      server,
      port,
      ports,
      password
    };
    const params = {};
    for (const addon of addons.split("&")) {
      if (addon) {
        const [key, valueRaw] = addon.split("=");
        let value = valueRaw;
        value = decodeURIComponent(valueRaw);
        params[key] = value;
      }
    }
    proxy.sni = params.sni;
    if (!proxy.sni && params.peer) {
      proxy.sni = params.peer;
    }
    if (params.obfs && params.obfs !== "none") {
      proxy.obfs = params.obfs;
    }
    if (params.mport) {
      proxy.ports = params.mport;
    }
    proxy["obfs-password"] = params["obfs-password"];
    proxy["skip-cert-verify"] = /(TRUE)|1/i.test(params.insecure);
    proxy.tfo = /(TRUE)|1/i.test(params.fastopen);
    proxy["tls-fingerprint"] = params.pinSHA256;
    let hop_interval = params["hop-interval"] || params["hop_interval"];
    if (/^\d+$/.test(hop_interval)) {
      proxy["hop-interval"] = parseInt(`${hop_interval}`, 10);
    }
    let keepalive = params["keepalive"];
    if (/^\d+$/.test(keepalive)) {
      proxy["keepalive"] = parseInt(`${keepalive}`, 10);
    }
    return proxy;
  };
  return { name, test, parse };
}
function URI_Hysteria() {
  const name = "URI Hysteria Parser";
  const test = (line) => {
    return /^(hysteria|hy):\/\//.test(line);
  };
  const parse = (line) => {
    line = line.split(/(hysteria|hy):\/\//)[2];
    let [__, server, ___, port, ____, addons = "", name2] = /^(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
    port = parseInt(`${port}`, 10);
    if (isNaN(port)) {
      port = 443;
    }
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    name2 = name2 ?? `Hysteria ${server}:${port}`;
    const proxy = {
      type: "hysteria",
      name: name2,
      server,
      port
    };
    const params = {};
    for (const addon of addons.split("&")) {
      if (addon) {
        let [key, value] = addon.split("=");
        key = key.replace(/_/, "-");
        value = decodeURIComponent(value);
        if (["alpn"].includes(key)) {
          proxy[key] = value ? value.split(",") : void 0;
        } else if (["insecure"].includes(key)) {
          proxy["skip-cert-verify"] = /(TRUE)|1/i.test(value);
        } else if (["auth"].includes(key)) {
          proxy["auth-str"] = value;
        } else if (["mport"].includes(key)) {
          proxy["ports"] = value;
        } else if (["obfsParam"].includes(key)) {
          proxy["obfs"] = value;
        } else if (["upmbps"].includes(key)) {
          proxy["up"] = value;
        } else if (["downmbps"].includes(key)) {
          proxy["down"] = value;
        } else if (["obfs"].includes(key)) {
          proxy["_obfs"] = value || "";
        } else if (["fast-open", "peer"].includes(key)) {
          params[key] = value;
        } else if (!Object.keys(proxy).includes(key)) {
          proxy[key] = value;
        }
      }
    }
    if (!proxy.sni && params.peer) {
      proxy.sni = params.peer;
    }
    if (!proxy["fast-open"] && params.fastopen) {
      proxy["fast-open"] = true;
    }
    if (!proxy.protocol) {
      proxy.protocol = "udp";
    }
    return proxy;
  };
  return { name, test, parse };
}
function URI_TUIC() {
  const name = "URI TUIC Parser";
  const test = (line) => {
    return /^tuic:\/\//.test(line);
  };
  const parse = (line) => {
    line = line.split(/tuic:\/\//)[1];
    let [__, auth, server, port, addons = "", name2] = /^(.*?)@(.*?)(?::(\d+))?\/?(?:\?(.*?))?(?:#(.*?))?$/.exec(line);
    auth = decodeURIComponent(auth);
    let [uuid2, ...passwordParts] = auth.split(":");
    let password = passwordParts.join(":");
    port = parseInt(`${port}`, 10);
    if (isNaN(port)) {
      port = 443;
    }
    password = decodeURIComponent(password);
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    name2 = name2 ?? `TUIC ${server}:${port}`;
    const proxy = {
      type: "tuic",
      name: name2,
      server,
      port,
      password,
      uuid: uuid2
    };
    for (const addon of addons.split("&")) {
      if (addon) {
        let [key, value] = addon.split("=");
        key = key.replace(/_/g, "-");
        value = decodeURIComponent(value);
        if (["alpn"].includes(key)) {
          proxy[key] = value ? value.split(",") : void 0;
        } else if (["allow-insecure", "insecure"].includes(key)) {
          proxy["skip-cert-verify"] = /(TRUE)|1/i.test(value);
        } else if (["fast-open"].includes(key)) {
          proxy.tfo = true;
        } else if (["disable-sni", "reduce-rtt"].includes(key)) {
          proxy[key] = /(TRUE)|1/i.test(value);
        } else if (key === "congestion-control") {
          proxy["congestion-controller"] = value;
          delete proxy[key];
        } else if (!Object.keys(proxy).includes(key)) {
          proxy[key] = value;
        }
      }
    }
    return proxy;
  };
  return { name, test, parse };
}
function URI_WireGuard() {
  const name = "URI WireGuard Parser";
  const test = (line) => {
    return /^(wireguard|wg):\/\//.test(line);
  };
  const parse = (line) => {
    line = line.split(/(wireguard|wg):\/\//)[2];
    let [
      __,
      ___,
      privateKey,
      server,
      ____,
      port,
      _____,
      addons = "",
      name2
    ] = /^((.*?)@)?(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
    port = parseInt(`${port}`, 10);
    if (isNaN(port)) {
      port = 51820;
    }
    privateKey = decodeURIComponent(privateKey);
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    name2 = name2 ?? `WireGuard ${server}:${port}`;
    const proxy = {
      type: "wireguard",
      name: name2,
      server,
      port,
      "private-key": privateKey,
      udp: true
    };
    for (const addon of addons.split("&")) {
      if (addon) {
        let [key, value] = addon.split("=");
        key = key.replace(/_/, "-");
        value = decodeURIComponent(value);
        if (["reserved"].includes(key)) {
          const parsed = value.split(",").map((i) => parseInt(i.trim(), 10)).filter((i) => Number.isInteger(i));
          if (parsed.length === 3) {
            proxy[key] = parsed;
          }
        } else if (["address", "ip"].includes(key)) {
          value.split(",").map((i) => {
            const ip = i.trim().replace(/\/\d+$/, "").replace(/^\[/, "").replace(/\]$/, "");
            if (isIPv4(ip)) {
              proxy.ip = ip;
            } else if (isIPv6(ip)) {
              proxy.ipv6 = ip;
            }
          });
        } else if (["mtu"].includes(key)) {
          const parsed = parseInt(value.trim(), 10);
          if (Number.isInteger(parsed)) {
            proxy[key] = parsed;
          }
        } else if (/publickey/i.test(key)) {
          proxy["public-key"] = value;
        } else if (/privatekey/i.test(key)) {
          proxy["private-key"] = value;
        } else if (["udp"].includes(key)) {
          proxy[key] = /(TRUE)|1/i.test(value);
        } else if (![...Object.keys(proxy), "flag"].includes(key)) {
          proxy[key] = value;
        }
      }
    }
    return proxy;
  };
  return { name, test, parse };
}
function URI_Trojan() {
  const name = "URI Trojan Parser";
  const test = (line) => {
    return /^trojan:\/\//.test(line);
  };
  const parse = (line) => {
    const matched = /^(trojan:\/\/.*?@.*?)(:(\d+))?\/?(\?.*?)?$/.exec(line);
    const port = matched?.[2];
    if (!port) {
      line = line.replace(matched[1], `${matched[1]}:443`);
    }
    let [newLine, name2] = line.split(/#(.+)/, 2);
    const parser5 = getParser4();
    const proxy = parser5.parse(newLine);
    if (isNotBlank(name2)) {
      try {
        proxy.name = decodeURIComponent(name2);
      } catch (e) {
        console.log(e);
      }
    }
    return proxy;
  };
  return { name, test, parse };
}
function Clash_All() {
  const name = "Clash Parser";
  const test = (line) => {
    let proxy;
    try {
      proxy = JSON5.parse(line);
    } catch (e) {
      proxy = yaml_default.parse(line);
    }
    return !!proxy?.type;
  };
  const parse = (line) => {
    let proxy;
    try {
      proxy = JSON5.parse(line);
    } catch (e) {
      proxy = yaml_default.parse(line);
    }
    if (![
      "anytls",
      "mieru",
      "juicity",
      "ss",
      "ssr",
      "vmess",
      "socks5",
      "http",
      "snell",
      "trojan",
      "tuic",
      "vless",
      "hysteria",
      "hysteria2",
      "wireguard",
      "ssh",
      "direct"
    ].includes(proxy.type)) {
      throw new Error(
        `Clash does not support proxy with type: ${proxy.type}`
      );
    }
    if (["vmess", "vless"].includes(proxy.type)) {
      proxy.sni = proxy.servername;
      delete proxy.servername;
    }
    if (proxy["server-cert-fingerprint"]) {
      proxy["tls-fingerprint"] = proxy["server-cert-fingerprint"];
    }
    if (proxy.fingerprint) {
      proxy["tls-fingerprint"] = proxy.fingerprint;
    }
    if (proxy["dialer-proxy"]) {
      proxy["underlying-proxy"] = proxy["dialer-proxy"];
    }
    if (proxy["benchmark-url"]) {
      proxy["test-url"] = proxy["benchmark-url"];
    }
    if (proxy["benchmark-timeout"]) {
      proxy["test-timeout"] = proxy["benchmark-timeout"];
    }
    return proxy;
  };
  return { name, test, parse };
}
function QX_SS() {
  const name = "QX SS Parser";
  const test = (line) => {
    return /^shadowsocks\s*=/.test(line.split(",")[0].trim()) && line.indexOf("ssr-protocol") === -1;
  };
  const parse = (line) => {
    const parser5 = getParser3();
    return parser5.parse(line);
  };
  return { name, test, parse };
}
function QX_SSR() {
  const name = "QX SSR Parser";
  const test = (line) => {
    return /^shadowsocks\s*=/.test(line.split(",")[0].trim()) && line.indexOf("ssr-protocol") !== -1;
  };
  const parse = (line) => getParser3().parse(line);
  return { name, test, parse };
}
function QX_VMess() {
  const name = "QX VMess Parser";
  const test = (line) => {
    return /^vmess\s*=/.test(line.split(",")[0].trim());
  };
  const parse = (line) => getParser3().parse(line);
  return { name, test, parse };
}
function QX_VLESS() {
  const name = "QX VLESS Parser";
  const test = (line) => {
    return /^vless\s*=/.test(line.split(",")[0].trim());
  };
  const parse = (line) => getParser3().parse(line);
  return { name, test, parse };
}
function QX_Trojan() {
  const name = "QX Trojan Parser";
  const test = (line) => {
    return /^trojan\s*=/.test(line.split(",")[0].trim());
  };
  const parse = (line) => getParser3().parse(line);
  return { name, test, parse };
}
function QX_Http() {
  const name = "QX HTTP Parser";
  const test = (line) => {
    return /^http\s*=/.test(line.split(",")[0].trim());
  };
  const parse = (line) => getParser3().parse(line);
  return { name, test, parse };
}
function QX_Socks5() {
  const name = "QX Socks5 Parser";
  const test = (line) => {
    return /^socks5\s*=/.test(line.split(",")[0].trim());
  };
  const parse = (line) => getParser3().parse(line);
  return { name, test, parse };
}
function Loon_SS() {
  const name = "Loon SS Parser";
  const test = (line) => {
    return line.split(",")[0].split("=")[1].trim().toLowerCase() === "shadowsocks";
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_SSR() {
  const name = "Loon SSR Parser";
  const test = (line) => {
    return line.split(",")[0].split("=")[1].trim().toLowerCase() === "shadowsocksr";
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_VMess() {
  const name = "Loon VMess Parser";
  const test = (line) => {
    return /^.*=\s*vmess/i.test(line.split(",")[0]) && line.indexOf("username") === -1;
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_Vless() {
  const name = "Loon Vless Parser";
  const test = (line) => {
    return /^.*=\s*vless/i.test(line.split(",")[0]);
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_Trojan() {
  const name = "Loon Trojan Parser";
  const test = (line) => {
    return /^.*=\s*trojan/i.test(line.split(",")[0]);
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_Hysteria2() {
  const name = "Loon Hysteria2 Parser";
  const test = (line) => {
    return /^.*=\s*Hysteria2/i.test(line.split(",")[0]);
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_Http() {
  const name = "Loon HTTP Parser";
  const test = (line) => {
    return /^.*=\s*http/i.test(line.split(",")[0]);
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_Socks5() {
  const name = "Loon SOCKS5 Parser";
  const test = (line) => {
    return /^.*=\s*socks5/i.test(line.split(",")[0]);
  };
  const parse = (line) => getParser2().parse(line);
  return { name, test, parse };
}
function Loon_WireGuard() {
  const name = "Loon WireGuard Parser";
  const test = (line) => {
    return /^.*=\s*wireguard/i.test(line.split(",")[0]);
  };
  const parse = (line) => {
    const name2 = line.match(
      /(^.*?)\s*?=\s*?wireguard\s*?,.+?\s*?=\s*?.+?/i
    )?.[1];
    line = line.replace(name2, "").replace(/^\s*?=\s*?wireguard\s*/i, "");
    let peers = line.match(
      /,\s*?peers\s*?=\s*?\[\s*?\{\s*?(.+?)\s*?\}\s*?\]/i
    )?.[1];
    let serverPort = peers.match(
      /(,|^)\s*?endpoint\s*?=\s*?"?(.+?):(\d+)"?\s*?(,|$)/i
    );
    let server = serverPort?.[2];
    let port = parseInt(serverPort?.[3], 10);
    let mtu = line.match(/(,|^)\s*?mtu\s*?=\s*?"?(\d+?)"?\s*?(,|$)/i)?.[2];
    if (mtu) {
      mtu = parseInt(mtu, 10);
    }
    let keepalive = line.match(
      /(,|^)\s*?keepalive\s*?=\s*?"?(\d+?)"?\s*?(,|$)/i
    )?.[2];
    if (keepalive) {
      keepalive = parseInt(keepalive, 10);
    }
    let reserved = peers.match(
      /(,|^)\s*?reserved\s*?=\s*?"?(\[\s*?.+?\s*?\])"?\s*?(,|$)/i
    )?.[2];
    if (reserved) {
      reserved = JSON.parse(reserved);
    }
    let dns;
    let dnsv4 = line.match(/(,|^)\s*?dns\s*?=\s*?"?(.+?)"?\s*?(,|$)/i)?.[2];
    let dnsv6 = line.match(
      /(,|^)\s*?dnsv6\s*?=\s*?"?(.+?)"?\s*?(,|$)/i
    )?.[2];
    if (dnsv4 || dnsv6) {
      dns = [];
      if (dnsv4) {
        dns.push(dnsv4);
      }
      if (dnsv6) {
        dns.push(dnsv6);
      }
    }
    let allowedIps = peers.match(/(,|^)\s*?allowed-ips\s*?=\s*?"(.+?)"\s*?(,|$)/i)?.[2]?.split(",").map((i) => i.trim());
    let preSharedKey = peers.match(
      /(,|^)\s*?preshared-key\s*?=\s*?"?(.+?)"?\s*?(,|$)/i
    )?.[2];
    let ip = line.match(
      /(,|^)\s*?interface-ip\s*?=\s*?"?(.+?)"?\s*?(,|$)/i
    )?.[2];
    let ipv6 = line.match(
      /(,|^)\s*?interface-ipv6\s*?=\s*?"?(.+?)"?\s*?(,|$)/i
    )?.[2];
    let publicKey = peers.match(
      /(,|^)\s*?public-key\s*?=\s*?"?(.+?)"?\s*?(,|$)/i
    )?.[2];
    const proxy = {
      type: "wireguard",
      name: name2,
      server,
      port,
      ip,
      ipv6,
      "private-key": line.match(
        /(,|^)\s*?private-key\s*?=\s*?"?(.+?)"?\s*?(,|$)/i
      )?.[2],
      "public-key": publicKey,
      mtu,
      keepalive,
      reserved,
      "allowed-ips": allowedIps,
      "preshared-key": preSharedKey,
      dns,
      udp: true,
      peers: [
        {
          server,
          port,
          ip,
          ipv6,
          "public-key": publicKey,
          "pre-shared-key": preSharedKey,
          "allowed-ips": allowedIps,
          reserved
        }
      ]
    };
    proxy;
    if (Array.isArray(proxy.dns) && proxy.dns.length > 0) {
      proxy["remote-dns-resolve"] = true;
    }
    return proxy;
  };
  return { name, test, parse };
}
function Surge_Direct() {
  const name = "Surge Direct Parser";
  const test = (line) => {
    return /^.*=\s*direct/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_SSH() {
  const name = "Surge SSH Parser";
  const test = (line) => {
    return /^.*=\s*ssh/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_SS() {
  const name = "Surge SS Parser";
  const test = (line) => {
    return /^.*=\s*ss/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_VMess() {
  const name = "Surge VMess Parser";
  const test = (line) => {
    return /^.*=\s*vmess/.test(line.split(",")[0]) && line.indexOf("username") !== -1;
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_Trojan() {
  const name = "Surge Trojan Parser";
  const test = (line) => {
    return /^.*=\s*trojan/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_Http() {
  const name = "Surge HTTP Parser";
  const test = (line) => {
    return /^.*=\s*https?/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_Socks5() {
  const name = "Surge Socks5 Parser";
  const test = (line) => {
    return /^.*=\s*socks5(-tls)?/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_External() {
  const name = "Surge External Parser";
  const test = (line) => {
    return /^.*=\s*external/.test(line.split(",")[0]);
  };
  const parse = (line) => {
    let parsed = /^\s*(.*?)\s*?=\s*?external\s*?,\s*(.*?)\s*$/.exec(line);
    let [_2, name2, other] = parsed;
    line = other;
    let exec = /(,|^)\s*?exec\s*?=\s*"(.*?)"\s*?(,|$)/.exec(line)?.[2];
    if (!exec) {
      exec = /(,|^)\s*?exec\s*?=\s*(.*?)\s*?(,|$)/.exec(line)?.[2];
    }
    let localPort = /(,|^)\s*?local-port\s*?=\s*"(.*?)"\s*?(,|$)/.exec(
      line
    )?.[2];
    if (!localPort) {
      localPort = /(,|^)\s*?local-port\s*?=\s*(.*?)\s*?(,|$)/.exec(
        line
      )?.[2];
    }
    const argsRegex = /(,|^)\s*?args\s*?=\s*("(.*?)"|(.*?))(?=\s*?(,|$))/g;
    let argsMatch;
    const args = [];
    while ((argsMatch = argsRegex.exec(line)) !== null) {
      if (argsMatch[3] != null) {
        args.push(argsMatch[3]);
      } else if (argsMatch[4] != null) {
        args.push(argsMatch[4]);
      }
    }
    const addressesRegex = /(,|^)\s*?addresses\s*?=\s*("(.*?)"|(.*?))(?=\s*?(,|$))/g;
    let addressesMatch;
    const addresses = [];
    while ((addressesMatch = addressesRegex.exec(line)) !== null) {
      let ip;
      if (addressesMatch[3] != null) {
        ip = addressesMatch[3];
      } else if (addressesMatch[4] != null) {
        ip = addressesMatch[4];
      }
      if (ip != null) {
        ip = `${ip}`.trim().replace(/^\[/, "").replace(/\]$/, "");
      }
      if (isIP(ip)) {
        addresses.push(ip);
      }
    }
    const proxy = {
      type: "external",
      name: name2,
      exec,
      "local-port": localPort,
      args,
      addresses
    };
    return proxy;
  };
  return { name, test, parse };
}
function Surge_Snell() {
  const name = "Surge Snell Parser";
  const test = (line) => {
    return /^.*=\s*snell/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_Tuic() {
  const name = "Surge Tuic Parser";
  const test = (line) => {
    return /^.*=\s*tuic(-v5)?/.test(line.split(",")[0]);
  };
  const parse = (raw) => {
    const { port_hopping, line } = surge_port_hopping(raw);
    const proxy = getParser().parse(line);
    proxy["ports"] = port_hopping;
    return proxy;
  };
  return { name, test, parse };
}
function Surge_WireGuard() {
  const name = "Surge WireGuard Parser";
  const test = (line) => {
    return /^.*=\s*wireguard/.test(line.split(",")[0]);
  };
  const parse = (line) => getParser().parse(line);
  return { name, test, parse };
}
function Surge_Hysteria2() {
  const name = "Surge Hysteria2 Parser";
  const test = (line) => {
    return /^.*=\s*hysteria2/.test(line.split(",")[0]);
  };
  const parse = (raw) => {
    const { port_hopping, line } = surge_port_hopping(raw);
    const proxy = getParser().parse(line);
    proxy["ports"] = port_hopping;
    return proxy;
  };
  return { name, test, parse };
}
function isIP(ip) {
  return isIPv4(ip) || isIPv6(ip);
}
var parsers_default = [
  URI_PROXY(),
  URI_SOCKS(),
  URI_SS(),
  URI_SSR(),
  URI_VMess(),
  URI_VLESS(),
  URI_TUIC(),
  URI_WireGuard(),
  URI_Hysteria(),
  URI_Hysteria2(),
  URI_Trojan(),
  URI_AnyTLS(),
  Clash_All(),
  Surge_Direct(),
  Surge_SSH(),
  Surge_SS(),
  Surge_VMess(),
  Surge_Trojan(),
  Surge_Http(),
  Surge_Snell(),
  Surge_Tuic(),
  Surge_WireGuard(),
  Surge_Hysteria2(),
  Surge_Socks5(),
  Surge_External(),
  Loon_SS(),
  Loon_SSR(),
  Loon_VMess(),
  Loon_Vless(),
  Loon_Hysteria2(),
  Loon_Trojan(),
  Loon_Http(),
  Loon_Socks5(),
  Loon_WireGuard(),
  QX_SS(),
  QX_SSR(),
  QX_VMess(),
  QX_VLESS(),
  QX_Trojan(),
  QX_Http(),
  QX_Socks5()
];

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/utils.js
import _ from "lodash";
var Result = class {
  constructor(proxy) {
    this.proxy = proxy;
    this.output = [];
  }
  append(data) {
    if (typeof data === "undefined") {
      throw new Error("required field is missing");
    }
    this.output.push(data);
  }
  appendIfPresent(data, attr) {
    if (isPresent2(this.proxy, attr)) {
      this.append(data);
    }
  }
  toString() {
    return this.output.join("");
  }
};
function isPresent2(obj, attr) {
  const data = _.get(obj, attr);
  return typeof data !== "undefined" && data !== null;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surge.js
var targetPlatform = "Surge";
var ipVersions = {
  dual: "dual",
  ipv4: "v4-only",
  ipv6: "v6-only",
  "ipv4-prefer": "prefer-v4",
  "ipv6-prefer": "prefer-v6"
};
function Surge_Producer() {
  const produce2 = (proxy, type, opts = {}) => {
    proxy.name = proxy.name.replace(/=|,/g, "");
    if (proxy.ports) {
      proxy.ports = String(proxy.ports);
    }
    switch (proxy.type) {
      case "ss":
        return shadowsocks(proxy, opts["include-unsupported-proxy"]);
      case "trojan":
        return trojan(proxy);
      case "vmess":
        return vmess(proxy, opts["include-unsupported-proxy"]);
      case "http":
        return http(proxy);
      case "direct":
        return direct(proxy);
      case "socks5":
        return socks5(proxy);
      case "snell":
        return snell(proxy);
      case "tuic":
        return tuic(proxy);
      case "wireguard-surge":
        return wireguard_surge(proxy);
      case "hysteria2":
        return hysteria2(proxy);
      case "ssh":
        return ssh(proxy);
    }
    if (opts["include-unsupported-proxy"] && proxy.type === "wireguard") {
      return wireguard(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform} does not support proxy type: ${proxy.type}`
    );
  };
  return { produce: produce2 };
}
function shadowsocks(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  if (!proxy.cipher) {
    proxy.cipher = "none";
  }
  if (![
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
    "none",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm"
  ].includes(proxy.cipher)) {
    throw new Error(`cipher ${proxy.cipher} is not supported`);
  }
  result.append(`,encrypt-method=${proxy.cipher}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  if (isPresent2(proxy, "plugin")) {
    if (proxy.plugin === "obfs") {
      result.append(`,obfs=${proxy["plugin-opts"].mode}`);
      result.appendIfPresent(
        `,obfs-host=${proxy["plugin-opts"].host}`,
        "plugin-opts.host"
      );
      result.appendIfPresent(
        `,obfs-uri=${proxy["plugin-opts"].path}`,
        "plugin-opts.path"
      );
    } else if (!["shadow-tls"].includes(proxy.plugin)) {
      throw new Error(`plugin ${proxy.plugin} is not supported`);
    }
  }
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
    result.appendIfPresent(`,udp-port=${proxy["udp-port"]}`, "udp-port");
  } else if (["shadow-tls"].includes(proxy.plugin) && proxy["plugin-opts"]) {
    const password = proxy["plugin-opts"].password;
    const host = proxy["plugin-opts"].host;
    const version = proxy["plugin-opts"].version;
    if (password) {
      result.append(`,shadow-tls-password=${password}`);
      if (host) {
        result.append(`,shadow-tls-sni=${host}`);
      }
      if (version) {
        if (version < 2) {
          throw new Error(
            `shadow-tls version ${version} is not supported`
          );
        }
        result.append(`,shadow-tls-version=${version}`);
      }
      result.appendIfPresent(
        `,udp-port=${proxy["udp-port"]}`,
        "udp-port"
      );
    }
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function trojan(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  handleTransport(result, proxy);
  result.appendIfPresent(`,tls=${proxy.tls}`, "tls");
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function vmess(proxy, includeUnsupportedProxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username=${proxy.uuid}`, "uuid");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  handleTransport(result, proxy, includeUnsupportedProxy);
  if (isPresent2(proxy, "aead")) {
    result.append(`,vmess-aead=${proxy.aead}`);
  } else {
    result.append(`,vmess-aead=${proxy.alterId === 0}`);
  }
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(`,tls=${proxy.tls}`, "tls");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function ssh(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=ssh,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username="${proxy.username}"`, "username");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  result.appendIfPresent(
    `,private-key=${proxy["keystore-private-key"]}`,
    "keystore-private-key"
  );
  result.appendIfPresent(
    `,idle-timeout=${proxy["idle-timeout"]}`,
    "idle-timeout"
  );
  result.appendIfPresent(
    `,server-fingerprint="${proxy["server-fingerprint"]}"`,
    "server-fingerprint"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function http(proxy) {
  if (proxy.headers && Object.keys(proxy.headers).length > 0) {
    throw new Error(`headers is unsupported`);
  }
  const result = new Result(proxy);
  const type = proxy.tls ? "https" : "http";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username="${proxy.username}"`, "username");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function direct(proxy) {
  const result = new Result(proxy);
  const type = "direct";
  result.append(`${proxy.name}=${type}`);
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function socks5(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "socks5-tls" : "socks5";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username="${proxy.username}"`, "username");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  if (proxy.tfo) {
    app_default.info(`Option tfo is not supported by Surge, thus omitted`);
  }
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function snell(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,version=${proxy.version}`, "version");
  result.appendIfPresent(`,psk=${proxy.psk}`, "psk");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(
    `,obfs=${proxy["obfs-opts"]?.mode}`,
    "obfs-opts.mode"
  );
  result.appendIfPresent(
    `,obfs-host=${proxy["obfs-opts"]?.host}`,
    "obfs-opts.host"
  );
  result.appendIfPresent(
    `,obfs-uri=${proxy["obfs-opts"]?.path}`,
    "obfs-opts.path"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  result.appendIfPresent(`,reuse=${proxy["reuse"]}`, "reuse");
  return result.toString();
}
function tuic(proxy) {
  const result = new Result(proxy);
  let type = proxy.type;
  if (!proxy.token || proxy.token.length === 0) {
    type = "tuic-v5";
  }
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,uuid=${proxy.uuid}`, "uuid");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  result.appendIfPresent(`,token=${proxy.token}`, "token");
  result.appendIfPresent(
    `,alpn=${Array.isArray(proxy.alpn) ? proxy.alpn[0] : proxy.alpn}`,
    "alpn"
  );
  if (isPresent2(proxy, "ports")) {
    result.append(`,port-hopping="${proxy.ports.replace(/,/g, ";")}"`);
  }
  result.appendIfPresent(
    `,port-hopping-interval=${proxy["hop-interval"]}`,
    "hop-interval"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  if (isPresent2(proxy, "tfo")) {
    result.append(`,tfo=${proxy["tfo"]}`);
  } else if (isPresent2(proxy, "fast-open")) {
    result.append(`,tfo=${proxy["fast-open"]}`);
  }
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  result.appendIfPresent(`,ecn=${proxy.ecn}`, "ecn");
  return result.toString();
}
function wireguard(proxy) {
  if (Array.isArray(proxy.peers) && proxy.peers.length > 0) {
    proxy.server = proxy.peers[0].server;
    proxy.port = proxy.peers[0].port;
    proxy.ip = proxy.peers[0].ip;
    proxy.ipv6 = proxy.peers[0].ipv6;
    proxy["public-key"] = proxy.peers[0]["public-key"];
    proxy["preshared-key"] = proxy.peers[0]["pre-shared-key"];
    proxy["allowed-ips"] = proxy.peers[0]["allowed-ips"];
    proxy.reserved = proxy.peers[0].reserved;
  }
  const result = new Result(proxy);
  result.append(`# > WireGuard Proxy ${proxy.name}
# ${proxy.name}=wireguard`);
  proxy["section-name"] = getIfNotBlank(proxy["section-name"], proxy.name);
  result.appendIfPresent(
    `,section-name=${proxy["section-name"]}`,
    "section-name"
  );
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  result.append(`
# > WireGuard Section ${proxy.name}
[WireGuard ${proxy["section-name"]}]
private-key = ${proxy["private-key"]}`);
  result.appendIfPresent(`
self-ip = ${proxy.ip}`, "ip");
  result.appendIfPresent(`
self-ip-v6 = ${proxy.ipv6}`, "ipv6");
  if (proxy.dns) {
    if (Array.isArray(proxy.dns)) {
      proxy.dns = proxy.dns.join(", ");
    }
    result.append(`
dns-server = ${proxy.dns}`);
  }
  result.appendIfPresent(`
mtu = ${proxy.mtu}`, "mtu");
  if (ip_version === "prefer-v6") {
    result.append(`
prefer-ipv6 = true`);
  }
  const allowedIps = Array.isArray(proxy["allowed-ips"]) ? proxy["allowed-ips"].join(",") : proxy["allowed-ips"];
  let reserved = Array.isArray(proxy.reserved) ? proxy.reserved.join("/") : proxy.reserved;
  let presharedKey = proxy["preshared-key"] ?? proxy["pre-shared-key"];
  const peer = {
    "public-key": proxy["public-key"],
    "allowed-ips": allowedIps ? `"${allowedIps}"` : void 0,
    endpoint: `${proxy.server}:${proxy.port}`,
    keepalive: proxy["persistent-keepalive"] || proxy.keepalive,
    "client-id": reserved,
    "preshared-key": presharedKey
  };
  result.append(
    `
peer = (${Object.keys(peer).filter((k) => peer[k] != null).map((k) => `${k} = ${peer[k]}`).join(", ")})`
  );
  return result.toString();
}
function wireguard_surge(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=wireguard`);
  result.appendIfPresent(
    `,section-name=${proxy["section-name"]}`,
    "section-name"
  );
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function hysteria2(proxy) {
  if (proxy.obfs || proxy["obfs-password"]) {
    throw new Error(`obfs is unsupported`);
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=hysteria2,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  if (isPresent2(proxy, "ports")) {
    result.append(`,port-hopping="${proxy.ports.replace(/,/g, ";")}"`);
  }
  result.appendIfPresent(
    `,port-hopping-interval=${proxy["hop-interval"]}`,
    "hop-interval"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  if (isPresent2(proxy, "tfo")) {
    result.append(`,tfo=${proxy["tfo"]}`);
  } else if (isPresent2(proxy, "fast-open")) {
    result.append(`,tfo=${proxy["fast-open"]}`);
  }
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(
    `,test-timeout=${proxy["test-timeout"]}`,
    "test-timeout"
  );
  result.appendIfPresent(`,test-udp=${proxy["test-udp"]}`, "test-udp");
  result.appendIfPresent(`,hybrid=${proxy["hybrid"]}`, "hybrid");
  result.appendIfPresent(`,tos=${proxy["tos"]}`, "tos");
  result.appendIfPresent(
    `,allow-other-interface=${proxy["allow-other-interface"]}`,
    "allow-other-interface"
  );
  result.appendIfPresent(
    `,interface=${proxy["interface-name"]}`,
    "interface-name"
  );
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  result.appendIfPresent(
    `,download-bandwidth=${`${proxy["down"]}`.match(/\d+/)?.[0] || 0}`,
    "down"
  );
  result.appendIfPresent(`,ecn=${proxy.ecn}`, "ecn");
  return result.toString();
}
function handleTransport(result, proxy, includeUnsupportedProxy) {
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      result.append(`,ws=true`);
      if (isPresent2(proxy, "ws-opts")) {
        result.appendIfPresent(
          `,ws-path=${proxy["ws-opts"].path}`,
          "ws-opts.path"
        );
        if (isPresent2(proxy, "ws-opts.headers")) {
          const headers = proxy["ws-opts"].headers;
          const value = Object.keys(headers).map((k) => {
            let v = headers[k];
            v = `"${v}"`;
            return `${k}:${v}`;
          }).join("|");
          if (isNotBlank(value)) {
            result.append(`,ws-headers=${value}`);
          }
        }
      }
    } else {
      if (includeUnsupportedProxy && ["http"].includes(proxy.network)) {
        app_default.info(
          `Include Unsupported Proxy: nework ${proxy.network} -> tcp`
        );
      } else {
        throw new Error(`network ${proxy.network} is unsupported`);
      }
    }
  }
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surgemac.js
import { Base64 as Base642 } from "js-base64";

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/clashmeta.js
var ipVersions2 = {
  dual: "dual",
  "v4-only": "ipv4",
  "v6-only": "ipv6",
  "prefer-v4": "ipv4-prefer",
  "prefer-v6": "ipv6-prefer"
};
function ClashMeta_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (opts["include-unsupported-proxy"]) return true;
      if (proxy.type === "snell" && proxy.version >= 4) {
        return false;
      } else if (["juicity"].includes(proxy.type)) {
        return false;
      } else if (["ss"].includes(proxy.type) && ![
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "aes-128-ccm",
        "aes-192-ccm",
        "aes-256-ccm",
        "aes-128-gcm-siv",
        "aes-256-gcm-siv",
        "chacha20-ietf",
        "chacha20",
        "xchacha20",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "chacha8-ietf-poly1305",
        "xchacha8-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "lea-128-gcm",
        "lea-192-gcm",
        "lea-256-gcm",
        "rabbit128-poly1305",
        "aegis-128l",
        "aegis-256",
        "aez-384",
        "deoxys-ii-256-128",
        "rc4-md5",
        "none"
      ].includes(proxy.cipher)) {
        return false;
      } else if (["anytls"].includes(proxy.type) && proxy.network && (!["tcp"].includes(proxy.network) || ["tcp"].includes(proxy.network) && proxy["reality-opts"])) {
        return false;
      } else if (["xhttp"].includes(proxy.network)) {
        return false;
      }
      return true;
    }).map((proxy) => {
      if (proxy.type === "vmess") {
        if (isPresent2(proxy, "aead")) {
          if (proxy.aead) {
            proxy.alterId = 0;
          }
          delete proxy.aead;
        }
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
        if (isPresent2(proxy, "cipher") && ![
          "auto",
          "none",
          "zero",
          "aes-128-gcm",
          "chacha20-poly1305"
        ].includes(proxy.cipher)) {
          proxy.cipher = "auto";
        }
      } else if (proxy.type === "tuic") {
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
        }
        if ((!proxy.token || proxy.token.length === 0) && !isPresent2(proxy, "version")) {
          proxy.version = 5;
        }
      } else if (proxy.type === "hysteria") {
        if (isPresent2(proxy, "auth_str") && !isPresent2(proxy, "auth-str")) {
          proxy["auth-str"] = proxy["auth_str"];
        }
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
        }
      } else if (proxy.type === "wireguard") {
        proxy.keepalive = proxy.keepalive ?? proxy["persistent-keepalive"];
        proxy["persistent-keepalive"] = proxy.keepalive;
        proxy["preshared-key"] = proxy["preshared-key"] ?? proxy["pre-shared-key"];
        proxy["pre-shared-key"] = proxy["preshared-key"];
      } else if (proxy.type === "snell" && proxy.version < 3) {
        delete proxy.udp;
      } else if (proxy.type === "vless") {
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
      } else if (proxy.type === "ss") {
        if (isPresent2(proxy, "shadow-tls-password") && !isPresent2(proxy, "plugin")) {
          proxy.plugin = "shadow-tls";
          proxy["plugin-opts"] = {
            host: proxy["shadow-tls-sni"],
            password: proxy["shadow-tls-password"],
            version: proxy["shadow-tls-version"]
          };
          delete proxy["shadow-tls-password"];
          delete proxy["shadow-tls-sni"];
          delete proxy["shadow-tls-version"];
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "http") {
        let httpPath = proxy["http-opts"]?.path;
        if (isPresent2(proxy, "http-opts.path") && !Array.isArray(httpPath)) {
          proxy["http-opts"].path = [httpPath];
        }
        let httpHost = proxy["http-opts"]?.headers?.Host;
        if (isPresent2(proxy, "http-opts.headers.Host") && !Array.isArray(httpHost)) {
          proxy["http-opts"].headers.Host = [httpHost];
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "h2") {
        let path = proxy["h2-opts"]?.path;
        if (isPresent2(proxy, "h2-opts.path") && Array.isArray(path)) {
          proxy["h2-opts"].path = path[0];
        }
        let host = proxy["h2-opts"]?.headers?.host;
        if (isPresent2(proxy, "h2-opts.headers.Host") && !Array.isArray(host)) {
          proxy["h2-opts"].headers.host = [host];
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkPath = proxy[`${proxy.network}-opts`]?.path;
        if (networkPath) {
          const reg = /^(.*?)(?:\?ed=(\d+))?$/;
          const [_2, path = "", ed = ""] = reg.exec(networkPath);
          proxy[`${proxy.network}-opts`].path = path;
          if (ed !== "") {
            proxy["ws-opts"]["early-data-header-name"] = "Sec-WebSocket-Protocol";
            proxy["ws-opts"]["max-early-data"] = parseInt(
              ed,
              10
            );
          }
        } else {
          proxy[`${proxy.network}-opts`] = proxy[`${proxy.network}-opts`] || {};
          proxy[`${proxy.network}-opts`].path = "/";
        }
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls"
      ].includes(proxy.type)) {
        delete proxy.tls;
      }
      if (proxy["tls-fingerprint"]) {
        proxy.fingerprint = proxy["tls-fingerprint"];
      }
      delete proxy["tls-fingerprint"];
      if (proxy["underlying-proxy"]) {
        proxy["dialer-proxy"] = proxy["underlying-proxy"];
      }
      delete proxy["underlying-proxy"];
      if (isPresent2(proxy, "tls") && typeof proxy.tls !== "boolean") {
        delete proxy.tls;
      }
      delete proxy.subName;
      delete proxy.collectionName;
      delete proxy.id;
      delete proxy.resolved;
      delete proxy["no-resolve"];
      if (type2 !== "internal" || opts["delete-underscore-fields"]) {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      if (proxy["ip-version"]) {
        proxy["ip-version"] = ipVersions2[proxy["ip-version"]] || proxy["ip-version"];
      }
      return proxy;
    });
    return type2 === "internal" ? list : "proxies:\n" + list.map((proxy) => "  - " + JSON.stringify(proxy) + "\n").join("");
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surgemac.js
var targetPlatform2 = "SurgeMac";
var surge_Producer = Surge_Producer();
function SurgeMac_Producer() {
  const produce2 = (proxy, type, opts = {}) => {
    switch (proxy.type) {
      case "external":
        return external(proxy);
      // case 'ssr':
      //     return shadowsocksr(proxy);
      default: {
        try {
          return surge_Producer.produce(proxy, type, opts);
        } catch (e) {
          if (opts.useMihomoExternal) {
            app_default.log(
              `${proxy.name} is not supported on ${targetPlatform2}, try to use Mihomo(SurgeMac - External Proxy Program) instead`
            );
            return mihomo(proxy, type, opts);
          } else {
            throw new Error(
              `Surge for macOS \u53EF\u624B\u52A8\u6307\u5B9A\u94FE\u63A5\u53C2\u6570 target=SurgeMac \u6216\u5728 \u540C\u6B65\u914D\u7F6E \u4E2D\u6307\u5B9A SurgeMac \u6765\u542F\u7528 mihomo \u652F\u63F4 Surge \u672C\u8EAB\u4E0D\u652F\u6301\u7684\u534F\u8BAE`
            );
          }
        }
      }
    }
  };
  return { produce: produce2 };
}
function external(proxy) {
  const result = new Result(proxy);
  if (!proxy.exec || !proxy["local-port"]) {
    throw new Error(`${proxy.type}: exec and local-port are required`);
  }
  result.append(
    `${proxy.name}=external,exec="${proxy.exec}",local-port=${proxy["local-port"]}`
  );
  if (Array.isArray(proxy.args)) {
    proxy.args.map((args) => {
      result.append(`,args="${args}"`);
    });
  }
  if (Array.isArray(proxy.addresses)) {
    proxy.addresses.map((addresses) => {
      result.append(`,addresses=${addresses}`);
    });
  }
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  if (isPresent2(proxy, "tfo")) {
    result.append(`,tfo=${proxy["tfo"]}`);
  } else if (isPresent2(proxy, "fast-open")) {
    result.append(`,tfo=${proxy["fast-open"]}`);
  }
  result.appendIfPresent(`,test-url=${proxy["test-url"]}`, "test-url");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function mihomo(proxy, type, opts) {
  const clashProxy = ClashMeta_Producer().produce([proxy], "internal")?.[0];
  if (clashProxy) {
    const localPort = opts?.localPort || proxy._localPort || 65535;
    const ipv6 = ["ipv4", "v4-only"].includes(proxy["ip-version"]) ? false : true;
    const external_proxy = {
      name: proxy.name,
      type: "external",
      exec: proxy._exec || "/usr/local/bin/mihomo",
      "local-port": localPort,
      args: [
        "-config",
        Base642.encode(
          JSON.stringify({
            "mixed-port": localPort,
            ipv6,
            mode: "global",
            dns: {
              enable: true,
              ipv6,
              "default-nameserver": opts?.defaultNameserver || proxy._defaultNameserver || [
                "180.76.76.76",
                "52.80.52.52",
                "119.28.28.28",
                "223.6.6.6"
              ],
              nameserver: opts?.nameserver || proxy._nameserver || [
                "https://doh.pub/dns-query",
                "https://dns.alidns.com/dns-query",
                "https://doh-pure.onedns.net/dns-query"
              ]
            },
            proxies: [
              {
                ...clashProxy,
                name: "proxy"
              }
            ],
            "proxy-groups": [
              {
                name: "GLOBAL",
                type: "select",
                proxies: ["proxy"]
              }
            ]
          })
        )
      ],
      addresses: []
    };
    if (isIP2(proxy.server)) {
      external_proxy.addresses.push(proxy.server);
    } else {
      app_default.log(
        `Platform ${targetPlatform2}, proxy type ${proxy.type}: addresses should be an IP address, but got ${proxy.server}`
      );
    }
    opts.localPort = localPort - 1;
    return external(external_proxy);
  }
}
function isIP2(ip) {
  return isIPv4(ip) || isIPv6(ip);
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/clash.js
function Clash_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (opts["include-unsupported-proxy"]) return true;
      if (![
        "ss",
        "ssr",
        "vmess",
        "vless",
        "socks5",
        "http",
        "snell",
        "trojan",
        "wireguard"
      ].includes(proxy.type) || proxy.type === "ss" && ![
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305"
      ].includes(proxy.cipher) || proxy.type === "snell" && proxy.version >= 4 || proxy.type === "vless" && (typeof proxy.flow !== "undefined" || proxy["reality-opts"])) {
        return false;
      } else if (proxy["underlying-proxy"] || proxy["dialer-proxy"]) {
        app_default.error(
          `Clash \u4E0D\u652F\u6301\u524D\u7F6E\u4EE3\u7406\u5B57\u6BB5. \u5DF2\u8FC7\u6EE4\u8282\u70B9 ${proxy.name}`
        );
        return false;
      }
      return true;
    }).map((proxy) => {
      if (proxy.type === "vmess") {
        if (isPresent2(proxy, "aead")) {
          if (proxy.aead) {
            proxy.alterId = 0;
          }
          delete proxy.aead;
        }
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
        if (isPresent2(proxy, "cipher") && ![
          "auto",
          "aes-128-gcm",
          "chacha20-poly1305",
          "none"
        ].includes(proxy.cipher)) {
          proxy.cipher = "auto";
        }
      } else if (proxy.type === "wireguard") {
        proxy.keepalive = proxy.keepalive ?? proxy["persistent-keepalive"];
        proxy["persistent-keepalive"] = proxy.keepalive;
        proxy["preshared-key"] = proxy["preshared-key"] ?? proxy["pre-shared-key"];
        proxy["pre-shared-key"] = proxy["preshared-key"];
      } else if (proxy.type === "snell" && proxy.version < 3) {
        delete proxy.udp;
      } else if (proxy.type === "vless") {
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "http") {
        let httpPath = proxy["http-opts"]?.path;
        if (isPresent2(proxy, "http-opts.path") && !Array.isArray(httpPath)) {
          proxy["http-opts"].path = [httpPath];
        }
        let httpHost = proxy["http-opts"]?.headers?.Host;
        if (isPresent2(proxy, "http-opts.headers.Host") && !Array.isArray(httpHost)) {
          proxy["http-opts"].headers.Host = [httpHost];
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "h2") {
        let path = proxy["h2-opts"]?.path;
        if (isPresent2(proxy, "h2-opts.path") && Array.isArray(path)) {
          proxy["h2-opts"].path = path[0];
        }
        let host = proxy["h2-opts"]?.headers?.host;
        if (isPresent2(proxy, "h2-opts.headers.Host") && !Array.isArray(host)) {
          proxy["h2-opts"].headers.host = [host];
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkPath = proxy[`${proxy.network}-opts`]?.path;
        if (networkPath) {
          const reg = /^(.*?)(?:\?ed=(\d+))?$/;
          const [_2, path = "", ed = ""] = reg.exec(networkPath);
          proxy[`${proxy.network}-opts`].path = path;
          if (ed !== "") {
            proxy["ws-opts"]["early-data-header-name"] = "Sec-WebSocket-Protocol";
            proxy["ws-opts"]["max-early-data"] = parseInt(
              ed,
              10
            );
          }
        } else {
          proxy[`${proxy.network}-opts`] = proxy[`${proxy.network}-opts`] || {};
          proxy[`${proxy.network}-opts`].path = "/";
        }
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls"
      ].includes(proxy.type)) {
        delete proxy.tls;
      }
      if (proxy["tls-fingerprint"]) {
        proxy.fingerprint = proxy["tls-fingerprint"];
      }
      delete proxy["tls-fingerprint"];
      if (isPresent2(proxy, "tls") && typeof proxy.tls !== "boolean") {
        delete proxy.tls;
      }
      delete proxy.subName;
      delete proxy.collectionName;
      delete proxy.id;
      delete proxy.resolved;
      delete proxy["no-resolve"];
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      return proxy;
    });
    return type2 === "internal" ? list : "proxies:\n" + list.map((proxy) => "  - " + JSON.stringify(proxy) + "\n").join("");
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/stash.js
function Stash_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (![
        "ss",
        "ssr",
        "vmess",
        "socks5",
        "http",
        "snell",
        "trojan",
        "tuic",
        "vless",
        "wireguard",
        "hysteria",
        "hysteria2",
        "ssh",
        "juicity"
      ].includes(proxy.type) || proxy.type === "ss" && ![
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm"
      ].includes(proxy.cipher) || proxy.type === "snell" && proxy.version >= 4 || proxy.type === "vless" && proxy["reality-opts"] && !["xtls-rprx-vision"].includes(proxy.flow)) {
        return false;
      } else if (proxy["underlying-proxy"] || proxy["dialer-proxy"]) {
        app_default.error(
          `Stash \u6682\u4E0D\u652F\u6301\u524D\u7F6E\u4EE3\u7406\u5B57\u6BB5. \u5DF2\u8FC7\u6EE4\u8282\u70B9 ${proxy.name}. \u8BF7\u4F7F\u7528 \u4EE3\u7406\u7684\u8F6C\u53D1\u94FE https://stash.wiki/proxy-protocols/proxy-groups#relay`
        );
        return false;
      }
      return true;
    }).map((proxy) => {
      if (proxy.type === "vmess") {
        if (isPresent2(proxy, "aead")) {
          if (proxy.aead) {
            proxy.alterId = 0;
          }
          delete proxy.aead;
        }
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
        if (isPresent2(proxy, "cipher") && ![
          "auto",
          "aes-128-gcm",
          "chacha20-poly1305",
          "none"
        ].includes(proxy.cipher)) {
          proxy.cipher = "auto";
        }
      } else if (proxy.type === "tuic") {
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        } else {
          proxy.alpn = ["h3"];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
          delete proxy.tfo;
        }
        if ((!proxy.token || proxy.token.length === 0) && !isPresent2(proxy, "version")) {
          proxy.version = 5;
        }
      } else if (proxy.type === "hysteria") {
        if (isPresent2(proxy, "auth_str") && !isPresent2(proxy, "auth-str")) {
          proxy["auth-str"] = proxy["auth_str"];
        }
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
          delete proxy.tfo;
        }
        if (isPresent2(proxy, "down") && !isPresent2(proxy, "down-speed")) {
          proxy["down-speed"] = proxy.down;
          delete proxy.down;
        }
        if (isPresent2(proxy, "up") && !isPresent2(proxy, "up-speed")) {
          proxy["up-speed"] = proxy.up;
          delete proxy.up;
        }
        if (isPresent2(proxy, "down-speed")) {
          proxy["down-speed"] = `${proxy["down-speed"]}`.match(/\d+/)?.[0] || 0;
        }
        if (isPresent2(proxy, "up-speed")) {
          proxy["up-speed"] = `${proxy["up-speed"]}`.match(/\d+/)?.[0] || 0;
        }
      } else if (proxy.type === "hysteria2") {
        if (isPresent2(proxy, "password") && !isPresent2(proxy, "auth")) {
          proxy.auth = proxy.password;
          delete proxy.password;
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
          delete proxy.tfo;
        }
        if (isPresent2(proxy, "down") && !isPresent2(proxy, "down-speed")) {
          proxy["down-speed"] = proxy.down;
          delete proxy.down;
        }
        if (isPresent2(proxy, "up") && !isPresent2(proxy, "up-speed")) {
          proxy["up-speed"] = proxy.up;
          delete proxy.up;
        }
        if (isPresent2(proxy, "down-speed")) {
          proxy["down-speed"] = `${proxy["down-speed"]}`.match(/\d+/)?.[0] || 0;
        }
        if (isPresent2(proxy, "up-speed")) {
          proxy["up-speed"] = `${proxy["up-speed"]}`.match(/\d+/)?.[0] || 0;
        }
      } else if (proxy.type === "wireguard") {
        proxy.keepalive = proxy.keepalive ?? proxy["persistent-keepalive"];
        proxy["persistent-keepalive"] = proxy.keepalive;
        proxy["preshared-key"] = proxy["preshared-key"] ?? proxy["pre-shared-key"];
        proxy["pre-shared-key"] = proxy["preshared-key"];
      } else if (proxy.type === "snell" && proxy.version < 3) {
        delete proxy.udp;
      } else if (proxy.type === "vless") {
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "http") {
        let httpPath = proxy["http-opts"]?.path;
        if (isPresent2(proxy, "http-opts.path") && !Array.isArray(httpPath)) {
          proxy["http-opts"].path = [httpPath];
        }
        let httpHost = proxy["http-opts"]?.headers?.Host;
        if (isPresent2(proxy, "http-opts.headers.Host") && !Array.isArray(httpHost)) {
          proxy["http-opts"].headers.Host = [httpHost];
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "h2") {
        let path = proxy["h2-opts"]?.path;
        if (isPresent2(proxy, "h2-opts.path") && Array.isArray(path)) {
          proxy["h2-opts"].path = path[0];
        }
        let host = proxy["h2-opts"]?.headers?.host;
        if (isPresent2(proxy, "h2-opts.headers.Host") && !Array.isArray(host)) {
          proxy["h2-opts"].headers.host = [host];
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkPath = proxy[`${proxy.network}-opts`]?.path;
        if (networkPath) {
          const reg = /^(.*?)(?:\?ed=(\d+))?$/;
          const [_2, path = "", ed = ""] = reg.exec(networkPath);
          proxy[`${proxy.network}-opts`].path = path;
          if (ed !== "") {
            proxy["ws-opts"]["early-data-header-name"] = "Sec-WebSocket-Protocol";
            proxy["ws-opts"]["max-early-data"] = parseInt(
              ed,
              10
            );
          }
        } else {
          proxy[`${proxy.network}-opts`] = proxy[`${proxy.network}-opts`] || {};
          proxy[`${proxy.network}-opts`].path = "/";
        }
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls"
      ].includes(proxy.type)) {
        delete proxy.tls;
      }
      if (proxy["tls-fingerprint"]) {
        proxy["server-cert-fingerprint"] = proxy["tls-fingerprint"];
      }
      delete proxy["tls-fingerprint"];
      if (isPresent2(proxy, "tls") && typeof proxy.tls !== "boolean") {
        delete proxy.tls;
      }
      if (proxy["test-url"]) {
        proxy["benchmark-url"] = proxy["test-url"];
        delete proxy["test-url"];
      }
      if (proxy["test-timeout"]) {
        proxy["benchmark-timeout"] = proxy["test-timeout"];
        delete proxy["test-timeout"];
      }
      delete proxy.subName;
      delete proxy.collectionName;
      delete proxy.id;
      delete proxy.resolved;
      delete proxy["no-resolve"];
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      return proxy;
    });
    return type2 === "internal" ? list : "proxies:\n" + list.map((proxy) => "  - " + JSON.stringify(proxy) + "\n").join("");
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/loon.js
var targetPlatform3 = "Loon";
var ipVersions3 = {
  dual: "dual",
  ipv4: "v4-only",
  ipv6: "v6-only",
  "ipv4-prefer": "prefer-v4",
  "ipv6-prefer": "prefer-v6"
};
function Loon_Producer() {
  const produce2 = (proxy, type, opts = {}) => {
    switch (proxy.type) {
      case "ss":
        return shadowsocks2(proxy);
      case "ssr":
        return shadowsocksr(proxy);
      case "trojan":
        return trojan2(proxy);
      case "vmess":
        return vmess2(proxy, opts["include-unsupported-proxy"]);
      case "vless":
        return vless(proxy, opts["include-unsupported-proxy"]);
      case "http":
        return http2(proxy);
      case "socks5":
        return socks52(proxy);
      case "wireguard":
        return wireguard2(proxy);
      case "hysteria2":
        return hysteria22(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform3} does not support proxy type: ${proxy.type}`
    );
  };
  return { produce: produce2 };
}
function shadowsocks2(proxy) {
  const result = new Result(proxy);
  if (![
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm"
  ].includes(proxy.cipher)) {
    throw new Error(`cipher ${proxy.cipher} is not supported`);
  }
  result.append(
    `${proxy.name}=shadowsocks,${proxy.server},${proxy.port},${proxy.cipher},"${proxy.password}"`
  );
  if (isPresent2(proxy, "plugin")) {
    if (proxy.plugin === "obfs") {
      if (proxy["plugin-opts"]?.mode && proxy.cipher.startsWith("2022-")) {
        throw new Error(
          `${proxy.cipher} ${proxy.plugin} is not supported`
        );
      }
      result.append(`,obfs-name=${proxy["plugin-opts"].mode}`);
      result.appendIfPresent(
        `,obfs-host=${proxy["plugin-opts"].host}`,
        "plugin-opts.host"
      );
      result.appendIfPresent(
        `,obfs-uri=${proxy["plugin-opts"].path}`,
        "plugin-opts.path"
      );
    } else if (!["shadow-tls"].includes(proxy.plugin)) {
      throw new Error(`plugin ${proxy.plugin} is not supported`);
    }
  }
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
    result.appendIfPresent(`,udp-port=${proxy["udp-port"]}`, "udp-port");
  } else if (["shadow-tls"].includes(proxy.plugin) && proxy["plugin-opts"]) {
    const password = proxy["plugin-opts"].password;
    const host = proxy["plugin-opts"].host;
    const version = proxy["plugin-opts"].version;
    if (password) {
      result.append(`,shadow-tls-password=${password}`);
      if (host) {
        result.append(`,shadow-tls-sni=${host}`);
      }
      if (version) {
        if (version < 2) {
          throw new Error(
            `shadow-tls version ${version} is not supported`
          );
        }
        result.append(`,shadow-tls-version=${version}`);
      }
      result.appendIfPresent(
        `,udp-port=${proxy["udp-port"]}`,
        "udp-port"
      );
    }
  }
  result.appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function shadowsocksr(proxy) {
  const result = new Result(proxy);
  result.append(
    `${proxy.name}=shadowsocksr,${proxy.server},${proxy.port},${proxy.cipher},"${proxy.password}"`
  );
  result.append(`,protocol=${proxy.protocol}`);
  result.appendIfPresent(
    `,protocol-param=${proxy["protocol-param"]}`,
    "protocol-param"
  );
  result.appendIfPresent(`,obfs=${proxy.obfs}`, "obfs");
  result.appendIfPresent(`,obfs-param=${proxy["obfs-param"]}`, "obfs-param");
  if (isPresent2(proxy, "shadow-tls-password")) {
    result.append(`,shadow-tls-password=${proxy["shadow-tls-password"]}`);
    result.appendIfPresent(
      `,shadow-tls-version=${proxy["shadow-tls-version"]}`,
      "shadow-tls-version"
    );
    result.appendIfPresent(
      `,shadow-tls-sni=${proxy["shadow-tls-sni"]}`,
      "shadow-tls-sni"
    );
    result.appendIfPresent(`,udp-port=${proxy["udp-port"]}`, "udp-port");
  } else if (["shadow-tls"].includes(proxy.plugin) && proxy["plugin-opts"]) {
    const password = proxy["plugin-opts"].password;
    const host = proxy["plugin-opts"].host;
    const version = proxy["plugin-opts"].version;
    if (password) {
      result.append(`,shadow-tls-password=${password}`);
      if (host) {
        result.append(`,shadow-tls-sni=${host}`);
      }
      if (version) {
        if (version < 2) {
          throw new Error(
            `shadow-tls version ${version} is not supported`
          );
        }
        result.append(`,shadow-tls-version=${version}`);
      }
      result.appendIfPresent(
        `,udp-port=${proxy["udp-port"]}`,
        "udp-port"
      );
    }
  }
  result.appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function trojan2(proxy) {
  const result = new Result(proxy);
  result.append(
    `${proxy.name}=trojan,${proxy.server},${proxy.port},"${proxy.password}"`
  );
  if (proxy.network === "tcp") {
    delete proxy.network;
  }
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      result.append(`,transport=ws`);
      result.appendIfPresent(
        `,path=${proxy["ws-opts"]?.path}`,
        "ws-opts.path"
      );
      result.appendIfPresent(
        `,host=${proxy["ws-opts"]?.headers?.Host}`,
        "ws-opts.headers.Host"
      );
    } else {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
  }
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tls-name=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(
    `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
    "tls-pubkey-sha256"
  );
  result.appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function vmess2(proxy) {
  const isReality = !!proxy["reality-opts"];
  const result = new Result(proxy);
  result.append(
    `${proxy.name}=vmess,${proxy.server},${proxy.port},${proxy.cipher},"${proxy.uuid}"`
  );
  if (proxy.network === "tcp") {
    delete proxy.network;
  }
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      result.append(`,transport=ws`);
      result.appendIfPresent(
        `,path=${proxy["ws-opts"]?.path}`,
        "ws-opts.path"
      );
      result.appendIfPresent(
        `,host=${proxy["ws-opts"]?.headers?.Host}`,
        "ws-opts.headers.Host"
      );
    } else if (proxy.network === "http") {
      result.append(`,transport=http`);
      let httpPath = proxy["http-opts"]?.path;
      let httpHost = proxy["http-opts"]?.headers?.Host;
      result.appendIfPresent(
        `,path=${Array.isArray(httpPath) ? httpPath[0] : httpPath}`,
        "http-opts.path"
      );
      result.appendIfPresent(
        `,host=${Array.isArray(httpHost) ? httpHost[0] : httpHost}`,
        "http-opts.headers.Host"
      );
    } else {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
  } else {
    result.append(`,transport=tcp`);
  }
  result.appendIfPresent(`,over-tls=${proxy.tls}`, "tls");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  if (isReality) {
    result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
    result.appendIfPresent(
      `,public-key="${proxy["reality-opts"]["public-key"]}"`,
      "reality-opts.public-key"
    );
    result.appendIfPresent(
      `,short-id=${proxy["reality-opts"]["short-id"]}`,
      "reality-opts.short-id"
    );
  } else {
    result.appendIfPresent(`,tls-name=${proxy.sni}`, "sni");
    result.appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    result.appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
  }
  if (isPresent2(proxy, "aead")) {
    result.append(`,alterId=${proxy.aead ? 0 : 1}`);
  } else {
    result.append(`,alterId=${proxy.alterId}`);
  }
  result.appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function vless(proxy) {
  let isXtls = false;
  const isReality = !!proxy["reality-opts"];
  if (typeof proxy.flow !== "undefined") {
    if (["xtls-rprx-vision"].includes(proxy.flow)) {
      isXtls = true;
    } else {
      throw new Error(`VLESS flow(${proxy.flow}) is not supported`);
    }
  }
  const result = new Result(proxy);
  result.append(
    `${proxy.name}=vless,${proxy.server},${proxy.port},"${proxy.uuid}"`
  );
  if (proxy.network === "tcp") {
    delete proxy.network;
  }
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      result.append(`,transport=ws`);
      result.appendIfPresent(
        `,path=${proxy["ws-opts"]?.path}`,
        "ws-opts.path"
      );
      result.appendIfPresent(
        `,host=${proxy["ws-opts"]?.headers?.Host}`,
        "ws-opts.headers.Host"
      );
    } else if (proxy.network === "http") {
      result.append(`,transport=http`);
      let httpPath = proxy["http-opts"]?.path;
      let httpHost = proxy["http-opts"]?.headers?.Host;
      result.appendIfPresent(
        `,path=${Array.isArray(httpPath) ? httpPath[0] : httpPath}`,
        "http-opts.path"
      );
      result.appendIfPresent(
        `,host=${Array.isArray(httpHost) ? httpHost[0] : httpHost}`,
        "http-opts.headers.Host"
      );
    } else {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
  } else {
    result.append(`,transport=tcp`);
  }
  result.appendIfPresent(`,over-tls=${proxy.tls}`, "tls");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  if (isXtls) {
    result.appendIfPresent(`,flow=${proxy.flow}`, "flow");
  }
  if (isReality) {
    result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
    result.appendIfPresent(
      `,public-key="${proxy["reality-opts"]["public-key"]}"`,
      "reality-opts.public-key"
    );
    result.appendIfPresent(
      `,short-id=${proxy["reality-opts"]["short-id"]}`,
      "reality-opts.short-id"
    );
  } else {
    result.appendIfPresent(`,tls-name=${proxy.sni}`, "sni");
    result.appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    result.appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
  }
  result.appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function http2(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "https" : "http";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,${proxy.username}`, "username");
  result.appendIfPresent(`,"${proxy.password}"`, "password");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function socks52(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=socks5,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,${proxy.username}`, "username");
  result.appendIfPresent(`,"${proxy.password}"`, "password");
  result.appendIfPresent(`,over-tls=${proxy.tls}`, "tls");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}
function wireguard2(proxy) {
  if (Array.isArray(proxy.peers) && proxy.peers.length > 0) {
    proxy.server = proxy.peers[0].server;
    proxy.port = proxy.peers[0].port;
    proxy.ip = proxy.peers[0].ip;
    proxy.ipv6 = proxy.peers[0].ipv6;
    proxy["public-key"] = proxy.peers[0]["public-key"];
    proxy["preshared-key"] = proxy.peers[0]["pre-shared-key"];
    proxy["allowed-ips"] = proxy.peers[0]["allowed-ips"];
    proxy.reserved = proxy.peers[0].reserved;
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=wireguard`);
  result.appendIfPresent(`,interface-ip=${proxy.ip}`, "ip");
  result.appendIfPresent(`,interface-ipv6=${proxy.ipv6}`, "ipv6");
  result.appendIfPresent(
    `,private-key="${proxy["private-key"]}"`,
    "private-key"
  );
  result.appendIfPresent(`,mtu=${proxy.mtu}`, "mtu");
  if (proxy.dns) {
    if (Array.isArray(proxy.dns)) {
      proxy.dnsv6 = proxy.dns.find((i) => isIPv6(i));
      let dns = proxy.dns.find((i) => isIPv4(i));
      if (!dns) {
        dns = proxy.dns.find((i) => !isIPv4(i) && !isIPv6(i));
      }
      proxy.dns = dns;
    }
  }
  result.appendIfPresent(`,dns=${proxy.dns}`, "dns");
  result.appendIfPresent(`,dnsv6=${proxy.dnsv6}`, "dnsv6");
  result.appendIfPresent(
    `,keepalive=${proxy["persistent-keepalive"]}`,
    "persistent-keepalive"
  );
  result.appendIfPresent(`,keepalive=${proxy.keepalive}`, "keepalive");
  const allowedIps = Array.isArray(proxy["allowed-ips"]) ? proxy["allowed-ips"].join(",") : proxy["allowed-ips"];
  let reserved = Array.isArray(proxy.reserved) ? proxy.reserved.join(",") : proxy.reserved;
  if (reserved) {
    reserved = `,reserved=[${reserved}]`;
  }
  let presharedKey = proxy["preshared-key"] ?? proxy["pre-shared-key"];
  if (presharedKey) {
    presharedKey = `,preshared-key="${presharedKey}"`;
  }
  result.append(
    `,peers=[{public-key="${proxy["public-key"]}",allowed-ips="${allowedIps ?? "0.0.0.0/0,::/0"}",endpoint=${proxy.server}:${proxy.port}${reserved ?? ""}${presharedKey ?? ""}}]`
  );
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  return result.toString();
}
function hysteria22(proxy) {
  if (proxy["obfs-password"] && proxy.obfs != "salamander") {
    throw new Error(`only salamander obfs is supported`);
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=Hysteria2,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,"${proxy.password}"`, "password");
  result.appendIfPresent(`,tls-name=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(
    `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
    "tls-pubkey-sha256"
  );
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  if (proxy["obfs-password"] && proxy.obfs == "salamander") {
    result.append(`,salamander-password=${proxy["obfs-password"]}`);
  }
  result.appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  if (proxy["block-quic"] === "on") {
    result.append(",block-quic=true");
  } else if (proxy["block-quic"] === "off") {
    result.append(",block-quic=false");
  }
  if (proxy.udp) {
    result.append(`,udp=true`);
  }
  result.appendIfPresent(
    `,download-bandwidth=${`${proxy["down"]}`.match(/\d+/)?.[0] || 0}`,
    "down"
  );
  result.appendIfPresent(`,ecn=${proxy.ecn}`, "ecn");
  const ip_version = ipVersions3[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-mode=${ip_version}`, "ip-version");
  return result.toString();
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/uri.js
import { Base64 as Base643 } from "js-base64";
function vless2(proxy) {
  let security = "none";
  const isReality = proxy["reality-opts"];
  let sid = "";
  let pbk = "";
  let spx = "";
  if (isReality) {
    security = "reality";
    const publicKey = proxy["reality-opts"]?.["public-key"];
    if (publicKey) {
      pbk = `&pbk=${encodeURIComponent(publicKey)}`;
    }
    const shortId = proxy["reality-opts"]?.["short-id"];
    if (shortId) {
      sid = `&sid=${encodeURIComponent(shortId)}`;
    }
    const spiderX = proxy["reality-opts"]?.["_spider-x"];
    if (spiderX) {
      spx = `&spx=${encodeURIComponent(spiderX)}`;
    }
  } else if (proxy.tls) {
    security = "tls";
  }
  let alpn = "";
  if (proxy.alpn) {
    alpn = `&alpn=${encodeURIComponent(
      Array.isArray(proxy.alpn) ? proxy.alpn : proxy.alpn.join(",")
    )}`;
  }
  let allowInsecure = "";
  if (proxy["skip-cert-verify"]) {
    allowInsecure = `&allowInsecure=1`;
  }
  let sni = "";
  if (proxy.sni) {
    sni = `&sni=${encodeURIComponent(proxy.sni)}`;
  }
  let fp = "";
  if (proxy["client-fingerprint"]) {
    fp = `&fp=${encodeURIComponent(proxy["client-fingerprint"])}`;
  }
  let flow = "";
  if (proxy.flow) {
    flow = `&flow=${encodeURIComponent(proxy.flow)}`;
  }
  let extra = "";
  if (proxy._extra) {
    extra = `&extra=${encodeURIComponent(proxy._extra)}`;
  }
  let mode = "";
  if (proxy._mode) {
    mode = `&mode=${encodeURIComponent(proxy._mode)}`;
  }
  let pqv = "";
  if (proxy._pqv) {
    pqv = `&pqv=${encodeURIComponent(proxy._pqv)}`;
  }
  let encryption = "";
  if (proxy.encryption) {
    encryption = `&encryption=${encodeURIComponent(proxy.encryption)}`;
  }
  let vlessType = proxy.network;
  if (proxy.network === "ws" && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
    vlessType = "httpupgrade";
  }
  let vlessTransport = `&type=${encodeURIComponent(vlessType)}`;
  if (["grpc"].includes(proxy.network)) {
    vlessTransport += `&mode=${encodeURIComponent(
      proxy[`${proxy.network}-opts`]?.["_grpc-type"] || "gun"
    )}`;
    const authority = proxy[`${proxy.network}-opts`]?.["_grpc-authority"];
    if (authority) {
      vlessTransport += `&authority=${encodeURIComponent(authority)}`;
    }
  }
  let vlessTransportServiceName = proxy[`${proxy.network}-opts`]?.[`${proxy.network}-service-name`];
  let vlessTransportPath = proxy[`${proxy.network}-opts`]?.path;
  let vlessTransportHost = proxy[`${proxy.network}-opts`]?.headers?.Host;
  if (vlessTransportPath) {
    vlessTransport += `&path=${encodeURIComponent(
      Array.isArray(vlessTransportPath) ? vlessTransportPath[0] : vlessTransportPath
    )}`;
  }
  if (vlessTransportHost) {
    vlessTransport += `&host=${encodeURIComponent(
      Array.isArray(vlessTransportHost) ? vlessTransportHost[0] : vlessTransportHost
    )}`;
  }
  if (vlessTransportServiceName) {
    vlessTransport += `&serviceName=${encodeURIComponent(
      vlessTransportServiceName
    )}`;
  }
  if (proxy.network === "kcp") {
    if (proxy.seed) {
      vlessTransport += `&seed=${encodeURIComponent(proxy.seed)}`;
    }
    if (proxy.headerType) {
      vlessTransport += `&headerType=${encodeURIComponent(
        proxy.headerType
      )}`;
    }
  }
  return `vless://${proxy.uuid}@${proxy.server}:${proxy.port}?security=${encodeURIComponent(
    security
  )}${vlessTransport}${alpn}${allowInsecure}${sni}${fp}${flow}${sid}${spx}${pbk}${mode}${extra}${pqv}${encryption}#${encodeURIComponent(
    proxy.name
  )}`;
}
function URI_Producer() {
  const type = "SINGLE";
  const produce2 = (proxy) => {
    let result = "";
    delete proxy.subName;
    delete proxy.collectionName;
    delete proxy.id;
    delete proxy.resolved;
    delete proxy["no-resolve"];
    for (const key in proxy) {
      if (proxy[key] == null) {
        delete proxy[key];
      }
    }
    if (["trojan", "tuic", "hysteria", "hysteria2", "juicity"].includes(
      proxy.type
    )) {
      delete proxy.tls;
    }
    if (!["vmess"].includes(proxy.type) && proxy.server && isIPv6(proxy.server)) {
      proxy.server = `[${proxy.server}]`;
    }
    switch (proxy.type) {
      case "socks5":
        result = `socks://${encodeURIComponent(
          Base643.encode(
            `${proxy.username ?? ""}:${proxy.password ?? ""}`
          )
        )}@${proxy.server}:${proxy.port}#${proxy.name}`;
        break;
      case "ss":
        const userinfo = `${proxy.cipher}:${proxy.password}`;
        result = `ss://${proxy.cipher?.startsWith("2022-blake3-") ? `${encodeURIComponent(
          proxy.cipher
        )}:${encodeURIComponent(proxy.password)}` : Base643.encode(userinfo)}@${proxy.server}:${proxy.port}${proxy.plugin ? "/" : ""}`;
        if (proxy.plugin) {
          result += "?plugin=";
          const opts = proxy["plugin-opts"];
          switch (proxy.plugin) {
            case "obfs":
              result += encodeURIComponent(
                `simple-obfs;obfs=${opts.mode}${opts.host ? ";obfs-host=" + opts.host : ""}`
              );
              break;
            case "v2ray-plugin":
              result += encodeURIComponent(
                `v2ray-plugin;obfs=${opts.mode}${opts.host ? ";obfs-host" + opts.host : ""}${opts.tls ? ";tls" : ""}`
              );
              break;
            case "shadow-tls":
              result += encodeURIComponent(
                `shadow-tls;host=${opts.host};password=${opts.password};version=${opts.version}`
              );
              break;
            default:
              throw new Error(
                `Unsupported plugin option: ${proxy.plugin}`
              );
          }
        }
        if (proxy["udp-over-tcp"]) {
          result = `${result}${proxy.plugin ? "&" : "?"}uot=1`;
        }
        if (proxy.tfo) {
          result = `${result}${proxy.plugin || proxy["udp-over-tcp"] ? "&" : "?"}tfo=1`;
        }
        result += `#${encodeURIComponent(proxy.name)}`;
        break;
      case "ssr":
        result = `${proxy.server}:${proxy.port}:${proxy.protocol}:${proxy.cipher}:${proxy.obfs}:${Base643.encode(proxy.password)}/`;
        result += `?remarks=${Base643.encode(proxy.name)}${proxy["obfs-param"] ? "&obfsparam=" + Base643.encode(proxy["obfs-param"]) : ""}${proxy["protocol-param"] ? "&protocolparam=" + Base643.encode(proxy["protocol-param"]) : ""}`;
        result = "ssr://" + Base643.encode(result);
        break;
      case "vmess":
        let type2 = "";
        let net = proxy.network || "tcp";
        if (proxy.network === "http") {
          net = "tcp";
          type2 = "http";
        } else if (proxy.network === "ws" && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
          net = "httpupgrade";
        }
        result = {
          v: "2",
          ps: proxy.name,
          add: proxy.server,
          port: `${proxy.port}`,
          id: proxy.uuid,
          aid: `${proxy.alterId || 0}`,
          scy: proxy.cipher,
          net,
          type: type2,
          tls: proxy.tls ? "tls" : "",
          alpn: Array.isArray(proxy.alpn) ? proxy.alpn.join(",") : proxy.alpn,
          fp: proxy["client-fingerprint"]
        };
        if (proxy.tls && proxy.sni) {
          result.sni = proxy.sni;
        }
        if (proxy.network) {
          let vmessTransportPath = proxy[`${proxy.network}-opts`]?.path;
          let vmessTransportHost = proxy[`${proxy.network}-opts`]?.headers?.Host;
          if (["grpc"].includes(proxy.network)) {
            result.path = proxy[`${proxy.network}-opts`]?.["grpc-service-name"];
            result.type = proxy[`${proxy.network}-opts`]?.["_grpc-type"] || "gun";
            result.host = proxy[`${proxy.network}-opts`]?.["_grpc-authority"];
          } else if (["kcp", "quic"].includes(proxy.network)) {
            result.type = proxy[`${proxy.network}-opts`]?.[`_${proxy.network}-type`] || "none";
            result.host = proxy[`${proxy.network}-opts`]?.[`_${proxy.network}-host`];
            result.path = proxy[`${proxy.network}-opts`]?.[`_${proxy.network}-path`];
          } else {
            if (vmessTransportPath) {
              result.path = Array.isArray(vmessTransportPath) ? vmessTransportPath[0] : vmessTransportPath;
            }
            if (vmessTransportHost) {
              result.host = Array.isArray(vmessTransportHost) ? vmessTransportHost[0] : vmessTransportHost;
            }
          }
        }
        result = "vmess://" + Base643.encode(JSON.stringify(result));
        break;
      case "vless":
        result = vless2(proxy);
        break;
      case "trojan":
        let trojanTransport = "";
        if (proxy.network) {
          let trojanType = proxy.network;
          if (proxy.network === "ws" && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
            trojanType = "httpupgrade";
          }
          trojanTransport = `&type=${encodeURIComponent(trojanType)}`;
          if (["grpc"].includes(proxy.network)) {
            let trojanTransportServiceName = proxy[`${proxy.network}-opts`]?.[`${proxy.network}-service-name`];
            let trojanTransportAuthority = proxy[`${proxy.network}-opts`]?.["_grpc-authority"];
            if (trojanTransportServiceName) {
              trojanTransport += `&serviceName=${encodeURIComponent(
                trojanTransportServiceName
              )}`;
            }
            if (trojanTransportAuthority) {
              trojanTransport += `&authority=${encodeURIComponent(
                trojanTransportAuthority
              )}`;
            }
            trojanTransport += `&mode=${encodeURIComponent(
              proxy[`${proxy.network}-opts`]?.["_grpc-type"] || "gun"
            )}`;
          }
          let trojanTransportPath = proxy[`${proxy.network}-opts`]?.path;
          let trojanTransportHost = proxy[`${proxy.network}-opts`]?.headers?.Host;
          if (trojanTransportPath) {
            trojanTransport += `&path=${encodeURIComponent(
              Array.isArray(trojanTransportPath) ? trojanTransportPath[0] : trojanTransportPath
            )}`;
          }
          if (trojanTransportHost) {
            trojanTransport += `&host=${encodeURIComponent(
              Array.isArray(trojanTransportHost) ? trojanTransportHost[0] : trojanTransportHost
            )}`;
          }
        }
        let trojanFp = "";
        if (proxy["client-fingerprint"]) {
          trojanFp = `&fp=${encodeURIComponent(
            proxy["client-fingerprint"]
          )}`;
        }
        let trojanAlpn = "";
        if (proxy.alpn) {
          trojanAlpn = `&alpn=${encodeURIComponent(
            Array.isArray(proxy.alpn) ? proxy.alpn : proxy.alpn.join(",")
          )}`;
        }
        const trojanIsReality = proxy["reality-opts"];
        let trojanSid = "";
        let trojanPbk = "";
        let trojanSpx = "";
        let trojanSecurity = "";
        let trojanMode = "";
        let trojanExtra = "";
        if (trojanIsReality) {
          trojanSecurity = `&security=reality`;
          const publicKey = proxy["reality-opts"]?.["public-key"];
          if (publicKey) {
            trojanPbk = `&pbk=${encodeURIComponent(publicKey)}`;
          }
          const shortId = proxy["reality-opts"]?.["short-id"];
          if (shortId) {
            trojanSid = `&sid=${encodeURIComponent(shortId)}`;
          }
          const spiderX = proxy["reality-opts"]?.["_spider-x"];
          if (spiderX) {
            trojanSpx = `&spx=${encodeURIComponent(spiderX)}`;
          }
          if (proxy._extra) {
            trojanExtra = `&extra=${encodeURIComponent(
              proxy._extra
            )}`;
          }
          if (proxy._mode) {
            trojanMode = `&mode=${encodeURIComponent(proxy._mode)}`;
          }
        }
        result = `trojan://${proxy.password}@${proxy.server}:${proxy.port}?sni=${encodeURIComponent(proxy.sni || proxy.server)}${proxy["skip-cert-verify"] ? "&allowInsecure=1" : ""}${trojanTransport}${trojanAlpn}${trojanFp}${trojanSecurity}${trojanSid}${trojanPbk}${trojanSpx}${trojanMode}${trojanExtra}#${encodeURIComponent(
          proxy.name
        )}`;
        break;
      case "hysteria2":
        let hysteria2params = [];
        if (proxy["hop-interval"]) {
          hysteria2params.push(
            `hop-interval=${proxy["hop-interval"]}`
          );
        }
        if (proxy["keepalive"]) {
          hysteria2params.push(`keepalive=${proxy["keepalive"]}`);
        }
        if (proxy["skip-cert-verify"]) {
          hysteria2params.push(`insecure=1`);
        }
        if (proxy.obfs) {
          hysteria2params.push(
            `obfs=${encodeURIComponent(proxy.obfs)}`
          );
          if (proxy["obfs-password"]) {
            hysteria2params.push(
              `obfs-password=${encodeURIComponent(
                proxy["obfs-password"]
              )}`
            );
          }
        }
        if (proxy.sni) {
          hysteria2params.push(
            `sni=${encodeURIComponent(proxy.sni)}`
          );
        }
        if (proxy.ports) {
          hysteria2params.push(`mport=${proxy.ports}`);
        }
        if (proxy["tls-fingerprint"]) {
          hysteria2params.push(
            `pinSHA256=${encodeURIComponent(
              proxy["tls-fingerprint"]
            )}`
          );
        }
        if (proxy.tfo) {
          hysteria2params.push(`fastopen=1`);
        }
        result = `hysteria2://${encodeURIComponent(proxy.password)}@${proxy.server}:${proxy.port}?${hysteria2params.join(
          "&"
        )}#${encodeURIComponent(proxy.name)}`;
        break;
      case "hysteria":
        let hysteriaParams = [];
        Object.keys(proxy).forEach((key) => {
          if (!["name", "type", "server", "port"].includes(key)) {
            const i = key.replace(/-/, "_");
            if (["alpn"].includes(key)) {
              if (proxy[key]) {
                hysteriaParams.push(
                  `${i}=${encodeURIComponent(
                    Array.isArray(proxy[key]) ? proxy[key][0] : proxy[key]
                  )}`
                );
              }
            } else if (["skip-cert-verify"].includes(key)) {
              if (proxy[key]) {
                hysteriaParams.push(`insecure=1`);
              }
            } else if (["tfo", "fast-open"].includes(key)) {
              if (proxy[key] && !hysteriaParams.includes("fastopen=1")) {
                hysteriaParams.push(`fastopen=1`);
              }
            } else if (["ports"].includes(key)) {
              hysteriaParams.push(`mport=${proxy[key]}`);
            } else if (["auth-str"].includes(key)) {
              hysteriaParams.push(`auth=${proxy[key]}`);
            } else if (["up"].includes(key)) {
              hysteriaParams.push(`upmbps=${proxy[key]}`);
            } else if (["down"].includes(key)) {
              hysteriaParams.push(`downmbps=${proxy[key]}`);
            } else if (["_obfs"].includes(key)) {
              hysteriaParams.push(`obfs=${proxy[key]}`);
            } else if (["obfs"].includes(key)) {
              hysteriaParams.push(`obfsParam=${proxy[key]}`);
            } else if (["sni"].includes(key)) {
              hysteriaParams.push(`peer=${proxy[key]}`);
            } else if (proxy[key] && !/^_/i.test(key)) {
              hysteriaParams.push(
                `${i}=${encodeURIComponent(proxy[key])}`
              );
            }
          }
        });
        result = `hysteria://${proxy.server}:${proxy.port}?${hysteriaParams.join("&")}#${encodeURIComponent(
          proxy.name
        )}`;
        break;
      case "tuic":
        if (!proxy.token || proxy.token.length === 0) {
          let tuicParams = [];
          Object.keys(proxy).forEach((key) => {
            if (![
              "name",
              "type",
              "uuid",
              "password",
              "server",
              "port",
              "tls"
            ].includes(key)) {
              const i = key.replace(/-/, "_");
              if (["alpn"].includes(key)) {
                if (proxy[key]) {
                  tuicParams.push(
                    `${i}=${encodeURIComponent(
                      Array.isArray(proxy[key]) ? proxy[key][0] : proxy[key]
                    )}`
                  );
                }
              } else if (["skip-cert-verify"].includes(key)) {
                if (proxy[key]) {
                  tuicParams.push(`allow_insecure=1`);
                }
              } else if (["tfo", "fast-open"].includes(key)) {
                if (proxy[key] && !tuicParams.includes("fast_open=1")) {
                  tuicParams.push(`fast_open=1`);
                }
              } else if (["disable-sni", "reduce-rtt"].includes(key) && proxy[key]) {
                tuicParams.push(`${i.replace(/-/g, "_")}=1`);
              } else if (["congestion-controller"].includes(key)) {
                tuicParams.push(
                  `congestion_control=${proxy[key]}`
                );
              } else if (proxy[key] && !/^_/i.test(key)) {
                tuicParams.push(
                  `${i.replace(
                    /-/g,
                    "_"
                  )}=${encodeURIComponent(proxy[key])}`
                );
              }
            }
          });
          result = `tuic://${encodeURIComponent(
            proxy.uuid
          )}:${encodeURIComponent(proxy.password)}@${proxy.server}:${proxy.port}?${tuicParams.join("&")}#${encodeURIComponent(
            proxy.name
          )}`;
        }
        break;
      case "anytls":
        result = vless2({
          ...proxy,
          uuid: proxy.password,
          network: proxy.network || "tcp"
        }).replace("vless", "anytls");
        let anytlsParams = [];
        Object.keys(proxy).forEach((key) => {
          if (![
            "name",
            "type",
            "password",
            "server",
            "port",
            "tls"
          ].includes(key)) {
            const i = key.replace(/-/, "_");
            if (["alpn"].includes(key)) {
              if (proxy[key]) {
                anytlsParams.push(
                  `${i}=${encodeURIComponent(
                    Array.isArray(proxy[key]) ? proxy[key][0] : proxy[key]
                  )}`
                );
              }
            } else if (["skip-cert-verify"].includes(key)) {
              if (proxy[key]) {
                anytlsParams.push(`insecure=1`);
              }
            } else if (["udp"].includes(key)) {
              if (proxy[key]) {
                anytlsParams.push(`udp=1`);
              }
            } else if (proxy[key] && !/^_|client-fingerprint/i.test(key) && ["number", "string", "boolean"].includes(
              typeof proxy[key]
            )) {
              anytlsParams.push(
                `${i.replace(/-/g, "_")}=${encodeURIComponent(
                  proxy[key]
                )}`
              );
            }
          }
        });
        const urlParts = result.split("?");
        let baseUrl = urlParts[0];
        let existingParams = {};
        if (urlParts.length > 1) {
          const queryString = urlParts[1].split("#")[0];
          const pairs = queryString.split("&");
          pairs.forEach((pair) => {
            const [key, value] = pair.split("=");
            if (key) {
              existingParams[key] = value;
            }
          });
        }
        anytlsParams.forEach((param) => {
          const [key, value] = param.split("=");
          if (key) {
            existingParams[key] = value;
          }
        });
        const newParams = Object.keys(existingParams).map((key) => `${key}=${existingParams[key]}`).join("&");
        const fragmentMatch = result.match(/#(.*)$/);
        const fragment = fragmentMatch ? `#${fragmentMatch[1]}` : "";
        result = `${baseUrl}?${newParams}${fragment}`;
        break;
      case "wireguard":
        let wireguardParams = [];
        Object.keys(proxy).forEach((key) => {
          if (![
            "name",
            "type",
            "server",
            "port",
            "ip",
            "ipv6",
            "private-key"
          ].includes(key)) {
            if (["public-key"].includes(key)) {
              wireguardParams.push(`publickey=${proxy[key]}`);
            } else if (["udp"].includes(key)) {
              if (proxy[key]) {
                wireguardParams.push(`${key}=1`);
              }
            } else if (proxy[key] && !/^_/i.test(key)) {
              wireguardParams.push(
                `${key}=${encodeURIComponent(proxy[key])}`
              );
            }
          }
        });
        if (proxy.ip && proxy.ipv6) {
          wireguardParams.push(
            `address=${proxy.ip}/32,${proxy.ipv6}/128`
          );
        } else if (proxy.ip) {
          wireguardParams.push(`address=${proxy.ip}/32`);
        } else if (proxy.ipv6) {
          wireguardParams.push(`address=${proxy.ipv6}/128`);
        }
        result = `wireguard://${encodeURIComponent(
          proxy["private-key"]
        )}@${proxy.server}:${proxy.port}/?${wireguardParams.join(
          "&"
        )}#${encodeURIComponent(proxy.name)}`;
        break;
    }
    return result;
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/v2ray.js
import { Base64 as Base644 } from "js-base64";
var URI = URI_Producer();
function V2Ray_Producer() {
  const type = "ALL";
  const produce2 = (proxies) => {
    let result = [];
    proxies.map((proxy) => {
      try {
        result.push(URI.produce(proxy));
      } catch (err) {
        app_default.error(
          `Cannot produce proxy: ${JSON.stringify(
            proxy,
            null,
            2
          )}
Reason: ${err}`
        );
      }
    });
    return Base644.encode(result.join("\n"));
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/qx.js
var targetPlatform4 = "QX";
function QX_Producer() {
  const produce2 = (proxy, type, opts = {}) => {
    switch (proxy.type) {
      case "ss":
        return shadowsocks3(proxy);
      case "ssr":
        return shadowsocksr2(proxy);
      case "trojan":
        return trojan3(proxy);
      case "vmess":
        return vmess3(proxy);
      case "http":
        return http3(proxy);
      case "socks5":
        return socks53(proxy);
      case "vless":
        return vless3(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform4} does not support proxy type: ${proxy.type}`
    );
  };
  return { produce: produce2 };
}
function shadowsocks3(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  if (!proxy.cipher) {
    proxy.cipher = "none";
  }
  if (![
    "none",
    "rc4-md5",
    "rc4-md5-6",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "cast5-cfb",
    "des-cfb",
    "rc2-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm"
  ].includes(proxy.cipher)) {
    throw new Error(`cipher ${proxy.cipher} is not supported`);
  }
  append(`shadowsocks=${proxy.server}:${proxy.port}`);
  append(`,method=${proxy.cipher}`);
  append(`,password=${proxy.password}`);
  if (needTls(proxy)) {
    proxy.tls = true;
  }
  if (isPresent2(proxy, "plugin")) {
    if (proxy.plugin === "obfs") {
      const opts = proxy["plugin-opts"];
      append(`,obfs=${opts.mode}`);
    } else if (proxy.plugin === "v2ray-plugin" && proxy["plugin-opts"].mode === "websocket") {
      const opts = proxy["plugin-opts"];
      if (opts.tls) append(`,obfs=wss`);
      else append(`,obfs=ws`);
    } else {
      throw new Error(`plugin is not supported`);
    }
    appendIfPresent(
      `,obfs-host=${proxy["plugin-opts"].host}`,
      "plugin-opts.host"
    );
    appendIfPresent(
      `,obfs-uri=${proxy["plugin-opts"].path}`,
      "plugin-opts.path"
    );
  }
  if (needTls(proxy)) {
    appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
    appendIfPresent(`,tls-alpn=${proxy["tls-alpn"]}`, "tls-alpn");
    appendIfPresent(
      `,tls-no-session-ticket=${proxy["tls-no-session-ticket"]}`,
      "tls-no-session-ticket"
    );
    appendIfPresent(
      `,tls-no-session-reuse=${proxy["tls-no-session-reuse"]}`,
      "tls-no-session-reuse"
    );
    appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    appendIfPresent(
      `,tls-verification=${!proxy["skip-cert-verify"]}`,
      "skip-cert-verify"
    );
    appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
  }
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  if (proxy["_ssr_python_uot"]) {
    append(`,udp-over-tcp=true`);
  } else if (proxy["udp-over-tcp"]) {
    if (!proxy["udp-over-tcp-version"] || proxy["udp-over-tcp-version"] === 1) {
      append(`,udp-over-tcp=sp.v1`);
    } else if (proxy["udp-over-tcp-version"] === 2) {
      append(`,udp-over-tcp=sp.v2`);
    }
  }
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function shadowsocksr2(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`shadowsocks=${proxy.server}:${proxy.port}`);
  append(`,method=${proxy.cipher}`);
  append(`,password=${proxy.password}`);
  append(`,ssr-protocol=${proxy.protocol}`);
  appendIfPresent(
    `,ssr-protocol-param=${proxy["protocol-param"]}`,
    "protocol-param"
  );
  appendIfPresent(`,obfs=${proxy.obfs}`, "obfs");
  appendIfPresent(`,obfs-host=${proxy["obfs-param"]}`, "obfs-param");
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function trojan3(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`trojan=${proxy.server}:${proxy.port}`);
  append(`,password=${proxy.password}`);
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      if (needTls(proxy)) append(`,obfs=wss`);
      else append(`,obfs=ws`);
      appendIfPresent(
        `,obfs-uri=${proxy["ws-opts"]?.path}`,
        "ws-opts.path"
      );
      appendIfPresent(
        `,obfs-host=${proxy["ws-opts"]?.headers?.Host}`,
        "ws-opts.headers.Host"
      );
    } else {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
  }
  if (proxy.network !== "ws" && needTls(proxy)) {
    append(`,over-tls=true`);
  }
  if (needTls(proxy)) {
    appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
    appendIfPresent(`,tls-alpn=${proxy["tls-alpn"]}`, "tls-alpn");
    appendIfPresent(
      `,tls-no-session-ticket=${proxy["tls-no-session-ticket"]}`,
      "tls-no-session-ticket"
    );
    appendIfPresent(
      `,tls-no-session-reuse=${proxy["tls-no-session-reuse"]}`,
      "tls-no-session-reuse"
    );
    appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    appendIfPresent(
      `,tls-verification=${!proxy["skip-cert-verify"]}`,
      "skip-cert-verify"
    );
    appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
  }
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function vmess3(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`vmess=${proxy.server}:${proxy.port}`);
  let cipher;
  if (proxy.cipher === "auto") {
    cipher = "chacha20-ietf-poly1305";
  } else {
    cipher = proxy.cipher;
  }
  append(`,method=${cipher}`);
  append(`,password=${proxy.uuid}`);
  if (needTls(proxy)) {
    proxy.tls = true;
  }
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      if (proxy.tls) append(`,obfs=wss`);
      else append(`,obfs=ws`);
    } else if (proxy.network === "http") {
      append(`,obfs=http`);
    } else {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
    let transportPath = proxy[`${proxy.network}-opts`]?.path;
    let transportHost = proxy[`${proxy.network}-opts`]?.headers?.Host;
    appendIfPresent(
      `,obfs-uri=${Array.isArray(transportPath) ? transportPath[0] : transportPath}`,
      `${proxy.network}-opts.path`
    );
    appendIfPresent(
      `,obfs-host=${Array.isArray(transportHost) ? transportHost[0] : transportHost}`,
      `${proxy.network}-opts.headers.Host`
    );
  } else {
    if (proxy.tls) append(`,obfs=over-tls`);
  }
  if (needTls(proxy)) {
    appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
    appendIfPresent(`,tls-alpn=${proxy["tls-alpn"]}`, "tls-alpn");
    appendIfPresent(
      `,tls-no-session-ticket=${proxy["tls-no-session-ticket"]}`,
      "tls-no-session-ticket"
    );
    appendIfPresent(
      `,tls-no-session-reuse=${proxy["tls-no-session-reuse"]}`,
      "tls-no-session-reuse"
    );
    appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    appendIfPresent(
      `,tls-verification=${!proxy["skip-cert-verify"]}`,
      "skip-cert-verify"
    );
    appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
  }
  if (isPresent2(proxy, "aead")) {
    append(`,aead=${proxy.aead}`);
  } else {
    append(`,aead=${proxy.alterId === 0}`);
  }
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function vless3(proxy) {
  if (typeof proxy.flow !== "undefined" || proxy["reality-opts"]) {
    throw new Error(`VLESS XTLS/REALITY is not supported`);
  }
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`vless=${proxy.server}:${proxy.port}`);
  let cipher = "none";
  append(`,method=${cipher}`);
  append(`,password=${proxy.uuid}`);
  if (needTls(proxy)) {
    proxy.tls = true;
  }
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      if (proxy.tls) append(`,obfs=wss`);
      else append(`,obfs=ws`);
    } else if (proxy.network === "http") {
      append(`,obfs=http`);
    } else if (["tcp"].includes(proxy.network)) {
      if (proxy.tls) append(`,obfs=over-tls`);
    } else if (!["tcp"].includes(proxy.network)) {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
    let transportPath = proxy[`${proxy.network}-opts`]?.path;
    let transportHost = proxy[`${proxy.network}-opts`]?.headers?.Host;
    appendIfPresent(
      `,obfs-uri=${Array.isArray(transportPath) ? transportPath[0] : transportPath}`,
      `${proxy.network}-opts.path`
    );
    appendIfPresent(
      `,obfs-host=${Array.isArray(transportHost) ? transportHost[0] : transportHost}`,
      `${proxy.network}-opts.headers.Host`
    );
  } else {
    if (proxy.tls) append(`,obfs=over-tls`);
  }
  if (needTls(proxy)) {
    appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
    appendIfPresent(`,tls-alpn=${proxy["tls-alpn"]}`, "tls-alpn");
    appendIfPresent(
      `,tls-no-session-ticket=${proxy["tls-no-session-ticket"]}`,
      "tls-no-session-ticket"
    );
    appendIfPresent(
      `,tls-no-session-reuse=${proxy["tls-no-session-reuse"]}`,
      "tls-no-session-reuse"
    );
    appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    appendIfPresent(
      `,tls-verification=${!proxy["skip-cert-verify"]}`,
      "skip-cert-verify"
    );
    appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
  }
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function http3(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`http=${proxy.server}:${proxy.port}`);
  appendIfPresent(`,username=${proxy.username}`, "username");
  appendIfPresent(`,password=${proxy.password}`, "password");
  if (needTls(proxy)) {
    proxy.tls = true;
  }
  appendIfPresent(`,over-tls=${proxy.tls}`, "tls");
  if (needTls(proxy)) {
    appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
    appendIfPresent(`,tls-alpn=${proxy["tls-alpn"]}`, "tls-alpn");
    appendIfPresent(
      `,tls-no-session-ticket=${proxy["tls-no-session-ticket"]}`,
      "tls-no-session-ticket"
    );
    appendIfPresent(
      `,tls-no-session-reuse=${proxy["tls-no-session-reuse"]}`,
      "tls-no-session-reuse"
    );
    appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    appendIfPresent(
      `,tls-verification=${!proxy["skip-cert-verify"]}`,
      "skip-cert-verify"
    );
    appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
  }
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function socks53(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`socks5=${proxy.server}:${proxy.port}`);
  appendIfPresent(`,username=${proxy.username}`, "username");
  appendIfPresent(`,password=${proxy.password}`, "password");
  if (needTls(proxy)) {
    proxy.tls = true;
  }
  appendIfPresent(`,over-tls=${proxy.tls}`, "tls");
  if (needTls(proxy)) {
    appendIfPresent(
      `,tls-pubkey-sha256=${proxy["tls-pubkey-sha256"]}`,
      "tls-pubkey-sha256"
    );
    appendIfPresent(`,tls-alpn=${proxy["tls-alpn"]}`, "tls-alpn");
    appendIfPresent(
      `,tls-no-session-ticket=${proxy["tls-no-session-ticket"]}`,
      "tls-no-session-ticket"
    );
    appendIfPresent(
      `,tls-no-session-reuse=${proxy["tls-no-session-reuse"]}`,
      "tls-no-session-reuse"
    );
    appendIfPresent(
      `,tls-cert-sha256=${proxy["tls-fingerprint"]}`,
      "tls-fingerprint"
    );
    appendIfPresent(
      `,tls-verification=${!proxy["skip-cert-verify"]}`,
      "skip-cert-verify"
    );
    appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
  }
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function needTls(proxy) {
  return proxy.tls;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/shadowrocket.js
function Shadowrocket_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (opts["include-unsupported-proxy"]) return true;
      if (proxy.type === "snell" && proxy.version >= 4) {
        return false;
      } else if (["mieru"].includes(proxy.type)) {
        return false;
      }
      return true;
    }).map((proxy) => {
      if (proxy.type === "vmess") {
        if (isPresent2(proxy, "aead")) {
          if (proxy.aead) {
            proxy.alterId = 0;
          }
          delete proxy.aead;
        }
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
        if (isPresent2(proxy, "cipher") && ![
          "auto",
          "none",
          "zero",
          "aes-128-gcm",
          "chacha20-poly1305"
        ].includes(proxy.cipher)) {
          proxy.cipher = "auto";
        }
      } else if (proxy.type === "tuic") {
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
        }
        if ((!proxy.token || proxy.token.length === 0) && !isPresent2(proxy, "version")) {
          proxy.version = 5;
        }
      } else if (proxy.type === "hysteria") {
        if (isPresent2(proxy, "auth_str") && !isPresent2(proxy, "auth-str")) {
          proxy["auth-str"] = proxy["auth_str"];
        }
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
        }
      } else if (proxy.type === "hysteria2") {
        if (isPresent2(proxy, "alpn")) {
          proxy.alpn = Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn];
        }
        if (isPresent2(proxy, "tfo") && !isPresent2(proxy, "fast-open")) {
          proxy["fast-open"] = proxy.tfo;
        }
      } else if (proxy.type === "wireguard") {
        proxy.keepalive = proxy.keepalive ?? proxy["persistent-keepalive"];
        proxy["persistent-keepalive"] = proxy.keepalive;
        proxy["preshared-key"] = proxy["preshared-key"] ?? proxy["pre-shared-key"];
        proxy["pre-shared-key"] = proxy["preshared-key"];
      } else if (proxy.type === "snell" && proxy.version < 3) {
        delete proxy.udp;
      } else if (proxy.type === "vless") {
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
      } else if (proxy.type === "ss") {
        if (isPresent2(proxy, "shadow-tls-password") && !isPresent2(proxy, "plugin")) {
          proxy.plugin = "shadow-tls";
          proxy["plugin-opts"] = {
            host: proxy["shadow-tls-sni"],
            password: proxy["shadow-tls-password"],
            version: proxy["shadow-tls-version"]
          };
          delete proxy["shadow-tls-password"];
          delete proxy["shadow-tls-sni"];
          delete proxy["shadow-tls-version"];
        }
      } else if (["anytls"].includes(proxy.type) && proxy.network && (!["tcp"].includes(proxy.network) || ["tcp"].includes(proxy.network) && proxy["reality-opts"])) {
        return false;
      } else if (["xhttp"].includes(proxy.network)) {
        return false;
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "http") {
        let httpPath = proxy["http-opts"]?.path;
        if (isPresent2(proxy, "http-opts.path") && !Array.isArray(httpPath)) {
          proxy["http-opts"].path = [httpPath];
        }
        let httpHost = proxy["http-opts"]?.headers?.Host;
        if (isPresent2(proxy, "http-opts.headers.Host") && !Array.isArray(httpHost)) {
          proxy["http-opts"].headers.Host = [httpHost];
        }
      }
      if (["vmess", "vless"].includes(proxy.type) && proxy.network === "h2") {
        let path = proxy["h2-opts"]?.path;
        if (isPresent2(proxy, "h2-opts.path") && Array.isArray(path)) {
          proxy["h2-opts"].path = path[0];
        }
        let host = proxy["h2-opts"]?.headers?.host;
        if (isPresent2(proxy, "h2-opts.headers.Host") && !Array.isArray(host)) {
          proxy["h2-opts"].headers.host = [host];
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkPath = proxy[`${proxy.network}-opts`]?.path;
        if (networkPath) {
          const reg = /^(.*?)(?:\?ed=(\d+))?$/;
          const [_2, path = "", ed = ""] = reg.exec(networkPath);
          proxy[`${proxy.network}-opts`].path = path;
          if (ed !== "") {
            proxy["ws-opts"]["early-data-header-name"] = "Sec-WebSocket-Protocol";
            proxy["ws-opts"]["max-early-data"] = parseInt(
              ed,
              10
            );
          }
        } else {
          proxy[`${proxy.network}-opts`] = proxy[`${proxy.network}-opts`] || {};
          proxy[`${proxy.network}-opts`].path = "/";
        }
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls"
      ].includes(proxy.type)) {
        delete proxy.tls;
      }
      if (proxy["tls-fingerprint"]) {
        proxy.fingerprint = proxy["tls-fingerprint"];
      }
      delete proxy["tls-fingerprint"];
      if (proxy["underlying-proxy"]) {
        proxy["dialer-proxy"] = proxy["underlying-proxy"];
      }
      delete proxy["underlying-proxy"];
      if (isPresent2(proxy, "tls") && typeof proxy.tls !== "boolean") {
        delete proxy.tls;
      }
      delete proxy.subName;
      delete proxy.collectionName;
      delete proxy.id;
      delete proxy.resolved;
      delete proxy["no-resolve"];
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      return proxy;
    });
    return type2 === "internal" ? list : "proxies:\n" + list.map((proxy) => {
      return "  - " + JSON.stringify(proxy) + "\n";
    }).join("");
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surfboard.js
var targetPlatform5 = "Surfboard";
function Surfboard_Producer() {
  const produce2 = (proxy) => {
    proxy.name = proxy.name.replace(/=|,/g, "");
    switch (proxy.type) {
      case "ss":
        return shadowsocks4(proxy);
      case "trojan":
        return trojan4(proxy);
      case "vmess":
        return vmess4(proxy);
      case "http":
        return http4(proxy);
      case "socks5":
        return socks54(proxy);
      case "wireguard-surge":
        return wireguard3(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform5} does not support proxy type: ${proxy.type}`
    );
  };
  return { produce: produce2 };
}
function shadowsocks4(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  if (![
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf"
  ].includes(proxy.cipher)) {
    throw new Error(`cipher ${proxy.cipher} is not supported`);
  }
  result.append(`,encrypt-method=${proxy.cipher}`);
  result.appendIfPresent(`,password=${proxy.password}`, "password");
  if (isPresent2(proxy, "plugin")) {
    if (proxy.plugin === "obfs") {
      result.append(`,obfs=${proxy["plugin-opts"].mode}`);
      result.appendIfPresent(
        `,obfs-host=${proxy["plugin-opts"].host}`,
        "plugin-opts.host"
      );
      result.appendIfPresent(
        `,obfs-uri=${proxy["plugin-opts"].path}`,
        "plugin-opts.path"
      );
    } else {
      throw new Error(`plugin ${proxy.plugin} is not supported`);
    }
  }
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  return result.toString();
}
function trojan4(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password=${proxy.password}`, "password");
  handleTransport2(result, proxy);
  result.appendIfPresent(`,tls=${proxy.tls}`, "tls");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  return result.toString();
}
function vmess4(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username=${proxy.uuid}`, "uuid");
  handleTransport2(result, proxy);
  if (isPresent2(proxy, "aead")) {
    result.append(`,vmess-aead=${proxy.aead}`);
  } else {
    result.append(`,vmess-aead=${proxy.alterId === 0}`);
  }
  result.appendIfPresent(`,tls=${proxy.tls}`, "tls");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  return result.toString();
}
function http4(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "https" : "http";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,${proxy.username}`, "username");
  result.appendIfPresent(`,${proxy.password}`, "password");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  return result.toString();
}
function socks54(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "socks5-tls" : "socks5";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,${proxy.username}`, "username");
  result.appendIfPresent(`,${proxy.password}`, "password");
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  return result.toString();
}
function wireguard3(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=wireguard`);
  result.appendIfPresent(
    `,section-name=${proxy["section-name"]}`,
    "section-name"
  );
  return result.toString();
}
function handleTransport2(result, proxy) {
  if (isPresent2(proxy, "network")) {
    if (proxy.network === "ws") {
      result.append(`,ws=true`);
      if (isPresent2(proxy, "ws-opts")) {
        result.appendIfPresent(
          `,ws-path=${proxy["ws-opts"].path}`,
          "ws-opts.path"
        );
        if (isPresent2(proxy, "ws-opts.headers")) {
          const headers = proxy["ws-opts"].headers;
          const value = Object.keys(headers).map((k) => {
            let v = headers[k];
            if (["Host"].includes(k)) {
              v = `"${v}"`;
            }
            return `${k}:${v}`;
          }).join("|");
          if (isNotBlank(value)) {
            result.append(`,ws-headers=${value}`);
          }
        }
      }
    } else {
      throw new Error(`network ${proxy.network} is unsupported`);
    }
  }
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/sing-box.js
var ipVersions4 = {
  ipv4: "ipv4_only",
  ipv6: "ipv6_only",
  "v4-only": "ipv4_only",
  "v6-only": "ipv6_only",
  "ipv4-prefer": "prefer_ipv4",
  "ipv6-prefer": "prefer_ipv6",
  "prefer-v4": "prefer_ipv4",
  "prefer-v6": "prefer_ipv6"
};
var ipVersionParser = (proxy, parsedProxy) => {
  const strategy = ipVersions4[proxy["ip-version"]];
  if (proxy._dns_server && strategy) {
    parsedProxy.domain_resolver = {
      server: proxy._dns_server,
      strategy
    };
  }
};
var detourParser = (proxy, parsedProxy) => {
  parsedProxy.detour = proxy["dialer-proxy"] || proxy.detour;
};
var networkParser = (proxy, parsedProxy) => {
  if (["tcp", "udp"].includes(proxy._network))
    parsedProxy.network = proxy._network;
};
var tfoParser = (proxy, parsedProxy) => {
  parsedProxy.tcp_fast_open = false;
  if (proxy.tfo) parsedProxy.tcp_fast_open = true;
  if (proxy.tcp_fast_open) parsedProxy.tcp_fast_open = true;
  if (proxy["tcp-fast-open"]) parsedProxy.tcp_fast_open = true;
  if (!parsedProxy.tcp_fast_open) delete parsedProxy.tcp_fast_open;
};
var smuxParser = (smux, proxy) => {
  if (!smux || !smux.enabled) return;
  proxy.multiplex = { enabled: true };
  proxy.multiplex.protocol = smux.protocol;
  if (smux["max-connections"])
    proxy.multiplex.max_connections = parseInt(
      `${smux["max-connections"]}`,
      10
    );
  if (smux["max-streams"])
    proxy.multiplex.max_streams = parseInt(`${smux["max-streams"]}`, 10);
  if (smux["min-streams"])
    proxy.multiplex.min_streams = parseInt(`${smux["min-streams"]}`, 10);
  if (smux.padding) proxy.multiplex.padding = true;
  if (smux["brutal-opts"]?.up || smux["brutal-opts"]?.down) {
    proxy.multiplex.brutal = {
      enabled: true
    };
    if (smux["brutal-opts"]?.up)
      proxy.multiplex.brutal.up_mbps = parseInt(
        `${smux["brutal-opts"]?.up}`,
        10
      );
    if (smux["brutal-opts"]?.down)
      proxy.multiplex.brutal.down_mbps = parseInt(
        `${smux["brutal-opts"]?.down}`,
        10
      );
  }
};
var wsParser = (proxy, parsedProxy) => {
  const transport = { type: "ws", headers: {} };
  if (proxy["ws-opts"]) {
    const {
      path: wsPath = "",
      headers: wsHeaders = {},
      "max-early-data": max_early_data,
      "early-data-header-name": early_data_header_name
    } = proxy["ws-opts"];
    transport.early_data_header_name = early_data_header_name;
    transport.max_early_data = max_early_data ? parseInt(max_early_data, 10) : void 0;
    if (wsPath !== "") transport.path = `${wsPath}`;
    if (Object.keys(wsHeaders).length > 0) {
      const headers = {};
      for (const key of Object.keys(wsHeaders)) {
        let value = wsHeaders[key];
        if (value === "") continue;
        if (!Array.isArray(value)) value = [`${value}`];
        if (value.length > 0) headers[key] = value;
      }
      const { Host: wsHost } = headers;
      if (wsHost.length === 1)
        for (const item of `Host:${wsHost[0]}`.split("\n")) {
          const [key, value] = item.split(":");
          if (value.trim() === "") continue;
          headers[key.trim()] = value.trim().split(",");
        }
      transport.headers = headers;
    }
  }
  if (proxy["ws-headers"]) {
    const headers = {};
    for (const key of Object.keys(proxy["ws-headers"])) {
      let value = proxy["ws-headers"][key];
      if (value === "") continue;
      if (!Array.isArray(value)) value = [`${value}`];
      if (value.length > 0) headers[key] = value;
    }
    const { Host: wsHost } = headers;
    if (wsHost.length === 1)
      for (const item of `Host:${wsHost[0]}`.split("\n")) {
        const [key, value] = item.split(":");
        if (value.trim() === "") continue;
        headers[key.trim()] = value.trim().split(",");
      }
    for (const key of Object.keys(headers))
      transport.headers[key] = headers[key];
  }
  if (proxy["ws-path"] && proxy["ws-path"] !== "")
    transport.path = `${proxy["ws-path"]}`;
  if (transport.path) {
    const reg = /^(.*?)(?:\?ed=(\d+))?$/;
    const [_2, path = "", ed = ""] = reg.exec(transport.path);
    transport.path = path;
    if (ed !== "") {
      transport.early_data_header_name = "Sec-WebSocket-Protocol";
      transport.max_early_data = parseInt(ed, 10);
    }
  }
  if (parsedProxy.tls.insecure)
    parsedProxy.tls.server_name = transport.headers.Host[0];
  if (proxy["ws-opts"] && proxy["ws-opts"]["v2ray-http-upgrade"]) {
    transport.type = "httpupgrade";
    if (transport.headers.Host) {
      transport.host = transport.headers.Host[0];
      delete transport.headers.Host;
    }
    if (transport.max_early_data) delete transport.max_early_data;
    if (transport.early_data_header_name)
      delete transport.early_data_header_name;
  }
  for (const key of Object.keys(transport.headers)) {
    const value = transport.headers[key];
    if (value.length === 1) transport.headers[key] = value[0];
  }
  parsedProxy.transport = transport;
};
var h1Parser = (proxy, parsedProxy) => {
  const transport = { type: "http", headers: {} };
  if (proxy["http-opts"]) {
    const {
      method = "",
      path: h1Path = "",
      headers: h1Headers = {}
    } = proxy["http-opts"];
    if (method !== "") transport.method = method;
    if (Array.isArray(h1Path)) {
      transport.path = `${h1Path[0]}`;
    } else if (h1Path !== "") transport.path = `${h1Path}`;
    for (const key of Object.keys(h1Headers)) {
      let value = h1Headers[key];
      if (value === "") continue;
      if (key.toLowerCase() === "host") {
        let host = value;
        if (!Array.isArray(host))
          host = `${host}`.split(",").map((i) => i.trim());
        if (host.length > 0) transport.host = host;
        continue;
      }
      if (!Array.isArray(value))
        value = `${value}`.split(",").map((i) => i.trim());
      if (value.length > 0) transport.headers[key] = value;
    }
  }
  if (proxy["http-host"] && proxy["http-host"] !== "") {
    let host = proxy["http-host"];
    if (!Array.isArray(host))
      host = `${host}`.split(",").map((i) => i.trim());
    if (host.length > 0) transport.host = host;
  }
  if (proxy["http-path"] && proxy["http-path"] !== "") {
    const path = proxy["http-path"];
    if (Array.isArray(path)) {
      transport.path = `${path[0]}`;
    } else if (path !== "") transport.path = `${path}`;
  }
  if (parsedProxy.tls.insecure)
    parsedProxy.tls.server_name = transport.host[0];
  if (transport.host?.length === 1) transport.host = transport.host[0];
  for (const key of Object.keys(transport.headers)) {
    const value = transport.headers[key];
    if (value.length === 1) transport.headers[key] = value[0];
  }
  parsedProxy.transport = transport;
};
var h2Parser = (proxy, parsedProxy) => {
  const transport = { type: "http" };
  if (proxy["h2-opts"]) {
    let { host = "", path = "" } = proxy["h2-opts"];
    if (path !== "") transport.path = `${path}`;
    if (host !== "") {
      if (!Array.isArray(host))
        host = `${host}`.split(",").map((i) => i.trim());
      if (host.length > 0) transport.host = host;
    }
  }
  if (proxy["h2-host"] && proxy["h2-host"] !== "") {
    let host = proxy["h2-host"];
    if (!Array.isArray(host))
      host = `${host}`.split(",").map((i) => i.trim());
    if (host.length > 0) transport.host = host;
  }
  if (proxy["h2-path"] && proxy["h2-path"] !== "")
    transport.path = `${proxy["h2-path"]}`;
  parsedProxy.tls.enabled = true;
  if (parsedProxy.tls.insecure)
    parsedProxy.tls.server_name = transport.host[0];
  if (transport.host.length === 1) transport.host = transport.host[0];
  parsedProxy.transport = transport;
};
var grpcParser = (proxy, parsedProxy) => {
  const transport = { type: "grpc" };
  if (proxy["grpc-opts"]) {
    const serviceName = proxy["grpc-opts"]["grpc-service-name"];
    if (serviceName != null && serviceName !== "")
      transport.service_name = `${serviceName}`;
  }
  parsedProxy.transport = transport;
};
var tlsParser = (proxy, parsedProxy) => {
  if (proxy.tls) parsedProxy.tls.enabled = true;
  if (proxy.servername && proxy.servername !== "")
    parsedProxy.tls.server_name = proxy.servername;
  if (proxy.peer && proxy.peer !== "")
    parsedProxy.tls.server_name = proxy.peer;
  if (proxy.sni && proxy.sni !== "") parsedProxy.tls.server_name = proxy.sni;
  if (proxy["skip-cert-verify"]) parsedProxy.tls.insecure = true;
  if (proxy.insecure) parsedProxy.tls.insecure = true;
  if (proxy["disable-sni"]) parsedProxy.tls.disable_sni = true;
  if (typeof proxy.alpn === "string") {
    parsedProxy.tls.alpn = [proxy.alpn];
  } else if (Array.isArray(proxy.alpn)) parsedProxy.tls.alpn = proxy.alpn;
  if (proxy.ca) parsedProxy.tls.certificate_path = `${proxy.ca}`;
  if (proxy.ca_str) parsedProxy.tls.certificate = [proxy.ca_str];
  if (proxy["ca-str"]) parsedProxy.tls.certificate = [proxy["ca-str"]];
  if (proxy["reality-opts"]) {
    parsedProxy.tls.reality = { enabled: true };
    if (proxy["reality-opts"]["public-key"])
      parsedProxy.tls.reality.public_key = proxy["reality-opts"]["public-key"];
    if (proxy["reality-opts"]["short-id"])
      parsedProxy.tls.reality.short_id = proxy["reality-opts"]["short-id"];
    parsedProxy.tls.utls = { enabled: true };
  }
  if (!["hysteria", "hysteria2", "tuic"].includes(proxy.type) && proxy["client-fingerprint"] && proxy["client-fingerprint"] !== "")
    parsedProxy.tls.utls = {
      enabled: true,
      fingerprint: proxy["client-fingerprint"]
    };
  if (proxy["_fragment"]) parsedProxy.tls.fragment = !!proxy["_fragment"];
  if (proxy["_fragment_fallback_delay"])
    parsedProxy.tls.fragment_fallback_delay = proxy["_fragment_fallback_delay"];
  if (proxy["_record_fragment"])
    parsedProxy.tls.record_fragment = !!proxy["_record_fragment"];
  if (proxy["_certificate"])
    parsedProxy.tls.certificate = proxy["_certificate"];
  if (proxy["_certificate_path"])
    parsedProxy.tls.certificate_path = proxy["_certificate_path"];
  if (proxy["_certificate_public_key_sha256"])
    parsedProxy.tls.certificate_public_key_sha256 = proxy["_certificate_public_key_sha256"];
  if (proxy["_client_certificate"])
    parsedProxy.tls.client_certificate = proxy["_client_certificate"];
  if (proxy["_client_certificate_path"])
    parsedProxy.tls.client_certificate_path = proxy["_client_certificate_path"];
  if (proxy["_client_key"]) parsedProxy.tls.client_key = proxy["_client_key"];
  if (proxy["_client_key_path"])
    parsedProxy.tls.client_key_path = proxy["_client_key_path"];
  if (!parsedProxy.tls.enabled) delete parsedProxy.tls;
};
var sshParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "ssh",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10)
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.username) parsedProxy.user = proxy.username;
  if (proxy.password) parsedProxy.password = proxy.password;
  if (proxy["privateKey"]) parsedProxy.private_key_path = proxy["privateKey"];
  if (proxy["private-key"])
    parsedProxy.private_key_path = proxy["private-key"];
  if (proxy["private-key-passphrase"])
    parsedProxy.private_key_passphrase = proxy["private-key-passphrase"];
  if (proxy["server-fingerprint"]) {
    parsedProxy.host_key = [proxy["server-fingerprint"]];
    parsedProxy.host_key_algorithms = [
      proxy["server-fingerprint"].split(" ")[0]
    ];
  }
  if (proxy["host-key"]) parsedProxy.host_key = proxy["host-key"];
  if (proxy["host-key-algorithms"])
    parsedProxy.host_key_algorithms = proxy["host-key-algorithms"];
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var httpParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "http",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    tls: { enabled: false, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.username) parsedProxy.username = proxy.username;
  if (proxy.password) parsedProxy.password = proxy.password;
  if (proxy.headers) {
    parsedProxy.headers = {};
    for (const k of Object.keys(proxy.headers)) {
      parsedProxy.headers[k] = `${proxy.headers[k]}`;
    }
    if (Object.keys(parsedProxy.headers).length === 0)
      delete parsedProxy.headers;
  }
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var socks5Parser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "socks",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    password: proxy.password,
    version: "5"
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.username) parsedProxy.username = proxy.username;
  if (proxy.password) parsedProxy.password = proxy.password;
  if (proxy.uot) parsedProxy.udp_over_tcp = true;
  if (proxy["udp-over-tcp"]) parsedProxy.udp_over_tcp = true;
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var shadowTLSParser = (proxy = {}) => {
  const ssPart = {
    tag: proxy.name,
    type: "shadowsocks",
    method: proxy.cipher,
    password: proxy.password,
    detour: `${proxy.name}_shadowtls`
  };
  if (proxy.uot) ssPart.udp_over_tcp = true;
  if (proxy["udp-over-tcp"]) {
    ssPart.udp_over_tcp = {
      enabled: true,
      version: !proxy["udp-over-tcp-version"] || proxy["udp-over-tcp-version"] === 1 ? 1 : 2
    };
  }
  const stPart = {
    tag: `${proxy.name}_shadowtls`,
    type: "shadowtls",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    version: proxy["plugin-opts"].version,
    password: proxy["plugin-opts"].password,
    tls: {
      enabled: true,
      server_name: proxy["plugin-opts"].host,
      utls: {
        enabled: true,
        fingerprint: proxy["client-fingerprint"]
      }
    }
  };
  if (stPart.server_port < 0 || stPart.server_port > 65535)
    throw "\u7AEF\u53E3\u503C\u975E\u6CD5";
  if (proxy["fast-open"] === true) stPart.udp_fragment = true;
  tfoParser(proxy, stPart);
  detourParser(proxy, stPart);
  smuxParser(proxy.smux, ssPart);
  ipVersionParser(proxy, stPart);
  return { type: "ss-with-st", ssPart, stPart };
};
var ssParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "shadowsocks",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    method: proxy.cipher,
    password: proxy.password
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.uot) parsedProxy.udp_over_tcp = true;
  if (proxy["udp-over-tcp"]) {
    parsedProxy.udp_over_tcp = {
      enabled: true,
      version: !proxy["udp-over-tcp-version"] || proxy["udp-over-tcp-version"] === 1 ? 1 : 2
    };
  }
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  if (proxy.plugin) {
    const optArr = [];
    if (proxy.plugin === "obfs") {
      parsedProxy.plugin = "obfs-local";
      parsedProxy.plugin_opts = "";
      if (proxy["obfs-host"])
        proxy["plugin-opts"].host = proxy["obfs-host"];
      Object.keys(proxy["plugin-opts"]).forEach((k) => {
        switch (k) {
          case "mode":
            optArr.push(`obfs=${proxy["plugin-opts"].mode}`);
            break;
          case "host":
            optArr.push(`obfs-host=${proxy["plugin-opts"].host}`);
            break;
          default:
            optArr.push(`${k}=${proxy["plugin-opts"][k]}`);
            break;
        }
      });
    }
    if (proxy.plugin === "v2ray-plugin") {
      parsedProxy.plugin = "v2ray-plugin";
      if (proxy["ws-host"]) proxy["plugin-opts"].host = proxy["ws-host"];
      if (proxy["ws-path"]) proxy["plugin-opts"].path = proxy["ws-path"];
      Object.keys(proxy["plugin-opts"]).forEach((k) => {
        switch (k) {
          case "tls":
            if (proxy["plugin-opts"].tls) optArr.push("tls");
            break;
          case "host":
            optArr.push(`host=${proxy["plugin-opts"].host}`);
            break;
          case "path":
            optArr.push(`path=${proxy["plugin-opts"].path}`);
            break;
          case "headers":
            optArr.push(
              `headers=${JSON.stringify(
                proxy["plugin-opts"].headers
              )}`
            );
            break;
          case "mux":
            if (proxy["plugin-opts"].mux)
              parsedProxy.multiplex = { enabled: true };
            break;
          default:
            optArr.push(`${k}=${proxy["plugin-opts"][k]}`);
        }
      });
    }
    parsedProxy.plugin_opts = optArr.join(";");
  }
  return parsedProxy;
};
var ssrParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "shadowsocksr",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    method: proxy.cipher,
    password: proxy.password,
    obfs: proxy.obfs,
    protocol: proxy.protocol
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy["obfs-param"]) parsedProxy.obfs_param = proxy["obfs-param"];
  if (proxy["protocol-param"] && proxy["protocol-param"] !== "")
    parsedProxy.protocol_param = proxy["protocol-param"];
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var vmessParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "vmess",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    uuid: proxy.uuid,
    security: proxy.cipher,
    alter_id: parseInt(`${proxy.alterId}`, 10),
    tls: { enabled: false, server_name: proxy.server, insecure: false }
  };
  if ([
    "auto",
    "none",
    "zero",
    "aes-128-gcm",
    "chacha20-poly1305",
    "aes-128-ctr"
  ].indexOf(parsedProxy.security) === -1)
    parsedProxy.security = "auto";
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.xudp) parsedProxy.packet_encoding = "xudp";
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  if (proxy.network === "ws") wsParser(proxy, parsedProxy);
  if (proxy.network === "h2") h2Parser(proxy, parsedProxy);
  if (proxy.network === "http") h1Parser(proxy, parsedProxy);
  if (proxy.network === "grpc") grpcParser(proxy, parsedProxy);
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var vlessParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "vless",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    uuid: proxy.uuid,
    tls: { enabled: false, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.xudp) parsedProxy.packet_encoding = "xudp";
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  if (proxy.flow != null) parsedProxy.flow = proxy.flow;
  if (proxy.network === "ws") wsParser(proxy, parsedProxy);
  if (proxy.network === "h2") h2Parser(proxy, parsedProxy);
  if (proxy.network === "http") h1Parser(proxy, parsedProxy);
  if (proxy.network === "grpc") grpcParser(proxy, parsedProxy);
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  tlsParser(proxy, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var trojanParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "trojan",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    password: proxy.password,
    tls: { enabled: true, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  if (proxy.network === "grpc") grpcParser(proxy, parsedProxy);
  if (proxy.network === "ws") wsParser(proxy, parsedProxy);
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var hysteriaParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "hysteria",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    disable_mtu_discovery: false,
    tls: { enabled: true, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy["hop-interval"])
    parsedProxy.hop_interval = /^\d+$/.test(proxy["hop-interval"]) ? `${proxy["hop-interval"]}s` : proxy["hop-interval"];
  if (proxy["ports"])
    parsedProxy.server_ports = proxy["ports"].split(/\s*,\s*/).map((p) => {
      const range = p.replace(/\s*-\s*/g, ":");
      return range.includes(":") ? range : `${range}:${range}`;
    });
  if (proxy.auth_str) parsedProxy.auth_str = `${proxy.auth_str}`;
  if (proxy["auth-str"]) parsedProxy.auth_str = `${proxy["auth-str"]}`;
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  const reg = new RegExp("^[0-9]+[ 	]*[KMGT]*[Bb]ps$");
  if (reg.test(`${proxy.up}`) && !`${proxy.up}`.endsWith("Mbps")) {
    parsedProxy.up = `${proxy.up}`;
  } else {
    parsedProxy.up_mbps = parseInt(`${proxy.up}`, 10);
  }
  if (reg.test(`${proxy.down}`) && !`${proxy.down}`.endsWith("Mbps")) {
    parsedProxy.down = `${proxy.down}`;
  } else {
    parsedProxy.down_mbps = parseInt(`${proxy.down}`, 10);
  }
  if (proxy.obfs) parsedProxy.obfs = proxy.obfs;
  if (proxy.recv_window_conn)
    parsedProxy.recv_window_conn = proxy.recv_window_conn;
  if (proxy["recv-window-conn"])
    parsedProxy.recv_window_conn = proxy["recv-window-conn"];
  if (proxy.recv_window) parsedProxy.recv_window = proxy.recv_window;
  if (proxy["recv-window"]) parsedProxy.recv_window = proxy["recv-window"];
  if (proxy.disable_mtu_discovery) {
    if (typeof proxy.disable_mtu_discovery === "boolean") {
      parsedProxy.disable_mtu_discovery = proxy.disable_mtu_discovery;
    } else {
      if (proxy.disable_mtu_discovery === 1)
        parsedProxy.disable_mtu_discovery = true;
    }
  }
  networkParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var hysteria2Parser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "hysteria2",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    password: proxy.password,
    obfs: {},
    tls: { enabled: true, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy["hop-interval"])
    parsedProxy.hop_interval = /^\d+$/.test(proxy["hop-interval"]) ? `${proxy["hop-interval"]}s` : proxy["hop-interval"];
  if (proxy["ports"])
    parsedProxy.server_ports = proxy["ports"].split(/\s*,\s*/).map((p) => {
      const range = p.replace(/\s*-\s*/g, ":");
      return range.includes(":") ? range : `${range}:${range}`;
    });
  if (proxy.up) parsedProxy.up_mbps = parseInt(`${proxy.up}`, 10);
  if (proxy.down) parsedProxy.down_mbps = parseInt(`${proxy.down}`, 10);
  if (proxy.obfs === "salamander") parsedProxy.obfs.type = "salamander";
  if (proxy["obfs-password"])
    parsedProxy.obfs.password = proxy["obfs-password"];
  if (!parsedProxy.obfs.type) delete parsedProxy.obfs;
  networkParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var tuic5Parser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "tuic",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    uuid: proxy.uuid,
    password: proxy.password,
    tls: { enabled: true, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  if (proxy["congestion-controller"] && proxy["congestion-controller"] !== "cubic")
    parsedProxy.congestion_control = proxy["congestion-controller"];
  if (proxy["udp-relay-mode"] && proxy["udp-relay-mode"] !== "native")
    parsedProxy.udp_relay_mode = proxy["udp-relay-mode"];
  if (proxy["reduce-rtt"]) parsedProxy.zero_rtt_handshake = true;
  if (proxy["udp-over-stream"]) parsedProxy.udp_over_stream = true;
  if (proxy["heartbeat-interval"])
    parsedProxy.heartbeat = `${proxy["heartbeat-interval"]}ms`;
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var anytlsParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "anytls",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    password: proxy.password,
    tls: { enabled: true, server_name: proxy.server, insecure: false }
  };
  if (/^\d+$/.test(proxy["idle-session-check-interval"]))
    parsedProxy.idle_session_check_interval = `${proxy["idle-session-check-interval"]}s`;
  if (/^\d+$/.test(proxy["idle-session-timeout"]))
    parsedProxy.idle_session_timeout = `${proxy["idle-session-timeout"]}s`;
  if (/^\d+$/.test(proxy["min-idle-session"]))
    parsedProxy.min_idle_session = parseInt(
      `${proxy["min-idle-session"]}`,
      10
    );
  networkParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
var wireguardParser = (proxy = {}) => {
  const local_address = ["ip", "ipv6"].map((i) => proxy[i]).map((i) => {
    if (isIPv4(i)) return `${i}/32`;
    if (isIPv6(i)) return `${i}/128`;
  }).filter((i) => i);
  const parsedProxy = {
    tag: proxy.name,
    type: "wireguard",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    local_address,
    private_key: proxy["private-key"],
    peer_public_key: proxy["public-key"],
    pre_shared_key: proxy["pre-shared-key"],
    reserved: []
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  if (typeof proxy.reserved === "string") {
    parsedProxy.reserved = proxy.reserved;
  } else if (Array.isArray(proxy.reserved)) {
    for (const r of proxy.reserved) parsedProxy.reserved.push(r);
  } else {
    delete parsedProxy.reserved;
  }
  if (proxy.peers && proxy.peers.length > 0) {
    parsedProxy.peers = [];
    for (const p of proxy.peers) {
      const peer = {
        server: p.server,
        server_port: parseInt(`${p.port}`, 10),
        public_key: p["public-key"],
        allowed_ips: p["allowed-ips"] || p.allowed_ips,
        reserved: []
      };
      if (typeof p.reserved === "string") {
        peer.reserved.push(p.reserved);
      } else if (Array.isArray(p.reserved)) {
        for (const r of p.reserved) peer.reserved.push(r);
      } else {
        delete peer.reserved;
      }
      if (p["pre-shared-key"]) peer.pre_shared_key = p["pre-shared-key"];
      parsedProxy.peers.push(peer);
    }
  }
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  return parsedProxy;
};
function singbox_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = [];
    ClashMeta_Producer().produce(proxies, "internal", { "include-unsupported-proxy": true }).map((proxy) => {
      try {
        switch (proxy.type) {
          case "ssh":
            list.push(sshParser(proxy));
            break;
          case "http":
            list.push(httpParser(proxy));
            break;
          case "socks5":
            if (proxy.tls) {
              throw new Error(
                `Platform sing-box does not support proxy type: ${proxy.type} with tls`
              );
            } else {
              list.push(socks5Parser(proxy));
            }
            break;
          case "ss":
            if (proxy.plugin === "shadow-tls") {
              const { ssPart, stPart } = shadowTLSParser(proxy);
              list.push(ssPart);
              list.push(stPart);
            } else {
              list.push(ssParser(proxy));
            }
            break;
          case "ssr":
            if (opts["include-unsupported-proxy"]) {
              list.push(ssrParser(proxy));
            } else {
              throw new Error(
                `Platform sing-box does not support proxy type: ${proxy.type}`
              );
            }
            break;
          case "vmess":
            if (!proxy.network || ["ws", "grpc", "h2", "http"].includes(
              proxy.network
            )) {
              list.push(vmessParser(proxy));
            } else {
              throw new Error(
                `Platform sing-box does not support proxy type: ${proxy.type} with network ${proxy.network}`
              );
            }
            break;
          case "vless":
            if (!proxy.flow || ["xtls-rprx-vision"].includes(proxy.flow)) {
              list.push(vlessParser(proxy));
            } else {
              throw new Error(
                `Platform sing-box does not support proxy type: ${proxy.type} with flow ${proxy.flow}`
              );
            }
            break;
          case "trojan":
            if (!proxy.flow) {
              list.push(trojanParser(proxy));
            } else {
              throw new Error(
                `Platform sing-box does not support proxy type: ${proxy.type} with flow ${proxy.flow}`
              );
            }
            break;
          case "hysteria":
            list.push(hysteriaParser(proxy));
            break;
          case "hysteria2":
            list.push(
              hysteria2Parser(
                proxy,
                opts["include-unsupported-proxy"]
              )
            );
            break;
          case "tuic":
            if (!proxy.token || proxy.token.length === 0) {
              list.push(tuic5Parser(proxy));
            } else {
              throw new Error(
                `Platform sing-box does not support proxy type: TUIC v4`
              );
            }
            break;
          case "wireguard":
            list.push(wireguardParser(proxy));
            break;
          case "anytls":
            list.push(anytlsParser(proxy));
            break;
          default:
            throw new Error(
              `Platform sing-box does not support proxy type: ${proxy.type}`
            );
        }
      } catch (e) {
        app_default.error(e.message ?? e);
      }
    });
    return type2 === "internal" ? list : JSON.stringify({ outbounds: list }, null, 2);
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/egern.js
function Egern_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (![
        "http",
        "socks5",
        "ss",
        "trojan",
        "hysteria2",
        "vless",
        "vmess",
        "tuic"
      ].includes(proxy.type) || proxy.type === "ss" && (proxy.plugin === "obfs" && !["http", "tls"].includes(
        proxy["plugin-opts"]?.mode
      ) || ![
        "chacha20-ietf-poly1305",
        "chacha20-poly1305",
        "aes-256-gcm",
        "aes-128-gcm",
        "none",
        "tbale",
        "rc4",
        "rc4-md5",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "bf-cfb",
        "camellia-128-cfb",
        "camellia-192-cfb",
        "camellia-256-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "seed-cfb",
        "salsa20",
        "chacha20",
        "chacha20-ietf",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm"
      ].includes(proxy.cipher)) || proxy.type === "vmess" && !["http", "ws", "tcp"].includes(proxy.network) && proxy.network || proxy.type === "trojan" && !["http", "ws", "tcp"].includes(proxy.network) && proxy.network || proxy.type === "vless" && !["http", "ws", "tcp"].includes(proxy.network) && proxy.network || proxy.type === "tuic" && proxy.token && proxy.token.length !== 0) {
        return false;
      }
      return true;
    }).map((proxy) => {
      const original = { ...proxy };
      let flow;
      if (proxy.tls && !proxy.sni) {
        proxy.sni = proxy.server;
      }
      const prev_hop = proxy.prev_hop || proxy["underlying-proxy"] || proxy["dialer-proxy"] || proxy.detour;
      if (proxy.type === "http") {
        proxy = {
          type: "http",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          username: proxy.username,
          password: proxy.password,
          tfo: proxy.tfo || proxy["fast-open"],
          next_hop: proxy.next_hop
        };
      } else if (proxy.type === "socks5") {
        proxy = {
          type: "socks5",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          username: proxy.username,
          password: proxy.password,
          tfo: proxy.tfo || proxy["fast-open"],
          udp_relay: proxy.udp || proxy.udp_relay || proxy.udp_relay,
          next_hop: proxy.next_hop
        };
      } else if (proxy.type === "ss") {
        proxy = {
          type: "shadowsocks",
          name: proxy.name,
          method: proxy.cipher === "chacha20-ietf-poly1305" ? "chacha20-poly1305" : proxy.cipher,
          server: proxy.server,
          port: proxy.port,
          password: proxy.password,
          tfo: proxy.tfo || proxy["fast-open"],
          udp_relay: proxy.udp || proxy.udp_relay || proxy.udp_relay,
          next_hop: proxy.next_hop
        };
        if (original.plugin === "obfs") {
          proxy.obfs = original["plugin-opts"].mode;
          proxy.obfs_host = original["plugin-opts"].host;
          proxy.obfs_uri = original["plugin-opts"].path;
        }
      } else if (proxy.type === "hysteria2") {
        proxy = {
          type: "hysteria2",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          auth: proxy.password,
          tfo: proxy.tfo || proxy["fast-open"],
          udp_relay: proxy.udp || proxy.udp_relay || proxy.udp_relay,
          next_hop: proxy.next_hop,
          sni: proxy.sni,
          skip_tls_verify: proxy["skip-cert-verify"],
          port_hopping: proxy.ports,
          port_hopping_interval: proxy["hop-interval"]
        };
        if (original["obfs-password"] && original.obfs == "salamander") {
          proxy.obfs = "salamander";
          proxy.obfs_password = original["obfs-password"];
        }
      } else if (proxy.type === "tuic") {
        proxy = {
          type: "tuic",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          uuid: proxy.uuid,
          password: proxy.password,
          next_hop: proxy.next_hop,
          sni: proxy.sni,
          alpn: Array.isArray(proxy.alpn) ? proxy.alpn : [proxy.alpn || "h3"],
          skip_tls_verify: proxy["skip-cert-verify"],
          port_hopping: proxy.ports,
          port_hopping_interval: proxy["hop-interval"]
        };
      } else if (proxy.type === "trojan") {
        if (proxy.network === "ws") {
          proxy.websocket = {
            path: proxy["ws-opts"]?.path,
            host: proxy["ws-opts"]?.headers?.Host
          };
        }
        proxy = {
          type: "trojan",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          password: proxy.password,
          tfo: proxy.tfo || proxy["fast-open"],
          udp_relay: proxy.udp || proxy.udp_relay || proxy.udp_relay,
          next_hop: proxy.next_hop,
          sni: proxy.sni,
          skip_tls_verify: proxy["skip-cert-verify"],
          websocket: proxy.websocket
        };
      } else if (proxy.type === "vmess") {
        let security = proxy.cipher;
        if (security && ![
          "auto",
          "none",
          "zero",
          "aes-128-gcm",
          "chacha20-poly1305"
        ].includes(security)) {
          security = "auto";
        }
        if (proxy.network === "ws") {
          proxy.transport = {
            [proxy.tls ? "wss" : "ws"]: {
              path: proxy["ws-opts"]?.path,
              headers: {
                Host: proxy["ws-opts"]?.headers?.Host
              },
              sni: proxy.tls ? proxy.sni : void 0,
              skip_tls_verify: proxy.tls ? proxy["skip-cert-verify"] : void 0
            }
          };
        } else if (proxy.network === "http") {
          proxy.transport = {
            http1: {
              method: proxy["http-opts"]?.method,
              path: Array.isArray(proxy["http-opts"]?.path) ? proxy["http-opts"]?.path[0] : proxy["http-opts"]?.path,
              headers: {
                Host: Array.isArray(
                  proxy["http-opts"]?.headers?.Host
                ) ? proxy["http-opts"]?.headers?.Host[0] : proxy["http-opts"]?.headers?.Host
              },
              skip_tls_verify: proxy["skip-cert-verify"]
            }
          };
        } else if (proxy.network === "h2") {
          proxy.transport = {
            http2: {
              method: proxy["h2-opts"]?.method,
              path: Array.isArray(proxy["h2-opts"]?.path) ? proxy["h2-opts"]?.path[0] : proxy["h2-opts"]?.path,
              headers: {
                Host: Array.isArray(
                  proxy["h2-opts"]?.headers?.Host
                ) ? proxy["h2-opts"]?.headers?.Host[0] : proxy["h2-opts"]?.headers?.Host
              },
              skip_tls_verify: proxy["skip-cert-verify"]
            }
          };
        } else if ((proxy.network === "tcp" || !proxy.network) && proxy.tls) {
          proxy.transport = {
            tls: {
              sni: proxy.tls ? proxy.sni : void 0,
              skip_tls_verify: proxy.tls ? proxy["skip-cert-verify"] : void 0
            }
          };
        }
        let legacy;
        if (isPresent2(proxy, "aead") && !proxy.aead) {
          legacy = true;
        } else if (proxy.alterId !== 0) {
          legacy = true;
        }
        proxy = {
          type: "vmess",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          user_id: proxy.uuid,
          security,
          tfo: proxy.tfo || proxy["fast-open"],
          legacy,
          udp_relay: proxy.udp || proxy.udp_relay || proxy.udp_relay,
          next_hop: proxy.next_hop,
          transport: proxy.transport
          // sni: proxy.sni,
          // skip_tls_verify: proxy['skip-cert-verify'],
        };
      } else if (proxy.type === "vless") {
        if (proxy.network === "ws") {
          proxy.transport = {
            [proxy.tls ? "wss" : "ws"]: {
              path: proxy["ws-opts"]?.path,
              headers: {
                Host: proxy["ws-opts"]?.headers?.Host
              },
              sni: proxy.tls ? proxy.sni : void 0,
              skip_tls_verify: proxy.tls ? proxy["skip-cert-verify"] : void 0
            }
          };
        } else if (proxy.network === "http") {
          proxy.transport = {
            http: {
              method: proxy["http-opts"]?.method,
              path: Array.isArray(proxy["http-opts"]?.path) ? proxy["http-opts"]?.path[0] : proxy["http-opts"]?.path,
              headers: {
                Host: Array.isArray(
                  proxy["http-opts"]?.headers?.Host
                ) ? proxy["http-opts"]?.headers?.Host[0] : proxy["http-opts"]?.headers?.Host
              },
              skip_tls_verify: proxy["skip-cert-verify"]
            }
          };
        } else if (proxy.network === "tcp" || !proxy.network) {
          let reality;
          if (proxy["reality-opts"]?.["short-id"] || proxy["reality-opts"]?.["public-key"]) {
            reality = {
              short_id: proxy["reality-opts"]["short-id"],
              public_key: proxy["reality-opts"]["public-key"]
            };
          }
          proxy.transport = {
            [proxy.tls ? "tls" : "tcp"]: {
              sni: proxy.tls ? proxy.sni : void 0,
              skip_tls_verify: proxy.tls ? proxy["skip-cert-verify"] : void 0,
              reality
            }
          };
          if (typeof proxy.flow !== "undefined") {
            if (!["xtls-rprx-vision"].includes(proxy.flow)) {
              throw new Error(
                `VLESS flow(${proxy.flow}) is not supported`
              );
            }
          }
          flow = proxy.flow;
        }
        proxy = {
          type: "vless",
          name: proxy.name,
          server: proxy.server,
          port: proxy.port,
          user_id: proxy.uuid,
          security: proxy.cipher,
          tfo: proxy.tfo || proxy["fast-open"],
          udp_relay: proxy.udp || proxy.udp_relay || proxy.udp_relay,
          next_hop: proxy.next_hop,
          transport: proxy.transport,
          flow
          // sni: proxy.sni,
          // skip_tls_verify: proxy['skip-cert-verify'],
        };
      }
      if ([
        "http",
        "socks5",
        "ss",
        "trojan",
        "vless",
        "vmess"
      ].includes(original.type)) {
        if (isPresent2(original, "shadow-tls-password")) {
          if (original["shadow-tls-version"] != 3)
            throw new Error(
              `shadow-tls version ${original["shadow-tls-version"]} is not supported`
            );
          proxy.shadow_tls = {
            password: original["shadow-tls-password"],
            sni: original["shadow-tls-sni"]
          };
        } else if (["shadow-tls"].includes(original.plugin) && original["plugin-opts"]) {
          if (original["plugin-opts"].version != 3)
            throw new Error(
              `shadow-tls version ${original["plugin-opts"].version} is not supported`
            );
          proxy.shadow_tls = {
            password: original["plugin-opts"].password,
            sni: original["plugin-opts"].host
          };
        }
      }
      if (["ss"].includes(original.type) && proxy.shadow_tls && original["udp-port"] > 0 && original["udp-port"] <= 65535) {
        proxy["udp_port"] = original["udp-port"];
      }
      delete proxy.subName;
      delete proxy.collectionName;
      delete proxy.id;
      delete proxy.resolved;
      delete proxy["no-resolve"];
      if (proxy.transport) {
        for (const key in proxy.transport) {
          if (Object.keys(proxy.transport[key]).length === 0 || Object.values(proxy.transport[key]).every(
            (v) => v == null
          )) {
            delete proxy.transport[key];
          }
        }
        if (Object.keys(proxy.transport).length === 0) {
          delete proxy.transport;
        }
      }
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
      }
      return {
        [proxy.type]: {
          ...proxy,
          type: void 0,
          prev_hop
        }
      };
    });
    return type2 === "internal" ? list : "proxies:\n" + list.map((proxy) => "  - " + JSON.stringify(proxy) + "\n").join("");
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/index.js
function JSON_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2) => type2 === "internal" ? proxies : JSON.stringify(proxies, null, 2);
  return { type, produce: produce2 };
}
var producers_default = {
  qx: QX_Producer(),
  QX: QX_Producer(),
  QuantumultX: QX_Producer(),
  surge: Surge_Producer(),
  Surge: Surge_Producer(),
  SurgeMac: SurgeMac_Producer(),
  Loon: Loon_Producer(),
  Clash: Clash_Producer(),
  meta: ClashMeta_Producer(),
  clashmeta: ClashMeta_Producer(),
  "clash.meta": ClashMeta_Producer(),
  "Clash.Meta": ClashMeta_Producer(),
  ClashMeta: ClashMeta_Producer(),
  mihomo: ClashMeta_Producer(),
  Mihomo: ClashMeta_Producer(),
  uri: URI_Producer(),
  URI: URI_Producer(),
  v2: V2Ray_Producer(),
  v2ray: V2Ray_Producer(),
  V2Ray: V2Ray_Producer(),
  json: JSON_Producer(),
  JSON: JSON_Producer(),
  stash: Stash_Producer(),
  Stash: Stash_Producer(),
  shadowrocket: Shadowrocket_Producer(),
  Shadowrocket: Shadowrocket_Producer(),
  ShadowRocket: Shadowrocket_Producer(),
  surfboard: Surfboard_Producer(),
  Surfboard: Surfboard_Producer(),
  singbox: singbox_Producer(),
  "sing-box": singbox_Producer(),
  egern: Egern_Producer(),
  Egern: Egern_Producer()
};

// src/index.js
var parsers = parsers_default;
var produce = producers_default;
export {
  parsers,
  produce
};
