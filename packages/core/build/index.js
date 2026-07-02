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
function isPlainObject(obj) {
  return obj !== null && typeof obj === "object" && [null, Object.prototype].includes(Object.getPrototypeOf(obj));
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/peggy/surge.js
import peggy from "peggy";
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
    const shadowTLS = {};
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
        if (shadowTLS.password && !shadowTLS.version) {
            shadowTLS.version = 2;
        }
        if (shadowTLS.password) {
            if (shadowTLS.version < 2) {
                throw new Error("shadow-tls version " + shadowTLS.version + " is not supported");
            }
            proxy.plugin = "shadow-tls";
            proxy["plugin-opts"] = {
                host: shadowTLS.host,
                password: shadowTLS.password,
                version: shadowTLS.version,
            };
            if (proxy.alpn) {
                $set(proxy, "plugin-opts.alpn", proxy.alpn);
                delete proxy.alpn;
            }
        }
    }
    function stripQuotes(value) {
        const trimmed = value.trim();
        const quote = trimmed[0];
        if (
            (quote === '"' || quote === "'") &&
            trimmed[trimmed.length - 1] === quote
        ) {
            return trimmed.slice(1, -1);
        }

        return trimmed;
    }
    function readQuotedHeaderKey(text, start) {
        const quote = text[start];
        let index = start + 1;
        let hasKey = false;

        while (index < text.length) {
            const char = text[index];
            if (char === quote) {
                return hasKey ? index + 1 : -1;
            }

            hasKey = true;
            index++;
        }

        return -1;
    }
    function startsWithQuotedHeaderKey(text) {
        const trimmed = text.trim();
        if (trimmed[0] !== '"' && trimmed[0] !== "'") return false;

        const index = readQuotedHeaderKey(trimmed, 0);
        if (index === -1) return false;

        let cursor = index;
        while (cursor < trimmed.length && /\s/.test(trimmed[cursor])) cursor++;
        return trimmed[cursor] === ":";
    }
    function stripOuterHeadersQuotes(headers) {
        const trimmed = headers.trim();
        const quote = trimmed[0];

        if (
            (quote === '"' || quote === "'") &&
            trimmed[trimmed.length - 1] === quote &&
            !startsWithQuotedHeaderKey(trimmed)
        ) {
            return trimmed.slice(1, -1);
        }

        return trimmed;
    }
    function isHeaderKeyStart(text, start) {
        let index = start;
        while (index < text.length && /\s/.test(text[index])) index++;

        if (text[index] === '"' || text[index] === "'") {
            index = readQuotedHeaderKey(text, index);
            if (index === -1) return false;
        } else {
            const keyStart = index;
            while (
                index < text.length &&
                /[!#$%&'*+\-.^_|~0-9A-Za-z]/.test(text[index])
            )
                index++;
            if (index === keyStart) return false;
        }

        while (index < text.length && /\s/.test(text[index])) index++;
        return text[index] === ":";
    }
    function isOptionStart(text, start) {
        let index = start;
        while (index < text.length && /\s/.test(text[index])) index++;

        const keyStart = index;
        while (index < text.length && /[0-9A-Za-z-]/.test(text[index])) index++;
        if (index === keyStart) return false;

        while (index < text.length && /\s/.test(text[index])) index++;
        return text[index] === "=";
    }
    function isHeaderValueQuoteEnd(text, index, pairSeparator, allowCommaEnd, containerQuote) {
        let cursor = index + 1;
        while (cursor < text.length && /\s/.test(text[cursor])) cursor++;

        if (cursor >= text.length) return true;
        if (allowCommaEnd && text[cursor] === "," && isOptionStart(text, cursor + 1)) {
            return true;
        }
        if (text[cursor] === pairSeparator && isHeaderKeyStart(text, cursor + 1)) {
            return true;
        }
        if (containerQuote && text[cursor] === containerQuote) {
            let next = cursor + 1;
            while (next < text.length && /\s/.test(text[next])) next++;
            return next >= text.length || text[next] === ",";
        }

        return false;
    }
    function findHeaderSeparator(pair) {
        let quote = "";

        for (let index = 0; index < pair.length; index++) {
            const char = pair[index];

            if (quote) {
                if (char === quote) {
                    quote = "";
                }
                continue;
            }

            if (char === '"' || char === "'") {
                quote = char;
                continue;
            }

            if (char === ":") {
                return index;
            }
        }

        return -1;
    }
    function readUnquotedHeadersEnd(text, start, pairSeparator) {
        let index = start;
        let quote = "";
        let quoteRole = "";
        let seenSeparator = false;

        while (index < text.length) {
            const char = text[index];

            if (quote) {
                if (char === quote) {
                    if (
                        quoteRole === "key" ||
                        isHeaderValueQuoteEnd(text, index, pairSeparator, true)
                    ) {
                        quote = "";
                        quoteRole = "";
                    }
                }
                index++;
                continue;
            }

            if (char === '"' || char === "'") {
                quote = char;
                quoteRole = seenSeparator ? "value" : "key";
                index++;
                continue;
            }

            if (char === ":" && !seenSeparator) {
                seenSeparator = true;
                index++;
                continue;
            }

            if (char === pairSeparator && isHeaderKeyStart(text, index + 1)) {
                seenSeparator = false;
                index++;
                continue;
            }

            if (char === ",") break;
            index++;
        }

        return index;
    }
    function readQuotedHeadersEnd(text, start, pairSeparator) {
        const quote = text[start];
        let index = start + 1;
        let innerQuote = "";
        let quoteRole = "";
        let seenSeparator = false;

        while (index < text.length) {
            const char = text[index];

            if (innerQuote) {
                if (char === innerQuote) {
                    if (
                        quoteRole === "key" ||
                        isHeaderValueQuoteEnd(text, index, pairSeparator, false, quote)
                    ) {
                        innerQuote = "";
                        quoteRole = "";
                    }
                }
                index++;
                continue;
            }

            if (char === quote) {
                let cursor = index + 1;
                while (cursor < text.length && /\s/.test(text[cursor])) cursor++;
                if (cursor >= text.length || text[cursor] === ",") {
                    return index + 1;
                }
            }

            if (char === '"' || char === "'") {
                innerQuote = char;
                quoteRole = seenSeparator ? "value" : "key";
                index++;
                continue;
            }

            if (char === ":" && !seenSeparator) {
                seenSeparator = true;
                index++;
                continue;
            }

            if (char === pairSeparator && isHeaderKeyStart(text, index + 1)) {
                seenSeparator = false;
                index++;
                continue;
            }
            index++;
        }

        return text.length;
    }
    function readHeadersEnd(text, start, pairSeparator) {
        let index = start;
        while (index < text.length && /\s/.test(text[index])) index++;

        if (
            (text[index] === '"' || text[index] === "'") &&
            !startsWithQuotedHeaderKey(text.slice(index))
        ) {
            return readQuotedHeadersEnd(text, index, pairSeparator);
        }

        return readUnquotedHeadersEnd(text, start, pairSeparator);
    }
    function splitHeaders(headers, pairSeparator) {
        const result = [];
        let start = 0;
        let quote = "";
        let quoteRole = "";
        let seenSeparator = false;

        for (let index = 0; index < headers.length; index++) {
            const char = headers[index];

            if (quote) {
                if (char === quote) {
                    if (
                        quoteRole === "key" ||
                        isHeaderValueQuoteEnd(headers, index, pairSeparator, false)
                    ) {
                        quote = "";
                        quoteRole = "";
                    }
                }
                continue;
            }

            if (char === '"' || char === "'") {
                quote = char;
                quoteRole = seenSeparator ? "value" : "key";
                continue;
            }

            if (char === ":" && !seenSeparator) {
                seenSeparator = true;
                continue;
            }

            if (char === pairSeparator && isHeaderKeyStart(headers, index + 1)) {
                result.push(headers.slice(start, index));
                start = index + 1;
                seenSeparator = false;
            }
        }

        result.push(headers.slice(start));
        return result;
    }
    function parseHeaders(headers, pairSeparator) {
        const result = {};
        splitHeaders(stripOuterHeadersQuotes(headers), pairSeparator).forEach((pair) => {
            const index = findHeaderSeparator(pair);
            if (index === -1) return;

            const key = stripQuotes(pair.slice(0, index));
            const value = stripQuotes(pair.slice(index + 1));

            if (key) {
                result[key] = value;
            }
        });
        return result;
    }
    function normalizeVmessSecurity(security) {
        const normalized = String(security || "").trim().toLowerCase();
        const supported = ["aes-128-gcm", "chacha20-ietf-poly1305"];
        if (!supported.includes(normalized)) return "auto";
        return normalized === "chacha20-ietf-poly1305" ? "chacha20-poly1305" : normalized;
    }
    function parseAlpn(value) {
        return stripQuotes(value)
            .split(",")
            .map((item) => item.trim())
            .filter((item) => item !== "");
    }
}

start = (anytls/shadowsocks/vmess/trojan/h2_connect/https/http/snell/socks5/socks5_tls/tuic/tuic_v5/wireguard/hysteria2/ssh/trust_tunnel/direct) {
    return proxy;
}

shadowsocks = tag equals "ss" address (method/passwordk/obfs/obfs_host/obfs_uri/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/udp_relay/alpn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/udp_port/others)* {
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
vmess = tag equals "vmess" address (vmess_uuid/vmess_aead/ws/ws_path/ws_headers/vmess_method/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls/sni/alpn/tls_fingerprint/tls_verification/client_cert/fast_open/tfo/udp_relay/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "vmess";
    proxy.cipher = proxy.cipher || "auto";
    // Surfboard 与 Surge 默认不一致, 不管 Surfboard https://getsurfboard.com/docs/profile-format/proxy/external-proxy/vmess
    if (proxy.aead) {
        proxy.alterId = 0;
    } else {
        proxy.alterId = 1;
    }
    handleWebsocket();
    handleShadowTLS();
}
trojan = tag equals "trojan" address (passwordk/ws/ws_path/ws_headers/tls/sni/alpn/tls_fingerprint/tls_verification/client_cert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/udp_relay/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "trojan";
    handleWebsocket();
    handleShadowTLS();
}
https = tag equals "https" address (username password)? (usernamek passwordk)? (headers/sni/alpn/tls_fingerprint/tls_verification/client_cert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "http";
    proxy.tls = true;
    handleShadowTLS();
}
h2_connect = tag equals "h2-connect" address (username password)? (usernamek passwordk)? (headers/max_streams/sni/alpn/tls_fingerprint/tls_verification/client_cert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "h2-connect";
    proxy.tls = true;
    handleShadowTLS();
}
http = tag equals "http" address (username password)? (usernamek passwordk)? (headers/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "http";
    handleShadowTLS();
}
ssh = tag equals "ssh" address (username password)? (usernamek passwordk)? (server_fingerprint/idle_timeout/private_key/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "ssh";
    handleShadowTLS();
}
snell = tag equals "snell" address (snell_version/snell_mode/snell_psk/obfs/obfs_host/obfs_uri/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/fast_open/tfo/udp_relay/reuse/alpn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "snell";
    // handle obfs
    if (obfs.type == "http" || obfs.type === "tls") {
        $set(proxy, "obfs-opts.mode", obfs.type);
        $set(proxy, "obfs-opts.host", obfs.host);
        $set(proxy, "obfs-opts.path", obfs.path);
    }
    handleShadowTLS();
}
tuic = tag equals "tuic" address (alpn/token/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls_fingerprint/tls_verification/client_cert/sni/fast_open/tfo/ecn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/port_hopping_interval/others)* {
    proxy.type = "tuic";
    handleShadowTLS();
}
tuic_v5 = tag equals "tuic-v5" address (alpn/passwordk/uuidk/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls_fingerprint/tls_verification/client_cert/sni/fast_open/tfo/ecn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/port_hopping_interval/others)* {
    proxy.type = "tuic";
    proxy.version = 5;
    handleShadowTLS();
}
wireguard = tag equals "wireguard" (section_name/no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "wireguard-surge";
    handleShadowTLS();
}
hysteria2 = tag equals "hysteria2" address (no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/sni/alpn/tls_verification/client_cert/passwordk/tls_fingerprint/download_bandwidth/ecn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/port_hopping_interval/salamander_password/gecko_password/others)* {
    proxy.type = "hysteria2";
    handleShadowTLS();
}
socks5 = tag equals "socks5" address (username password)? (usernamek passwordk)? (udp_relay/no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "socks5";
    handleShadowTLS();
}
socks5_tls = tag equals "socks5-tls" address (username password)? (usernamek passwordk)? (udp_relay/no_error_alert/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/sni/alpn/tls_fingerprint/tls_verification/client_cert/fast_open/tfo/shadow_tls_version/shadow_tls_sni/shadow_tls_password/block_quic/others)* {
    proxy.type = "socks5";
    proxy.tls = true;
    handleShadowTLS();
}
anytls = tag equals "anytls" address (passwordk/reuse/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls_fingerprint/tls_verification/client_cert/sni/alpn/fast_open/tfo/block_quic/others)* {
    proxy.type = "anytls";
    proxy.tls = true;
}
trust_tunnel = tag equals "trust-tunnel" address (usernamek/passwordk/headers/max_streams/reuse/ip_version/underlying_proxy/tos/allow_other_interface/interface/test_url/test_udp/test_timeout/hybrid/no_error_alert/tls_fingerprint/tls_verification/client_cert/sni/alpn/fast_open/tfo/block_quic/others)* {
    proxy.type = "trusttunnel";
    proxy.tls = true;
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
sni = comma "sni" equals match:[^,]+ { 
    const sni = match.join("").replace(/^"(.*)"$/, '$1');
    if (sni === "off") {
        proxy["disable-sni"] = true;
    } else {
        proxy.sni = sni;
    }
}
tls_verification = comma "skip-cert-verify" equals flag:bool { proxy["skip-cert-verify"] = flag; }
tls_fingerprint = comma "server-cert-fingerprint-sha256" equals tls_fingerprint:$[^,]+ { proxy["tls-fingerprint"] = tls_fingerprint.trim(); }
client_cert = comma "client-cert" equals match:[^,]+ { proxy["keystore-client-cert"] = stripQuotes(match.join("")); }

snell_psk = comma "psk" equals match:[^,]+ { proxy.psk = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
snell_version = comma "version" equals match:$[0-9]+ { proxy.version = parseInt(match.trim()); }
snell_mode = comma "mode" equals match:[^,]+ {
    const mode = stripQuotes(match.join("")).trim();
    if (["default", "unshaped", "unsafe-raw"].includes(mode)) {
        proxy.mode = mode;
    }
}

usernamek = comma "username" equals match:[^,]+ { proxy.username = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
passwordk = comma "password" equals match:[^,]+ { proxy.password = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
vmess_uuid = comma "username" equals match:[^,]+ { proxy.uuid = match.join(""); }
vmess_aead = comma "vmess-aead" equals flag:bool { proxy.aead = flag; }

method = comma "encrypt-method" equals cipher:cipher {
    proxy.cipher = cipher;
}
vmess_method = comma "encrypt-method" equals cipher:$[^,]+ {
    proxy.cipher = normalizeVmessSecurity(cipher);
}
cipher = ("aes-128-cfb"/"aes-128-ctr"/"aes-128-gcm"/"aes-192-cfb"/"aes-192-ctr"/"aes-192-gcm"/"aes-256-cfb"/"aes-256-ctr"/"aes-256-gcm"/"bf-cfb"/"camellia-128-cfb"/"camellia-192-cfb"/"camellia-256-cfb"/"cast5-cfb"/"chacha20-ietf-poly1305"/"chacha20-ietf"/"chacha20-poly1305"/"chacha20"/"des-cfb"/"idea-cfb"/"none"/"rc2-cfb"/"rc4-md5"/"rc4"/"salsa20"/"seed-cfb"/"xchacha20-ietf-poly1305"/"2022-blake3-aes-128-gcm"/"2022-blake3-aes-256-gcm");

ws = comma "ws" equals flag:bool { obfs.type = "ws"; }
ws_headers = comma "ws-headers" equals & {
    const start = peg$currPos;
    const index = readHeadersEnd(input, start, "|");

    $.headers = input.substring(start, index);
    peg$currPos = index;
    return $.headers.trim().length > 0;
} { obfs["ws-headers"] = parseHeaders($.headers, "|"); }
ws_path = comma "ws-path" equals path:uri { obfs.path = path.trim().replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
headers = comma "headers" equals & {
    const start = peg$currPos;
    const index = readHeadersEnd(input, start, ";");

    $.headers = input.substring(start, index);
    peg$currPos = index;
    return $.headers.trim().length > 0;
} { proxy.headers = parseHeaders($.headers, ";"); }

obfs = comma "obfs" equals type:("http"/"tls") { obfs.type = type; }
obfs_host = comma "obfs-host" equals match:[^,]+ { obfs.host = match.join("").replace(/^"(.*)"$/, '$1'); };
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
max_streams = comma "max-streams" equals match:quoted_integer { proxy["max-streams"] = match; }
quoted_integer = '"' match:$[0-9]+ '"' { return parseInt(match.trim()); } / "'" match:$[0-9]+ "'" { return parseInt(match.trim()); } / match:$[0-9]+ { return parseInt(match.trim()); }
tos = comma "tos" equals match:$[0-9]+ { proxy.tos = parseInt(match.trim()); }
interface = comma "interface" equals match:[^,]+ { proxy.interface = match.join(""); }
allow_other_interface = comma "allow-other-interface" equals flag:bool { proxy["allow-other-interface"] = flag; }
hybrid = comma "hybrid" equals flag:bool { proxy.hybrid = flag; }
idle_timeout = comma "idle-timeout" equals match:$[0-9]+ { proxy["idle-timeout"] = parseInt(match.trim()); }
private_key = comma "private-key" equals match:[^,]+ { proxy["keystore-private-key"] = stripQuotes(match.join("")); }
server_fingerprint = comma "server-fingerprint" equals match:[^,]+ { proxy["server-fingerprint"] = match.join("").replace(/^"(.*)"$/, '$1'); }
block_quic = comma "block-quic" equals match:[^,]+ { proxy["block-quic"] = match.join(""); }
udp_port = comma "udp-port" equals match:$[0-9]+ { proxy["udp-port"] = parseInt(match.trim()); }
shadow_tls_version = comma "shadow-tls-version" equals match:$[0-9]+ { shadowTLS.version = parseInt(match.trim()); }
shadow_tls_sni = comma "shadow-tls-sni" equals match:[^,]+ { shadowTLS.host = match.join(""); }
shadow_tls_password = comma "shadow-tls-password" equals match:[^,]+ { shadowTLS.password = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }
token = comma "token" equals match:[^,]+ { proxy.token = match.join(""); }
alpn = comma "alpn" equals match:quoted_value {
    const values = parseAlpn(match);
    if (values.length > 0) proxy.alpn = values;
}
quoted_value = '"' match:$[^"]* '"' { return match; } / "'" match:$[^']* "'" { return match; } / match:$[^,]+ { return match; }
uuidk = comma "uuid" equals match:[^,]+ { proxy.uuid = match.join(""); }
salamander_password = comma "salamander-password" equals match:[^,]+ { proxy['obfs-password'] = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); proxy.obfs = 'salamander'; }
gecko_password = comma "gecko-password" equals match:[^,]+ { proxy['obfs-password'] = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); proxy.obfs = 'gecko'; }

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
import peggy2 from "peggy";
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
    const shadowTLS = {};
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

    function handleShadowTLS() {
        if (shadowTLS.password) {
            if (shadowTLS.version < 2) {
                throw new Error("shadow-tls version " + shadowTLS.version + " is not supported");
            }
            proxy.plugin = "shadow-tls";
            proxy["plugin-opts"] = {
                host: shadowTLS.host,
                password: shadowTLS.password,
                version: shadowTLS.version,
            };
            if (proxy.alpn) {
                $set(proxy, "plugin-opts.alpn", proxy.alpn);
                delete proxy.alpn;
            }
        }
    }

    function normalizeVmessSecurity(security) {
        const normalized = String(security || "").trim().toLowerCase();
        const supported = ["none", "auto", "aes-128-gcm", "chacha20-ietf-poly1305"];
        if (!supported.includes(normalized)) return "auto";
        return normalized === "chacha20-ietf-poly1305" ? "chacha20-poly1305" : normalized;
    }

    function loonClientFingerprint(tlsProfile) {
        switch (String(tlsProfile || "").trim()) {
            case "chrome":
                return "chrome";
            case "ios18":
            case "ios26":
                return "ios";
        }
    }
}

start = (shadowsocksr/shadowsocks/vmess/vless/trojan/https/http/socks5/hysteria2/anytls) {
    return proxy;
}

shadowsocksr = tag equals "shadowsocksr"i address method password (ssr_protocol/ssr_protocol_param/obfs_ssr/obfs_ssr_param/obfs_host/obfs_uri/fast_open/udp_relay/udp_port/tls_profile/alpn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/ip_mode/block_quic/others)*{
    proxy.type = "ssr";
    // handle ssr obfs
    proxy.obfs = obfs.type;
    handleShadowTLS();
}
shadowsocks = tag equals "shadowsocks"i address method password (obfs_typev obfs_hostv)? (obfs_ss/obfs_host/obfs_uri/fast_open/udp_relay/udp_port/tls_profile/alpn/shadow_tls_version/shadow_tls_sni/shadow_tls_password/ip_mode/block_quic/udp_over_tcp/others)* {
    proxy.type = "ss";
    // handle ss obfs
    if (obfs.type == "http" || obfs.type === "tls") {
        proxy.plugin = "obfs";
        $set(proxy, "plugin-opts.mode", obfs.type);
        $set(proxy, "plugin-opts.host", obfs.host);
        $set(proxy, "plugin-opts.path", obfs.path);
    }
    handleShadowTLS();
}
vmess = tag equals "vmess"i address vmess_method uuid (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/vmess_alterId/fast_open/udp_relay/ip_mode/public_key/short_id/block_quic/others)* {
    proxy.type = "vmess";
    proxy.cipher = proxy.cipher || "auto";
    proxy.alterId = proxy.alterId || 0;
    handleTransport();
}
vless = tag equals "vless"i address uuid (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/fast_open/udp_relay/ip_mode/flow/public_key/short_id/block_quic/others)* {
    proxy.type = "vless";
    handleTransport();
}
trojan = tag equals "trojan"i address password (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/fast_open/udp_relay/ip_mode/public_key/short_id/block_quic/others)* {
    proxy.type = "trojan";
    handleTransport();
}
anytls = tag equals "anytls"i address password (transport/transport_host/transport_path/over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/fast_open/udp_relay/ip_mode/public_key/short_id/block_quic/idle_session_check_interval/idle_session_timeout/min_idle_session/max_stream_count/others)* {
    proxy.type = "anytls";
    handleTransport();
}
hysteria2 = tag equals "hysteria2"i address password (tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/udp_relay/fast_open/download_bandwidth/server_ports/hop_interval/salamander_password/ecn/ip_mode/block_quic/others)* {
    proxy.type = "hysteria2";
}
https = tag equals "https"i address (username password)? (tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/fast_open/udp_relay/ip_mode/block_quic/others)* {
    proxy.type = "http";
    proxy.tls = true;
}
http = tag equals "http"i address (username password)? (fast_open/udp_relay/ip_mode/block_quic/others)* {
    proxy.type = "http";
}
socks5 = tag equals "socks5"i address (username password)? (over_tls/tls_name/sni/tls_verification/tls_cert_sha256/tls_pubkey_sha256/tls_profile/alpn/fast_open/udp_relay/ip_mode/block_quic/others)* {
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
vmess_method = comma cipher:$[^,]+ {
    proxy.cipher = normalizeVmessSecurity(cipher);
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

obfs_host = comma "obfs-host" equals match:[^,]+ { obfs.host = match.join("").replace(/^"(.*)"$/, '$1'); }
obfs_uri = comma "obfs-uri" equals uri:uri { obfs.path = uri; }
uri = $[^,]+

transport = comma "transport" equals type:("tcp"/"ws"/"http") { transport.type = type; }
transport_host = comma "host" equals match:[^,]+ { transport.host = match.join("").replace(/^"(.*)"$/, '$1'); }
transport_path = comma "path" equals path:uri { transport.path = path; }

ssr_protocol = comma "protocol" equals protocol:("origin"/"auth_sha1_v4"/"auth_aes128_md5"/"auth_aes128_sha1"/"auth_chain_a"/"auth_chain_b") { proxy.protocol = protocol; }
ssr_protocol_param = comma "protocol-param" equals param:$[^=,]+ { proxy["protocol-param"] = param; }

vmess_alterId = comma "alterId" equals alterId:$[0-9]+ { proxy.alterId = parseInt(alterId); } 

udp_port = comma "udp-port" equals match:$[0-9]+ { proxy["udp-port"] = parseInt(match.trim()); }
shadow_tls_version = comma "shadow-tls-version" equals match:$[0-9]+ { shadowTLS.version = parseInt(match.trim()); }
shadow_tls_sni = comma "shadow-tls-sni" equals match:[^,]+ { shadowTLS.host = match.join(""); }
shadow_tls_password = comma "shadow-tls-password" equals match:[^,]+ { shadowTLS.password = match.join("").replace(/^"(.*?)"$/, '$1').replace(/^'(.*?)'$/, '$1'); }

over_tls = comma "over-tls" equals flag:bool { proxy.tls = flag; }
tls_name = comma sni:("tls-name") equals match:[^,]+ { proxy.sni = match.join("").replace(/^"(.*)"$/, '$1'); }
sni = comma "sni" equals match:[^,]+ { proxy.sni = match.join("").replace(/^"(.*)"$/, '$1'); }
tls_verification = comma "skip-cert-verify" equals flag:bool { proxy["skip-cert-verify"] = flag; }
tls_cert_sha256 = comma "tls-cert-sha256" equals match:[^,]+ { proxy["tls-fingerprint"] = match.join("").replace(/^"(.*)"$/, '$1'); }
tls_pubkey_sha256 = comma "tls-pubkey-sha256" equals match:[^,]+ { proxy["tls-pubkey-sha256"] = match.join("").replace(/^"(.*)"$/, '$1'); }
tls_profile = comma "tls-profile" equals match:[^,]+ {
    const tlsProfile = match.join("").replace(/^"(.*)"$/, '$1').trim();
    proxy["_loon_tls_profile"] = tlsProfile;
    const clientFingerprint = loonClientFingerprint(tlsProfile);
    if (clientFingerprint) proxy["client-fingerprint"] = clientFingerprint;
}
alpn = comma "alpn" equals '"' match:$[^"]* '"' {
    const values = match
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item !== "");
    if (values.length > 0) proxy.alpn = values;
}

flow = comma "flow" equals match:[^,]+ { proxy["flow"] = match.join("").replace(/^"(.*)"$/, '$1'); }
public_key = comma "public-key" equals match:[^,]+ { proxy["reality-opts"] = proxy["reality-opts"] || {}; proxy["reality-opts"]["public-key"] = match.join("").replace(/^"(.*)"$/, '$1'); }
short_id = comma "short-id" equals match:[^,]+ { proxy["reality-opts"] = proxy["reality-opts"] || {}; proxy["reality-opts"]["short-id"] = match.join("").replace(/^"(.*)"$/, '$1'); }

fast_open = comma "fast-open" equals flag:bool { proxy.tfo = flag; }
udp_relay = comma "udp" equals flag:bool { proxy.udp = flag; }
ip_mode = comma "ip-mode" equals match:[^,]+ { proxy["ip-version"] = match.join(""); }

ecn = comma "ecn" equals flag:bool { proxy.ecn = flag; }
download_bandwidth = comma "download-bandwidth" equals match:[^,]+ { proxy.down = match.join(""); }
server_ports = comma "server-ports" equals '"' match:$[^"]+ '"' { proxy.ports = match.trim().replace(/\s*-\s*/g, "-").replace(/\s*,\s*/g, ","); }
hop_interval = comma "hop-interval" equals match:$[0-9]+ { proxy["hop-interval"] = parseInt(match, 10); }
salamander_password = comma "salamander-password" equals match:[^,]+ { proxy['obfs-password'] = match.join(""); proxy.obfs = 'salamander'; }

block_quic = comma "block-quic" equals flag:bool { if(flag) proxy["block-quic"] = "on"; else proxy["block-quic"] = "off"; }

idle_session_check_interval = comma "idle-session-check-interval" equals match:$[0-9]+ { proxy["idle-session-check-interval"] = parseInt(match.trim()); }
idle_session_timeout = comma "idle-session-timeout" equals match:$[0-9]+ { proxy["idle-session-timeout"] = parseInt(match.trim()); }
min_idle_session = comma "min-idle-session" equals match:$[0-9]+ { proxy["min-idle-session"] = parseInt(match.trim()); }
max_stream_count = comma "max-stream-count" equals match:$[0-9]+ { proxy["max-stream-count"] = parseInt(match.trim()); }

udp_over_tcp = comma "udp-over-tcp" equals flag:bool { proxy["udp-over-tcp"] = true; proxy["udp-over-tcp-version"] = 2; }

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
import peggy3 from "peggy";
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

    function setQxHttpObfs(type) {
        // Preserve the original QX http-obfs token for round-trip output,
        // including the upstream "vemss-http" typo that appears in QX
        // examples.
        proxy._qx_obfs_http = type;
        obfs.type = "http";
        return type;
    }

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
            // Some QX share links use obfs-host as the TLS server name for
            // plain over-tls TCP nodes instead of the explicit tls-host field.
            // Accept it as a compatibility alias, but do not override tls-host.
            if (obfs.host && !proxy.sni) {
                proxy.sni = obfs.host;
            }
        } else if (obfs.type === "http") {
            proxy.network = "http";
            $set(proxy, "http-opts.path", obfs.path);
            $set(proxy, "http-opts.headers.Host", obfs.host);
        }
    }
}

start = (trojan/shadowsocks/vmess/vless/anytls/http/socks5) {
    return proxy
}

trojan = "trojan" equals address
    (password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/obfs/obfs_host/obfs_uri/tag/udp_relay/udp_over_tcp/fast_open/server_check_url/reality_base64_pubkey/reality_hex_shortid/others)* {
    proxy.type = "trojan";
    handleObfs();
}

shadowsocks = "shadowsocks" equals address
    (password/method/obfs_ssr/obfs_ss/obfs_host/obfs_uri/ssr_protocol/ssr_protocol_param/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/udp_relay/udp_over_tcp_new/fast_open/tag/server_check_url/reality_base64_pubkey/reality_hex_shortid/others)* {
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
            proxy.tls = true;
            if (obfs.host) {
                proxy.sni = obfs.host;
            }
        }
        if (obfs.type && obfs.type !== 'over-tls') {
            $set(proxy, "plugin-opts.host", obfs.host);
            $set(proxy, "plugin-opts.path", obfs.path);
        }
    }
}

vmess = "vmess" equals address
    (uuid/method/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/obfs_vmess/obfs_host/obfs_uri/udp_relay/udp_over_tcp/fast_open/aead/server_check_url/reality_base64_pubkey/reality_hex_shortid/others)* {
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
    (uuid/method/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/obfs_vless/obfs_host/obfs_uri/udp_relay/udp_over_tcp/fast_open/aead/server_check_url/reality_base64_pubkey/reality_hex_shortid/vless_flow/others)* {
    proxy.type = "vless";
    proxy.cipher = proxy.cipher || "none";
    handleObfs();
}

anytls = "anytls" equals address
    (password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/udp_relay/fast_open/server_check_url/reality_base64_pubkey/reality_hex_shortid/others)* {
    proxy.type = "anytls";
    proxy.tls = true;
}

http = "http" equals address 
    (username/password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/fast_open/udp_relay/udp_over_tcp/server_check_url/reality_base64_pubkey/reality_hex_shortid/others)*{
    proxy.type = "http";
}

socks5 = "socks5" equals address
    (username/password/password/over_tls/tls_host/tls_pubkey_sha256/tls_alpn/tls_no_session_ticket/tls_no_session_reuse/tls_fingerprint/tls_verification/tag/fast_open/udp_relay/udp_over_tcp/server_check_url/reality_base64_pubkey/reality_hex_shortid/others)* {
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
tls_host = comma sni:("tls-host") equals match:[^,]+ { proxy.sni = match.join("").replace(/^"(.*)"$/, '$1'); }
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

obfs_ss = comma "obfs" equals (
    type:("tls"/"wss"/"ws"/"over-tls") { obfs.type = type; return type; }
  / type:("http"/"vmess-http"/"vemss-http"/"shadowsocks-http") {
        // QX accepts multiple http-obfs spellings for ss/vmess/vless; keep
        // the original token so QX output can round-trip it unchanged.
        return setQxHttpObfs(type);
    }
)
obfs_ssr = comma "obfs" equals type:("plain"/"http_simple"/"http_post"/"random_head"/"tls1.2_ticket_auth"/"tls1.2_ticket_fastauth") { proxy.type = "ssr"; obfs.type = type; return type; }
obfs = comma "obfs" equals type:("wss"/"ws"/"over-tls"/"http") { obfs.type = type; return type; };
obfs_vmess = comma "obfs" equals (
    type:("wss"/"ws"/"over-tls") { obfs.type = type; return type; }
  / type:("http"/"vmess-http"/"vemss-http"/"shadowsocks-http") {
        // QX accepts multiple http-obfs spellings for ss/vmess/vless; keep
        // the original token so QX output can round-trip it unchanged.
        return setQxHttpObfs(type);
    }
);
obfs_vless = comma "obfs" equals (
    type:("wss"/"ws"/"over-tls") { obfs.type = type; return type; }
  / type:("http"/"vmess-http"/"vemss-http"/"shadowsocks-http") {
        // QX accepts multiple http-obfs spellings for ss/vmess/vless; keep
        // the original token so QX output can round-trip it unchanged.
        return setQxHttpObfs(type);
    }
);

obfs_host = comma "obfs-host" equals match:[^,]+ { obfs.host = match.join("").replace(/^"(.*)"$/, '$1'); }
obfs_uri = comma "obfs-uri" equals uri:uri { obfs.path = uri; }

ssr_protocol = comma "ssr-protocol" equals protocol:("origin"/"auth_sha1_v4"/"auth_aes128_md5"/"auth_aes128_sha1"/"auth_chain_a"/"auth_chain_b") { proxy.protocol = protocol; return protocol; }
ssr_protocol_param = comma "ssr-protocol-param" equals param:$[^=,]+ { proxy["protocol-param"] = param; }

reality_base64_pubkey = comma "reality-base64-pubkey" equals param:$[^=,]+ {
    $set(proxy, "reality-opts.public-key", param);
 }
reality_hex_shortid = comma "reality-hex-shortid" equals param:$[^=,]+ {
    $set(proxy, "reality-opts.short-id", param);
}

vless_flow = comma "vless-flow" equals param:$[^=,]+ { proxy["flow"] = param; }
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
import peggy4 from "peggy";
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

  function decodeQueryComponent(value) {
    try {
      return decodeURIComponent(String(value).replace(/\+/g, '%20'));
    } catch (e) {
      return value;
    }
  }

  function splitQueryPart(part) {
    const separatorIndex = part.indexOf('=');
    if (separatorIndex === -1) {
      return {
        key: decodeQueryComponent(part),
        value: '',
      };
    }

    return {
      key: decodeQueryComponent(part.slice(0, separatorIndex)),
      value: decodeQueryComponent(part.slice(separatorIndex + 1)),
    };
  }

  function getPathQueryParam(path, paramName) {
    const queryIndex = path.indexOf('?');
    if (queryIndex === -1) return '';

    const query = path.slice(queryIndex + 1);
    for (const part of query.split('&')) {
      if (part === '') continue;

      const parsed = splitQueryPart(part);
      if (parsed.key === paramName && parsed.value !== '') {
        return parsed.value;
      }
    }

    return '';
  }

  function extractPathQueryParam(path, paramName) {
    const queryIndex = path.indexOf('?');
    if (queryIndex === -1) {
      return {
        path,
        value: '',
      };
    }

    const basePath = path.slice(0, queryIndex);
    const query = path.slice(queryIndex + 1);
    const keptParts = [];
    let value = '';

    for (const part of query.split('&')) {
      if (part === '') continue;

      const parsed = splitQueryPart(part);
      if (parsed.key === paramName) {
        if (value === '' && parsed.value !== '') {
          value = parsed.value;
        }
        continue;
      }

      keptParts.push(part);
    }

    return {
      path: keptParts.length > 0 ? basePath + '?' + keptParts.join('&') : basePath,
      value,
    };
  }

  function parseEarlyDataSize(value) {
    if (value == null || !/^\d+$/.test(String(value))) return null;

    const parsed = parseInt(String(value), 10);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }

  function isNumericEarlyData(value) {
    return parseEarlyDataSize(value) != null;
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
  proxy['tls-fingerprint'] = params.pcs;
  proxy.alpn = params.alpn ? decodeURIComponent(params.alpn).split(',') : undefined;

  if (toBool(params["ws"])) {
    proxy.network = "ws";
    $set(proxy, "ws-opts.path", params["wspath"]);
  }
  
  if (params["type"]) {
    let httpupgrade
    let httpUpgradeEd = ''
    let pathEarlyData = ''
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
        let transportPath = params["path"]
        if (proxy.network === 'ws') {
          const pathEd = getPathQueryParam(transportPath, 'ed')
          if (isNumericEarlyData(pathEd)) {
            transportPath = extractPathQueryParam(transportPath, 'ed').path
            if (httpupgrade) {
              httpUpgradeEd = pathEd
            } else {
              pathEarlyData = pathEd
            }
          }
        }
        $set(proxy, proxy.network+"-opts.path", transportPath);
      }
      if (params["host"]) {
        $set(proxy, proxy.network+"-opts.headers.Host", decodeURIComponent(params["host"])); 
      }
      if (httpupgrade) {
        httpUpgradeEd = httpUpgradeEd || (isNumericEarlyData(params.ed) ? String(params.ed) : '')
        $set(proxy, proxy.network+"-opts.v2ray-http-upgrade", true); 
        if (httpUpgradeEd !== '') {
          $set(proxy, proxy.network+"-opts.v2ray-http-upgrade-fast-open", true);
          $set(proxy, proxy.network+"-opts._v2ray-http-upgrade-ed", httpUpgradeEd);
        }
      } else if (proxy.network === 'ws' && pathEarlyData !== '') {
        $set(proxy, proxy.network+"-opts.max-early-data", parseEarlyDataSize(pathEarlyData));
        $set(proxy, proxy.network+"-opts.early-data-header-name", 'Sec-WebSocket-Protocol');
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
var app_default = console;

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/index.js
import JSON5 from "json5";

// src/vendors/Sub-Store/backend/src/utils/yaml.js
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
var DEFAULT_PARSE_OPTIONS = {
  logLevel: "error",
  merge: true
};
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
function toSerializable(content) {
  return JSON.parse(JSON.stringify(content));
}
function normalizeParseOptions(options) {
  return {
    ...DEFAULT_PARSE_OPTIONS,
    ...options || {}
  };
}
function normalizeStringifyOptions(options = {}) {
  const {
    forceQuotes,
    lineWidth,
    noArrayIndent,
    noRefs,
    quotingType,
    sortKeys,
    ...rest
  } = options || {};
  const normalized = { ...rest };
  if (typeof lineWidth === "number") {
    normalized.lineWidth = lineWidth <= 0 ? 0 : lineWidth;
  }
  if (typeof noArrayIndent === "boolean") {
    normalized.indentSeq = !noArrayIndent;
  }
  if (typeof noRefs === "boolean") {
    normalized.aliasDuplicateObjects = !noRefs;
  }
  if (typeof sortKeys !== "undefined") {
    normalized.sortMapEntries = sortKeys;
  }
  if (quotingType === "'") {
    normalized.singleQuote = true;
  } else if (quotingType === '"') {
    normalized.singleQuote = false;
  }
  if (forceQuotes) {
    normalized.defaultStringType = quotingType === "'" ? "QUOTE_SINGLE" : "QUOTE_DOUBLE";
  }
  return normalized;
}
function parse(content, options) {
  return parseYaml(content, normalizeParseOptions(options));
}
function stringify(content, options) {
  return stringifyYaml(content, normalizeStringifyOptions(options));
}
function safeLoad(content, ...args) {
  return retry(parse, toSerializable(content), ...args);
}
function load(content, ...args) {
  return retry(parse, toSerializable(content), ...args);
}
function safeDump(content, ...args) {
  return stringify(toSerializable(content), ...args);
}
function dump(content, ...args) {
  return stringify(toSerializable(content), ...args);
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
import _ from "lodash";
import { Base64 } from "js-base64";

// src/vendors/Sub-Store/backend/src/core/proxy-utils/xhttp-utils.js
function parseNormalizedXhttpRangeBounds(value, { allowZeroLowerBound = true, allowZeroUpperBound = true } = {}) {
  if (typeof value !== "string" && typeof value !== "number") {
    return void 0;
  }
  const parseUnsignedIntegerToken = (token) => {
    const normalizedToken = token.trim();
    if (!/^\+?\d+$/.test(normalizedToken)) {
      return void 0;
    }
    const parsedInteger = parseInt(normalizedToken, 10);
    return Number.isSafeInteger(parsedInteger) ? parsedInteger : void 0;
  };
  const normalizedValue = `${value}`.trim();
  const rangeParts = normalizedValue.split("-");
  const minimumAllowedLowerBound = allowZeroLowerBound ? 0 : 1;
  const minimumAllowedUpperBound = allowZeroUpperBound ? 0 : 1;
  if (rangeParts.length === 1) {
    const normalizedInteger = parseUnsignedIntegerToken(rangeParts[0]);
    const minimumAllowedValue = Math.max(
      minimumAllowedLowerBound,
      minimumAllowedUpperBound
    );
    return normalizedInteger >= minimumAllowedValue ? {
      lowerBound: normalizedInteger,
      upperBound: normalizedInteger
    } : void 0;
  }
  if (rangeParts.length !== 2) {
    return void 0;
  }
  const lowerBound = parseUnsignedIntegerToken(rangeParts[0]);
  const upperBound = parseUnsignedIntegerToken(rangeParts[1]);
  if (lowerBound == null || upperBound == null) {
    return void 0;
  }
  return lowerBound >= minimumAllowedLowerBound && upperBound >= minimumAllowedUpperBound && upperBound >= lowerBound ? {
    lowerBound,
    upperBound
  } : void 0;
}
function parseNormalizedXhttpPositiveRangeBounds(value) {
  return parseNormalizedXhttpRangeBounds(value, {
    allowZeroUpperBound: false
  });
}
function parseNormalizedXhttpStrictPositiveRangeBounds(value) {
  return parseNormalizedXhttpRangeBounds(value, {
    allowZeroLowerBound: false,
    allowZeroUpperBound: false
  });
}
function normalizeXhttpPositiveRange(value) {
  const normalizedBounds = parseNormalizedXhttpPositiveRangeBounds(value);
  if (!normalizedBounds) {
    return void 0;
  }
  const { lowerBound, upperBound } = normalizedBounds;
  return lowerBound === upperBound ? upperBound : `${lowerBound}-${upperBound}`;
}
function normalizeXhttpStrictPositiveRangeString(value) {
  const normalizedBounds = parseNormalizedXhttpStrictPositiveRangeBounds(value);
  if (!normalizedBounds) {
    return void 0;
  }
  const { lowerBound, upperBound } = normalizedBounds;
  return lowerBound === upperBound ? `${upperBound}` : `${lowerBound}-${upperBound}`;
}
function normalizeXhttpStrictPositiveRangeValue(value) {
  const normalizedBounds = parseNormalizedXhttpStrictPositiveRangeBounds(value);
  if (!normalizedBounds) {
    return void 0;
  }
  const { lowerBound, upperBound } = normalizedBounds;
  return lowerBound === upperBound ? upperBound : `${lowerBound}-${upperBound}`;
}
function normalizeXhttpNonNegativeRange(value) {
  const normalizedBounds = parseNormalizedXhttpRangeBounds(value);
  if (!normalizedBounds) {
    return void 0;
  }
  const { lowerBound, upperBound } = normalizedBounds;
  return lowerBound === upperBound ? upperBound : `${lowerBound}-${upperBound}`;
}
function normalizeXhttpIntegerValue(value, { allowNegative = true } = {}) {
  if (typeof value === "number" && Number.isFinite(value) && Number.isSafeInteger(value)) {
    if (!allowNegative && value < 0) {
      return void 0;
    }
    return value;
  }
  if (typeof value !== "string") {
    return void 0;
  }
  const normalizedValue = value.trim();
  const integerPattern = allowNegative ? /^[+-]?\d+$/ : /^\+?\d+$/;
  if (!integerPattern.test(normalizedValue)) {
    return void 0;
  }
  const parsedInteger = parseInt(normalizedValue, 10);
  if (!Number.isSafeInteger(parsedInteger)) {
    return void 0;
  }
  if (!allowNegative && parsedInteger < 0) {
    return void 0;
  }
  return parsedInteger;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/transport-path.js
function decodeQueryComponent(value) {
  try {
    return decodeURIComponent(`${value}`.replace(/\+/g, "%20"));
  } catch (e) {
    return value;
  }
}
function splitQueryPart(part) {
  const separatorIndex = part.indexOf("=");
  if (separatorIndex === -1) {
    return {
      key: decodeQueryComponent(part),
      value: ""
    };
  }
  return {
    key: decodeQueryComponent(part.slice(0, separatorIndex)),
    value: decodeQueryComponent(part.slice(separatorIndex + 1))
  };
}
function parseSafeIntegerValue(value) {
  if (!/^\d+$/.test(`${value}`)) return null;
  const parsed = parseInt(`${value}`, 10);
  return Number.isSafeInteger(parsed) ? parsed : null;
}
function extractPathQueryParam(rawPath, paramName) {
  const path = rawPath == null ? "" : `${rawPath}`;
  const queryIndex = path.indexOf("?");
  if (queryIndex === -1) {
    return {
      path,
      value: ""
    };
  }
  const basePath = path.slice(0, queryIndex);
  const query = path.slice(queryIndex + 1);
  const keptParts = [];
  let value = "";
  for (const part of query.split("&")) {
    if (part === "") continue;
    const parsed = splitQueryPart(part);
    if (parsed.key === paramName) {
      if (value === "" && parsed.value !== "") {
        value = parsed.value;
      }
      continue;
    }
    keptParts.push(part);
  }
  return {
    path: keptParts.length > 0 ? `${basePath}?${keptParts.join("&")}` : basePath,
    value
  };
}
function getPathQueryParam(rawPath, paramName) {
  const path = rawPath == null ? "" : `${rawPath}`;
  const queryIndex = path.indexOf("?");
  if (queryIndex === -1) return "";
  const query = path.slice(queryIndex + 1);
  for (const part of query.split("&")) {
    if (part === "") continue;
    const parsed = splitQueryPart(part);
    if (parsed.key === paramName && parsed.value !== "") {
      return parsed.value;
    }
  }
  return "";
}
function getSafeIntegerPathQueryParam(rawPath, paramName) {
  const value = getPathQueryParam(rawPath, paramName);
  const parsed = parseSafeIntegerValue(value);
  if (parsed == null) {
    return {
      value: "",
      parsed: null
    };
  }
  return {
    value,
    parsed
  };
}
function appendPathQueryParam(path, paramName, value) {
  const separator = path.includes("?") ? path.endsWith("?") || path.endsWith("&") ? "" : "&" : "?";
  return `${path}${separator}${encodeURIComponent(
    paramName
  )}=${encodeURIComponent(`${value}`)}`;
}
function setPathQueryParam(rawPath, paramName, value) {
  const path = rawPath == null || rawPath === "" ? "/" : `${rawPath}`;
  const { path: pathWithoutParam } = extractPathQueryParam(path, paramName);
  return appendPathQueryParam(pathWithoutParam, paramName, value);
}
function normalizeWebSocketEarlyDataPath(wsOpts) {
  const networkPath = wsOpts?.path;
  if (!wsOpts) return;
  const { value: ed, parsed: maxEarlyData } = getSafeIntegerPathQueryParam(
    networkPath,
    "ed"
  );
  if (wsOpts["v2ray-http-upgrade"]) {
    if (ed !== "") {
      wsOpts.path = extractPathQueryParam(networkPath, "ed").path;
      wsOpts["v2ray-http-upgrade-fast-open"] = true;
      if (wsOpts["_v2ray-http-upgrade-ed"] == null || `${wsOpts["_v2ray-http-upgrade-ed"]}` === "") {
        wsOpts["_v2ray-http-upgrade-ed"] = ed;
      }
    }
    delete wsOpts["early-data-header-name"];
    delete wsOpts["max-early-data"];
    return;
  }
  if (ed === "") return;
  wsOpts.path = extractPathQueryParam(networkPath, "ed").path;
  if (wsOpts["early-data-header-name"] == null) {
    wsOpts["early-data-header-name"] = "Sec-WebSocket-Protocol";
  }
  if (wsOpts["max-early-data"] == null) {
    wsOpts["max-early-data"] = maxEarlyData;
  }
}
function deleteHttpUpgradeEarlyDataMetadata(wsOpts) {
  if (!wsOpts) return;
  delete wsOpts["_v2ray-http-upgrade-ed"];
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/ech-utils.js
var ECH_DNS_FIELD = "_dns";
var ECH_FORCE_QUERY_FIELD = "_force-query";
var ECH_SOCKOPT_FIELD = "_sockopt";
var DEFAULT_XRAY_ECH_DNS = "https://dns.alidns.com/dns-query";
function parseXrayEchConfigList(echConfigList) {
  if (!isNotBlank(echConfigList)) {
    return void 0;
  }
  if (!echConfigList.includes("://")) {
    return {
      type: "config",
      config: echConfigList
    };
  }
  const parts = echConfigList.split("+");
  if (parts.length === 1 && isNotBlank(parts[0])) {
    return {
      type: "dns",
      dns: parts[0]
    };
  }
  if (parts.length === 2 && isNotBlank(parts[0]) && isNotBlank(parts[1])) {
    return {
      type: "dns",
      queryServerName: parts[0],
      dns: parts[1]
    };
  }
  return void 0;
}
function isSupportedXrayEchConfigList(echConfigList) {
  return parseXrayEchConfigList(echConfigList) != null;
}
function isSupportedXrayEchForceQuery(forceQuery) {
  return ["none", "half", "full"].includes(forceQuery);
}
function isMihomoEchEnabled(value) {
  if (typeof value === "boolean") {
    return value;
  }
  return typeof value === "number" && Number.isInteger(value) && value !== 0;
}
function buildMihomoEchOptsFromXrayFields({
  echConfigList,
  echForceQuery,
  echSockopt
} = {}) {
  const parsedEchConfigList = parseXrayEchConfigList(echConfigList);
  if (!parsedEchConfigList) {
    return void 0;
  }
  const echOpts = {
    enable: true
  };
  if (parsedEchConfigList.type === "config") {
    echOpts.config = parsedEchConfigList.config;
  } else {
    echOpts[ECH_DNS_FIELD] = parsedEchConfigList.dns;
    if (parsedEchConfigList.queryServerName) {
      echOpts["query-server-name"] = parsedEchConfigList.queryServerName;
    }
  }
  if (isSupportedXrayEchForceQuery(echForceQuery)) {
    echOpts[ECH_FORCE_QUERY_FIELD] = echForceQuery;
  }
  if (isPlainObject(echSockopt)) {
    echOpts[ECH_SOCKOPT_FIELD] = echSockopt;
  }
  return echOpts;
}
function buildXrayEchFieldsFromMihomo(echOpts, fallbackEchConfigList, { dnsFieldPath = "ech-opts._dns", warnDefaultDns } = {}) {
  const fields = {};
  if (isPlainObject(echOpts)) {
    if (!isMihomoEchEnabled(echOpts.enable)) {
      return fields;
    }
    const queryServerName = echOpts["query-server-name"];
    if (isNotBlank(echOpts.config)) {
      fields.echConfigList = echOpts.config;
    } else if (isNotBlank(echOpts[ECH_DNS_FIELD])) {
      fields.echConfigList = isNotBlank(queryServerName) ? `${queryServerName}+${echOpts[ECH_DNS_FIELD]}` : echOpts[ECH_DNS_FIELD];
    } else if (isNotBlank(queryServerName)) {
      fields.echConfigList = `${queryServerName}+${DEFAULT_XRAY_ECH_DNS}`;
      warnDefaultDns?.({
        defaultDns: DEFAULT_XRAY_ECH_DNS,
        dnsFieldPath,
        queryServerName
      });
    }
    if (fields.echConfigList && isSupportedXrayEchForceQuery(echOpts[ECH_FORCE_QUERY_FIELD])) {
      fields.echForceQuery = echOpts[ECH_FORCE_QUERY_FIELD];
    }
    if (fields.echConfigList && isPlainObject(echOpts[ECH_SOCKOPT_FIELD])) {
      fields.echSockopt = echOpts[ECH_SOCKOPT_FIELD];
    }
    return fields;
  }
  if (isNotBlank(fallbackEchConfigList)) {
    fields.echConfigList = fallbackEchConfigList;
  }
  return fields;
}
function buildXrayEchConfigListFromMihomo(echOpts, fallbackEchConfigList, options) {
  return buildXrayEchFieldsFromMihomo(echOpts, fallbackEchConfigList, options).echConfigList;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/vmess-security.js
var VMESS_SECURITY_AUTO = "auto";
var VMESS_SECURITY_COMMON_VALUES = [
  VMESS_SECURITY_AUTO,
  "none",
  "zero",
  "aes-128-gcm",
  "chacha20-poly1305"
];
var VMESS_SECURITY_CLASH_VALUES = [
  VMESS_SECURITY_AUTO,
  "aes-128-gcm",
  "chacha20-poly1305",
  "none"
];
var VMESS_SECURITY_QX_METHOD_VALUES = ["none", "chacha20-poly1305"];
var VMESS_SECURITY_ALIASES = {
  "chacha20-ietf-poly1305": "chacha20-poly1305"
};
function normalizeSecurityValue(security) {
  if (security == null) return "";
  return `${security}`.trim().toLowerCase();
}
function canonicalizeVmessSecurity(security) {
  return VMESS_SECURITY_ALIASES[security] || security;
}
function normalizeVmessSecurity(security, supportedValues = VMESS_SECURITY_COMMON_VALUES, { acceptAliases = true, fallback = VMESS_SECURITY_AUTO } = {}) {
  const normalized = normalizeSecurityValue(security);
  if (!normalized) return fallback;
  const normalizedSupported = supportedValues.map(normalizeSecurityValue);
  if (normalizedSupported.includes(normalized)) {
    return canonicalizeVmessSecurity(normalized);
  }
  const canonical = canonicalizeVmessSecurity(normalized);
  const canonicalSupported = normalizedSupported.map(
    canonicalizeVmessSecurity
  );
  if (acceptAliases && canonicalSupported.includes(canonical)) {
    return canonical;
  }
  return fallback;
}
function normalizeClashVmessSecurity(security) {
  return normalizeVmessSecurity(security, VMESS_SECURITY_CLASH_VALUES);
}
function formatQXVmessMethod(security) {
  return normalizeVmessSecurity(security, VMESS_SECURITY_QX_METHOD_VALUES, {
    fallback: "chacha20-poly1305"
  });
}
function formatLoonVmessSecurity(security) {
  const normalized = normalizeClashVmessSecurity(security);
  return normalized === "chacha20-poly1305" ? "chacha20-ietf-poly1305" : normalized;
}
function formatSurgeVmessEncryptMethod(security) {
  const normalized = normalizeVmessSecurity(security, [
    "aes-128-gcm",
    "chacha20-poly1305"
  ]);
  if (normalized === VMESS_SECURITY_AUTO) return void 0;
  return normalized === "chacha20-poly1305" ? "chacha20-ietf-poly1305" : normalized;
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/parsers/index.js
function surge_port_hopping(raw) {
  const [parts, port_hopping] = raw.match(
    /,\s*?port-hopping\s*?=\s*?["']?\s*?((\d+(-\d+)?)([,;]\d+(-\d+)?)*)\s*?["']?\s*?/
  ) || [];
  return {
    port_hopping: port_hopping ? port_hopping.replace(/;/g, ",") : void 0,
    line: parts ? raw.replace(parts, "") : raw
  };
}
function splitURIFragment(raw) {
  const [__, content, fragment] = /^(.*?)(?:#(.*?))?$/.exec(raw);
  return {
    content,
    fragment: fragment != null ? decodeURIComponent(fragment) : void 0
  };
}
function decodeShadowsocksUserInfo(rawUserInfoStr) {
  const separatorIndex = rawUserInfoStr.indexOf(":");
  if (separatorIndex !== -1) {
    return [
      decodeURIComponent(rawUserInfoStr.slice(0, separatorIndex)),
      decodeURIComponent(rawUserInfoStr.slice(separatorIndex + 1))
    ].join(":");
  }
  const decodedUserInfoStr = decodeURIComponent(rawUserInfoStr);
  if (decodedUserInfoStr.includes(":")) {
    return decodedUserInfoStr;
  }
  return Base64.decode(decodedUserInfoStr);
}
function isNumericEarlyData(value) {
  if (value == null || !/^\d+$/.test(`${value}`)) return false;
  return Number.isSafeInteger(parseInt(`${value}`, 10));
}
function extractEarlyDataFromPath(path) {
  const ed = getPathQueryParam(path, "ed");
  if (!isNumericEarlyData(ed)) {
    return {
      path,
      ed: ""
    };
  }
  return {
    path: extractPathQueryParam(path, "ed").path,
    ed
  };
}
function parseEarlyDataSize(value) {
  const raw = `${value}`;
  if (!/^\d+$/.test(raw)) {
    throw new Error(`bad WebSocket max early data size: ${value}`);
  }
  const parsed = parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`bad WebSocket max early data size: ${value}`);
  }
  return parsed;
}
function splitURIHostList(host) {
  if (Array.isArray(host)) {
    return host.flatMap((item) => splitURIHostList(item) || []);
  }
  if (typeof host !== "string") {
    return host == null ? void 0 : [host];
  }
  const hosts = host.split(",").map((item) => item.trim()).filter(Boolean);
  return hosts.length > 0 ? hosts : void 0;
}
function parseWireGuardURIAddressValue(value) {
  if (value == null) return null;
  const raw = `${value}`.trim();
  if (!raw) return null;
  const [, hostRaw = raw, cidrRaw] = /^(.*?)(?:\/(\d+))?$/.exec(raw) || [];
  const host = `${hostRaw}`.trim().replace(/^\[/, "").replace(/\]$/, "");
  const normalizeCIDR = (cidr, max) => {
    if (cidr == null) return void 0;
    if (!/^\d+$/.test(cidr)) return void 0;
    const parsed = parseInt(cidr, 10);
    if (parsed < 0 || parsed > max) return void 0;
    return parsed;
  };
  if (isIPv4(host)) {
    return {
      family: "ipv4",
      address: host,
      cidr: normalizeCIDR(cidrRaw, 32)
    };
  }
  if (isIPv6(host)) {
    return {
      family: "ipv6",
      address: host,
      cidr: normalizeCIDR(cidrRaw, 128)
    };
  }
  return null;
}
function URI_PROXY() {
  const name = "URI PROXY Parser";
  const test = (line) => {
    return /^(socks5\+tls|socks5|http|https):\/\//.test(line);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
}
function URI_SOCKS() {
  const name = "URI SOCKS Parser";
  const test = (line) => {
    return /^socks:\/\//.test(line);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
}
function URI_SS() {
  const name = "URI SS Parser";
  const test = (line) => {
    return /^ss:\/\//.test(line);
  };
  const parse2 = (line) => {
    let { content, fragment: name2 } = splitURIFragment(
      line.split("ss://")[1]
    );
    const proxy = {
      type: "ss"
    };
    let serverAndPortArray = content.match(/@([^/?]*)(\/|\?|$)/);
    let userInfoStr = decodeShadowsocksUserInfo(content.split("@")[0]);
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
    const params = {};
    for (const addon of query.replace(/^\?/, "").split("&")) {
      if (addon) {
        const [key, valueRaw] = addon.split("=");
        let value = valueRaw;
        value = decodeURIComponent(valueRaw);
        params[key] = value;
      }
    }
    proxy.tls = params.security && params.security !== "none";
    proxy["skip-cert-verify"] = !!params["allowInsecure"];
    proxy.sni = params["sni"] || params["peer"];
    proxy["client-fingerprint"] = params.fp;
    proxy.alpn = params.alpn ? decodeURIComponent(params.alpn).split(",") : void 0;
    if (params["ws"]) {
      proxy.network = "ws";
      _.set(proxy, "ws-opts.path", params["wspath"]);
    }
    if (params["type"]) {
      let httpupgrade;
      let httpUpgradeEd = "";
      let pathEarlyData = "";
      proxy.network = params["type"];
      if (proxy.network === "httpupgrade") {
        proxy.network = "ws";
        httpupgrade = true;
      }
      if (["grpc"].includes(proxy.network)) {
        proxy[proxy.network + "-opts"] = {
          "grpc-service-name": params["serviceName"],
          "_grpc-type": params["mode"],
          "_grpc-authority": params["authority"]
        };
      } else {
        if (params["path"]) {
          let transportPath = params["path"];
          if (proxy.network === "ws") {
            const extracted = extractEarlyDataFromPath(transportPath);
            transportPath = extracted.path;
            if (httpupgrade) {
              httpUpgradeEd = extracted.ed;
            } else {
              pathEarlyData = extracted.ed;
            }
          }
          _.set(proxy, proxy.network + "-opts.path", transportPath);
        }
        if (params["host"]) {
          _.set(
            proxy,
            proxy.network + "-opts.headers.Host",
            decodeURIComponent(params["host"])
          );
        }
        if (httpupgrade) {
          httpUpgradeEd = httpUpgradeEd || (isNumericEarlyData(params.ed) ? `${params.ed}` : "");
          _.set(
            proxy,
            proxy.network + "-opts.v2ray-http-upgrade",
            true
          );
          if (httpUpgradeEd !== "") {
            _.set(
              proxy,
              proxy.network + "-opts.v2ray-http-upgrade-fast-open",
              true
            );
            _.set(
              proxy,
              proxy.network + "-opts._v2ray-http-upgrade-ed",
              httpUpgradeEd
            );
          }
        } else if (proxy.network === "ws" && pathEarlyData !== "") {
          _.set(
            proxy,
            proxy.network + "-opts.max-early-data",
            parseEarlyDataSize(pathEarlyData)
          );
          _.set(
            proxy,
            proxy.network + "-opts.early-data-header-name",
            "Sec-WebSocket-Protocol"
          );
        }
      }
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
        if (params.mode) {
          proxy._mode = params.mode;
        }
        if (params.extra) {
          proxy._extra = params.extra;
        }
        if (Object.keys(opts).length > 0) {
          _.set(proxy, params.security + "-opts", opts);
        }
      }
    }
    proxy.udp = !!params["udp"];
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
    const gostMatch = content.match(/[?&]gost=([^&]+)/);
    if (pluginMatch) {
      const pluginInfo = ("plugin=" + decodeURIComponent(pluginMatch[1])).split(";");
      const params2 = {};
      for (const item of pluginInfo) {
        const separatorIndex = item.indexOf("=");
        if (separatorIndex === -1) {
          if (item) params2[item] = true;
          continue;
        }
        const key = item.slice(0, separatorIndex);
        const val = item.slice(separatorIndex + 1).replace(/\\=/g, "=");
        if (key) params2[key] = val || true;
      }
      switch (params2.plugin) {
        case "obfs-local":
        case "simple-obfs":
          proxy.plugin = "obfs";
          proxy["plugin-opts"] = {
            mode: params2.obfs,
            host: getIfNotBlank(params2["obfs-host"])
          };
          break;
        case "v2ray-plugin":
          proxy.plugin = "v2ray-plugin";
          proxy["plugin-opts"] = {
            mode: getIfNotBlank(params2["obfs"]) || getIfNotBlank(params2["mode"]) || "websocket",
            host: getIfNotBlank(params2["obfs-host"]) || getIfNotBlank(params2["host"]),
            path: getIfNotBlank(params2.path),
            tls: getIfPresent(params2.tls),
            sni: getIfPresent(params2.sni),
            "skip-cert-verify": ["1", "true", 1, true].includes(
              params2["skip-cert-verify"]
            ),
            mux: /^\d+$/.test(params2.mux) ? parseInt(params2.mux, 10) : void 0
          };
          break;
        case "shadow-tls": {
          proxy.plugin = "shadow-tls";
          const version = getIfNotBlank(params2["version"]);
          proxy["plugin-opts"] = {
            host: getIfNotBlank(params2["host"]),
            password: getIfNotBlank(params2["password"]),
            version: version ? parseInt(version, 10) : void 0
          };
          break;
        }
        default:
          throw new Error(
            `Unsupported plugin option: ${params2.plugin}`
          );
      }
    }
    if (shadowTlsMatch) {
      const params2 = JSON.parse(Base64.decode(shadowTlsMatch[1]));
      const version = getIfNotBlank(params2["version"]);
      const address = getIfNotBlank(params2["address"]);
      const port = getIfNotBlank(params2["port"]);
      proxy.plugin = "shadow-tls";
      proxy["plugin-opts"] = {
        host: getIfNotBlank(params2["host"]),
        password: getIfNotBlank(params2["password"]),
        version: version ? parseInt(version, 10) : void 0
      };
      if (address) {
        proxy.server = address;
      }
      if (port) {
        proxy.port = parseInt(port, 10);
      }
    }
    if (gostMatch) {
      const params2 = JSON.parse(
        Base64.decode(decodeURIComponent(gostMatch[1]))
      );
      const address = getIfNotBlank(params2["address"]);
      const port = getIfNotBlank(params2["port"]);
      const route = getIfNotBlank(params2["route"]);
      const normalizedRoute = route?.trim().toLowerCase();
      const isWebsocketRoute = ["ws", "wss", "websocket"].includes(
        normalizedRoute
      );
      proxy.plugin = "gost-plugin";
      proxy["plugin-opts"] = {
        mode: isWebsocketRoute ? "websocket" : route,
        host: getIfNotBlank(params2["host"]),
        path: getIfNotBlank(params2["path"])
      };
      if (normalizedRoute === "wss") {
        proxy["plugin-opts"].tls = true;
      }
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
    proxy.name = name2 ?? `SS ${proxy.server}:${proxy.port}`;
    return proxy;
  };
  return { name, test, parse: parse2 };
}
function URI_SSR() {
  const name = "URI SSR Parser";
  const test = (line) => {
    return /^ssr:\/\//.test(line);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
}
function URI_VMess() {
  const name = "URI VMess Parser";
  const test = (line) => {
    return /^vmess:\/\//.test(line);
  };
  const parse2 = (line) => {
    let { content: lineWithoutFragment, fragment: fragmentName } = splitURIFragment(line.split("vmess://")[1]);
    let content = Base64.decode(lineWithoutFragment.replace(/\?.*?$/, ""));
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
        cipher: normalizeVmessSecurity(
          getIfNotBlank(partitions[3], "auto")
        ),
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
      if (isNotBlank(fragmentName)) {
        proxy.name = fragmentName;
      }
      return proxy;
    } else {
      let params = {};
      try {
        params = JSON.parse(content);
      } catch (e) {
        let [__, base64Line, qs] = /(^[^?]+?)\/?\?(.*)$/.exec(
          lineWithoutFragment
        );
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
        let [___, cipher, uuid, server2, port2] = /(^[^:]+?):([^:]+?)@(.*):(\d+)$/.exec(content);
        params.scy = cipher;
        params.id = uuid;
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
        cipher: normalizeVmessSecurity(params.scy),
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
      } else if (["http"].includes(params.obfs) || ["http"].includes(params.type)) {
        proxy.network = "http";
      } else if (params.net === "http") {
        proxy.network = "h2";
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
        let httpUpgradeEd = "";
        let pathEarlyData = "";
        if (proxy.network === "ws" && transportPath) {
          const extracted = extractEarlyDataFromPath(transportPath);
          transportPath = extracted.path;
          if (httpupgrade) {
            httpUpgradeEd = extracted.ed;
          } else {
            pathEarlyData = extracted.ed;
          }
        }
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
        } else if (proxy.network === "h2") {
          if (!transportPath) {
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
              path: getIfNotBlank(transportPath)
            };
            const normalizedTransportHost = getIfNotBlank(transportHost);
            if (proxy.network === "h2") {
              const h2Hosts = splitURIHostList(
                normalizedTransportHost
              );
              if (h2Hosts) {
                opts.host = h2Hosts;
              }
            } else {
              opts.headers = { Host: normalizedTransportHost };
            }
            if (httpupgrade) {
              opts["v2ray-http-upgrade"] = true;
              httpUpgradeEd = httpUpgradeEd || (isNumericEarlyData(params.ed) ? `${params.ed}` : "");
              if (httpUpgradeEd !== "") {
                opts["v2ray-http-upgrade-fast-open"] = true;
                opts["_v2ray-http-upgrade-ed"] = httpUpgradeEd;
              }
            } else if (proxy.network === "ws" && pathEarlyData !== "") {
              opts["max-early-data"] = parseEarlyDataSize(pathEarlyData);
              opts["early-data-header-name"] = "Sec-WebSocket-Protocol";
            }
            proxy[`${proxy.network}-opts`] = opts;
          }
        } else {
          delete proxy.network;
        }
      }
      proxy["client-fingerprint"] = params.fp;
      proxy.alpn = params.alpn ? params.alpn.split(",") : void 0;
      if (isNotBlank(fragmentName)) {
        proxy.name = fragmentName;
      }
      return proxy;
    }
  };
  return { name, test, parse: parse2 };
}
function URI_VLESS() {
  const name = "URI VLESS Parser";
  const test = (line) => {
    return /^vless:\/\//.test(line);
  };
  const parse2 = (line) => {
    const mapXmuxToReuseSettings = (xmux) => {
      if (!isPlainObject(xmux)) {
        return void 0;
      }
      const reuseSettings = {};
      const xmuxFieldMap = {
        maxConnections: "max-connections",
        maxConcurrency: "max-concurrency",
        cMaxReuseTimes: "c-max-reuse-times",
        hMaxRequestTimes: "h-max-request-times",
        hMaxReusableSecs: "h-max-reusable-secs"
      };
      for (const [sourceKey, targetKey] of Object.entries(xmuxFieldMap)) {
        const normalizedValue = normalizeXhttpNonNegativeRange(
          xmux[sourceKey]
        );
        if (normalizedValue != null) {
          reuseSettings[targetKey] = typeof normalizedValue === "number" ? `${normalizedValue}` : normalizedValue;
        }
      }
      const hKeepAlivePeriod = normalizeXhttpIntegerValue(
        xmux.hKeepAlivePeriod
      );
      if (hKeepAlivePeriod != null) {
        reuseSettings["h-keep-alive-period"] = hKeepAlivePeriod;
      }
      return Object.keys(reuseSettings).length > 0 ? reuseSettings : void 0;
    };
    const toStringHeaderMap2 = (headers) => {
      if (!isPlainObject(headers)) {
        return void 0;
      }
      const parsedHeaders = {};
      for (const [key, value] of Object.entries(headers)) {
        if (typeof value === "string") {
          parsedHeaders[key] = value;
        }
      }
      return Object.keys(parsedHeaders).length > 0 ? parsedHeaders : void 0;
    };
    const cloneUnsupportedXhttpValue = (value) => {
      if (Array.isArray(value)) {
        return value.map(cloneUnsupportedXhttpValue);
      }
      if (isPlainObject(value)) {
        const clonedValue = {};
        for (const [key, entryValue] of Object.entries(value)) {
          clonedValue[key] = cloneUnsupportedXhttpValue(entryValue);
        }
        return clonedValue;
      }
      return value;
    };
    const compactUnsupportedXhttpValue = (value) => {
      if (Array.isArray(value)) {
        return value.map(compactUnsupportedXhttpValue).filter((entryValue) => entryValue !== void 0);
      }
      if (!isPlainObject(value)) {
        return value;
      }
      const compactedValue = {};
      for (const [key, entryValue] of Object.entries(value)) {
        const compactedEntryValue = compactUnsupportedXhttpValue(entryValue);
        if (compactedEntryValue !== void 0) {
          compactedValue[key] = compactedEntryValue;
        }
      }
      return Object.keys(compactedValue).length > 0 ? compactedValue : void 0;
    };
    const setUnsupportedXhttpField = (target, key, value) => {
      const normalizedValue = compactUnsupportedXhttpValue(
        cloneUnsupportedXhttpValue(value)
      );
      if (normalizedValue !== void 0) {
        target[key] = normalizedValue;
      }
    };
    const collectUnsupportedXhttpHeaders = (headers) => {
      if (headers == null) {
        return void 0;
      }
      if (!isPlainObject(headers)) {
        return cloneUnsupportedXhttpValue(headers);
      }
      const unsupportedHeaders = {};
      for (const [key, value] of Object.entries(headers)) {
        if (typeof value === "string") {
          continue;
        }
        setUnsupportedXhttpField(unsupportedHeaders, key, value);
      }
      return compactUnsupportedXhttpValue(unsupportedHeaders);
    };
    const isSupportedXmuxFieldValue = (key, value) => {
      if ([
        "maxConnections",
        "maxConcurrency",
        "cMaxReuseTimes",
        "hMaxRequestTimes",
        "hMaxReusableSecs"
      ].includes(key)) {
        return normalizeXhttpNonNegativeRange(value) != null;
      }
      if (key === "hKeepAlivePeriod") {
        return normalizeXhttpIntegerValue(value) != null;
      }
      return false;
    };
    const collectUnsupportedXmux = (xmux) => {
      if (xmux == null) {
        return void 0;
      }
      if (!isPlainObject(xmux)) {
        return cloneUnsupportedXhttpValue(xmux);
      }
      const unsupportedXmux = {};
      for (const [key, value] of Object.entries(xmux)) {
        if (isSupportedXmuxFieldValue(key, value)) {
          continue;
        }
        setUnsupportedXhttpField(unsupportedXmux, key, value);
      }
      return compactUnsupportedXhttpValue(unsupportedXmux);
    };
    const collectUnsupportedXhttpExtra = (extra) => {
      if (extra == null) {
        return void 0;
      }
      if (!isPlainObject(extra)) {
        return cloneUnsupportedXhttpValue(extra);
      }
      const unsupportedExtra = {};
      for (const [key, value] of Object.entries(extra)) {
        switch (key) {
          case "headers": {
            const unsupportedHeaders = collectUnsupportedXhttpHeaders(value);
            if (unsupportedHeaders !== void 0) {
              unsupportedExtra.headers = unsupportedHeaders;
            }
            break;
          }
          case "noGRPCHeader":
          case "xPaddingObfsMode":
            if (value !== true) {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "xPaddingBytes":
            if (normalizeXhttpStrictPositiveRangeString(value) == null) {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "xPaddingKey":
          case "xPaddingHeader":
          case "xPaddingPlacement":
          case "xPaddingMethod":
          case "uplinkHTTPMethod":
          case "sessionIDPlacement":
          case "sessionPlacement":
          case "sessionIDKey":
          case "sessionKey":
          case "seqPlacement":
          case "seqKey":
          case "uplinkDataPlacement":
          case "uplinkDataKey":
            if (typeof value !== "string") {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "sessionIDTable":
            if (typeof value !== "string") {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "uplinkChunkSize":
            if (normalizeXhttpNonNegativeRange(value) == null) {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "scMaxEachPostBytes":
            if (normalizeXhttpStrictPositiveRangeString(value) == null) {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "scMinPostsIntervalMs":
            if (normalizeXhttpPositiveRange(value) == null) {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "sessionIDLength":
            if (normalizeXhttpStrictPositiveRangeString(value) == null) {
              setUnsupportedXhttpField(
                unsupportedExtra,
                key,
                value
              );
            }
            break;
          case "xmux": {
            const unsupportedXmux = collectUnsupportedXmux(value);
            if (unsupportedXmux !== void 0) {
              unsupportedExtra.xmux = unsupportedXmux;
            }
            break;
          }
          default:
            setUnsupportedXhttpField(unsupportedExtra, key, value);
            break;
        }
      }
      return compactUnsupportedXhttpValue(unsupportedExtra);
    };
    const collectUnsupportedNestedXhttpSettings = (xhttpSettings) => {
      if (xhttpSettings == null) {
        return void 0;
      }
      if (!isPlainObject(xhttpSettings)) {
        return cloneUnsupportedXhttpValue(xhttpSettings);
      }
      const unsupportedXhttpSettings = {};
      if (Object.prototype.hasOwnProperty.call(xhttpSettings, "path") && !isNotBlank(xhttpSettings.path)) {
        setUnsupportedXhttpField(
          unsupportedXhttpSettings,
          "path",
          xhttpSettings.path
        );
      }
      if (Object.prototype.hasOwnProperty.call(xhttpSettings, "host") && !isNotBlank(xhttpSettings.host)) {
        setUnsupportedXhttpField(
          unsupportedXhttpSettings,
          "host",
          xhttpSettings.host
        );
      }
      if (Object.prototype.hasOwnProperty.call(xhttpSettings, "mode") && !isNotBlank(xhttpSettings.mode)) {
        setUnsupportedXhttpField(
          unsupportedXhttpSettings,
          "mode",
          xhttpSettings.mode
        );
      }
      const inlineExtra = {};
      for (const [key, value] of Object.entries(xhttpSettings)) {
        if (["path", "host", "mode", "extra"].includes(key)) {
          continue;
        }
        inlineExtra[key] = value;
      }
      const unsupportedInlineExtra = collectUnsupportedXhttpExtra(inlineExtra);
      if (isPlainObject(unsupportedInlineExtra)) {
        Object.assign(unsupportedXhttpSettings, unsupportedInlineExtra);
      }
      if (Object.prototype.hasOwnProperty.call(xhttpSettings, "extra")) {
        const unsupportedExtra = collectUnsupportedXhttpExtra(
          xhttpSettings.extra
        );
        if (unsupportedExtra !== void 0) {
          unsupportedXhttpSettings.extra = unsupportedExtra;
        }
      }
      return compactUnsupportedXhttpValue(unsupportedXhttpSettings);
    };
    const collectUnsupportedDownloadSettings = (downloadSettings) => {
      if (downloadSettings == null) {
        return void 0;
      }
      if (!isPlainObject(downloadSettings)) {
        return cloneUnsupportedXhttpValue(downloadSettings);
      }
      const unsupportedDownloadSettings = {};
      for (const [key, value] of Object.entries(downloadSettings)) {
        switch (key) {
          case "address":
            if (!isNotBlank(value)) {
              setUnsupportedXhttpField(
                unsupportedDownloadSettings,
                key,
                value
              );
            }
            break;
          case "port":
            if (normalizeXhttpIntegerValue(value, {
              allowNegative: false
            }) == null) {
              setUnsupportedXhttpField(
                unsupportedDownloadSettings,
                key,
                value
              );
            }
            break;
          case "security": {
            const normalizedSecurity = typeof value === "string" ? value.toLowerCase() : "";
            if (!["tls", "reality"].includes(normalizedSecurity)) {
              setUnsupportedXhttpField(
                unsupportedDownloadSettings,
                key,
                value
              );
            }
            break;
          }
          case "tlsSettings": {
            if (!isPlainObject(value)) {
              setUnsupportedXhttpField(
                unsupportedDownloadSettings,
                key,
                value
              );
              break;
            }
            const unsupportedTlsSettings = {};
            const hasSupportedEchConfigList = isSupportedXrayEchConfigList(value.echConfigList);
            for (const [tlsKey, tlsValue] of Object.entries(
              value
            )) {
              switch (tlsKey) {
                case "serverName":
                case "fingerprint":
                  if (!isNotBlank(tlsValue)) {
                    setUnsupportedXhttpField(
                      unsupportedTlsSettings,
                      tlsKey,
                      tlsValue
                    );
                  }
                  break;
                case "echConfigList":
                  if (!isSupportedXrayEchConfigList(tlsValue)) {
                    setUnsupportedXhttpField(
                      unsupportedTlsSettings,
                      tlsKey,
                      tlsValue
                    );
                  }
                  break;
                case "echForceQuery":
                  if (!hasSupportedEchConfigList || !isSupportedXrayEchForceQuery(tlsValue)) {
                    setUnsupportedXhttpField(
                      unsupportedTlsSettings,
                      tlsKey,
                      tlsValue
                    );
                  }
                  break;
                case "echSockopt":
                  if (!hasSupportedEchConfigList || !isPlainObject(tlsValue)) {
                    setUnsupportedXhttpField(
                      unsupportedTlsSettings,
                      tlsKey,
                      tlsValue
                    );
                  }
                  break;
                case "alpn":
                  if (!(Array.isArray(tlsValue) && tlsValue.length > 0 && tlsValue.every(
                    (item) => typeof item === "string" && item !== ""
                  ))) {
                    setUnsupportedXhttpField(
                      unsupportedTlsSettings,
                      tlsKey,
                      tlsValue
                    );
                  }
                  break;
                case "allowInsecure":
                  if (tlsValue !== true) {
                    setUnsupportedXhttpField(
                      unsupportedTlsSettings,
                      tlsKey,
                      tlsValue
                    );
                  }
                  break;
                default:
                  setUnsupportedXhttpField(
                    unsupportedTlsSettings,
                    tlsKey,
                    tlsValue
                  );
                  break;
              }
            }
            const compactedTlsSettings = compactUnsupportedXhttpValue(
              unsupportedTlsSettings
            );
            if (compactedTlsSettings !== void 0) {
              unsupportedDownloadSettings.tlsSettings = compactedTlsSettings;
            }
            break;
          }
          case "realitySettings": {
            if (!isPlainObject(value)) {
              setUnsupportedXhttpField(
                unsupportedDownloadSettings,
                key,
                value
              );
              break;
            }
            const unsupportedRealitySettings = {};
            for (const [realityKey, realityValue] of Object.entries(
              value
            )) {
              switch (realityKey) {
                case "publicKey":
                case "shortId":
                case "serverName":
                case "fingerprint":
                  if (!isNotBlank(realityValue)) {
                    setUnsupportedXhttpField(
                      unsupportedRealitySettings,
                      realityKey,
                      realityValue
                    );
                  }
                  break;
                default:
                  setUnsupportedXhttpField(
                    unsupportedRealitySettings,
                    realityKey,
                    realityValue
                  );
                  break;
              }
            }
            const compactedRealitySettings = compactUnsupportedXhttpValue(
              unsupportedRealitySettings
            );
            if (compactedRealitySettings !== void 0) {
              unsupportedDownloadSettings.realitySettings = compactedRealitySettings;
            }
            break;
          }
          case "xhttpSettings": {
            const unsupportedXhttpSettings = collectUnsupportedNestedXhttpSettings(value);
            if (unsupportedXhttpSettings !== void 0) {
              unsupportedDownloadSettings.xhttpSettings = unsupportedXhttpSettings;
            }
            break;
          }
          case "network": {
            const normalizedNetwork = typeof value === "string" ? value.toLowerCase() : "";
            if (normalizedNetwork !== "xhttp" && normalizedNetwork !== "splithttp") {
              setUnsupportedXhttpField(
                unsupportedDownloadSettings,
                key,
                value
              );
            }
            break;
          }
          default:
            setUnsupportedXhttpField(
              unsupportedDownloadSettings,
              key,
              value
            );
            break;
        }
      }
      return compactUnsupportedXhttpValue(unsupportedDownloadSettings);
    };
    const collectUnsupportedRootXhttpExtra = (extra, { parsedDownloadSettings } = {}) => {
      if (!isPlainObject(extra)) {
        return void 0;
      }
      const {
        downloadSettings: rawDownloadSettings,
        ...rootInlineExtra
      } = extra;
      const unsupportedExtra = collectUnsupportedXhttpExtra(rootInlineExtra) || {};
      if (Object.prototype.hasOwnProperty.call(extra, "downloadSettings")) {
        const unsupportedDownloadSettings = collectUnsupportedDownloadSettings(rawDownloadSettings);
        if (unsupportedDownloadSettings !== void 0) {
          unsupportedExtra.downloadSettings = unsupportedDownloadSettings;
        }
      }
      return compactUnsupportedXhttpValue(unsupportedExtra);
    };
    const applyXhttpExtraFields = (target, extra) => {
      if (!isPlainObject(target) || !isPlainObject(extra)) {
        return;
      }
      const parsedHeaders = toStringHeaderMap2(extra.headers);
      if (parsedHeaders) {
        const headers = { ...target.headers || {} };
        for (const [key, value] of Object.entries(parsedHeaders)) {
          if (/^host$/i.test(key)) {
            if (!Object.prototype.hasOwnProperty.call(
              headers,
              "Host"
            ) && !Object.prototype.hasOwnProperty.call(
              headers,
              "host"
            )) {
              headers.Host = value;
            }
            continue;
          }
          headers[key] = value;
        }
        if (Object.keys(headers).length > 0) {
          target.headers = headers;
        }
      }
      if (extra.noGRPCHeader === true) {
        target["no-grpc-header"] = true;
      }
      const xPaddingBytes = normalizeXhttpStrictPositiveRangeString(
        extra.xPaddingBytes
      );
      if (xPaddingBytes != null) {
        target["x-padding-bytes"] = xPaddingBytes;
      }
      if (extra.xPaddingObfsMode === true) {
        target["x-padding-obfs-mode"] = true;
      }
      if (isNotBlank(extra.xPaddingKey)) {
        target["x-padding-key"] = extra.xPaddingKey;
      }
      if (isNotBlank(extra.xPaddingHeader)) {
        target["x-padding-header"] = extra.xPaddingHeader;
      }
      if (isNotBlank(extra.xPaddingPlacement)) {
        target["x-padding-placement"] = extra.xPaddingPlacement;
      }
      if (isNotBlank(extra.xPaddingMethod)) {
        target["x-padding-method"] = extra.xPaddingMethod;
      }
      if (isNotBlank(extra.uplinkHTTPMethod)) {
        target["uplink-http-method"] = extra.uplinkHTTPMethod;
      }
      if (isNotBlank(extra.sessionIDPlacement)) {
        target["session-placement"] = extra.sessionIDPlacement;
      } else if (isNotBlank(extra.sessionPlacement)) {
        target["session-placement"] = extra.sessionPlacement;
      }
      if (isNotBlank(extra.sessionIDKey)) {
        target["session-key"] = extra.sessionIDKey;
      } else if (isNotBlank(extra.sessionKey)) {
        target["session-key"] = extra.sessionKey;
      }
      if (typeof extra.sessionIDTable === "string") {
        target["session-table"] = extra.sessionIDTable;
      }
      const sessionIDLength = normalizeXhttpStrictPositiveRangeString(
        extra.sessionIDLength
      );
      if (sessionIDLength != null) {
        target["session-length"] = sessionIDLength;
      }
      if (isNotBlank(extra.seqPlacement)) {
        target["seq-placement"] = extra.seqPlacement;
      }
      if (isNotBlank(extra.seqKey)) {
        target["seq-key"] = extra.seqKey;
      }
      if (isNotBlank(extra.uplinkDataPlacement)) {
        target["uplink-data-placement"] = extra.uplinkDataPlacement;
      }
      if (isNotBlank(extra.uplinkDataKey)) {
        target["uplink-data-key"] = extra.uplinkDataKey;
      }
      const uplinkChunkSize = normalizeXhttpNonNegativeRange(
        extra.uplinkChunkSize
      );
      if (uplinkChunkSize != null) {
        target["uplink-chunk-size"] = uplinkChunkSize;
      }
      const scMaxEachPostBytes = normalizeXhttpStrictPositiveRangeValue(
        extra.scMaxEachPostBytes
      );
      if (scMaxEachPostBytes != null) {
        target["sc-max-each-post-bytes"] = scMaxEachPostBytes;
      }
      const scMinPostsIntervalMs = normalizeXhttpPositiveRange(
        extra.scMinPostsIntervalMs
      );
      if (scMinPostsIntervalMs != null) {
        target["sc-min-posts-interval-ms"] = scMinPostsIntervalMs;
      }
      const reuseSettings = mapXmuxToReuseSettings(extra.xmux);
      if (reuseSettings) {
        target["reuse-settings"] = reuseSettings;
      }
    };
    const parseDownloadSettings = (downloadSettings) => {
      if (!isPlainObject(downloadSettings)) {
        return void 0;
      }
      const parsedDownloadSettings = {};
      const downloadNetwork = typeof downloadSettings.network === "string" ? downloadSettings.network.toLowerCase() : "";
      if (downloadNetwork === "xhttp" || downloadNetwork === "splithttp") {
        parsedDownloadSettings.network = "xhttp";
      }
      if (isNotBlank(downloadSettings.address)) {
        parsedDownloadSettings.server = downloadSettings.address;
      }
      const parsedPort = normalizeXhttpIntegerValue(
        downloadSettings.port,
        {
          allowNegative: false
        }
      );
      if (parsedPort != null) {
        parsedDownloadSettings.port = parsedPort;
      }
      const downloadSecurity = typeof downloadSettings.security === "string" ? downloadSettings.security.toLowerCase() : "";
      if (downloadSecurity === "tls" || downloadSecurity === "reality") {
        parsedDownloadSettings.tls = true;
      }
      if (isPlainObject(downloadSettings.tlsSettings)) {
        if (isNotBlank(downloadSettings.tlsSettings.serverName)) {
          parsedDownloadSettings.servername = downloadSettings.tlsSettings.serverName;
        }
        if (isNotBlank(downloadSettings.tlsSettings.fingerprint)) {
          parsedDownloadSettings["client-fingerprint"] = downloadSettings.tlsSettings.fingerprint;
        }
        if (Array.isArray(downloadSettings.tlsSettings.alpn) && downloadSettings.tlsSettings.alpn.length > 0 && downloadSettings.tlsSettings.alpn.every(
          (item) => typeof item === "string" && item !== ""
        )) {
          parsedDownloadSettings.alpn = downloadSettings.tlsSettings.alpn;
        }
        if (downloadSettings.tlsSettings.allowInsecure === true) {
          parsedDownloadSettings["skip-cert-verify"] = true;
        }
        const echOpts2 = buildMihomoEchOptsFromXrayFields({
          echConfigList: downloadSettings.tlsSettings.echConfigList,
          echForceQuery: downloadSettings.tlsSettings.echForceQuery,
          echSockopt: downloadSettings.tlsSettings.echSockopt
        });
        if (echOpts2) {
          parsedDownloadSettings["ech-opts"] = echOpts2;
        }
      }
      let realityOpts;
      if (isPlainObject(downloadSettings.realitySettings)) {
        realityOpts = {};
        if (isNotBlank(downloadSettings.realitySettings.publicKey)) {
          realityOpts["public-key"] = downloadSettings.realitySettings.publicKey;
        }
        if (isNotBlank(downloadSettings.realitySettings.shortId)) {
          realityOpts["short-id"] = downloadSettings.realitySettings.shortId;
        }
        if (isNotBlank(downloadSettings.realitySettings.serverName)) {
          parsedDownloadSettings.servername = downloadSettings.realitySettings.serverName;
        }
        if (isNotBlank(downloadSettings.realitySettings.fingerprint)) {
          parsedDownloadSettings["client-fingerprint"] = downloadSettings.realitySettings.fingerprint;
        }
      }
      if (downloadSecurity === "reality") {
        parsedDownloadSettings["reality-opts"] = realityOpts || {};
      } else if (realityOpts && Object.keys(realityOpts).length > 0) {
        parsedDownloadSettings["reality-opts"] = realityOpts;
      }
      if (isPlainObject(downloadSettings.xhttpSettings)) {
        if (isNotBlank(downloadSettings.xhttpSettings.path)) {
          parsedDownloadSettings.path = downloadSettings.xhttpSettings.path;
        }
        if (isNotBlank(downloadSettings.xhttpSettings.host)) {
          parsedDownloadSettings.host = downloadSettings.xhttpSettings.host;
        }
        if (isNotBlank(downloadSettings.xhttpSettings.mode)) {
          parsedDownloadSettings.mode = downloadSettings.xhttpSettings.mode;
        }
        applyXhttpExtraFields(
          parsedDownloadSettings,
          downloadSettings.xhttpSettings
        );
        if (isPlainObject(downloadSettings.xhttpSettings.extra)) {
          applyXhttpExtraFields(
            parsedDownloadSettings,
            downloadSettings.xhttpSettings.extra
          );
        }
      }
      return Object.keys(parsedDownloadSettings).length > 0 ? parsedDownloadSettings : void 0;
    };
    line = line.split("vless://")[1];
    let isShadowrocket;
    let parsed = /^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
    if (!parsed) {
      let [_3, base64, other] = /^(.*?)(\?.*?$)/.exec(line);
      line = `${Base64.decode(base64)}${other}`;
      parsed = /^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
      isShadowrocket = true;
    }
    let [__, uuid, server, port, ___, addons = "", name2] = parsed;
    if (isShadowrocket) {
      uuid = uuid.replace(/^.*?:/g, "");
    }
    port = parseInt(`${port}`, 10);
    uuid = decodeURIComponent(uuid);
    if (name2 != null) {
      name2 = decodeURIComponent(name2);
    }
    const proxy = {
      type: "vless",
      name: name2,
      server,
      port,
      uuid,
      udp: true
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
    if (params.pbk) {
      params.security = "reality";
    }
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
    proxy._echConfigList = getIfPresent(params.ech);
    const echOpts = buildMihomoEchOptsFromXrayFields({
      echConfigList: params.ech
    });
    if (echOpts) {
      proxy["ech-opts"] = echOpts;
    }
    proxy["tls-fingerprint"] = getIfPresent(params.pcs);
    proxy._h2 = /(TRUE)|1/i.test(params.h2);
    switch (`${params.packetEncoding || ""}`.trim().toLowerCase()) {
      case "none":
        proxy["packet-encoding"] = "";
        break;
      case "packet":
        proxy["packet-encoding"] = "packetaddr";
        break;
      default:
        proxy["packet-encoding"] = "xudp";
        break;
    }
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
    proxy.network = params.type || "tcp";
    if (proxy.network === "tcp" && params.headerType === "http") {
      proxy.network = "http";
    } else if (proxy.network === "http") {
      proxy.network = "h2";
    } else if (proxy.network === "httpupgrade") {
      proxy.network = "ws";
      httpupgrade = true;
    }
    if (!params.type && isShadowrocket && params.obfs) {
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
      let pathEarlyData = "";
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
        if (["xhttp"].includes(proxy.network) && opts.headers?.Host) {
          opts.host = opts.headers.Host;
          delete opts.headers.Host;
          if (Object.keys(opts.headers).length === 0) {
            delete opts.headers;
          }
        }
        const h2Host = opts.headers?.Host ?? opts.headers?.host;
        if (["h2"].includes(proxy.network) && h2Host) {
          opts.host = splitURIHostList(h2Host);
          delete opts.headers.Host;
          delete opts.headers.host;
          if (Object.keys(opts.headers).length === 0) {
            delete opts.headers;
          }
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
        let transportPath = params.path;
        if (proxy.network === "ws") {
          const extracted = extractEarlyDataFromPath(transportPath);
          transportPath = extracted.path;
          pathEarlyData = extracted.ed;
        }
        opts.path = transportPath;
      } else if (proxy.network === "h2") {
        opts.path = "/";
      }
      if (proxy.network === "http" && params.method) {
        opts.method = params.method;
      }
      if (["grpc"].includes(proxy.network)) {
        opts["_grpc-type"] = params.mode || "gun";
      }
      if (httpupgrade) {
        opts["v2ray-http-upgrade"] = true;
      }
      const earlyDataRaw = pathEarlyData || params.ed;
      if (earlyDataRaw) {
        const maxEarlyData = parseEarlyDataSize(earlyDataRaw);
        if (httpupgrade) {
          opts["v2ray-http-upgrade-fast-open"] = true;
          opts["_v2ray-http-upgrade-ed"] = `${earlyDataRaw}`;
        } else if (proxy.network === "ws") {
          opts["max-early-data"] = maxEarlyData;
          opts["early-data-header-name"] = params.eh || "Sec-WebSocket-Protocol";
        }
      }
      if (params.eh && (proxy.network === "ws" || httpupgrade)) {
        opts["early-data-header-name"] = params.eh;
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
      if (params.extra && !["xhttp"].includes(proxy.network)) {
        proxy._extra = params.extra;
      }
      if (["xhttp"].includes(proxy.network)) {
        let extra = {};
        let invalidRawExtra;
        try {
          extra = params.extra ? JSON.parse(params.extra) : {};
        } catch (e) {
          app_default.error(
            `Failed to parse extra field as JSON: ${params.extra}`
          );
          invalidRawExtra = params.extra;
        }
        const xhttpOpts = {
          ...proxy[`${proxy.network}-opts`] || {}
        };
        if (params.mode) {
          xhttpOpts.mode = params.mode;
        }
        applyXhttpExtraFields(xhttpOpts, extra);
        const downloadSettings = parseDownloadSettings(
          extra?.downloadSettings
        );
        if (downloadSettings) {
          xhttpOpts["download-settings"] = downloadSettings;
        }
        if (Object.keys(xhttpOpts).length > 0) {
          proxy[`${proxy.network}-opts`] = xhttpOpts;
        }
        if (invalidRawExtra != null) {
          proxy._extra = invalidRawExtra;
        }
        const unsupportedExtra = collectUnsupportedRootXhttpExtra(
          extra,
          {
            parsedDownloadSettings: downloadSettings
          }
        );
        if (unsupportedExtra) {
          proxy._extra_unsupported = unsupportedExtra;
        }
      } else if (params.mode) {
        proxy._mode = params.mode;
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
  return { name, test, parse: parse2 };
}
function URI_AnyTLS() {
  const name = "URI AnyTLS Parser";
  const test = (line) => {
    return /^anytls:\/\//.test(line);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
}
function URI_Hysteria2() {
  const name = "URI Hysteria2 Parser";
  const test = (line) => {
    return /^(hysteria2|hy2):\/\//.test(line);
  };
  const parse2 = (line) => {
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
    if (hop_interval != null) {
      proxy["hop-interval"] = hop_interval;
    }
    let keepalive = params["keepalive"];
    if (/^\d+$/.test(keepalive)) {
      proxy["keepalive"] = parseInt(`${keepalive}`, 10);
    }
    if (params.upmbps) {
      proxy.up = params.upmbps;
    }
    if (params.downmbps) {
      proxy.down = params.downmbps;
    }
    return proxy;
  };
  return { name, test, parse: parse2 };
}
function URI_Hysteria() {
  const name = "URI Hysteria Parser";
  const test = (line) => {
    return /^(hysteria|hy):\/\//.test(line);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
}
function URI_TUIC() {
  const name = "URI TUIC Parser";
  const test = (line) => {
    return /^tuic:\/\//.test(line);
  };
  const parse2 = (line) => {
    line = line.split(/tuic:\/\//)[1];
    let [__, auth, server, port, addons = "", name2] = /^(.*?)@(.*?)(?::(\d+))?\/?(?:\?(.*?))?(?:#(.*?))?$/.exec(line);
    auth = decodeURIComponent(auth);
    let [uuid, ...passwordParts] = auth.split(":");
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
      uuid
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
  return { name, test, parse: parse2 };
}
function URI_WireGuard() {
  const name = "URI WireGuard Parser";
  const test = (line) => {
    return /^(wireguard|wg):\/\//.test(line);
  };
  const parse2 = (line) => {
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
        const equalIndex = addon.indexOf("=");
        let key;
        let value;
        if (equalIndex === -1) {
          key = addon;
          value = "";
        } else {
          key = addon.slice(0, equalIndex);
          value = addon.slice(equalIndex + 1);
        }
        key = key.replace(/_/, "-");
        value = decodeURIComponent(value);
        if (["reserved"].includes(key)) {
          const parsed = value.split(",").map((i) => parseInt(i.trim(), 10)).filter((i) => Number.isInteger(i));
          if (parsed.length === 3) {
            proxy[key] = parsed;
          }
        } else if (["address", "ip"].includes(key)) {
          value.split(",").map((i) => {
            const parsed = parseWireGuardURIAddressValue(i);
            if (!parsed) return;
            if (parsed.family === "ipv4") {
              proxy.ip = parsed.address;
              if (typeof parsed.cidr !== "undefined") {
                proxy["ip-cidr"] = parsed.cidr;
              }
            } else if (parsed.family === "ipv6") {
              proxy.ipv6 = parsed.address;
              if (typeof parsed.cidr !== "undefined") {
                proxy["ipv6-cidr"] = parsed.cidr;
              }
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
  return { name, test, parse: parse2 };
}
function URI_Trojan() {
  const name = "URI Trojan Parser";
  const test = (line) => {
    return /^trojan:\/\//.test(line);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
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
  const parse2 = (line) => {
    let proxy;
    try {
      proxy = JSON5.parse(line);
    } catch (e) {
      proxy = yaml_default.parse(line);
    }
    if (![
      "gost-relay",
      "openvpn",
      "tailscale",
      "trusttunnel",
      "h2-connect",
      "naive",
      "anytls",
      "mieru",
      "masque",
      "sudoku",
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
    if (["vmess", "vless"].includes(proxy.type) && proxy.servername) {
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
    if (proxy.type === "vmess") {
      proxy.cipher = normalizeVmessSecurity(proxy.cipher);
    }
    return proxy;
  };
  return { name, test, parse: parse2 };
}
function QX_SS() {
  const name = "QX SS Parser";
  const test = (line) => {
    return /^shadowsocks\s*=/.test(line.split(",")[0].trim()) && line.indexOf("ssr-protocol") === -1;
  };
  const parse2 = (line) => {
    const parser5 = getParser3();
    return parser5.parse(line);
  };
  return { name, test, parse: parse2 };
}
function QX_SSR() {
  const name = "QX SSR Parser";
  const test = (line) => {
    return /^shadowsocks\s*=/.test(line.split(",")[0].trim()) && line.indexOf("ssr-protocol") !== -1;
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function QX_VMess() {
  const name = "QX VMess Parser";
  const test = (line) => {
    return /^vmess\s*=/.test(line.split(",")[0].trim());
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function QX_VLESS() {
  const name = "QX VLESS Parser";
  const test = (line) => {
    return /^vless\s*=/.test(line.split(",")[0].trim());
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function QX_AnyTLS() {
  const name = "QX AnyTLS Parser";
  const test = (line) => {
    return /^anytls\s*=/.test(line.split(",")[0].trim());
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function QX_Trojan() {
  const name = "QX Trojan Parser";
  const test = (line) => {
    return /^trojan\s*=/.test(line.split(",")[0].trim());
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function QX_Http() {
  const name = "QX HTTP Parser";
  const test = (line) => {
    return /^http\s*=/.test(line.split(",")[0].trim());
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function QX_Socks5() {
  const name = "QX Socks5 Parser";
  const test = (line) => {
    return /^socks5\s*=/.test(line.split(",")[0].trim());
  };
  const parse2 = (line) => getParser3().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_SS() {
  const name = "Loon SS Parser";
  const test = (line) => {
    return line.split(",")[0].split("=")[1].trim().toLowerCase() === "shadowsocks";
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_SSR() {
  const name = "Loon SSR Parser";
  const test = (line) => {
    return line.split(",")[0].split("=")[1].trim().toLowerCase() === "shadowsocksr";
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_VMess() {
  const name = "Loon VMess Parser";
  const test = (line) => {
    return /^.*=\s*vmess/i.test(line.split(",")[0]) && line.indexOf("username") === -1;
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_Vless() {
  const name = "Loon Vless Parser";
  const test = (line) => {
    return /^.*=\s*vless/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_Trojan() {
  const name = "Loon Trojan Parser";
  const test = (line) => {
    return /^.*=\s*trojan/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_AnyTLS() {
  const name = "Loon AnyTLS Parser";
  const test = (line) => {
    return /^.*=\s*anytls/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_Hysteria2() {
  const name = "Loon Hysteria2 Parser";
  const test = (line) => {
    return /^.*=\s*Hysteria2/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_Http() {
  const name = "Loon HTTP Parser";
  const test = (line) => {
    return /^.*=\s*http/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_Socks5() {
  const name = "Loon SOCKS5 Parser";
  const test = (line) => {
    return /^.*=\s*socks5/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser2().parse(line);
  return { name, test, parse: parse2 };
}
function Loon_WireGuard() {
  const name = "Loon WireGuard Parser";
  const test = (line) => {
    return /^.*=\s*wireguard/i.test(line.split(",")[0]);
  };
  const parse2 = (line) => {
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
  return { name, test, parse: parse2 };
}
function Surge_Direct() {
  const name = "Surge Direct Parser";
  const test = (line) => {
    return /^.*=\s*direct/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_AnyTLS() {
  const name = "Surge AnyTLS Parser";
  const test = (line) => {
    return /^.*=\s*anytls/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_TrustTunnel() {
  const name = "Surge TrustTunnel Parser";
  const test = (line) => {
    return /^.*=\s*trust-tunnel/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_H2Connect() {
  const name = "Surge HTTP/2 CONNECT Parser";
  const test = (line) => {
    return /^.*=\s*h2-connect/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_SSH() {
  const name = "Surge SSH Parser";
  const test = (line) => {
    return /^.*=\s*ssh/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_SS() {
  const name = "Surge SS Parser";
  const test = (line) => {
    return /^.*=\s*ss/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_VMess() {
  const name = "Surge VMess Parser";
  const test = (line) => {
    return /^.*=\s*vmess/.test(line.split(",")[0]) && line.indexOf("username") !== -1;
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_Trojan() {
  const name = "Surge Trojan Parser";
  const test = (line) => {
    return /^.*=\s*trojan/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
var LOON_ONLY_OPTIONS = /(^|,)\s*(fast-open|over-tls|tls-name|ip-mode|tls-cert-sha256|tls-pubkey-sha256)\s*=/i;
function Surge_Http() {
  const name = "Surge HTTP Parser";
  const test = (line) => {
    return /^.*=\s*https?/.test(line.split(",")[0]) && !LOON_ONLY_OPTIONS.test(line);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_Socks5() {
  const name = "Surge Socks5 Parser";
  const test = (line) => {
    return /^.*=\s*socks5(-tls)?/.test(line.split(",")[0]) && !LOON_ONLY_OPTIONS.test(line);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_External() {
  const name = "Surge External Parser";
  const test = (line) => {
    return /^.*=\s*external/.test(line.split(",")[0]);
  };
  const parse2 = (line) => {
    let parsed = /^\s*(.*?)\s*?=\s*?external\s*?,\s*(.*?)\s*$/.exec(line);
    let [_3, name2, other] = parsed;
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
  return { name, test, parse: parse2 };
}
function Surge_Snell() {
  const name = "Surge Snell Parser";
  const test = (line) => {
    return /^.*=\s*snell/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_Tuic() {
  const name = "Surge Tuic Parser";
  const test = (line) => {
    return /^.*=\s*tuic(-v5)?/.test(line.split(",")[0]);
  };
  const parse2 = (raw) => {
    const { port_hopping, line } = surge_port_hopping(raw);
    const proxy = getParser().parse(line);
    proxy["ports"] = port_hopping;
    return proxy;
  };
  return { name, test, parse: parse2 };
}
function Surge_WireGuard() {
  const name = "Surge WireGuard Parser";
  const test = (line) => {
    return /^.*=\s*wireguard/.test(line.split(",")[0]);
  };
  const parse2 = (line) => getParser().parse(line);
  return { name, test, parse: parse2 };
}
function Surge_Hysteria2() {
  const name = "Surge Hysteria2 Parser";
  const test = (line) => {
    return /^.*=\s*hysteria2/.test(line.split(",")[0]);
  };
  const parse2 = (raw) => {
    const { port_hopping, line } = surge_port_hopping(raw);
    const proxy = getParser().parse(line);
    proxy["ports"] = port_hopping;
    return proxy;
  };
  return { name, test, parse: parse2 };
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
  Surge_AnyTLS(),
  Surge_TrustTunnel(),
  Surge_H2Connect(),
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
  Loon_AnyTLS(),
  Loon_Http(),
  Loon_Socks5(),
  Loon_WireGuard(),
  QX_SS(),
  QX_SSR(),
  QX_VMess(),
  QX_VLESS(),
  QX_AnyTLS(),
  QX_Trojan(),
  QX_Http(),
  QX_Socks5()
];

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/utils.js
import _2 from "lodash";

// src/vendors/Sub-Store/backend/src/core/proxy-utils/preprocessors/index.js
import { Base64 as Base642 } from "js-base64";
function normalizeClashYaml(raw) {
  if (typeof raw !== "string" || !raw.includes("proxies:") || !raw.includes("short-id:")) {
    return raw;
  }
  try {
    const content = safeLoad(raw);
    if (!Array.isArray(content.proxies) || content.proxies.length === 0)
      return raw;
  } catch (e) {
    return raw;
  }
  return raw.replace(/short-id:([ \t]*[^#\n,}]*)/g, (matched, value) => {
    const afterTrim = value.trim();
    if (!afterTrim || afterTrim === "") {
      return 'short-id: ""';
    }
    if (/^(['"]).*\1$/.test(afterTrim)) {
      return `short-id: ${afterTrim}`;
    } else if (["null"].includes(afterTrim)) {
      return `short-id: ${afterTrim}`;
    } else {
      return `short-id: "${afterTrim}"`;
    }
  });
}
function HTML() {
  const name = "HTML";
  const test = (raw) => /^<!DOCTYPE html>/.test(raw);
  const parse2 = () => "";
  return { name, test, parse: parse2 };
}
function Base64Encoded() {
  const name = "Base64 Pre-processor";
  const keys = [
    "dm1lc3M",
    // vmess
    "c3NyOi8v",
    // ssr://
    "c29ja3M6Ly",
    // socks://
    "dHJvamFu",
    // trojan
    "c3M6Ly",
    // ss:/
    "c3NkOi8v",
    // ssd://
    "c2hhZG93",
    // shadow
    "aHR0c",
    // htt
    "dmxlc3M=",
    // vless
    "aHlzdGVyaWEy",
    // hysteria2
    "aHkyOi8v",
    // hy2://
    "d2lyZWd1YXJkOi8v",
    // wireguard://
    "d2c6Ly8=",
    // wg://
    "dHVpYzovLw=="
    // tuic://
  ];
  const test = function(raw) {
    return !/^\w+:\/\/\w+/im.test(raw) && keys.some((k) => raw.indexOf(k) !== -1);
  };
  const parse2 = function(raw) {
    const decoded = Base642.decode(raw);
    if (!/^\w+(:\/\/|\s*?=\s*?)\w+/m.test(decoded)) {
      app_default.error(
        `Base64 Pre-processor error: decoded line does not start with protocol`
      );
      return raw;
    }
    return decoded;
  };
  return { name, test, parse: parse2 };
}
function fallbackBase64Encoded() {
  const name = "Fallback Base64 Pre-processor";
  const test = function(raw) {
    return true;
  };
  const parse2 = function(raw) {
    const decoded = Base642.decode(raw);
    if (!/^\w+(:\/\/|\s*?=\s*?)\w+/m.test(decoded)) {
      app_default.error(
        `Fallback Base64 Pre-processor error: decoded line does not start with protocol`
      );
      return raw;
    }
    return decoded;
  };
  return { name, test, parse: parse2 };
}
function Clash() {
  const name = "Clash Pre-processor";
  const test = function(raw) {
    if (!/proxies/.test(raw)) return false;
    const content = safeLoad(raw);
    return content.proxies && Array.isArray(content.proxies);
  };
  const parse2 = function(raw, includeProxies) {
    const afterReplace = normalizeClashYaml(raw);
    const { proxies } = safeLoad(afterReplace);
    return (includeProxies ? "proxies:\n" : "") + proxies.map((p) => {
      return `${includeProxies ? "  - " : ""}${JSON.stringify(
        p
      )}
`;
    }).join("");
  };
  return { name, test, parse: parse2 };
}
function SSD() {
  const name = "SSD Pre-processor";
  const test = function(raw) {
    return raw.indexOf("ssd://") === 0;
  };
  const parse2 = function(raw) {
    const output = [];
    let ssdinfo = JSON.parse(Base642.decode(raw.split("ssd://")[1]));
    let port = ssdinfo.port;
    let method = ssdinfo.encryption;
    let password = ssdinfo.password;
    let servers = ssdinfo.servers;
    for (let i = 0; i < servers.length; i++) {
      let server = servers[i];
      method = server.encryption ? server.encryption : method;
      password = server.password ? server.password : password;
      let userinfo = Base642.encode(method + ":" + password);
      let hostname = server.server;
      port = server.port ? server.port : port;
      let tag = server.remarks ? server.remarks : i;
      let plugin = server.plugin_options ? "/?plugin=" + encodeURIComponent(
        server.plugin + ";" + server.plugin_options
      ) : "";
      output[i] = "ss://" + userinfo + "@" + hostname + ":" + port + plugin + "#" + tag;
    }
    return output.join("\n");
  };
  return { name, test, parse: parse2 };
}
function FullConfig() {
  const name = "Full Config Preprocessor";
  const test = function(raw) {
    return /^(\[server_local\]|\[Proxy\])/gm.test(raw);
  };
  const parse2 = function(raw) {
    const match = raw.match(
      /^\[server_local|Proxy\]([\s\S]+?)^\[.+?\](\r?\n|$)/im
    )?.[1];
    return match || raw;
  };
  return { name, test, parse: parse2 };
}
var preprocessors_default = [
  HTML(),
  Clash(),
  Base64Encoded(),
  SSD(),
  FullConfig(),
  fallbackBase64Encoded()
];

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/utils.js
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
  const data = _2.get(obj, attr);
  return typeof data !== "undefined" && data !== null;
}
function isShadowsocksOverTls(proxy) {
  const normalizedNetwork = typeof proxy?.network === "string" ? proxy.network.trim().toLowerCase() : proxy?.network;
  return proxy?.type === "ss" && proxy?.tls === true && !isPresent2(proxy, "plugin") && (!isPresent2(proxy, "network") || normalizedNetwork === "tcp");
}
function normalizePluginMuxValue(mux) {
  if (typeof mux === "boolean") return Number(mux);
  if (typeof mux === "string") {
    const normalized = mux.trim().toLowerCase();
    if (normalized === "true") return 1;
    if (normalized === "false") return 0;
    if (/^\d+$/.test(normalized)) return parseInt(normalized, 10);
  }
  return mux;
}
function normalizePluginMuxBooleanValue(mux) {
  return Boolean(normalizePluginMuxValue(mux));
}
function supportsShadowsocksV2rayPluginMode(proxy, supportedModes) {
  if (proxy?.type !== "ss" || proxy?.plugin !== "v2ray-plugin") return true;
  const normalizedMode = typeof proxy?.["plugin-opts"]?.mode === "string" ? proxy["plugin-opts"].mode.trim().toLowerCase() : proxy?.["plugin-opts"]?.mode;
  return supportedModes.includes(normalizedMode);
}
function parseWireGuardCIDR(cidr, max) {
  if (cidr == null) return void 0;
  const normalized = `${cidr}`.trim();
  if (!/^\d+$/.test(normalized)) return void 0;
  const parsed = parseInt(normalized, 10);
  if (parsed < 0 || parsed > max) return void 0;
  return parsed;
}
function parseWireGuardInterfaceAddress(value, family) {
  if (value == null) return null;
  const raw = `${value}`.trim();
  if (!raw) return null;
  const [, hostRaw = raw, cidrRaw] = /^(.*?)(?:\/(\d+))?$/.exec(raw) || [];
  const host = `${hostRaw}`.trim().replace(/^\[/, "").replace(/\]$/, "");
  const isIPv4Family = family === "ipv4";
  const isValid = isIPv4Family ? isIPv4(host) : isIPv6(host);
  if (!isValid) return null;
  const max = isIPv4Family ? 32 : 128;
  return {
    address: host,
    cidr: parseWireGuardCIDR(cidrRaw, max)
  };
}
function getWireGuardAddressWithCIDR(proxy = {}, family = "ipv4") {
  const config = family === "ipv6" ? { addressKey: "ipv6", cidrKey: "ipv6-cidr", defaultCIDR: 128 } : { addressKey: "ip", cidrKey: "ip-cidr", defaultCIDR: 32 };
  const parsed = parseWireGuardInterfaceAddress(
    proxy[config.addressKey],
    family
  );
  if (!parsed) return void 0;
  const normalizedCIDR = parseWireGuardCIDR(
    proxy[config.cidrKey],
    config.defaultCIDR
  );
  return `${parsed.address}/${normalizedCIDR ?? parsed.cidr ?? config.defaultCIDR}`;
}
function produceProxyListOutput(list, type, opts = {}) {
  if (type === "internal") return list;
  if (opts.prettyYaml || opts["pretty-yaml"]) {
    return normalizeClashYaml(
      yaml_default.safeDump(
        {
          proxies: list
        },
        {
          lineWidth: -1
        }
      )
    );
  }
  return "proxies:\n" + list.map((proxy) => "  - " + JSON.stringify(proxy) + "\n").join("");
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surge.js
var targetPlatform = "Surge";
var SurgeUnsupportedProxyError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "SurgeUnsupportedProxyError";
  }
};
function unsupported(message) {
  return new SurgeUnsupportedProxyError(message);
}
var ipVersions = {
  dual: "dual",
  ipv4: "v4-only",
  ipv6: "v6-only",
  "ipv4-prefer": "prefer-v4",
  "ipv6-prefer": "prefer-v6"
};
function stripSurgeQuotes(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  const quote = trimmed[0];
  if ((quote === '"' || quote === "'") && trimmed[trimmed.length - 1] === quote) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}
function quoteSurgeValue(value) {
  const text = String(stripSurgeQuotes(value));
  return `"${text}"`;
}
function hasNonBlankValue(value) {
  return value != null && `${value}`.trim().length > 0;
}
function formatSurgeAlpn(alpn) {
  const values = Array.isArray(alpn) ? alpn : stripSurgeQuotes(`${alpn || ""}`).split(",");
  return values.filter((item) => item != null).map((item) => String(stripSurgeQuotes(item)).trim()).filter((item) => item !== "").join(",");
}
function appendAlpn(result, proxy) {
  const alpn = formatSurgeAlpn(proxy.alpn);
  if (alpn) result.append(`,alpn="${alpn}"`);
}
function getShadowTLSAlpn(proxy) {
  return formatSurgeAlpn(proxy?.["plugin-opts"]?.alpn ?? proxy?.alpn);
}
function appendShadowTLS(result, proxy, includeUdpPort = false) {
  if (proxy.plugin !== "shadow-tls" || !proxy["plugin-opts"]) return;
  const password = proxy["plugin-opts"].password;
  const host = proxy["plugin-opts"].host;
  const version = proxy["plugin-opts"].version;
  if (!password) return;
  result.append(`,shadow-tls-password="${password}"`);
  if (host) result.append(`,shadow-tls-sni=${host}`);
  if (version) {
    if (version < 2) {
      throw unsupported(`shadow-tls version ${version} is not supported`);
    }
    result.append(`,shadow-tls-version=${version}`);
  }
  const alpn = getShadowTLSAlpn(proxy);
  if (alpn) result.append(`,alpn="${alpn}"`);
  if (includeUdpPort) {
    result.appendIfPresent(`,udp-port=${proxy["udp-port"]}`, "udp-port");
  }
}
function appendTlsProxyParams(result, proxy, enabled = true) {
  if (!enabled) {
    return;
  }
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(`,sni="${proxy.sni}"`, "sni");
  if (proxy.plugin !== "shadow-tls") {
    appendAlpn(result, proxy);
  }
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  const clientCert = isPresent2(proxy, "keystore-client-cert") ? proxy["keystore-client-cert"] : proxy["client-cert"];
  if (isPresent2(proxy, "keystore-client-cert") || isPresent2(proxy, "client-cert")) {
    result.append(`,client-cert=${quoteSurgeValue(clientCert)}`);
  }
}
function appendSshPrivateKey(result, proxy) {
  const privateKey = isPresent2(proxy, "keystore-private-key") ? proxy["keystore-private-key"] : proxy["private-key"];
  if (isPresent2(proxy, "keystore-private-key") || isPresent2(proxy, "private-key")) {
    result.append(`,private-key=${quoteSurgeValue(privateKey)}`);
  }
}
function warnMaxStreamsIfNeeded(proxy) {
  if (!isPresent2(proxy, "max-streams")) return;
  const maxStreams = Number(stripSurgeQuotes(proxy["max-streams"]));
  if (!Number.isInteger(maxStreams) || maxStreams <= 3) return;
  app_default.warn(
    `Surge ${proxy.type} proxy ${proxy.name}: max-streams=${maxStreams} is greater than 3. Too many streams sharing one TCP connection may hurt performance.`
  );
}
function hasSnellObfs(proxy) {
  return isPresent2(proxy, "obfs-opts.mode") || isPresent2(proxy, "obfs-opts.host") || isPresent2(proxy, "obfs-opts.path");
}
function isUnsupportedSnellV6Obfs(proxy) {
  return Number(proxy.version) === 6 && hasSnellObfs(proxy);
}
function Surge_Producer() {
  const produce2 = (proxy, type, opts = {}) => {
    if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
      throw unsupported(
        `Platform ${targetPlatform} does not support network ${proxy.network} with http upgrade`
      );
    }
    proxy.name = proxy.name.replace(/=|,/g, "");
    if (proxy.ports) {
      proxy.ports = String(proxy.ports);
    }
    switch (proxy.type) {
      case "ss":
        return shadowsocks(proxy);
      case "trojan":
        return trojan(proxy);
      case "vmess":
        return vmess(proxy, opts["include-unsupported-proxy"]);
      case "http":
        return http(proxy);
      case "h2-connect":
        return h2Connect(proxy);
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
      case "trusttunnel":
        return trusttunnel(proxy);
    }
    if (opts["include-unsupported-proxy"] && proxy.type === "wireguard") {
      return wireguard(proxy);
    }
    if (proxy.type === "anytls") {
      if (proxy.network && (!["tcp"].includes(proxy.network) || ["tcp"].includes(proxy.network) && proxy["reality-opts"])) {
        throw unsupported(
          `Platform ${targetPlatform} does not support proxy type ${proxy.type} with network or REALITY`
        );
      }
      return anytls(proxy);
    }
    throw unsupported(
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
    throw unsupported(`cipher ${proxy.cipher} is not supported`);
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
      throw unsupported(`plugin ${proxy.plugin} is not supported`);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy, true);
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
  appendTlsProxyParams(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function anytls(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  appendTlsProxyParams(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  result.appendIfPresent(`,reuse=${proxy["reuse"]}`, "reuse");
  return result.toString();
}
function trusttunnel(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=trust-tunnel,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username="${proxy.username}"`, "username");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  appendHeaders(result, proxy);
  warnMaxStreamsIfNeeded(proxy);
  result.appendIfPresent(
    `,max-streams=${proxy["max-streams"]}`,
    "max-streams"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  appendTlsProxyParams(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  result.appendIfPresent(`,reuse=${proxy["reuse"]}`, "reuse");
  return result.toString();
}
function h2Connect(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=h2-connect,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username="${proxy.username}"`, "username");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  appendHeaders(result, proxy);
  warnMaxStreamsIfNeeded(proxy);
  result.appendIfPresent(
    `,max-streams=${proxy["max-streams"]}`,
    "max-streams"
  );
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  appendTlsProxyParams(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
  const encryptMethod = formatSurgeVmessEncryptMethod(proxy.cipher);
  if (encryptMethod) {
    result.append(`,encrypt-method=${encryptMethod}`);
  }
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
  result.appendIfPresent(`,tls=${proxy.tls}`, "tls");
  appendTlsProxyParams(result, proxy, Boolean(proxy.tls));
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
  appendSshPrivateKey(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function http(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "https" : "http";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,username="${proxy.username}"`, "username");
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  appendHeaders(result, proxy);
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  appendTlsProxyParams(result, proxy, Boolean(proxy.tls));
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
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
  appendTlsProxyParams(result, proxy, Boolean(proxy.tls));
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function appendHeaders(result, proxy) {
  const value = formatHeaders(proxy.headers);
  if (isNotBlank(value)) {
    result.append(`,headers=${quoteSurgeValue(value)}`);
  }
}
function formatHeaders(headers) {
  return formatHeaderMap(headers, ";");
}
function formatHeaderMap(headers, separator) {
  if (!headers || typeof headers !== "object") {
    return "";
  }
  return Object.entries(headers).filter(([key, value]) => isNotBlank(key) && value != null).map(([key, value]) => `${key}:${quoteSurgeValue(value)}`).join(separator);
}
function snell(proxy) {
  if (isUnsupportedSnellV6Obfs(proxy)) {
    app_default.error(
      `Platform ${targetPlatform} does not support Snell version ${proxy.version} with obfs`
    );
    return "";
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,version=${proxy.version}`, "version");
  result.appendIfPresent(`,psk="${proxy.psk}"`, "psk");
  if (Number(proxy.version) === 6) {
    result.appendIfPresent(`,mode=${proxy.mode}`, "mode");
  }
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
  if (hasNonBlankValue(proxy.ports)) {
    result.append(
      `,port-hopping="${String(proxy.ports).replace(/,/g, ";")}"`
    );
  }
  if (hasNonBlankValue(proxy["hop-interval"])) {
    result.append(`,port-hopping-interval=${proxy["hop-interval"]}`);
  }
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  appendTlsProxyParams(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  result.appendIfPresent(
    `,underlying-proxy=${proxy["underlying-proxy"]}`,
    "underlying-proxy"
  );
  return result.toString();
}
function hysteria2(proxy) {
  const obfsPasswordField = {
    salamander: "salamander-password",
    gecko: "gecko-password"
  }[proxy.obfs];
  if (proxy["obfs-password"] && !obfsPasswordField) {
    throw unsupported(`only salamander and gecko obfs are supported`);
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=hysteria2,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  if (hasNonBlankValue(proxy.ports)) {
    result.append(
      `,port-hopping="${String(proxy.ports).replace(/,/g, ";")}"`
    );
  }
  if (hasNonBlankValue(proxy["hop-interval"])) {
    result.append(`,port-hopping-interval=${proxy["hop-interval"]}`);
  }
  if (proxy["obfs-password"] && obfsPasswordField) {
    result.append(`,${obfsPasswordField}="${proxy["obfs-password"]}"`);
  }
  const ip_version = ipVersions[proxy["ip-version"]] || proxy["ip-version"];
  result.appendIfPresent(`,ip-version=${ip_version}`, "ip-version");
  result.appendIfPresent(
    `,no-error-alert=${proxy["no-error-alert"]}`,
    "no-error-alert"
  );
  appendTlsProxyParams(result, proxy);
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
  result.appendIfPresent(`,interface=${proxy["interface"]}`, "interface");
  appendShadowTLS(result, proxy);
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
          const value = formatHeaderMap(headers, "|");
          if (isNotBlank(value)) {
            result.append(`,ws-headers=${quoteSurgeValue(value)}`);
          }
        }
      }
    } else {
      if (includeUnsupportedProxy && ["http"].includes(proxy.network)) {
        app_default.info(
          `Include Unsupported Proxy: network ${proxy.network} -> tcp`
        );
      } else if (["tcp"].includes(proxy.network) && proxy["reality-opts"]) {
        throw unsupported(`reality is unsupported`);
      } else if (!["tcp"].includes(proxy.network)) {
        throw unsupported(`network ${proxy.network} is unsupported`);
      }
    }
  }
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surgemac.js
import { Base64 as Base643 } from "js-base64";

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/clashmeta.js
var ipVersions2 = {
  dual: "dual",
  "v4-only": "ipv4",
  "v6-only": "ipv6",
  "prefer-v4": "ipv4-prefer",
  "prefer-v6": "ipv6-prefer"
};
function warnMihomoUnsupportedEchDns(proxy, echOpts, echOptsPath) {
  if (!isPlainObject(echOpts) || !isNotBlank(echOpts[ECH_DNS_FIELD])) {
    return;
  }
  const queryServerName = isNotBlank(echOpts["query-server-name"]) ? echOpts["query-server-name"] : "\u8FD9\u91CC\u662F query-server-name";
  app_default.warn(
    `mihomo \u4E0D\u652F\u6301\u5728 ech-opts \u4E2D\u914D\u7F6E ECH DNS. \u5982\u9700\u8DDF\u8282\u70B9 ECH \u914D\u7F6E\u4E00\u81F4, \u8BF7\u5728 mihomo \u914D\u7F6E\u6587\u4EF6\u91CC\u8BBE\u7F6E dns["nameserver-policy"]["${queryServerName}"] = ["${echOpts[ECH_DNS_FIELD]}"].`
  );
}
function warnMihomoUnsupportedEchDnsFields(proxy, type) {
  if (type === "internal") {
    return;
  }
  warnMihomoUnsupportedEchDns(proxy, proxy["ech-opts"], "ech-opts");
  warnMihomoUnsupportedEchDns(
    proxy,
    proxy["xhttp-opts"]?.["download-settings"]?.["ech-opts"],
    "xhttp-opts.download-settings.ech-opts"
  );
}
function ClashMeta_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (opts["include-unsupported-proxy"]) return true;
      if (proxy.type === "h2-connect") {
        app_default.error(
          `mihomo does not support HTTP/2 CONNECT proxy type. Proxy ${proxy.name} has been filtered.`
        );
        return false;
      }
      if (hasRootHeaders(proxy) && proxy.type === "trusttunnel") {
        app_default.error(
          `mihomo does not support headers for TrustTunnel proxy ${proxy.name}. Proxy has been filtered.`
        );
        return false;
      }
      if (!supportsShadowsocksV2rayPluginMode(proxy, ["websocket"])) {
        return false;
      } else if (proxy.type === "snell" && !isSupportedMihomoVersion(proxy.version, [1, 2, 3, 4, 5])) {
        return false;
      } else if (hasMihomoShadowTls(proxy) && (!["ss", "snell"].includes(proxy.type) || !isSupportedMihomoVersion(
        getMihomoShadowTlsVersion(proxy),
        [1, 2, 3]
      ))) {
        return false;
      } else if (hasMihomoSnellShadowTlsObfsConflict(proxy)) {
        app_default.error(
          `Platform Mihomo does not support Snell shadow-tls with obfs for proxy ${proxy.name}. Proxy has been filtered.`
        );
        return false;
      } else if (["juicity", "naive"].includes(proxy.type)) {
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
      } else if (!["vless"].includes(proxy.type) && ["xhttp"].includes(proxy.network)) {
        return false;
      }
      return true;
    }).map((proxy) => {
      warnMihomoUnsupportedEchDnsFields(proxy, type2);
      if (proxy["reality-opts"] && !proxy["client-fingerprint"]) {
        proxy["client-fingerprint"] = "chrome";
      }
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
        proxy.cipher = normalizeVmessSecurity(proxy.cipher);
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
        proxy.ip = getWireGuardAddressWithCIDR(proxy, "ipv4");
        proxy.ipv6 = getWireGuardAddressWithCIDR(proxy, "ipv6");
      } else if (proxy.type === "snell" && proxy.version < 3) {
        delete proxy.udp;
      } else if (proxy.type === "vless") {
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
        if (proxy.network === "xhttp" && proxy["xhttp-opts"]?.["download-settings"]) {
          const ds = proxy["xhttp-opts"]["download-settings"];
          if (proxy.tls && ds.tls && proxy["reality-opts"] && !ds["reality-opts"]) {
            ds["reality-opts"] = { "public-key": "" };
          }
        }
      }
      if (isPresent2(proxy, "plugin-opts.mux")) {
        proxy["plugin-opts"].mux = normalizePluginMuxBooleanValue(
          proxy["plugin-opts"].mux
        );
      }
      if (proxy.type === "snell") {
        const shadowTLSOpts = getMihomoShadowTlsOpts(proxy);
        if (shadowTLSOpts) {
          proxy["obfs-opts"] = {
            mode: "shadow-tls",
            host: shadowTLSOpts.host,
            password: shadowTLSOpts.password,
            version: shadowTLSOpts.version
          };
          if (shadowTLSOpts.alpn) {
            proxy["obfs-opts"].alpn = shadowTLSOpts.alpn;
          }
          delete proxy.plugin;
          delete proxy["plugin-opts"];
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
        let host = proxy["h2-opts"]?.host ?? proxy["h2-opts"]?.headers?.host ?? proxy["h2-opts"]?.headers?.Host;
        if (isPresent2(proxy, "h2-opts.host") || isPresent2(proxy, "h2-opts.headers.host") || isPresent2(proxy, "h2-opts.headers.Host")) {
          proxy["h2-opts"].host = Array.isArray(host) ? host : [host];
        }
        if (proxy["h2-opts"]?.headers) {
          delete proxy["h2-opts"].headers.host;
          delete proxy["h2-opts"].headers.Host;
          if (Object.keys(proxy["h2-opts"].headers).length === 0) {
            delete proxy["h2-opts"].headers;
          }
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkOptsKey = `${proxy.network}-opts`;
        proxy[networkOptsKey] = proxy[networkOptsKey] || {};
        if (!proxy[networkOptsKey].path) {
          proxy[networkOptsKey].path = "/";
        }
        normalizeWebSocketEarlyDataPath(proxy[networkOptsKey]);
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["plugin-opts"]["skip-cert-verify"] || proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls",
        "trusttunnel",
        "naive"
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
      delete proxy["ip-cidr"];
      delete proxy["ipv6-cidr"];
      if (type2 !== "internal" || opts["delete-underscore-fields"]) {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
        deleteHttpUpgradeEarlyDataMetadata(
          proxy[`${proxy.network}-opts`]
        );
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
    return produceProxyListOutput(list, type2, opts);
  };
  return { type, produce: produce2 };
}
function hasRootHeaders(proxy) {
  return proxy?.headers && typeof proxy.headers === "object" && Object.keys(proxy.headers).length > 0;
}
function isSupportedMihomoVersion(version, supportedVersions) {
  if (version == null) {
    return true;
  }
  const normalized = typeof version === "string" ? version.trim() : `${version}`;
  if (!normalized) {
    return false;
  }
  const parsed = Number(normalized);
  return Number.isInteger(parsed) && supportedVersions.includes(parsed);
}
function hasMihomoShadowTls(proxy) {
  return Boolean(getMihomoShadowTlsOpts(proxy));
}
function hasMihomoSnellShadowTlsObfsConflict(proxy) {
  return proxy?.type === "snell" && proxy?.plugin === "shadow-tls" && (isPresent2(proxy, "obfs-opts.mode") || isPresent2(proxy, "obfs-opts.host") || isPresent2(proxy, "obfs-opts.path"));
}
function getMihomoShadowTlsVersion(proxy) {
  return getMihomoShadowTlsOpts(proxy)?.version;
}
function getMihomoShadowTlsOpts(proxy) {
  if (proxy?.plugin === "shadow-tls" && proxy?.["plugin-opts"]) {
    return proxy["plugin-opts"];
  }
  if (proxy?.type === "snell" && proxy?.["obfs-opts"]?.mode === "shadow-tls") {
    return proxy["obfs-opts"];
  }
  return void 0;
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
        if (opts.mihomoExternal || proxy._mihomoExternal) {
          return mihomo(proxy, type, opts) || "";
        }
        try {
          return surge_Producer.produce(proxy, type, opts);
        } catch (e) {
          if (opts.useMihomoExternal && e instanceof SurgeUnsupportedProxyError) {
            const output = mihomo(proxy, type, opts) || "";
            if (!output) {
              throw e;
            }
            app_default.log(
              `${proxy.name} is not supported on ${targetPlatform2}, try to use mihomo(SurgeMac - External Proxy Program) instead`
            );
            return output;
          }
          if (e instanceof SurgeUnsupportedProxyError) {
            throw new Error(
              `${e.message}. Surge for macOS \u53EF\u624B\u52A8\u6307\u5B9A\u94FE\u63A5\u53C2\u6570 target=SurgeMac \u6216\u5728 \u540C\u6B65\u914D\u7F6E \u4E2D\u6307\u5B9A SurgeMac \u6765\u542F\u7528 mihomo \u652F\u63F4 Surge \u672C\u8EAB\u4E0D\u652F\u6301\u7684\u534F\u8BAE`
            );
          }
          throw e;
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
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
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
    let localPort = opts?.localPort || proxy._localPort || 65535;
    const ipv6 = ["ipv4", "v4-only"].includes(proxy["ip-version"]) ? false : true;
    const dns = {
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
    };
    const merge = opts?.merge || proxy._merge;
    let result;
    if (merge) {
      const socks55 = {
        name: proxy.name,
        type: "socks5",
        server: "127.0.0.1",
        port: localPort,
        udp: true
      };
      result = surge_Producer.produce(socks55, "socks5", opts);
      opts._merged = opts._merged || {
        name: opts?.mergeName || proxy._mergeName || "mihomo merged",
        exec: opts?.exec || proxy._exec || "/usr/local/bin/mihomo",
        config: {
          // 最后输出的时候加
          // 'mixed-port':,
          ipv6,
          mode: "global",
          dns,
          proxies: [],
          "proxy-groups": [
            {
              name: "GLOBAL",
              type: "fallback",
              proxies: []
            }
          ],
          listeners: []
        }
      };
      const proxyName = `${localPort}`;
      opts._merged.config.listeners.push({
        name: `socks5-${localPort}`,
        type: "socks",
        port: localPort,
        listen: "127.0.0.1",
        udp: true,
        proxy: proxyName
      });
      opts._merged.config["proxy-groups"][0].proxies.push(proxyName);
      opts._merged.config.proxies.push({
        ...clashProxy,
        name: proxyName
      });
      opts._merged.config = {
        ...opts._merged.config,
        ...opts?.config || proxy._config || {}
      };
    } else {
      const external_proxy = {
        name: proxy.name,
        type: "external",
        udp: true,
        exec: opts?.exec || proxy._exec || "/usr/local/bin/mihomo",
        "local-port": localPort,
        args: [
          "-config",
          Base643.encode(
            JSON.stringify({
              "mixed-port": localPort,
              ipv6,
              mode: "global",
              dns,
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
              ],
              ...opts?.config || proxy._config || {}
            })
          )
        ],
        addresses: []
      };
      if (isIP2(proxy.server)) {
        external_proxy.addresses.push(proxy.server);
      } else {
        app_default.warn(
          `Platform ${targetPlatform2}, proxy type ${proxy.type}: addresses should be an IP address, but got ${proxy.server}`
        );
      }
      result = external(external_proxy);
    }
    opts.localPort = localPort - 1;
    return result;
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
      } else if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
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
        proxy.cipher = normalizeClashVmessSecurity(proxy.cipher);
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
        let host = proxy["h2-opts"]?.host ?? proxy["h2-opts"]?.headers?.host ?? proxy["h2-opts"]?.headers?.Host;
        if (isPresent2(proxy, "h2-opts.host") || isPresent2(proxy, "h2-opts.headers.host") || isPresent2(proxy, "h2-opts.headers.Host")) {
          proxy["h2-opts"].host = Array.isArray(host) ? host : [host];
        }
        if (proxy["h2-opts"]?.headers) {
          delete proxy["h2-opts"].headers.host;
          delete proxy["h2-opts"].headers.Host;
          if (Object.keys(proxy["h2-opts"].headers).length === 0) {
            delete proxy["h2-opts"].headers;
          }
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkOptsKey = `${proxy.network}-opts`;
        proxy[networkOptsKey] = proxy[networkOptsKey] || {};
        if (!proxy[networkOptsKey].path) {
          proxy[networkOptsKey].path = "/";
        }
        normalizeWebSocketEarlyDataPath(proxy[networkOptsKey]);
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["plugin-opts"]["skip-cert-verify"] || proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls",
        "trusttunnel",
        "naive"
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
      delete proxy["ip-cidr"];
      delete proxy["ipv6-cidr"];
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
        deleteHttpUpgradeEarlyDataMetadata(
          proxy[`${proxy.network}-opts`]
        );
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      return proxy;
    });
    return produceProxyListOutput(list, type2, opts);
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/stash.js
function Stash_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = proxies.filter((proxy) => {
      if (opts["include-unsupported-proxy"]) return true;
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
        "juicity",
        "anytls",
        "tailscale",
        "trusttunnel"
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
      ].includes(proxy.cipher) || proxy.type === "snell" && proxy.version >= 4) {
        return false;
      } else if (!supportsShadowsocksV2rayPluginMode(proxy, ["websocket"])) {
        return false;
      } else if (["vless"].includes(proxy.type) && proxy["reality-opts"] && proxy.network && !["tcp"].includes(proxy.network)) {
        return false;
      } else if (["anytls"].includes(proxy.type) && proxy.network && (!["tcp"].includes(proxy.network) || ["tcp"].includes(proxy.network) && proxy["reality-opts"])) {
        return false;
      } else if (["xhttp"].includes(proxy.network)) {
        return false;
      } else if (proxy.encryption && proxy.encryption !== "none" && ["vless"].includes(proxy.type)) {
        return false;
      } else if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
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
        proxy.cipher = normalizeClashVmessSecurity(proxy.cipher);
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
        let host = proxy["h2-opts"]?.host ?? proxy["h2-opts"]?.headers?.host ?? proxy["h2-opts"]?.headers?.Host;
        if (isPresent2(proxy, "h2-opts.host") || isPresent2(proxy, "h2-opts.headers.host") || isPresent2(proxy, "h2-opts.headers.Host")) {
          proxy["h2-opts"].host = Array.isArray(host) ? host : [host];
        }
        if (proxy["h2-opts"]?.headers) {
          delete proxy["h2-opts"].headers.host;
          delete proxy["h2-opts"].headers.Host;
          if (Object.keys(proxy["h2-opts"].headers).length === 0) {
            delete proxy["h2-opts"].headers;
          }
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkOptsKey = `${proxy.network}-opts`;
        proxy[networkOptsKey] = proxy[networkOptsKey] || {};
        if (!proxy[networkOptsKey].path) {
          proxy[networkOptsKey].path = "/";
        }
        normalizeWebSocketEarlyDataPath(proxy[networkOptsKey]);
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["plugin-opts"]["skip-cert-verify"] || proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls",
        "trusttunnel",
        "naive"
      ].includes(proxy.type)) {
        delete proxy.tls;
      }
      if (proxy["tls-fingerprint"]) {
        proxy["server-cert-fingerprint"] = proxy["tls-fingerprint"];
      }
      delete proxy["tls-fingerprint"];
      if (proxy["underlying-proxy"]) {
        proxy["dialer-proxy"] = proxy["underlying-proxy"];
      }
      delete proxy["underlying-proxy"];
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
      delete proxy["ip-cidr"];
      delete proxy["ipv6-cidr"];
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
        deleteHttpUpgradeEarlyDataMetadata(
          proxy[`${proxy.network}-opts`]
        );
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      return proxy;
    });
    return produceProxyListOutput(list, type2, opts);
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
    if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
      throw new Error(
        `Platform ${targetPlatform3} does not support network ${proxy.network} with http upgrade`
      );
    }
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
    if (proxy.type === "anytls") {
      if (proxy.network && !["tcp"].includes(proxy.network)) {
        throw new Error(
          `Platform ${targetPlatform3} does not support proxy type ${proxy.type} with network ${proxy.network}`
        );
      }
      return anytls2(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform3} does not support proxy type: ${proxy.type}`
    );
  };
  return { produce: produce2 };
}
function appendTlsProfile(result, proxy) {
  const tlsProfile = getLoonTlsProfile(proxy);
  if (tlsProfile) result.append(`,tls-profile=${tlsProfile}`);
}
function appendAlpn2(result, proxy) {
  const alpn = getLoonAlpn(proxy);
  if (alpn) result.append(`,alpn="${alpn}"`);
}
function getLoonShadowTLSAlpn(proxy) {
  const values = proxy?.["plugin-opts"]?.alpn ?? proxy?.alpn;
  const normalized = Array.isArray(values) ? values : `${values || ""}`.split(",");
  return normalized.map((item) => `${item}`.trim()).filter((item) => item !== "").join(",");
}
function appendShadowTLS2(result, proxy) {
  if (proxy.plugin !== "shadow-tls" || !proxy["plugin-opts"]) return;
  const password = proxy["plugin-opts"].password;
  const host = proxy["plugin-opts"].host;
  const version = proxy["plugin-opts"].version;
  if (!password) return;
  result.append(`,shadow-tls-password=${password}`);
  if (host) result.append(`,shadow-tls-sni=${host}`);
  if (version) {
    if (version < 2) {
      throw new Error(`shadow-tls version ${version} is not supported`);
    }
    result.append(`,shadow-tls-version=${version}`);
  }
  appendTlsProfile(result, proxy);
  const alpn = getLoonShadowTLSAlpn(proxy);
  if (alpn) result.append(`,alpn="${alpn}"`);
  result.appendIfPresent(`,udp-port=${proxy["udp-port"]}`, "udp-port");
}
function appendReality(result, proxy) {
  result.appendIfPresent(`,sni=${proxy.sni}`, "sni");
  result.appendIfPresent(
    `,public-key="${proxy["reality-opts"]["public-key"]}"`,
    "reality-opts.public-key"
  );
  result.appendIfPresent(
    `,short-id=${proxy["reality-opts"]["short-id"]}`,
    "reality-opts.short-id"
  );
}
function getLoonAlpn(proxy) {
  const values = Array.isArray(proxy.alpn) ? proxy.alpn : `${proxy.alpn || ""}`.split(",");
  return values.map((item) => `${item}`.trim()).filter((item) => item !== "").join(",");
}
function getLoonTlsProfile(proxy) {
  const tlsProfile = `${proxy._loon_tls_profile || ""}`.trim();
  if (["default", "chrome", "ios18", "ios26"].includes(tlsProfile)) {
    return tlsProfile;
  }
  switch (`${proxy["client-fingerprint"] || ""}`.trim()) {
    case "chrome":
      return "chrome";
    case "ios":
      return "ios26";
  }
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
  appendShadowTLS2(result, proxy);
  if (proxy["udp-over-tcp"]) {
    if (proxy["udp-over-tcp-version"] === 2) {
      if (proxy.plugin === "obfs") {
        app_default.error(
          `Platform ${targetPlatform3} shadowsocks udp-over-tcp does not support obfs`
        );
      } else {
        result.append(`,udp-over-tcp=true`);
      }
    } else {
      app_default.error(
        `Platform ${targetPlatform3} shadowsocks only supports udp-over-tcp-version 2`
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
  appendShadowTLS2(result, proxy);
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
  const isReality = !!proxy["reality-opts"];
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
  appendTlsProfile(result, proxy);
  appendAlpn2(result, proxy);
  if (isReality) {
    appendReality(result, proxy);
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
function anytls2(proxy) {
  const isReality = !!proxy["reality-opts"];
  const result = new Result(proxy);
  result.append(
    `${proxy.name}=anytls,${proxy.server},${proxy.port},"${proxy.password}"`
  );
  for (const key of [
    // 'idle-session-check-interval',
    "idle-session-timeout",
    // 'min-idle-session',
    "max-stream-count"
  ]) {
    if (isPresent2(proxy, key) && Number.isInteger(proxy[key])) {
      result.append(`,${key}=${proxy[key]}`);
    }
  }
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
  appendTlsProfile(result, proxy);
  appendAlpn2(result, proxy);
  if (isReality) {
    appendReality(result, proxy);
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
function vmess2(proxy) {
  const isReality = !!proxy["reality-opts"];
  const security = formatLoonVmessSecurity(proxy.cipher);
  const result = new Result(proxy);
  result.append(
    `${proxy.name}=vmess,${proxy.server},${proxy.port},${security},"${proxy.uuid}"`
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
  if (proxy.tls || isReality) {
    appendTlsProfile(result, proxy);
    appendAlpn2(result, proxy);
  }
  if (isReality) {
    appendReality(result, proxy);
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
  if (proxy.encryption && proxy.encryption !== "none")
    throw new Error(`VLESS encryption is not supported`);
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
  if (proxy.tls || isReality || isXtls) {
    appendTlsProfile(result, proxy);
    appendAlpn2(result, proxy);
  }
  if (isXtls) {
    result.appendIfPresent(`,flow=${proxy.flow}`, "flow");
  }
  if (isReality) {
    appendReality(result, proxy);
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
  if (proxy.tls) {
    appendTlsProfile(result, proxy);
    appendAlpn2(result, proxy);
  }
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
  if (proxy.tls) {
    appendTlsProfile(result, proxy);
    appendAlpn2(result, proxy);
  }
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
  if (isPresent2(proxy, "ports") && `${proxy.ports}`.trim().length > 0) {
    result.append(`,server-ports="${proxy.ports}"`);
  }
  if (isPresent2(proxy, "hop-interval") && `${proxy["hop-interval"]}`.trim().length > 0) {
    result.append(`,hop-interval=${proxy["hop-interval"]}`);
  }
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
  appendTlsProfile(result, proxy);
  appendAlpn2(result, proxy);
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
import { Base64 as Base644 } from "js-base64";
function toStringHeaderMap(headers, { excludeHost = false } = {}) {
  if (!isPlainObject(headers)) {
    return void 0;
  }
  const parsedHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value !== "string") {
      continue;
    }
    if (excludeHost && /^host$/i.test(key)) {
      continue;
    }
    parsedHeaders[key] = value;
  }
  return Object.keys(parsedHeaders).length > 0 ? parsedHeaders : void 0;
}
function getHttpUpgradeEarlyData(transportOpts, path) {
  const httpUpgradeEd = getSafeEarlyDataValue(
    transportOpts?.["_v2ray-http-upgrade-ed"]
  );
  if (httpUpgradeEd !== "") return httpUpgradeEd;
  const pathEd = getSafeEarlyDataValue(
    extractPathQueryParam(path || "/", "ed").value
  );
  return pathEd !== "" ? pathEd : 2560;
}
function setHttpUpgradeEarlyDataPath(path, transportOpts) {
  if (!transportOpts?.["v2ray-http-upgrade-fast-open"]) {
    return path;
  }
  return setPathQueryParam(
    path || "/",
    "ed",
    getHttpUpgradeEarlyData(transportOpts, path)
  );
}
function setWebSocketEarlyDataPath(path, transportOpts) {
  const earlyDataValue = transportOpts?.["max-early-data"];
  const earlyData = getSafeEarlyDataValue(earlyDataValue);
  if (earlyData === "") {
    if (earlyDataValue != null && `${earlyDataValue}` !== "") {
      return path == null ? path : extractPathQueryParam(path, "ed").path;
    }
    return path;
  }
  const earlyDataHeaderName = transportOpts?.["early-data-header-name"];
  if (earlyDataHeaderName && earlyDataHeaderName !== "Sec-WebSocket-Protocol") {
    return path == null ? path : extractPathQueryParam(path, "ed").path;
  }
  return setPathQueryParam(path || "/", "ed", earlyData);
}
function getSafeEarlyDataValue(value) {
  if (value == null || `${value}` === "") return "";
  return parseSafeIntegerValue(value) == null ? "" : `${value}`;
}
function parseIntegerLikeValue(value) {
  return normalizeXhttpIntegerValue(value);
}
function getSerializableXhttpRangeValue(value) {
  return normalizeXhttpNonNegativeRange(value);
}
function warnEchDefaultDns({
  defaultDns,
  dnsFieldPath,
  echOptsPath,
  proxyName,
  queryServerName
}) {
  const proxyLabel = proxyName || "\u672A\u547D\u540D\u8282\u70B9";
  app_default.warn(
    `URI ECH: \u8282\u70B9 "${proxyLabel}" \u7684 ${echOptsPath} \u5DF2\u5F00\u542F\u4E14\u8BBE\u7F6E query-server-name="${queryServerName}", \u4F46\u672A\u8BBE\u7F6E ${dnsFieldPath}; \u5DF2\u4F7F\u7528\u9ED8\u8BA4 DNS ${defaultDns}. \u5982\u9700\u81EA\u5B9A\u4E49, \u8BF7\u8BBE\u7F6E ${dnsFieldPath}.`
  );
}
function getTransportHost(network, transportOpts = {}) {
  if (network === "h2") {
    return transportOpts.host ?? transportOpts.headers?.host ?? transportOpts.headers?.Host;
  }
  if (network === "xhttp") {
    return transportOpts.host ?? transportOpts.headers?.Host ?? transportOpts.headers?.host;
  }
  return transportOpts.headers?.Host ?? transportOpts.headers?.host ?? transportOpts.host;
}
function mapReuseSettingsToXmux(reuseSettings) {
  if (!isPlainObject(reuseSettings)) {
    return void 0;
  }
  const xmux = {};
  const reuseFieldMap = {
    "max-connections": "maxConnections",
    "max-concurrency": "maxConcurrency",
    "c-max-reuse-times": "cMaxReuseTimes",
    "h-max-request-times": "hMaxRequestTimes",
    "h-max-reusable-secs": "hMaxReusableSecs"
  };
  for (const [sourceKey, targetKey] of Object.entries(reuseFieldMap)) {
    const normalizedValue = normalizeXhttpNonNegativeRange(
      reuseSettings[sourceKey]
    );
    if (normalizedValue != null) {
      xmux[targetKey] = typeof normalizedValue === "number" ? `${normalizedValue}` : normalizedValue;
    }
  }
  const hKeepAlivePeriod = parseIntegerLikeValue(
    reuseSettings["h-keep-alive-period"]
  );
  if (hKeepAlivePeriod != null) {
    xmux.hKeepAlivePeriod = hKeepAlivePeriod;
  }
  return Object.keys(xmux).length > 0 ? xmux : void 0;
}
function applyStructuredXhttpExtraFields(target, xhttpOpts, { excludeHostHeader = true, xmuxTarget = "root" } = {}) {
  if (!isPlainObject(target) || !isPlainObject(xhttpOpts)) {
    return;
  }
  const headers = toStringHeaderMap(xhttpOpts.headers, {
    excludeHost: excludeHostHeader
  });
  if (headers) {
    target.headers = headers;
  }
  if (xhttpOpts["no-grpc-header"] === true) {
    target.noGRPCHeader = true;
  }
  if (xhttpOpts["x-padding-bytes"]) {
    target.xPaddingBytes = xhttpOpts["x-padding-bytes"];
  }
  if (xhttpOpts["x-padding-obfs-mode"] === true) {
    target.xPaddingObfsMode = true;
  }
  if (xhttpOpts["x-padding-key"]) {
    target.xPaddingKey = xhttpOpts["x-padding-key"];
  }
  if (xhttpOpts["x-padding-header"]) {
    target.xPaddingHeader = xhttpOpts["x-padding-header"];
  }
  if (xhttpOpts["x-padding-placement"]) {
    target.xPaddingPlacement = xhttpOpts["x-padding-placement"];
  }
  if (xhttpOpts["x-padding-method"]) {
    target.xPaddingMethod = xhttpOpts["x-padding-method"];
  }
  if (xhttpOpts["uplink-http-method"]) {
    target.uplinkHTTPMethod = xhttpOpts["uplink-http-method"];
  }
  if (xhttpOpts["session-placement"]) {
    target.sessionIDPlacement = xhttpOpts["session-placement"];
  }
  if (xhttpOpts["session-key"]) {
    target.sessionIDKey = xhttpOpts["session-key"];
  }
  if (typeof xhttpOpts["session-table"] === "string") {
    target.sessionIDTable = xhttpOpts["session-table"];
  }
  if (xhttpOpts["session-length"] != null) {
    const sessionIDLength = normalizeXhttpStrictPositiveRangeValue(
      xhttpOpts["session-length"]
    );
    if (sessionIDLength != null) {
      target.sessionIDLength = sessionIDLength;
    }
  }
  if (xhttpOpts["seq-placement"]) {
    target.seqPlacement = xhttpOpts["seq-placement"];
  }
  if (xhttpOpts["seq-key"]) {
    target.seqKey = xhttpOpts["seq-key"];
  }
  if (xhttpOpts["uplink-data-placement"]) {
    target.uplinkDataPlacement = xhttpOpts["uplink-data-placement"];
  }
  if (xhttpOpts["uplink-data-key"]) {
    target.uplinkDataKey = xhttpOpts["uplink-data-key"];
  }
  const uplinkChunkSize = getSerializableXhttpRangeValue(
    xhttpOpts["uplink-chunk-size"]
  );
  if (uplinkChunkSize != null) {
    target.uplinkChunkSize = uplinkChunkSize;
  }
  if (xhttpOpts["sc-max-each-post-bytes"] != null) {
    const scMaxEachPostBytes = normalizeXhttpStrictPositiveRangeValue(
      xhttpOpts["sc-max-each-post-bytes"]
    );
    if (scMaxEachPostBytes != null) {
      target.scMaxEachPostBytes = scMaxEachPostBytes;
    }
  }
  if (xhttpOpts["sc-min-posts-interval-ms"] != null) {
    const scMinPostsIntervalMs = normalizeXhttpPositiveRange(
      xhttpOpts["sc-min-posts-interval-ms"]
    );
    if (scMinPostsIntervalMs != null) {
      target.scMinPostsIntervalMs = scMinPostsIntervalMs;
    }
  }
  const xmux = mapReuseSettingsToXmux(xhttpOpts["reuse-settings"]);
  if (xmux) {
    if (xmuxTarget === "extra") {
      target.extra = {
        ...isPlainObject(target.extra) ? target.extra : {},
        xmux
      };
    } else {
      target.xmux = xmux;
    }
  }
}
function buildXhttpDownloadSettings(downloadSettings, outerXhttpOpts = {}, proxy = {}) {
  if (!isPlainObject(downloadSettings)) {
    return void 0;
  }
  const explicitNetwork = typeof downloadSettings.network === "string" ? downloadSettings.network.toLowerCase() : "";
  const normalizedNetwork = explicitNetwork === "xhttp" || explicitNetwork === "splithttp" ? "xhttp" : void 0;
  const result = {};
  if (downloadSettings.server) {
    result.address = downloadSettings.server;
  }
  const parsedPort = normalizeXhttpIntegerValue(downloadSettings.port, {
    allowNegative: false
  });
  if (parsedPort != null) {
    result.port = parsedPort;
  }
  const realityOpts = isPlainObject(downloadSettings["reality-opts"]) ? downloadSettings["reality-opts"] : void 0;
  if (realityOpts) {
    result.security = "reality";
  } else if (downloadSettings.tls) {
    result.security = "tls";
  }
  const tlsSettings = {};
  if (downloadSettings.servername) {
    tlsSettings.serverName = downloadSettings.servername;
  }
  if (downloadSettings["client-fingerprint"]) {
    tlsSettings.fingerprint = downloadSettings["client-fingerprint"];
  }
  if (downloadSettings["skip-cert-verify"]) {
    tlsSettings.allowInsecure = true;
  }
  if (downloadSettings.alpn) {
    tlsSettings.alpn = Array.isArray(downloadSettings.alpn) ? downloadSettings.alpn : [downloadSettings.alpn];
  }
  const echFields = buildXrayEchFieldsFromMihomo(
    downloadSettings["ech-opts"],
    void 0,
    {
      dnsFieldPath: "xhttp-opts.download-settings.ech-opts._dns",
      warnDefaultDns: (context) => warnEchDefaultDns({
        ...context,
        echOptsPath: "xhttp-opts.download-settings.ech-opts",
        proxyName: proxy.name
      })
    }
  );
  if (echFields.echConfigList) {
    tlsSettings.echConfigList = echFields.echConfigList;
  }
  if (echFields.echForceQuery) {
    tlsSettings.echForceQuery = echFields.echForceQuery;
  }
  if (echFields.echSockopt) {
    tlsSettings.echSockopt = cloneXhttpExtraValue(echFields.echSockopt);
  }
  if (Object.keys(tlsSettings).length > 0) {
    result.tlsSettings = tlsSettings;
  }
  if (realityOpts) {
    const realitySettings = {};
    if (downloadSettings.servername) {
      realitySettings.serverName = downloadSettings.servername;
    }
    if (downloadSettings["client-fingerprint"]) {
      realitySettings.fingerprint = downloadSettings["client-fingerprint"];
    }
    if (realityOpts["public-key"]) {
      realitySettings.publicKey = realityOpts["public-key"];
    }
    if (realityOpts["short-id"]) {
      realitySettings.shortId = realityOpts["short-id"];
    }
    if (Object.keys(realitySettings).length > 0) {
      result.realitySettings = realitySettings;
    }
  }
  const xhttpSettings = {};
  const dsPath = downloadSettings.path ?? outerXhttpOpts.path;
  if (dsPath) {
    xhttpSettings.path = dsPath;
  }
  const downloadHost = getTransportHost("xhttp", downloadSettings) ?? getTransportHost("xhttp", outerXhttpOpts);
  if (downloadHost) {
    xhttpSettings.host = downloadHost;
  }
  const mode = downloadSettings.mode ?? outerXhttpOpts.mode;
  if (mode) {
    xhttpSettings.mode = mode;
  }
  applyStructuredXhttpExtraFields(xhttpSettings, downloadSettings, {
    excludeHostHeader: true,
    xmuxTarget: "extra"
  });
  if (Object.keys(xhttpSettings).length > 0) {
    result.xhttpSettings = xhttpSettings;
  }
  if (Object.keys(result).length === 0 && normalizedNetwork == null) {
    return void 0;
  }
  return {
    ...result.address != null ? { address: result.address } : {},
    network: normalizedNetwork || "xhttp",
    ...result.port != null ? { port: result.port } : {},
    ...result.security != null ? { security: result.security } : {},
    ...result.tlsSettings != null ? { tlsSettings: result.tlsSettings } : {},
    ...result.realitySettings != null ? { realitySettings: result.realitySettings } : {},
    ...result.xhttpSettings != null ? { xhttpSettings: result.xhttpSettings } : {}
  };
}
function buildStructuredVlessExtraObject(proxy) {
  const xhttpOpts = proxy["xhttp-opts"] || {};
  const extra = {};
  applyStructuredXhttpExtraFields(extra, xhttpOpts, {
    excludeHostHeader: true,
    xmuxTarget: "root"
  });
  const downloadSettings = buildXhttpDownloadSettings(
    xhttpOpts["download-settings"],
    xhttpOpts,
    proxy
  );
  if (downloadSettings) {
    extra.downloadSettings = downloadSettings;
  }
  return Object.keys(extra).length > 0 ? extra : void 0;
}
function cloneXhttpExtraValue(value) {
  if (Array.isArray(value)) {
    return value.map(cloneXhttpExtraValue);
  }
  if (isPlainObject(value)) {
    const clonedValue = {};
    for (const [key, entryValue] of Object.entries(value)) {
      clonedValue[key] = cloneXhttpExtraValue(entryValue);
    }
    return clonedValue;
  }
  return value;
}
function mergeUnsupportedXhttpExtraValue(baseValue, unsupportedValue) {
  if (baseValue == null) {
    return cloneXhttpExtraValue(unsupportedValue);
  }
  if (Array.isArray(baseValue) || Array.isArray(unsupportedValue)) {
    return cloneXhttpExtraValue(baseValue);
  }
  if (isPlainObject(baseValue) && isPlainObject(unsupportedValue)) {
    return mergeUnsupportedXhttpExtraObject(baseValue, unsupportedValue);
  }
  return cloneXhttpExtraValue(baseValue);
}
function mergeUnsupportedXhttpExtraObject(baseObject, unsupportedObject) {
  const mergedExtra = isPlainObject(baseObject) ? cloneXhttpExtraValue(baseObject) : {};
  if (!isPlainObject(unsupportedObject)) {
    return mergedExtra;
  }
  for (const [key, value] of Object.entries(unsupportedObject)) {
    if (!Object.prototype.hasOwnProperty.call(mergedExtra, key)) {
      mergedExtra[key] = cloneXhttpExtraValue(value);
      continue;
    }
    mergedExtra[key] = mergeUnsupportedXhttpExtraValue(
      mergedExtra[key],
      value
    );
  }
  return mergedExtra;
}
function getExplicitExtraOverride(proxy) {
  if (typeof proxy._extra === "string") {
    return proxy._extra;
  }
  if (isPlainObject(proxy._extra)) {
    return JSON.stringify(proxy._extra);
  }
  return void 0;
}
function buildVlessExtra(proxy) {
  const explicitExtraOverride = getExplicitExtraOverride(proxy);
  if (explicitExtraOverride != null) {
    return explicitExtraOverride;
  }
  if (proxy.network !== "xhttp") {
    return proxy._extra || "";
  }
  const structuredExtra = buildStructuredVlessExtraObject(proxy);
  const mergedExtra = mergeUnsupportedXhttpExtraObject(
    structuredExtra,
    proxy._extra_unsupported
  );
  return Object.keys(mergedExtra).length > 0 ? JSON.stringify(mergedExtra) : "";
}
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
  let h2 = "";
  if (proxy._h2) {
    h2 = `&h2=1`;
  }
  let pcs = "";
  if (proxy["tls-fingerprint"]) {
    pcs = `&pcs=${encodeURIComponent(proxy["tls-fingerprint"])}`;
  }
  let ech = "";
  const echConfigList = buildXrayEchConfigListFromMihomo(
    proxy["ech-opts"],
    proxy._echConfigList,
    {
      dnsFieldPath: "ech-opts._dns",
      warnDefaultDns: (context) => warnEchDefaultDns({
        ...context,
        echOptsPath: "ech-opts",
        proxyName: proxy.name
      })
    }
  );
  if (echConfigList) {
    ech = `&ech=${encodeURIComponent(echConfigList)}`;
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
  const extraPayload = buildVlessExtra(proxy);
  if (extraPayload) {
    extra = `&extra=${encodeURIComponent(extraPayload)}`;
  }
  let mode = "";
  if (["xhttp"].includes(proxy.network) && proxy[`${proxy.network}-opts`]?.mode) {
    mode = `&mode=${encodeURIComponent(
      proxy[`${proxy.network}-opts`].mode
    )}`;
  } else if (proxy._mode) {
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
  } else if (proxy.network === "http") {
    vlessType = "tcp";
  } else if (proxy.network === "h2") {
    vlessType = "http";
  }
  let vlessTransport = `&type=${encodeURIComponent(vlessType)}`;
  if (proxy.network === "http") {
    vlessTransport += "&headerType=http";
  }
  if (["grpc"].includes(proxy.network)) {
    vlessTransport += `&mode=${encodeURIComponent(
      proxy[`${proxy.network}-opts`]?.["_grpc-type"] || "gun"
    )}`;
    const authority = proxy[`${proxy.network}-opts`]?.["_grpc-authority"];
    if (authority) {
      vlessTransport += `&authority=${encodeURIComponent(authority)}`;
    }
  }
  const transportOpts = proxy[`${proxy.network}-opts`] || {};
  const isVlessHttpUpgrade = proxy.network === "ws" && transportOpts?.["v2ray-http-upgrade"];
  let vlessTransportServiceName = transportOpts?.[`${proxy.network}-service-name`];
  let vlessTransportPath = transportOpts?.path;
  let vlessTransportHost = getTransportHost(proxy.network, transportOpts);
  const vlessWsEarlyData = getSafeEarlyDataValue(
    proxy["ws-opts"]?.["max-early-data"]
  );
  if (Array.isArray(vlessTransportPath)) {
    vlessTransportPath = vlessTransportPath[0];
  }
  if (isVlessHttpUpgrade && transportOpts?.["v2ray-http-upgrade-fast-open"]) {
    vlessTransportPath = setHttpUpgradeEarlyDataPath(
      vlessTransportPath,
      transportOpts
    );
  } else if (proxy.network === "ws" && proxy["ws-opts"]?.["max-early-data"] != null && vlessTransportPath) {
    vlessTransportPath = extractPathQueryParam(
      vlessTransportPath,
      "ed"
    ).path;
  }
  if (vlessTransportPath) {
    vlessTransport += `&path=${encodeURIComponent(vlessTransportPath)}`;
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
  if (proxy.network === "http" && proxy["http-opts"]?.method) {
    vlessTransport += `&method=${encodeURIComponent(
      proxy["http-opts"].method
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
  if (proxy.network === "ws" && !isVlessHttpUpgrade && vlessWsEarlyData !== "") {
    vlessTransport += `&ed=${encodeURIComponent(vlessWsEarlyData)}`;
  }
  const earlyDataHeaderName = proxy["ws-opts"]?.["early-data-header-name"];
  if (earlyDataHeaderName && (isVlessHttpUpgrade || proxy["ws-opts"]?.["max-early-data"] == null || earlyDataHeaderName !== "Sec-WebSocket-Protocol")) {
    vlessTransport += `&eh=${encodeURIComponent(earlyDataHeaderName)}`;
  }
  let packetEncoding = "";
  let canonicalPacketEncoding;
  if (proxy["packet-encoding"] != null) {
    canonicalPacketEncoding = `${proxy["packet-encoding"]}`.trim().toLowerCase();
  } else if (proxy.xudp) {
    canonicalPacketEncoding = "xudp";
  } else if (proxy["packet-addr"]) {
    canonicalPacketEncoding = "packetaddr";
  } else if (proxy.udp === true) {
    canonicalPacketEncoding = "";
  }
  switch (canonicalPacketEncoding) {
    case "":
      packetEncoding = "&packetEncoding=none";
      break;
    case "packetaddr":
      packetEncoding = "&packetEncoding=packet";
      break;
    case "xudp":
      packetEncoding = "&packetEncoding=xudp";
      break;
  }
  return `vless://${proxy.uuid}@${proxy.server}:${proxy.port}?security=${encodeURIComponent(
    security
  )}${vlessTransport}${packetEncoding}${alpn}${allowInsecure}${pcs}${ech}${h2}${sni}${fp}${flow}${sid}${spx}${pbk}${mode}${extra}${pqv}${encryption}#${encodeURIComponent(
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
    if ([
      "tuic",
      "hysteria",
      "hysteria2",
      "juicity",
      "trusttunnel"
    ].includes(proxy.type)) {
      delete proxy.tls;
    }
    if (!["vmess"].includes(proxy.type) && proxy.server && isIPv6(proxy.server)) {
      proxy.server = `[${proxy.server}]`;
    }
    switch (proxy.type) {
      case "socks5":
        result = `socks://${encodeURIComponent(
          Base644.encode(
            `${proxy.username ?? ""}:${proxy.password ?? ""}`
          )
        )}@${proxy.server}:${proxy.port}#${proxy.name}`;
        break;
      case "ss":
        const userinfo = `${proxy.cipher}:${proxy.password}`;
        result = `ss://${proxy.cipher?.startsWith("2022-blake3-") ? `${encodeURIComponent(
          proxy.cipher
        )}:${encodeURIComponent(proxy.password)}` : Base644.encode(userinfo)}@${proxy.server}:${proxy.port}${proxy.plugin ? "/" : ""}`;
        let query = "";
        if (proxy.plugin) {
          query += "&plugin=";
          const opts = proxy["plugin-opts"];
          switch (proxy.plugin) {
            case "obfs":
              query += encodeURIComponent(
                `simple-obfs;obfs=${opts.mode}${opts.host ? ";obfs-host=" + opts.host : ""}`
              );
              break;
            case "v2ray-plugin":
              const mux = normalizePluginMuxValue(opts.mux);
              query += encodeURIComponent(
                `v2ray-plugin;obfs=${opts.mode};mode=${opts.mode}${opts.host ? ";obfs-host=" + opts.host : ""}${opts.host ? ";host=" + opts.host : ""}${opts.path ? ";path=" + opts.path : ""}${opts.tls ? ";tls" : ""}${opts.sni ? ";sni=" + opts.sni : ""}${opts["skip-cert-verify"] ? ";skip-cert-verify=" + opts["skip-cert-verify"] : ""}${mux != null ? ";mux=" + mux : ""}`
              );
              break;
            case "shadow-tls":
              query += encodeURIComponent(
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
          query += "&uot=1";
        }
        if (proxy.tfo) {
          query += "&tfo=1";
        }
        let ssTransport = "";
        if (proxy.network) {
          let ssType = proxy.network;
          if (proxy.network === "ws" && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
            ssType = "httpupgrade";
          }
          ssTransport = `&type=${encodeURIComponent(ssType)}`;
          if (["grpc"].includes(proxy.network)) {
            let ssTransportServiceName = proxy[`${proxy.network}-opts`]?.[`${proxy.network}-service-name`];
            let ssTransportAuthority = proxy[`${proxy.network}-opts`]?.["_grpc-authority"];
            if (ssTransportServiceName) {
              ssTransport += `&serviceName=${encodeURIComponent(
                ssTransportServiceName
              )}`;
            }
            if (ssTransportAuthority) {
              ssTransport += `&authority=${encodeURIComponent(
                ssTransportAuthority
              )}`;
            }
            ssTransport += `&mode=${encodeURIComponent(
              proxy[`${proxy.network}-opts`]?.["_grpc-type"] || "gun"
            )}`;
          }
          const ssTransportOpts = proxy[`${proxy.network}-opts`] || {};
          const isSsHttpUpgrade = proxy.network === "ws" && ssTransportOpts?.["v2ray-http-upgrade"];
          let ssTransportPath = ssTransportOpts?.path;
          let ssTransportHost = ssTransportOpts?.headers?.Host;
          if (Array.isArray(ssTransportPath)) {
            ssTransportPath = ssTransportPath[0];
          }
          if (isSsHttpUpgrade) {
            ssTransportPath = setHttpUpgradeEarlyDataPath(
              ssTransportPath,
              ssTransportOpts
            );
          } else if (proxy.network === "ws") {
            ssTransportPath = setWebSocketEarlyDataPath(
              ssTransportPath,
              ssTransportOpts
            );
          }
          if (ssTransportPath) {
            ssTransport += `&path=${encodeURIComponent(
              ssTransportPath
            )}`;
          }
          if (ssTransportHost) {
            ssTransport += `&host=${encodeURIComponent(
              Array.isArray(ssTransportHost) ? ssTransportHost[0] : ssTransportHost
            )}`;
          }
        }
        let ssFp = "";
        if (proxy["client-fingerprint"]) {
          ssFp = `&fp=${encodeURIComponent(
            proxy["client-fingerprint"]
          )}`;
        }
        let ssAlpn = "";
        if (proxy.alpn) {
          ssAlpn = `&alpn=${encodeURIComponent(
            Array.isArray(proxy.alpn) ? proxy.alpn : proxy.alpn.join(",")
          )}`;
        }
        const ssIsReality = proxy["reality-opts"];
        let ssSid = "";
        let ssPbk = "";
        let ssSpx = "";
        let ssSecurity = proxy.tls ? "&security=tls" : "";
        let ssMode = "";
        let ssExtra = "";
        if (ssIsReality) {
          ssSecurity = `&security=reality`;
          const publicKey = proxy["reality-opts"]?.["public-key"];
          if (publicKey) {
            ssPbk = `&pbk=${encodeURIComponent(publicKey)}`;
          }
          const shortId = proxy["reality-opts"]?.["short-id"];
          if (shortId) {
            ssSid = `&sid=${encodeURIComponent(shortId)}`;
          }
          const spiderX = proxy["reality-opts"]?.["_spider-x"];
          if (spiderX) {
            ssSpx = `&spx=${encodeURIComponent(spiderX)}`;
          }
          if (proxy._extra) {
            ssExtra = `&extra=${encodeURIComponent(proxy._extra)}`;
          }
          if (proxy._mode) {
            ssMode = `&mode=${encodeURIComponent(proxy._mode)}`;
          }
        }
        if (proxy.tls) {
          query += `&sni=${encodeURIComponent(
            proxy.sni || proxy.server
          )}${proxy["skip-cert-verify"] ? "&allowInsecure=1" : ""}`;
        }
        query += `${ssTransport}${ssAlpn}${ssFp}${ssSecurity}${ssSid}${ssPbk}${ssSpx}${ssMode}${ssExtra}#${encodeURIComponent(
          proxy.name
        )}`;
        result += query.replace(/^&/, "?");
        break;
      case "ssr":
        result = `${proxy.server}:${proxy.port}:${proxy.protocol}:${proxy.cipher}:${proxy.obfs}:${Base644.encode(proxy.password)}/`;
        result += `?remarks=${Base644.encode(proxy.name)}${proxy["obfs-param"] ? "&obfsparam=" + Base644.encode(proxy["obfs-param"]) : ""}${proxy["protocol-param"] ? "&protocolparam=" + Base644.encode(proxy["protocol-param"]) : ""}`;
        result = "ssr://" + Base644.encode(result);
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
          scy: normalizeVmessSecurity(proxy.cipher),
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
          const vmessTransportOpts = proxy[`${proxy.network}-opts`] || {};
          const isVmessHttpUpgrade = proxy.network === "ws" && vmessTransportOpts?.["v2ray-http-upgrade"];
          let vmessTransportPath = vmessTransportOpts?.path;
          let vmessTransportHost = getTransportHost(
            proxy.network,
            vmessTransportOpts
          );
          if (["grpc"].includes(proxy.network)) {
            result.path = proxy[`${proxy.network}-opts`]?.["grpc-service-name"];
            result.type = proxy[`${proxy.network}-opts`]?.["_grpc-type"] || "gun";
            result.host = proxy[`${proxy.network}-opts`]?.["_grpc-authority"];
          } else if (["kcp", "quic"].includes(proxy.network)) {
            result.type = proxy[`${proxy.network}-opts`]?.[`_${proxy.network}-type`] || "none";
            result.host = proxy[`${proxy.network}-opts`]?.[`_${proxy.network}-host`];
            result.path = proxy[`${proxy.network}-opts`]?.[`_${proxy.network}-path`];
          } else {
            if (Array.isArray(vmessTransportPath)) {
              vmessTransportPath = vmessTransportPath[0];
            }
            if (isVmessHttpUpgrade) {
              vmessTransportPath = setHttpUpgradeEarlyDataPath(
                vmessTransportPath,
                vmessTransportOpts
              );
            } else if (proxy.network === "ws") {
              vmessTransportPath = setWebSocketEarlyDataPath(
                vmessTransportPath,
                vmessTransportOpts
              );
            }
            if (vmessTransportPath) {
              result.path = vmessTransportPath;
            }
            if (vmessTransportHost) {
              result.host = Array.isArray(vmessTransportHost) ? vmessTransportHost[0] : vmessTransportHost;
            }
          }
        }
        result = "vmess://" + Base644.encode(JSON.stringify(result));
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
          const trojanTransportOpts = proxy[`${proxy.network}-opts`] || {};
          const isTrojanHttpUpgrade = proxy.network === "ws" && trojanTransportOpts?.["v2ray-http-upgrade"];
          let trojanTransportPath = trojanTransportOpts?.path;
          let trojanTransportHost = trojanTransportOpts?.headers?.Host;
          if (Array.isArray(trojanTransportPath)) {
            trojanTransportPath = trojanTransportPath[0];
          }
          if (isTrojanHttpUpgrade) {
            trojanTransportPath = setHttpUpgradeEarlyDataPath(
              trojanTransportPath,
              trojanTransportOpts
            );
          } else if (proxy.network === "ws") {
            trojanTransportPath = setWebSocketEarlyDataPath(
              trojanTransportPath,
              trojanTransportOpts
            );
          }
          if (trojanTransportPath) {
            trojanTransport += `&path=${encodeURIComponent(
              trojanTransportPath
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
        let trojanPcs = "";
        if (proxy["tls-fingerprint"]) {
          trojanPcs = `&pcs=${encodeURIComponent(
            proxy["tls-fingerprint"]
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
        result = `trojan://${proxy.password}@${proxy.server}:${proxy.port}?sni=${encodeURIComponent(proxy.sni || proxy.server)}${proxy["skip-cert-verify"] ? "&allowInsecure=1" : ""}${trojanTransport}${trojanAlpn}${trojanFp}${trojanPcs}${trojanSecurity}${trojanSid}${trojanPbk}${trojanSpx}${trojanMode}${trojanExtra}#${encodeURIComponent(
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
            "ip-cidr",
            "ipv6-cidr",
            "private-key"
          ].includes(key)) {
            if (["public-key"].includes(key)) {
              wireguardParams.push(
                `publickey=${encodeURIComponent(proxy[key])}`
              );
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
        const wireguardIPv4 = getWireGuardAddressWithCIDR(
          proxy,
          "ipv4"
        );
        const wireguardIPv6 = getWireGuardAddressWithCIDR(
          proxy,
          "ipv6"
        );
        if (wireguardIPv4 && wireguardIPv6) {
          wireguardParams.push(
            `address=${encodeURIComponent(
              `${wireguardIPv4},${wireguardIPv6}`
            )}`
          );
        } else if (wireguardIPv4) {
          wireguardParams.push(
            `address=${encodeURIComponent(wireguardIPv4)}`
          );
        } else if (wireguardIPv6) {
          wireguardParams.push(
            `address=${encodeURIComponent(wireguardIPv6)}`
          );
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
import { Base64 as Base645 } from "js-base64";
var URI = URI_Producer();
function V2Ray_Producer() {
  const type = "ALL";
  const produce2 = (proxies) => {
    let result = [];
    proxies.map((proxy) => {
      try {
        result.push(URI.produce(proxy));
      } catch (err) {
        app_default.error(`Cannot produce proxy: ${proxy.name}
Reason: ${err}`);
      }
    });
    return Base645.encode(result.join("\n"));
  };
  return { type, produce: produce2 };
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/qx.js
var targetPlatform4 = "QX";
function QX_Producer() {
  const produce2 = (proxy, type, opts = {}) => {
    if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
      throw new Error(
        `Platform ${targetPlatform4} does not support network ${proxy.network} with http upgrade`
      );
    }
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
      case "anytls":
        return anytls3(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform4} does not support proxy type: ${proxy.type}`
    );
  };
  return {
    produce: (proxy, type, opts = {}) => {
      let result = produce2(proxy, type, opts);
      if (proxy.flow && proxy.flow !== "xtls-rprx-vision") {
        throw new Error(
          `Platform ${targetPlatform4} does not support flow ${proxy.flow}`
        );
      }
      if (proxy["reality-opts"]) {
        if (proxy["reality-opts"]["public-key"]) {
          result = `${result},reality-base64-pubkey=${proxy["reality-opts"]["public-key"]}`;
        }
        if (proxy["reality-opts"]["short-id"]) {
          result = `${result},reality-hex-shortid=${proxy["reality-opts"]["short-id"]}`;
        }
      }
      return result;
    }
  };
}
function getQxHttpObfs(proxy) {
  return ["http", "vmess-http", "vemss-http", "shadowsocks-http"].includes(
    proxy._qx_obfs_http
  ) ? proxy._qx_obfs_http : "http";
}
function shadowsocks3(proxy) {
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  const isSSOverTls = isShadowsocksOverTls(proxy);
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
  if (isSSOverTls) {
    append(`,obfs=over-tls`);
    if (isPresent2(proxy, "sni")) {
      append(`,obfs-host=${proxy.sni}`);
    } else {
      appendIfPresent(`,obfs-host=${proxy.servername}`, "servername");
    }
  } else if (isPresent2(proxy, "plugin")) {
    if (proxy.plugin === "obfs") {
      const opts = proxy["plugin-opts"];
      if (opts.mode === "http") {
        append(`,obfs=${getQxHttpObfs(proxy)}`);
      } else {
        append(`,obfs=${opts.mode}`);
      }
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
    if (!isSSOverTls) {
      appendIfPresent(`,tls-host=${proxy.sni}`, "sni");
    }
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
    } else if (!["tcp"].includes(proxy.network)) {
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
  let cipher = formatQXVmessMethod(proxy.cipher);
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
      append(`,obfs=${getQxHttpObfs(proxy)}`);
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
  if (proxy.encryption && proxy.encryption !== "none")
    throw new Error(`VLESS encryption is not supported`);
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
      append(`,obfs=${getQxHttpObfs(proxy)}`);
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
  appendIfPresent(`,vless-flow=${proxy.flow}`, "flow");
  appendIfPresent(`,fast-open=${proxy.tfo}`, "tfo");
  appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(
    `,server_check_url=${proxy["test-url"]}`,
    "test-url"
  );
  append(`,tag=${proxy.name}`);
  return result.toString();
}
function anytls3(proxy) {
  const network = proxy.network?.trim().toLowerCase();
  if (network && network !== "tcp") {
    throw new Error(
      `Platform ${targetPlatform4} does not support AnyTLS with transport ${proxy.network}`
    );
  }
  const result = new Result(proxy);
  const append = result.append.bind(result);
  const appendIfPresent = result.appendIfPresent.bind(result);
  append(`anytls=${proxy.server}:${proxy.port}`);
  append(`,password=${proxy.password}`);
  proxy.tls = true;
  append(`,over-tls=true`);
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
      if (!supportsShadowsocksV2rayPluginMode(proxy, [
        "websocket",
        "quic",
        "http2",
        "mkcp",
        "grpc"
      ])) {
        return false;
      } else if (proxy.type === "snell" && ![1, 2, 3, 4, 5].includes(proxy.version)) {
        return false;
      } else if (hasShadowrocketSnellShadowTlsObfsConflict(proxy)) {
        app_default.error(
          `Platform Shadowrocket does not support Snell shadow-tls with obfs for proxy ${proxy.name}. Proxy has been filtered.`
        );
        return false;
      } else if ([
        "tailscale",
        "sudoku",
        "naive",
        "openvpn",
        "gost-relay"
      ].includes(proxy.type)) {
        return false;
      } else if (["xhttp"].includes(proxy.network)) {
        app_default.warn(
          `VLESS XHTTP \u7ED3\u6784\u590D\u6742, Shadowrocket \u53EF\u80FD\u65E0\u6CD5\u5B8C\u5168\u517C\u5BB9`
        );
        return true;
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
        proxy.cipher = normalizeVmessSecurity(proxy.cipher);
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
        proxy.ip = getWireGuardAddressWithCIDR(proxy, "ipv4");
        proxy.ipv6 = getWireGuardAddressWithCIDR(proxy, "ipv6");
      } else if (proxy.type === "snell") {
        if (proxy.version < 3) {
          delete proxy.udp;
        }
        if (proxy.plugin === "shadow-tls" && proxy["plugin-opts"]) {
          proxy["obfs-opts"] = {
            mode: "shadow-tls",
            host: proxy["plugin-opts"].host,
            password: proxy["plugin-opts"].password,
            version: proxy["plugin-opts"].version
          };
          if (proxy["plugin-opts"].alpn) {
            proxy["obfs-opts"].alpn = proxy["plugin-opts"].alpn;
          }
          delete proxy.plugin;
          delete proxy["plugin-opts"];
        }
      } else if (proxy.type === "vless") {
        if (isPresent2(proxy, "sni")) {
          proxy.servername = proxy.sni;
          delete proxy.sni;
        }
      } else if (proxy.type === "ss") {
        if (isShadowsocksOverTls(proxy)) {
          if (isPresent2(proxy, "sni")) {
            proxy.servername = proxy.sni;
          }
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
        let host = proxy["h2-opts"]?.host ?? proxy["h2-opts"]?.headers?.host ?? proxy["h2-opts"]?.headers?.Host;
        if (isPresent2(proxy, "h2-opts.host") || isPresent2(proxy, "h2-opts.headers.host") || isPresent2(proxy, "h2-opts.headers.Host")) {
          proxy["h2-opts"].host = Array.isArray(host) ? host : [host];
        }
        if (proxy["h2-opts"]?.headers) {
          delete proxy["h2-opts"].headers.host;
          delete proxy["h2-opts"].headers.Host;
          if (Object.keys(proxy["h2-opts"].headers).length === 0) {
            delete proxy["h2-opts"].headers;
          }
        }
      }
      if (["ws"].includes(proxy.network)) {
        const networkOptsKey = `${proxy.network}-opts`;
        proxy[networkOptsKey] = proxy[networkOptsKey] || {};
        if (!proxy[networkOptsKey].path) {
          proxy[networkOptsKey].path = "/";
        }
        normalizeWebSocketEarlyDataPath(proxy[networkOptsKey]);
      }
      if (proxy["plugin-opts"]?.tls) {
        if (isPresent2(proxy, "skip-cert-verify")) {
          proxy["plugin-opts"]["skip-cert-verify"] = proxy["plugin-opts"]["skip-cert-verify"] || proxy["skip-cert-verify"];
        }
      }
      if ([
        "trojan",
        "tuic",
        "hysteria",
        "hysteria2",
        "juicity",
        "anytls",
        "trusttunnel",
        "naive"
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
      delete proxy["ip-cidr"];
      delete proxy["ipv6-cidr"];
      if (type2 !== "internal") {
        for (const key in proxy) {
          if (proxy[key] == null || /^_/i.test(key)) {
            delete proxy[key];
          }
        }
        deleteHttpUpgradeEarlyDataMetadata(
          proxy[`${proxy.network}-opts`]
        );
      }
      if (["grpc"].includes(proxy.network) && proxy[`${proxy.network}-opts`]) {
        delete proxy[`${proxy.network}-opts`]["_grpc-type"];
        delete proxy[`${proxy.network}-opts`]["_grpc-authority"];
      }
      return proxy;
    });
    return produceProxyListOutput(list, type2, opts);
  };
  return { type, produce: produce2 };
}
function hasShadowrocketSnellShadowTlsObfsConflict(proxy) {
  return proxy?.type === "snell" && proxy?.plugin === "shadow-tls" && (isPresent2(proxy, "obfs-opts.mode") || isPresent2(proxy, "obfs-opts.host") || isPresent2(proxy, "obfs-opts.path"));
}

// src/vendors/Sub-Store/backend/src/core/proxy-utils/producers/surfboard.js
var targetPlatform5 = "Surfboard";
function hasNonBlankValue2(value) {
  return value != null && `${value}`.trim().length > 0;
}
function appendTlsProxyParams2(result, proxy, enabled = true) {
  if (!enabled) {
    return;
  }
  result.appendIfPresent(
    `,server-cert-fingerprint-sha256=${proxy["tls-fingerprint"]}`,
    "tls-fingerprint"
  );
  result.appendIfPresent(`,sni="${proxy.sni}"`, "sni");
  result.appendIfPresent(
    `,skip-cert-verify=${proxy["skip-cert-verify"]}`,
    "skip-cert-verify"
  );
}
function Surfboard_Producer() {
  const produce2 = (proxy) => {
    if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
      throw new Error(
        `Platform ${targetPlatform5} does not support network ${proxy.network} with http upgrade`
      );
    }
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
      case "snell":
        return snell2(proxy);
      case "socks5":
        return socks54(proxy);
      case "hysteria2":
        return hysteria23(proxy);
      case "wireguard-surge":
        return wireguard3(proxy);
    }
    if (proxy.type === "anytls") {
      if (proxy.network && (!["tcp"].includes(proxy.network) || ["tcp"].includes(proxy.network) && proxy["reality-opts"])) {
        throw new Error(
          `Platform ${targetPlatform5} does not support proxy type ${proxy.type} with network or REALITY`
        );
      }
      return anytls4(proxy);
    }
    throw new Error(
      `Platform ${targetPlatform5} does not support proxy type: ${proxy.type}`
    );
  };
  return { produce: produce2 };
}
function hysteria23(proxy) {
  if (proxy.obfs && proxy.obfs !== "salamander" || proxy["obfs-password"] && proxy.obfs !== "salamander") {
    throw new Error(`Surfboard Hysteria2 only supports salamander obfs`);
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=hysteria2,${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  if (hasNonBlankValue2(proxy.ports)) {
    result.append(
      `,port-hopping="${String(proxy.ports).replace(/,/g, ";")}"`
    );
  }
  if (hasNonBlankValue2(proxy["hop-interval"])) {
    result.append(`,port-hopping-interval=${proxy["hop-interval"]}`);
  }
  if (proxy["obfs-password"]) {
    result.append(`,salamander-password="${proxy["obfs-password"]}"`);
  }
  appendTlsProxyParams2(result, proxy);
  result.appendIfPresent(
    `,download-bandwidth=${`${proxy["down"]}`.match(/\d+/)?.[0] || 0}`,
    "down"
  );
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function anytls4(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
  appendTlsProxyParams2(result, proxy);
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,reuse=${proxy["reuse"]}`, "reuse");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function snell2(proxy) {
  if (isPresent2(proxy, "version") && ![1, 2, 3, 4, 5].includes(Number(proxy.version))) {
    throw new Error(
      `Platform ${targetPlatform5} does not support snell version ${proxy.version}`
    );
  }
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,version=${proxy.version}`, "version");
  result.appendIfPresent(`,psk="${proxy.psk}"`, "psk");
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
  if (proxy.version >= 3) {
    result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  }
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
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
    "chacha20-ietf",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm"
  ].includes(proxy.cipher)) {
    throw new Error(`cipher ${proxy.cipher} is not supported`);
  }
  result.append(`,encrypt-method=${proxy.cipher}`);
  result.appendIfPresent(`,password="${proxy.password}"`, "password");
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
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function trojan4(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=${proxy.type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,password=${proxy.password}`, "password");
  handleTransport2(result, proxy);
  result.appendIfPresent(`,tls=${proxy.tls}`, "tls");
  appendTlsProxyParams2(result, proxy);
  result.appendIfPresent(`,tfo=${proxy.tfo}`, "tfo");
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
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
  appendTlsProxyParams2(result, proxy, Boolean(proxy.tls));
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function http4(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "https" : "http";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,${proxy.username}`, "username");
  result.appendIfPresent(`,${proxy.password}`, "password");
  appendTlsProxyParams2(result, proxy, Boolean(proxy.tls));
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function socks54(proxy) {
  const result = new Result(proxy);
  const type = proxy.tls ? "socks5-tls" : "socks5";
  result.append(`${proxy.name}=${type},${proxy.server},${proxy.port}`);
  result.appendIfPresent(`,${proxy.username}`, "username");
  result.appendIfPresent(`,${proxy.password}`, "password");
  appendTlsProxyParams2(result, proxy, Boolean(proxy.tls));
  result.appendIfPresent(`,udp-relay=${proxy.udp}`, "udp");
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
  return result.toString();
}
function wireguard3(proxy) {
  const result = new Result(proxy);
  result.append(`${proxy.name}=wireguard`);
  result.appendIfPresent(
    `,section-name=${proxy["section-name"]}`,
    "section-name"
  );
  result.appendIfPresent(`,block-quic=${proxy["block-quic"]}`, "block-quic");
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
    } else if (["tcp"].includes(proxy.network) && proxy["reality-opts"]) {
      throw new Error(`reality is unsupported`);
    } else if (!["tcp"].includes(proxy.network)) {
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
var domainResolverParser = (proxy, parsedProxy) => {
  if (proxy._domain_resolver) {
    parsedProxy.domain_resolver = {
      ...parsedProxy.domain_resolver,
      ...proxy._domain_resolver
    };
  }
};
var hasControlHTTPClient = (proxy) => {
  const value = proxy["control-http-client"];
  if (value === void 0 || value === null) return false;
  if (typeof value === "string") return value.trim() !== "";
  if (isPlainObject(value)) {
    return Object.values(value).some(
      (item) => item !== void 0 && item !== null && item !== ""
    );
  }
  return true;
};
var detourParser = (proxy, parsedProxy) => {
  parsedProxy.detour = proxy["dialer-proxy"] || proxy.detour;
};
var networkParser = (proxy, parsedProxy) => {
  if (["tcp", "udp"].includes(proxy._network)) {
    parsedProxy.network = proxy._network;
    return;
  }
  if (proxy.udp === false) {
    parsedProxy.network = "tcp";
  }
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
    const { value: ed, parsed: maxEarlyData } = getSafeIntegerPathQueryParam(transport.path, "ed");
    if (ed !== "") {
      transport.path = extractPathQueryParam(transport.path, "ed").path;
      transport.early_data_header_name = "Sec-WebSocket-Protocol";
      transport.max_early_data = maxEarlyData;
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
var normalizePemLines = (value, label) => {
  const items = Array.isArray(value) ? value : [value];
  const lines = [];
  for (const item of items) {
    const normalized = `${item}`.trim().replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n");
    if (normalized === "") continue;
    for (const line of normalized.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed !== "") lines.push(trimmed);
    }
  }
  if (lines.length === 0) return void 0;
  if (lines.some((line) => /^-----BEGIN [A-Za-z0-9 -]+-----$/.test(line))) {
    return lines;
  }
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`];
};
var singBoxUtlsFingerprints = [
  "chrome",
  "firefox",
  "edge",
  "safari",
  "360",
  "qq",
  "ios",
  "android",
  "random",
  "randomized"
];
var getSingBoxUtlsFingerprint = (value) => {
  const fingerprint = `${value || ""}`.trim().toLowerCase();
  if (singBoxUtlsFingerprints.includes(fingerprint)) return fingerprint;
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
  if (!["hysteria", "hysteria2", "tuic"].includes(proxy.type) && proxy["client-fingerprint"] && proxy["client-fingerprint"] !== "") {
    const fingerprint = getSingBoxUtlsFingerprint(
      proxy["client-fingerprint"]
    );
    if (fingerprint)
      parsedProxy.tls.utls = {
        ...parsedProxy.tls.utls,
        enabled: true,
        fingerprint
      };
  }
  if (proxy._ech && isPlainObject(proxy._ech)) {
    parsedProxy.tls.ech = proxy._ech;
  } else if (proxy["ech-opts"] && isPlainObject(proxy["ech-opts"])) {
    parsedProxy.tls.ech = parsedProxy.tls.ech || {};
    parsedProxy.tls.ech.enabled = proxy["ech-opts"].enable;
    const echOptsConfig = proxy["ech-opts"].config;
    if (Array.isArray(echOptsConfig) || typeof echOptsConfig === "string") {
      const config = normalizePemLines(echOptsConfig, "ECH CONFIGS");
      if (config) parsedProxy.tls.ech.config = config;
    }
    parsedProxy.tls.ech.query_server_name = proxy["ech-opts"]["query-server-name"];
    parsedProxy.tls.ech.config_path = proxy["ech-opts"]["config-path"];
    parsedProxy.tls.ech.fragment = proxy["ech-opts"]["fragment"];
    parsedProxy.tls.ech.fragment_fallback_delay = proxy["ech-opts"]["fragment-fallback-delay"];
    parsedProxy.tls.ech.record_fragment = proxy["ech-opts"]["record-fragment"];
  }
  if (proxy._curve_preferences && Array.isArray(proxy._curve_preferences)) {
    parsedProxy.tls.curve_preferences = proxy._curve_preferences;
  }
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
  domainResolverParser(proxy, parsedProxy);
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
  domainResolverParser(proxy, parsedProxy);
  return parsedProxy;
};
var socks5Parser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "socks",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    version: "5"
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.username) parsedProxy.username = proxy.username;
  if (proxy.password) parsedProxy.password = proxy.password;
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
  ipVersionParser(proxy, parsedProxy);
  domainResolverParser(proxy, parsedProxy);
  return parsedProxy;
};
var shadowTLSParser = (proxy = {}) => {
  const pluginOpts = getShadowTLSPluginOpts(proxy);
  const ssPart = {
    tag: proxy.name,
    type: "shadowsocks",
    method: proxy.cipher,
    password: proxy.password,
    detour: getShadowTLSTag(proxy)
  };
  if (proxy.uot) ssPart.udp_over_tcp = true;
  if (proxy["udp-over-tcp"]) {
    ssPart.udp_over_tcp = {
      enabled: true,
      version: !proxy["udp-over-tcp-version"] || proxy["udp-over-tcp-version"] === 1 ? 1 : 2
    };
  }
  networkParser(proxy, ssPart);
  smuxParser(proxy.smux, ssPart);
  return {
    type: "ss-with-st",
    ssPart,
    stPart: shadowTLSOutboundParser(proxy, pluginOpts)
  };
};
var getShadowTLSTag = (proxy = {}) => `${proxy.name}_shadowtls`;
var getShadowTLSPluginOpts = (proxy = {}) => {
  if (proxy.plugin === "shadow-tls" && proxy["plugin-opts"]) {
    return proxy["plugin-opts"];
  }
  if (proxy.type === "snell" && proxy["obfs-opts"]?.mode === "shadow-tls") {
    return {
      host: proxy["obfs-opts"].host,
      password: proxy["obfs-opts"].password,
      version: proxy["obfs-opts"].version,
      alpn: proxy["obfs-opts"].alpn
    };
  }
  return void 0;
};
var normalizeALPN = (alpn) => {
  if (typeof alpn === "string") {
    return alpn.split(",").map((item) => item.trim()).filter((item) => item !== "");
  }
  if (Array.isArray(alpn)) return alpn;
  return void 0;
};
var shadowTLSOutboundParser = (proxy = {}, pluginOpts) => {
  if (!pluginOpts) throw new Error("shadow-tls plugin options are missing");
  const fingerprint = getSingBoxUtlsFingerprint(proxy["client-fingerprint"]);
  const stPart = {
    tag: getShadowTLSTag(proxy),
    type: "shadowtls",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    version: pluginOpts.version,
    password: pluginOpts.password,
    tls: {
      enabled: true,
      server_name: pluginOpts.host
    }
  };
  if (fingerprint) {
    stPart.tls.utls = {
      enabled: true,
      fingerprint
    };
  }
  if (stPart.server_port < 0 || stPart.server_port > 65535)
    throw "\u7AEF\u53E3\u503C\u975E\u6CD5";
  const alpn = normalizeALPN(pluginOpts.alpn) ?? normalizeALPN(proxy.alpn);
  if (alpn) stPart.tls.alpn = alpn;
  if (proxy["fast-open"] === true) stPart.udp_fragment = true;
  tfoParser(proxy, stPart);
  detourParser(proxy, stPart);
  ipVersionParser(proxy, stPart);
  domainResolverParser(proxy, stPart);
  return stPart;
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
  domainResolverParser(proxy, parsedProxy);
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
          case "mux": {
            const mux = normalizePluginMuxValue(
              proxy["plugin-opts"].mux
            );
            if (mux) parsedProxy.multiplex = { enabled: true };
            optArr.push(`mux=${mux}`);
            break;
          }
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
  networkParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  domainResolverParser(proxy, parsedProxy);
  return parsedProxy;
};
var getSnellVersion = (version) => {
  if (version == null) return void 0;
  const normalized = `${version}`.trim();
  if (!/^\d+$/.test(normalized)) return NaN;
  return parseInt(normalized, 10);
};
var snellParser = (proxy = {}) => {
  const version = getSnellVersion(proxy.version);
  const shadowTLSPluginOpts = getShadowTLSPluginOpts(proxy);
  if (version != null && (![1, 2, 3, 4, 5].includes(version) || Number.isNaN(version))) {
    throw new Error(
      `Platform sing-box does not support snell version ${proxy.version}`
    );
  }
  const parsedProxy = {
    tag: proxy.name,
    type: "snell",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    psk: proxy.psk
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (version != null) parsedProxy.version = version;
  if (proxy["obfs-opts"]?.mode && proxy["obfs-opts"].mode !== "shadow-tls")
    parsedProxy.obfs_mode = proxy["obfs-opts"].mode;
  if (proxy["obfs-opts"]?.host && proxy["obfs-opts"]?.mode !== "shadow-tls")
    parsedProxy.obfs_host = proxy["obfs-opts"].host;
  if (proxy.reuse && (version == null || version >= 4))
    parsedProxy.reuse = true;
  networkParser(proxy, parsedProxy);
  if (shadowTLSPluginOpts) {
    parsedProxy.detour = getShadowTLSTag(proxy);
    delete parsedProxy.server;
    delete parsedProxy.server_port;
  } else {
    if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
    tfoParser(proxy, parsedProxy);
    detourParser(proxy, parsedProxy);
    ipVersionParser(proxy, parsedProxy);
    domainResolverParser(proxy, parsedProxy);
  }
  return parsedProxy;
};
var singBoxPacketEncodings = ["", "packetaddr", "xudp"];
var normalizeSingBoxPacketEncoding = (value) => {
  const packetEncoding = `${value}`.trim().toLowerCase();
  if (singBoxPacketEncodings.includes(packetEncoding)) {
    return packetEncoding;
  }
  return void 0;
};
var vmessVlessPacketEncodingParser = (proxy, parsedProxy) => {
  if (proxy["packet-encoding"] != null) {
    const packetEncoding = normalizeSingBoxPacketEncoding(
      proxy["packet-encoding"]
    );
    if (packetEncoding != null)
      parsedProxy.packet_encoding = packetEncoding;
  } else if (proxy.xudp) {
    parsedProxy.packet_encoding = "xudp";
  } else if (proxy["packet-addr"]) {
    parsedProxy.packet_encoding = "packetaddr";
  }
};
var vmessProtocolOptionsParser = (proxy, parsedProxy) => {
  vmessVlessPacketEncodingParser(proxy, parsedProxy);
  if (proxy["global-padding"] != null) {
    parsedProxy.global_padding = !!proxy["global-padding"];
  }
  if (proxy["authenticated-length"] != null) {
    parsedProxy.authenticated_length = !!proxy["authenticated-length"];
  }
};
var vmessParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "vmess",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    uuid: proxy.uuid,
    security: normalizeVmessSecurity(proxy.cipher),
    alter_id: parseInt(`${proxy.alterId}`, 10),
    tls: { enabled: false, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  vmessProtocolOptionsParser(proxy, parsedProxy);
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
  domainResolverParser(proxy, parsedProxy);
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
  vmessVlessPacketEncodingParser(proxy, parsedProxy);
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
  domainResolverParser(proxy, parsedProxy);
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
  domainResolverParser(proxy, parsedProxy);
  return parsedProxy;
};
var naiveParser = (proxy = {}) => {
  const parsedProxy = {
    tag: proxy.name,
    type: "naive",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    tls: { enabled: true, server_name: proxy.server, insecure: false }
  };
  if (parsedProxy.server_port < 0 || parsedProxy.server_port > 65535)
    throw "invalid port";
  if (proxy.username) parsedProxy.username = proxy.username;
  if (proxy.password) parsedProxy.password = proxy.password;
  if (proxy.uot) parsedProxy.udp_over_tcp = true;
  if (proxy["udp-over-tcp"]) {
    parsedProxy.udp_over_tcp = {
      enabled: true,
      version: !proxy["udp-over-tcp-version"] || proxy["udp-over-tcp-version"] === 1 ? 1 : 2
    };
  }
  const insecure_concurrency = parseInt(
    `${proxy["insecure-concurrency"]}`,
    10
  );
  if (Number.isInteger(insecure_concurrency) && insecure_concurrency >= 0)
    parsedProxy.insecure_concurrency = insecure_concurrency;
  if (proxy["extra-headers"])
    parsedProxy.extra_headers = proxy["extra-headers"];
  if (proxy.quic) parsedProxy.quic = !!proxy.quic;
  if (proxy["quic-congestion-control"])
    parsedProxy.quic_congestion_control = proxy["quic-congestion-control"];
  if (proxy["fast-open"]) parsedProxy.udp_fragment = true;
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  domainResolverParser(proxy, parsedProxy);
  if (parsedProxy.tls?.insecure) {
    app_default.info(
      `Platform sing-box: insecure is not supported on naive outbound`
    );
    delete parsedProxy.tls.insecure;
  }
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
  domainResolverParser(proxy, parsedProxy);
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
  if (["salamander", "gecko"].includes(proxy.obfs))
    parsedProxy.obfs.type = proxy.obfs;
  if (proxy.obfs === "gecko") {
    const minRaw = proxy["obfs-min-packet-size"];
    const maxRaw = proxy["obfs-max-packet-size"];
    const hasMin = minRaw !== void 0 && minRaw !== null && `${minRaw}` !== "";
    const hasMax = maxRaw !== void 0 && maxRaw !== null && `${maxRaw}` !== "";
    if (hasMin || hasMax) {
      const minPacketSize = hasMin ? parseSafeIntegerValue(`${minRaw}`.trim()) : void 0;
      const rawMaxPacketSize = hasMax ? parseSafeIntegerValue(`${maxRaw}`.trim()) : void 0;
      const maxPacketSize = rawMaxPacketSize != null ? Math.min(rawMaxPacketSize, 2048) : rawMaxPacketSize;
      const effectiveMinPacketSize = minPacketSize ?? 512;
      const effectiveMaxPacketSize = maxPacketSize ?? 1200;
      if (hasMax && rawMaxPacketSize != null && rawMaxPacketSize > 2048) {
        app_default.warn(
          `Gecko obfs max packet size for proxy ${proxy.name} exceeds 2048, clamped to 2048: ${maxRaw}`
        );
      }
      if (hasMin && (minPacketSize == null || minPacketSize <= 0) || hasMax && (rawMaxPacketSize == null || rawMaxPacketSize <= 0) || effectiveMaxPacketSize < effectiveMinPacketSize) {
        app_default.error(
          `Invalid obfs packet size for proxy ${proxy.name}: min=${minRaw} max=${maxRaw}`
        );
      } else {
        if (hasMin) parsedProxy.obfs.min_packet_size = minPacketSize;
        if (hasMax) parsedProxy.obfs.max_packet_size = maxPacketSize;
      }
    }
  }
  if (proxy["obfs-password"])
    parsedProxy.obfs.password = proxy["obfs-password"];
  if (!parsedProxy.obfs.type) delete parsedProxy.obfs;
  networkParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  domainResolverParser(proxy, parsedProxy);
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
  domainResolverParser(proxy, parsedProxy);
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
  detourParser(proxy, parsedProxy);
  tlsParser(proxy, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  domainResolverParser(proxy, parsedProxy);
  return parsedProxy;
};
var tailscaleParser = (proxy = {}) => {
  const useControlHTTPClient = hasControlHTTPClient(proxy);
  const parsedProxy = {
    tag: proxy.name,
    type: "tailscale",
    control_http_client: proxy["control-http-client"],
    udp_timeout: proxy["udp-timeout"],
    state_directory: proxy["state-dir"] || proxy["state-directory"],
    auth_key: proxy["auth-key"],
    control_url: proxy["control-url"],
    ephemeral: proxy.ephemeral,
    hostname: proxy.hostname,
    accept_routes: proxy["accept-routes"],
    exit_node: proxy["exit-node"],
    exit_node_allow_lan_access: proxy["exit-node-allow-lan-access"],
    advertise_routes: Array.isArray(proxy["advertise-routes"]) ? proxy["advertise-routes"] : void 0,
    advertise_exit_node: proxy["advertise-exit-node"],
    advertise_tags: Array.isArray(proxy["advertise-tags"]) ? proxy["advertise-tags"] : void 0,
    relay_server_static_endpoints: Array.isArray(
      proxy["relay-server-static-endpoints"]
    ) ? proxy["relay-server-static-endpoints"] : void 0,
    system_interface: proxy["system-interface"],
    system_interface_name: proxy["system-interface-name"]
  };
  if (/^\d+$/.test(proxy["system-interface-mtu"]))
    parsedProxy.system_interface_mtu = parseInt(
      `${proxy["system-interface-mtu"]}`,
      10
    );
  if (/^\d+$/.test(proxy["relay-server-port"]))
    parsedProxy.relay_server_port = parseInt(
      `${proxy["relay-server-port"]}`,
      10
    );
  if (!useControlHTTPClient) {
    detourParser(proxy, parsedProxy);
    ipVersionParser(proxy, parsedProxy);
    domainResolverParser(proxy, parsedProxy);
  }
  if (isPlainObject(proxy["ssh-server"])) {
    parsedProxy.ssh_server = {
      enabled: proxy["ssh-server"].enabled !== false,
      disable_pty: proxy["ssh-server"]["disable-pty"],
      disable_sftp: proxy["ssh-server"]["disable-sftp"],
      disable_forwarding: proxy["ssh-server"]["disable-forwarding"]
    };
  } else if (proxy["ssh-server"]) {
    parsedProxy.ssh_server = !!proxy["ssh-server"];
  }
  return parsedProxy;
};
var wireguardParser = (proxy = {}) => {
  const address = ["ipv4", "ipv6"].map((family) => getWireGuardAddressWithCIDR(proxy, family)).filter((i) => i);
  const parsedProxy = {
    system: !!proxy.system,
    mtu: proxy.mtu ? parseInt(`${proxy.mtu}`, 10) : void 0,
    udp_timeout: proxy["udp-timeout"],
    workers: proxy["workers"] ? parseInt(`${proxy["workers"]}`, 10) : void 0,
    tag: proxy.name,
    type: "wireguard",
    server: proxy.server,
    server_port: parseInt(`${proxy.port}`, 10),
    address,
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
  if (!Array.isArray(proxy.peers) || proxy.peers.length === 0) {
    proxy.peers = [{}];
  }
  if (proxy.peers && proxy.peers.length > 0) {
    parsedProxy.peers = [];
    for (const p of proxy.peers) {
      let address2;
      let port;
      if (p.server && p.port) {
        address2 = p.server;
        port = parseInt(`${p.port}`, 10);
      } else {
        address2 = parsedProxy.server;
        port = parseInt(`${parsedProxy.server_port}`, 10);
      }
      const peer = {
        address: address2,
        port,
        persistent_keepalive_interval: p["persistent-keepalive-interval"] ? parseInt(`${p["persistent-keepalive-interval"]}`, 10) : void 0,
        public_key: p["public-key"] || p["public_key"] || parsedProxy.peer_public_key,
        pre_shared_key: p["pre-shared-key"] || p["pre_shared_key"] || parsedProxy.pre_shared_key,
        allowed_ips: p["allowed-ips"] || p.allowed_ips || [
          "0.0.0.0/0",
          ...proxy.ipv6 ? ["::/0"] : []
        ],
        reserved: []
      };
      if (typeof p.reserved === "string") {
        peer.reserved.push(p.reserved);
      } else if (Array.isArray(p.reserved)) {
        for (const r of p.reserved) peer.reserved.push(r);
      } else {
        delete peer.reserved;
      }
      if (!Array.isArray(peer.reserved) || peer.reserved.length === 0) {
        peer.reserved = parsedProxy.reserved;
      }
      parsedProxy.peers.push(peer);
    }
  }
  tfoParser(proxy, parsedProxy);
  detourParser(proxy, parsedProxy);
  smuxParser(proxy.smux, parsedProxy);
  ipVersionParser(proxy, parsedProxy);
  domainResolverParser(proxy, parsedProxy);
  delete parsedProxy.server;
  delete parsedProxy.server_port;
  delete parsedProxy.pre_shared_key;
  delete parsedProxy.peer_public_key;
  delete parsedProxy.reserved;
  return parsedProxy;
};
function singbox_Producer() {
  const type = "ALL";
  const produce2 = (proxies, type2, opts = {}) => {
    const list = [];
    const originalSnellShadowTLS = new Map(
      proxies.filter(
        (proxy) => proxy?.type === "snell" && proxy?.plugin === "shadow-tls" && proxy?.["plugin-opts"]
      ).map((proxy) => [
        proxy,
        {
          plugin: proxy.plugin,
          "plugin-opts": proxy["plugin-opts"] ? JSON.parse(JSON.stringify(proxy["plugin-opts"])) : void 0,
          "obfs-opts": proxy["obfs-opts"] ? JSON.parse(JSON.stringify(proxy["obfs-opts"])) : void 0
        }
      ])
    );
    ClashMeta_Producer().produce(proxies, "internal", { "include-unsupported-proxy": true }).map((proxy) => {
      try {
        const originalShadowTLS = originalSnellShadowTLS.get(proxy);
        if (originalShadowTLS) {
          proxy.plugin = originalShadowTLS.plugin;
          proxy["plugin-opts"] = originalShadowTLS["plugin-opts"];
          if (originalShadowTLS["obfs-opts"]) {
            proxy["obfs-opts"] = originalShadowTLS["obfs-opts"];
          } else {
            delete proxy["obfs-opts"];
          }
        }
        if (["xhttp"].includes(proxy.network))
          throw new Error(
            `Platform sing-box does not support network: ${proxy.network}`
          );
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
          case "snell":
            if (opts["include-unsupported-proxy"]) {
              list.push(snellParser(proxy));
              const shadowTLSPluginOpts = getShadowTLSPluginOpts(proxy);
              if (shadowTLSPluginOpts) {
                list.push(
                  shadowTLSOutboundParser(
                    proxy,
                    shadowTLSPluginOpts
                  )
                );
              }
            } else {
              throw new Error(
                `Platform sing-box does not support proxy type: ${proxy.type}`
              );
            }
            break;
          case "vmess":
            if (!proxy.network || ["tcp", "ws", "grpc", "h2", "http"].includes(
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
            if (proxy.encryption && proxy.encryption !== "none") {
              throw new Error(
                `VLESS encryption is not supported`
              );
            }
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
          case "naive":
            list.push(naiveParser(proxy));
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
          case "tailscale":
            list.push(tailscaleParser(proxy));
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
    if (type2 === "internal") return list;
    const categorized = list.reduce(
      (result, item) => {
        if (["wireguard", "tailscale"].includes(item.type)) {
          result.endpoints.push(item);
        } else {
          result.outbounds.push(item);
        }
        return result;
      },
      { outbounds: [], endpoints: [] }
    );
    return JSON.stringify(categorized, null, 2);
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
        "https",
        "socks5",
        "ss",
        "trojan",
        "hysteria2",
        "vless",
        "vmess",
        "tuic",
        "wireguard",
        "anytls",
        "ssh",
        "snell"
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
      ].includes(proxy.cipher)) || proxy.type === "vmess" && (!["h2", "http", "ws", "tcp", "grpc"].includes(
        proxy.network
      ) && proxy.network || !isEgernGrpcGun(proxy)) || proxy.type === "trojan" && !["http", "ws", "tcp"].includes(proxy.network) && proxy.network || proxy.type === "vless" && (!["h2", "http", "ws", "tcp", "grpc"].includes(
        proxy.network
      ) && proxy.network || !isEgernGrpcGun(proxy) || typeof proxy.flow !== "undefined" && !["xtls-rprx-vision", ""].includes(
        proxy.flow
      )) || proxy.type === "tuic" && proxy.token && proxy.token.length !== 0) {
        return false;
      } else if (proxy.type === "snell" && normalizeSnellVersion(proxy.version) === null) {
        return false;
      } else if (proxy.type === "snell" && hasShadowTls(proxy)) {
        app_default.error(
          `Platform Egern does not support Snell shadow-tls proxy ${proxy.name}. Proxy has been filtered.`
        );
        return false;
      } else if (["anytls"].includes(proxy.type) && proxy.network && !["tcp"].includes(proxy.network)) {
        return false;
      } else if (["ws"].includes(proxy.network) && proxy["ws-opts"]?.["v2ray-http-upgrade"]) {
        return false;
      }
      return true;
    }).map((proxy) => {
      const sourceProxy = proxy;
      try {
        const original = { ...proxy };
        let flow;
        if (proxy.tls && !proxy.sni) {
          proxy.sni = proxy.server;
        }
        const prev_hop = proxy.prev_hop || proxy["underlying-proxy"] || proxy["dialer-proxy"] || proxy.detour;
        if (proxy.type === "http") {
          proxy = {
            type: proxy.tls ? "https" : "http",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            username: proxy.username,
            password: proxy.password,
            ...hasHeaders(proxy) ? {
              headers: proxy.headers
            } : {},
            tfo: getTfo(proxy),
            ...proxy.tls ? {
              sni: proxy.sni,
              skip_tls_verify: proxy["skip-cert-verify"],
              reality: getReality(proxy)
            } : {}
          };
        } else if (proxy.type === "https") {
          proxy = {
            type: "https",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            username: proxy.username,
            password: proxy.password,
            ...hasHeaders(proxy) ? {
              headers: proxy.headers
            } : {},
            tfo: getTfo(proxy),
            sni: proxy.sni,
            skip_tls_verify: proxy["skip-cert-verify"],
            reality: getReality(proxy)
          };
        } else if (proxy.type === "socks5") {
          proxy = {
            type: proxy.tls ? "socks5_tls" : "socks5",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            username: proxy.username,
            password: proxy.password,
            tfo: getTfo(proxy),
            udp_relay: getUdpRelay(proxy),
            ...proxy.tls ? {
              sni: proxy.sni,
              skip_tls_verify: proxy["skip-cert-verify"],
              reality: getReality(proxy)
            } : {}
          };
        } else if (proxy.type === "ss") {
          proxy = {
            type: "shadowsocks",
            name: proxy.name,
            method: proxy.cipher === "chacha20-ietf-poly1305" ? "chacha20-poly1305" : proxy.cipher,
            server: proxy.server,
            port: proxy.port,
            password: proxy.password,
            tfo: getTfo(proxy),
            udp_relay: getUdpRelay(proxy)
          };
          if (isPresent2(original, "plugin")) {
            if (original.plugin === "obfs") {
              proxy.obfs = original["plugin-opts"].mode;
              proxy.obfs_host = original["plugin-opts"].host;
              proxy.obfs_uri = original["plugin-opts"].path;
            } else if (!["shadow-tls"].includes(original.plugin)) {
              throw new Error(
                `plugin ${original.plugin} is not supported`
              );
            }
          }
        } else if (proxy.type === "hysteria2") {
          proxy = {
            type: "hysteria2",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            auth: proxy.password,
            ...isPresent2(proxy, "up") ? {
              bandwidth: parseInt(
                `${proxy.up}`.match(/\d+/)?.[0] || 0,
                10
              )
            } : {},
            tfo: getTfo(proxy),
            udp_relay: getUdpRelay(proxy),
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
            tfo: getTfo(proxy),
            udp_relay: getUdpRelay(proxy),
            sni: proxy.sni,
            skip_tls_verify: proxy["skip-cert-verify"],
            reality: getReality(proxy),
            websocket: proxy.websocket
          };
        } else if (proxy.type === "anytls") {
          proxy = {
            type: "anytls",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            password: proxy.password,
            tfo: getTfo(proxy),
            udp_relay: getUdpRelay(proxy),
            sni: proxy.sni,
            skip_tls_verify: proxy["skip-cert-verify"],
            reality: getReality(proxy)
          };
        } else if (proxy.type === "vmess") {
          const security = normalizeVmessSecurity(proxy.cipher);
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
                path: Array.isArray(
                  proxy["http-opts"]?.path
                ) ? proxy["http-opts"]?.path[0] : proxy["http-opts"]?.path,
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
                headers: getH2Headers(proxy["h2-opts"]),
                sni: proxy.sni,
                skip_tls_verify: proxy["skip-cert-verify"]
              }
            };
          } else if (proxy.network === "grpc") {
            proxy.transport = getGrpcTransport(proxy);
          } else if ((proxy.network === "tcp" || !proxy.network) && proxy.tls) {
            proxy.transport = {
              tls: {
                sni: proxy.tls ? proxy.sni : void 0,
                skip_tls_verify: proxy.tls ? proxy["skip-cert-verify"] : void 0
              }
            };
          }
          let legacy = false;
          if (isPresent2(proxy, "aead") && !proxy.aead) {
            legacy = true;
          } else if (isPresent2(proxy, "alterId") && proxy.alterId !== 0) {
            legacy = true;
          }
          proxy = {
            type: "vmess",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            user_id: proxy.uuid,
            security,
            tfo: getTfo(proxy),
            legacy,
            udp_relay: getUdpRelay(proxy),
            transport: proxy.transport
          };
        } else if (proxy.type === "vless") {
          if (proxy.encryption && proxy.encryption !== "none")
            throw new Error(
              `VLESS encryption is not supported`
            );
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
                path: Array.isArray(
                  proxy["http-opts"]?.path
                ) ? proxy["http-opts"]?.path[0] : proxy["http-opts"]?.path,
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
                headers: getH2Headers(proxy["h2-opts"]),
                sni: proxy.sni,
                skip_tls_verify: proxy["skip-cert-verify"]
              }
            };
          } else if (proxy.network === "grpc") {
            proxy.transport = getGrpcTransport(proxy);
          } else if (proxy.network === "tcp" || !proxy.network) {
            proxy.transport = {
              [proxy.tls ? "tls" : "tcp"]: {
                sni: proxy.tls ? proxy.sni : void 0,
                skip_tls_verify: proxy.tls ? proxy["skip-cert-verify"] : void 0,
                reality: getReality(proxy)
              }
            };
            flow = proxy.flow;
            if (flow === "") flow = void 0;
          }
          proxy = {
            type: "vless",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            user_id: proxy.uuid,
            security: proxy.cipher,
            tfo: getTfo(proxy),
            udp_relay: getUdpRelay(proxy),
            transport: proxy.transport,
            flow
          };
        } else if (proxy.type === "wireguard") {
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
          proxy = {
            type: "wireguard",
            name: proxy.name,
            local_ipv4: getWireGuardAddressWithCIDR(
              proxy,
              "ipv4"
            ),
            local_ipv6: getWireGuardAddressWithCIDR(
              proxy,
              "ipv6"
            ),
            server: proxy.server,
            port: proxy.port,
            private_key: proxy["private-key"],
            peer_public_key: proxy["public-key"],
            preshared_key: proxy["preshared-key"],
            reserved: proxy.reserved ? Array.isArray(proxy.reserved) ? proxy.reserved : proxy.reserved.split(/\s*\/\s*/).map((item) => item.trim()).filter((item) => item.length > 0) : void 0,
            dns_servers: proxy.dns ? Array.isArray(proxy.dns) ? proxy.dns : proxy.dns.split(/\s*,\s*/).map((item) => item.trim()).filter((item) => item.length > 0) : void 0,
            mtu: proxy.mtu,
            keepalive: proxy.keepalive
          };
        } else if (proxy.type === "ssh") {
          proxy = {
            type: "ssh",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            username: proxy.username,
            password: proxy.password,
            private_key: proxy["private-key"],
            // private_key_passphrase: proxy['private-key-passphrase'],
            host_keys: proxy["host-key"],
            tfo: getTfo(proxy)
          };
        } else if (proxy.type === "snell") {
          const snellVersion = normalizeSnellVersion(
            proxy.version
          );
          proxy = {
            type: "snell",
            name: proxy.name,
            server: proxy.server,
            port: proxy.port,
            psk: proxy.psk,
            version: snellVersion,
            ...snellVersion == null || snellVersion >= 3 ? {
              udp_relay: getUdpRelay(proxy)
            } : {},
            reuse: proxy.reuse,
            obfs: proxy["obfs-opts"]?.mode || proxy.obfs,
            obfs_host: proxy["obfs-opts"]?.host || proxy["obfs-host"] || proxy.obfs_host,
            tfo: getTfo(proxy)
          };
        }
        if ([
          "http",
          "https",
          "socks5",
          "ss",
          "trojan",
          "vless",
          "vmess",
          "anytls",
          "ssh"
        ].includes(original.type)) {
          if (["shadow-tls"].includes(original.plugin) && original["plugin-opts"]) {
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
        const fingerprintSha256 = getFingerprintSha256(original);
        if (fingerprintSha256) {
          if (supportsRootFingerprintSha256(original, proxy)) {
            proxy.fingerprint_sha256 = fingerprintSha256;
          }
          addTransportFingerprintSha256(
            proxy.transport,
            fingerprintSha256
          );
        }
        if ([
          "socks5",
          "ss",
          "trojan",
          "vless",
          "vmess",
          "wireguard",
          "tuic",
          "hysteria2",
          "anytls",
          "ssh",
          "snell"
        ].includes(original.type)) {
          if (["on", "true", true, "1", 1].includes(
            original["block-quic"]
          )) {
            proxy.block_quic = true;
          } else if (["off", "false", false, "0", 0].includes(
            original["block-quic"]
          )) {
            proxy.block_quic = false;
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
            if (key !== "grpc" && (Object.keys(proxy.transport[key]).length === 0 || Object.values(proxy.transport[key]).every(
              (value) => value == null
            ))) {
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
      } catch (err) {
        app_default.error(
          `Cannot produce proxy: ${proxy.name}
Reason: ${err}`
        );
        return null;
      }
    }).filter(Boolean);
    return produceProxyListOutput(list, type2, opts);
  };
  return { type, produce: produce2 };
}
function hasHeaders(proxy) {
  return proxy?.headers && typeof proxy.headers === "object" && Object.keys(proxy.headers).length > 0;
}
function getTfo(proxy) {
  return proxy.tfo ?? proxy["fast-open"];
}
function getUdpRelay(proxy) {
  return proxy.udp ?? proxy.udp_relay;
}
function hasShadowTls(proxy) {
  return proxy.plugin === "shadow-tls";
}
function getNonEmptyValue(value) {
  if (value == null) return void 0;
  if (typeof value === "string" && value.length === 0) return void 0;
  return value;
}
function getReality(proxy) {
  const realityOpts = proxy?.["reality-opts"];
  if (!realityOpts) return void 0;
  const reality = {};
  const publicKey = getNonEmptyValue(realityOpts["public-key"]);
  const shortId = getNonEmptyValue(realityOpts["short-id"]);
  if (publicKey != null) reality.public_key = publicKey;
  if (shortId != null) reality.short_id = shortId;
  return Object.keys(reality).length > 0 ? reality : void 0;
}
function getGrpcTransport(proxy) {
  return {
    grpc: {
      service_name: proxy["grpc-opts"]?.["grpc-service-name"],
      sni: proxy.sni,
      reality: getReality(proxy),
      skip_tls_verify: proxy["skip-cert-verify"]
    }
  };
}
function isEgernGrpcGun(proxy) {
  if (proxy.network !== "grpc") return true;
  const grpcType = proxy["grpc-opts"]?.["_grpc-type"];
  if (grpcType == null) return true;
  return `${grpcType}`.trim().toLowerCase() === "gun";
}
function normalizeSnellVersion(version) {
  if (version == null) return void 0;
  const normalized = `${version}`.trim();
  if (!/^[1-5]$/.test(normalized)) return null;
  return parseInt(normalized, 10);
}
function getFirstHeaderValue(headers, ...keys) {
  for (const key of keys) {
    const value = getFirstValue(headers?.[key]);
    if (value) return value;
  }
  return void 0;
}
function getFirstH2Host(h2Opts) {
  return getFirstValue(h2Opts?.host) || getFirstHeaderValue(h2Opts?.headers, "host", "Host");
}
function getH2Headers(h2Opts) {
  const headers = {};
  if (h2Opts?.headers && typeof h2Opts.headers === "object" && !Array.isArray(h2Opts.headers)) {
    for (const [key, value] of Object.entries(h2Opts.headers)) {
      if (/^host$/i.test(key)) continue;
      const headerValue = getFirstValue(value);
      if (headerValue != null) {
        headers[key] = headerValue;
      }
    }
  }
  const host = getFirstH2Host(h2Opts);
  if (host) {
    headers.Host = host;
  }
  return Object.keys(headers).length > 0 ? headers : void 0;
}
function getFirstValue(value) {
  if (Array.isArray(value)) return value[0];
  if (value != null) return value;
  return void 0;
}
function getFingerprintSha256(proxy) {
  const fingerprint = proxy?.["tls-fingerprint"];
  if (typeof fingerprint !== "string") return void 0;
  const trimmedFingerprint = fingerprint.trim();
  return trimmedFingerprint.length > 0 ? trimmedFingerprint : void 0;
}
function supportsRootFingerprintSha256(original, proxy) {
  return ["anytls", "https", "hysteria2", "trojan", "tuic"].includes(
    original.type
  ) || original.type === "socks5" && proxy.type === "socks5_tls" || original.type === "http" && proxy.type === "https";
}
function addTransportFingerprintSha256(transport, fingerprintSha256) {
  if (!transport) return;
  for (const key of ["grpc", "http2", "tls", "wss"]) {
    if (transport[key]) {
      transport[key].fingerprint_sha256 = fingerprintSha256;
    }
  }
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
var preprocessors = preprocessors_default;
function loadProducer(target) {
  const targetLower = target.toLowerCase();
  for (const key of Object.keys(produce)) {
    if (key.toLowerCase() === targetLower) {
      return produce[key];
    }
  }
  return null;
}
async function loadRemoteData(url) {
  try {
    const response = await fetch(url);
    const raw = await response.text();
    for (const preprocessor of preprocessors) {
      try {
        if (preprocessor.test(raw)) {
          return preprocessor.parse(raw).split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
        }
      } catch (error) {
        console.error("Preprocessor error:", error);
      }
    }
    return [];
  } catch (error) {
    console.error("Failed to load remote data:", error);
    return [];
  }
}
function tryParseProxy(parser5, line) {
  try {
    if (parser5.test(line)) {
      return parser5.parse(line);
    }
  } catch {
  }
  return null;
}
function buildProxyServer(proxy, opts) {
  const server = { ...proxy, ...opts };
  if (server.name) {
    server.name = server.name.trim();
  }
  return server;
}
function parseProxyLines(lines, opts) {
  const proxyList = [];
  let lastParser = null;
  for (const line of lines) {
    if (line.length === 0) continue;
    let proxy = null;
    if (lastParser) {
      proxy = tryParseProxy(lastParser, line);
      if (proxy) {
        proxyList.push(buildProxyServer(proxy, opts));
        continue;
      }
    }
    for (const parser5 of parsers) {
      proxy = tryParseProxy(parser5, line);
      if (proxy) {
        proxyList.push(buildProxyServer(proxy, opts));
        lastParser = parser5;
        break;
      }
    }
  }
  return proxyList;
}
function produceOutput(producer, proxyList) {
  if (producer.type === "ALL") {
    return producer.produce(proxyList);
  }
  const results = [];
  for (const proxy of proxyList) {
    try {
      results.push(producer.produce(proxy, proxy.type));
    } catch {
    }
  }
  return results.join("\n");
}
async function convert(url, target, opts = {}) {
  const producer = loadProducer(target);
  if (!producer) {
    throw new Error(`Unknown target: ${target}`);
  }
  const urls = url.split("|");
  const allLines = await Promise.all(urls.map(loadRemoteData));
  const lines = allLines.flat();
  const proxyList = parseProxyLines(lines, opts);
  return produceOutput(producer, proxyList);
}
export {
  buildProxyServer,
  convert,
  loadProducer,
  loadRemoteData,
  parseProxyLines,
  parsers,
  preprocessors,
  produce,
  produceOutput,
  tryParseProxy
};
