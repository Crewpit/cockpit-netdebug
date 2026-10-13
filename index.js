(function () {
    "use strict";

    // Theme sync happens in theme.js, loaded in index.html's <head>.
    // Reusable features live in functions.js (window.App).
    //
    // Every tool below is described by a config (fields + build()) and driven by
    // the same runner: validate -> build argv -> cockpit.spawn with a pty -> stream
    // the output into the page. No shell is ever involved, so a host or option can
    // never be interpreted as anything but an argument.

    var el = App.el;

    var MENU = {
        label: "NetDebug",
        items: [
            { label: "Ping", path: "/ping", pane: "pane-ping", onShow: function () { focusHost("ping") } },
            { label: "Traceroute", path: "/traceroute", pane: "pane-traceroute", onShow: function () { focusHost("traceroute") } },
            { label: "iPerf3", path: "/iperf3", pane: "pane-iperf3", onShow: function () { focusHost("iperf3") } },
            {
                label: "Port Check", path: "/portcheck", pane: "pane-portcheck", onShow: function () { focusHost("portcheck") },
                children: [
                    { label: "Port Scan", path: "/portcheck/scan", pane: "pane-portscan", onShow: function () { focusHost("portscan") } },
                ],
            },
            { label: "DNS Lookup", path: "/dns", pane: "pane-dns", onShow: function () { focusHost("dns") } },
        ],
    };

    // ------------------------------------------------------------------
    // Validation helpers. Each throws an Error whose message is shown to the user.
    // ------------------------------------------------------------------

    // Hostname, IPv4 or IPv6 (with optional %zone). Must not start with "-", so it
    // can never be taken for an option.
    var HOST_RE = /^[A-Za-z0-9_][A-Za-z0-9._:%-]*$/;

    function host(value) {
        var h = String(value).trim();
        if (!h)
            throw new Error("Enter a host name or IP address.");
        if (h.length > 253 || !HOST_RE.test(h))
            throw new Error("\"" + h + "\" is not a valid host name or IP address.");
        return h;
    }

    // Empty -> null (option left out). Otherwise a number within min..max.
    function num(value, label, min, max, whole) {
        var s = String(value).trim();
        if (s === "")
            return null;
        var n = Number(s);
        if (!isFinite(n) || n < min || n > max || (whole && Math.floor(n) !== n))
            throw new Error(label + " must be " + (whole ? "a whole number" : "a number") + " from " + min + " to " + max + ".");
        return n;
    }

    // iperf3 sizes/rates: 100, 100K, 10M, 1.5G
    function size(value, label, re) {
        var s = String(value).trim();
        if (s === "")
            return null;
        if (!re.test(s))
            throw new Error(label + " looks like \"100\", \"100K\", \"10M\" or \"1G\".");
        return s;
    }

    // "22, 80,8000-8010" -> "22,80,8000-8010" (numbers normalised), at most `max` ports.
    function ports(value, max) {
        var items = String(value).replace(/\s+/g, "").split(",").filter(Boolean);
        if (!items.length)
            throw new Error("Enter at least one port, e.g. 443 or 22,80,8000-8010.");
        var total = 0;
        var out = items.map(function (item) {
            var m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(item);
            var lo = m ? Number(m[1]) : 0;
            var hi = m && m[2] ? Number(m[2]) : lo;
            if (!m || lo < 1 || hi > 65535 || hi < lo)
                throw new Error("\"" + item + "\" is not a valid port or range (1-65535).");
            total += hi - lo + 1;
            return lo === hi ? String(lo) : lo + "-" + hi;
        });
        if (total > max)
            throw new Error("That is " + total + " ports; at most " + max + " are allowed here.");
        return out.join(",");
    }

    // A host, or a CIDR range (nmap). Ranges bigger than a /16 are refused.
    function target(value) {
        var t = String(value).trim();
        var m = /^(.*)\/(\d{1,3})$/.exec(t);
        if (!m)
            return host(t);
        var base = host(m[1]);
        var bits = Number(m[2]);
        var v6 = base.indexOf(":") !== -1;
        if (bits > (v6 ? 128 : 32) || bits < (v6 ? 112 : 16))
            throw new Error("Ranges must be between /16 and /32 (IPv6: /112 to /128), to avoid accidental huge scans.");
        return base + "/" + bits;
    }

    var DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA", "DS", "DNSKEY", "ANY"];

    var FAMILY = [["", "Automatic"], ["4", "IPv4 Only"], ["6", "IPv6 Only"]];

    // ------------------------------------------------------------------
    // Tool configs.
    //   fields: key, label, type (text|number|select|checkbox), value (default),
    //           placeholder, help, options ([value, label]), span (full row)
    //   build(values) -> { argv, superuser }
    // ------------------------------------------------------------------

    var TOOLS = {
        ping: {
            id: "ping", bin: "ping",
            fields: [
                { key: "host", label: "Host", type: "text", value: "1.1.1.1", placeholder: "example.com or 1.1.1.1", span: true },
                { key: "count", label: "Count", type: "number", value: "4", help: "Echo requests to send" },
                {
                    key: "infinite", label: "Infinite Test", type: "checkbox", value: false,
                    help: "Keeps going until you press Stop (or leave the page)", disables: ["count", "deadline"],
                },
                { key: "interval", label: "Interval (s)", type: "number", value: "1", help: "Under 0.2 needs root" },
                { key: "size", label: "Payload Size (bytes)", type: "number", value: "56" },
                { key: "ttl", label: "TTL", type: "number", value: "", placeholder: "system default" },
                { key: "wait", label: "Reply Timeout (s)", type: "number", value: "2" },
                { key: "deadline", label: "Total Timeout (s)", type: "number", value: "", placeholder: "none" },
                { key: "family", label: "IP Version", type: "select", value: "", options: FAMILY },
                { key: "df", label: "Don't Fragment", type: "checkbox", value: false, help: "Set the DF bit, for MTU probing" },
            ],
            build: function (v) {
                var argv = ["ping"];
                if (v.family)
                    argv.push("-" + v.family);
                var n;
                if (!v.infinite && (n = num(v.count, "Count", 1, 100000, true)))
                    argv.push("-c", String(n));
                if ((n = num(v.interval, "Interval", 0.2, 60)) !== null)
                    argv.push("-i", String(n));
                if ((n = num(v.size, "Payload size", 0, 65507, true)) !== null)
                    argv.push("-s", String(n));
                if ((n = num(v.ttl, "TTL", 1, 255, true)) !== null)
                    argv.push("-t", String(n));
                if ((n = num(v.wait, "Reply timeout", 1, 60, true)) !== null)
                    argv.push("-W", String(n));
                if (!v.infinite && (n = num(v.deadline, "Total timeout", 1, 86400, true)) !== null)
                    argv.push("-w", String(n));
                if (v.df)
                    argv.push("-M", "do");
                argv.push(host(v.host));
                return { argv: argv };
            },
            // Live reply statistics, parsed from "... time=12.3 ms" lines.
            stats: [["replies", "Replies"], ["last", "Last"], ["min", "Min"], ["avg", "Avg"], ["max", "Max"]],
            parse: function (line, st) {
                var m = /\btime[=<]([\d.]+)\s*ms/.exec(line);
                if (!m || !/icmp_seq=/.test(line))
                    return;
                var t = parseFloat(m[1]);
                st.n = (st.n || 0) + 1;
                st.sum = (st.sum || 0) + t;
                st.last = t;
                st.min = st.min === undefined ? t : Math.min(st.min, t);
                st.max = st.max === undefined ? t : Math.max(st.max, t);
            },
            format: function (st) {
                function ms(v) { return v === undefined ? "-" : v.toFixed(1) + " ms" }
                return {
                    replies: String(st.n || 0), last: ms(st.last), min: ms(st.min),
                    avg: st.n ? ms(st.sum / st.n) : "-", max: ms(st.max),
                };
            },
        },

        traceroute: {
            id: "traceroute", bin: "traceroute",
            fields: [
                { key: "host", label: "Host", type: "text", value: "1.1.1.1", placeholder: "example.com or 1.1.1.1", span: true },
                {
                    key: "method", label: "Method", type: "select", value: "udp",
                    options: [["udp", "UDP (Default)"], ["icmp", "ICMP (Needs Admin)"], ["tcp", "TCP (Needs Admin)"]],
                },
                { key: "port", label: "Port", type: "number", value: "", placeholder: "method default", help: "TCP: destination port. UDP: starting port" },
                { key: "maxhops", label: "Max Hops", type: "number", value: "30" },
                { key: "queries", label: "Queries per Hop", type: "number", value: "3" },
                { key: "wait", label: "Wait per Probe (s)", type: "number", value: "3" },
                { key: "first", label: "First Hop (TTL)", type: "number", value: "1" },
                { key: "family", label: "IP Version", type: "select", value: "", options: FAMILY },
                { key: "nodns", label: "Don't Resolve Names", type: "checkbox", value: false, help: "Faster, shows addresses only" },
            ],
            build: function (v) {
                var argv = ["traceroute"];
                if (v.family)
                    argv.push("-" + v.family);
                if (v.method === "icmp")
                    argv.push("-I");
                else if (v.method === "tcp")
                    argv.push("-T");
                var n;
                if ((n = num(v.port, "Port", 1, 65535, true)) !== null)
                    argv.push("-p", String(n));
                if ((n = num(v.maxhops, "Max hops", 1, 255, true)) !== null)
                    argv.push("-m", String(n));
                if ((n = num(v.queries, "Queries per hop", 1, 10, true)) !== null)
                    argv.push("-q", String(n));
                if ((n = num(v.wait, "Wait per probe", 0.5, 60)) !== null)
                    argv.push("-w", String(n));
                if ((n = num(v.first, "First hop", 1, 255, true)) !== null)
                    argv.push("-f", String(n));
                if (v.nodns)
                    argv.push("-n");
                argv.push(host(v.host));
                return { argv: argv, superuser: v.method !== "udp" };
            },
        },

        iperf3: {
            id: "iperf3", bin: "iperf3",
            fields: [
                { key: "host", label: "Server", type: "text", value: "", placeholder: "iperf3 server host or IP", span: true },
                { key: "port", label: "Port", type: "number", value: "5201" },
                { key: "time", label: "Duration (s)", type: "number", value: "10" },
                {
                    key: "infinite", label: "Infinite Test", type: "checkbox", value: false,
                    help: "Keeps going until you press Stop (or leave the page)", disables: ["time"],
                },
                { key: "parallel", label: "Parallel Streams", type: "number", value: "1" },
                { key: "proto", label: "Protocol", type: "select", value: "tcp", options: [["tcp", "TCP"], ["udp", "UDP"]] },
                { key: "bitrate", label: "Target Bitrate", type: "text", value: "", placeholder: "default (UDP: 1M)", help: "e.g. 100M" },
                { key: "length", label: "Buffer Length", type: "text", value: "", placeholder: "default (128K TCP)" },
                { key: "window", label: "TCP Window", type: "text", value: "", placeholder: "system default" },
                { key: "omit", label: "Omit Warm-up (s)", type: "number", value: "0" },
                { key: "interval", label: "Report Interval (s)", type: "number", value: "1" },
                {
                    key: "format", label: "Units", type: "select", value: "",
                    options: [["", "Automatic"], ["k", "Kbits/s"], ["m", "Mbits/s"], ["g", "Gbits/s"], ["K", "KBytes/s"], ["M", "MBytes/s"], ["G", "GBytes/s"]],
                },
                { key: "family", label: "IP Version", type: "select", value: "", options: FAMILY },
                { key: "reverse", label: "Reverse (Server Sends)", type: "checkbox", value: false, help: "Tests the download direction" },
                { key: "bidir", label: "Bidirectional", type: "checkbox", value: false, help: "Both directions at once (iperf3 3.7+)" },
            ],
            build: function (v) {
                if (v.reverse && v.bidir)
                    throw new Error("Reverse and Bidirectional can't be combined; pick one.");
                var argv = ["iperf3", "-c", host(v.host)];
                var n, s;
                if ((n = num(v.port, "Port", 1, 65535, true)) !== null)
                    argv.push("-p", String(n));
                if (v.infinite)
                    argv.push("-t", "0");
                else if ((n = num(v.time, "Duration", 1, 86400, true)) !== null)
                    argv.push("-t", String(n));
                if ((n = num(v.parallel, "Parallel streams", 1, 128, true)) !== null)
                    argv.push("-P", String(n));
                if (v.proto === "udp")
                    argv.push("-u");
                if ((s = size(v.bitrate, "Target bitrate", /^\d+(\.\d+)?[KkMmGg]?$/)) !== null)
                    argv.push("-b", s);
                if ((s = size(v.length, "Buffer length", /^\d+[KkMm]?$/)) !== null)
                    argv.push("-l", s);
                if ((s = size(v.window, "TCP window", /^\d+[KkMm]?$/)) !== null)
                    argv.push("-w", s);
                if ((n = num(v.omit, "Warm-up", 0, 60, true)) !== null && n > 0)
                    argv.push("-O", String(n));
                if ((n = num(v.interval, "Report interval", 0.1, 60)) !== null)
                    argv.push("-i", String(n));
                if (v.format)
                    argv.push("-f", v.format);
                if (v.family)
                    argv.push("-" + v.family);
                if (v.reverse)
                    argv.push("-R");
                if (v.bidir)
                    argv.push("--bidir");
                // Without a pty-friendly flush iperf3 can hold its report lines back.
                argv.push("--forceflush");
                return { argv: argv };
            },
        },

        portcheck: {
            id: "portcheck", bin: "nc",
            fields: [
                { key: "host", label: "Host", type: "text", value: "1.1.1.1", placeholder: "example.com or 192.0.2.10", span: true },
                { key: "port", label: "Port", type: "number", value: "443" },
                { key: "proto", label: "Protocol", type: "select", value: "tcp", options: [["tcp", "TCP"], ["udp", "UDP"]] },
                { key: "timeout", label: "Timeout (s)", type: "number", value: "3", help: "UDP: open means no \"unreachable\" came back" },
            ],
            build: function (v) {
                var argv = ["nc", "-z", "-v"];
                var t = num(v.timeout, "Timeout", 1, 60, true);
                if (t !== null)
                    argv.push("-w", String(t));
                if (v.proto === "udp")
                    argv.push("-u");
                var p = num(v.port, "Port", 1, 65535, true);
                if (p === null)
                    throw new Error("Enter a port from 1 to 65535.");
                argv.push(host(v.host), String(p));
                return { argv: argv };
            },
        },

        portscan: {
            id: "portscan", bin: "nmap",
            fields: [
                {
                    key: "host", label: "Target", type: "text", value: "127.0.0.1", span: true,
                    placeholder: "host, IP or range like 192.168.1.0/24", help: "Only scan systems you are allowed to test",
                },
                {
                    key: "portset", label: "Ports", type: "select", value: "common",
                    options: [["common", "Common (Top 1000)"], ["fast", "Fast (Top 100)"], ["custom", "Custom List"], ["all", "All (1-65535)"]],
                },
                { key: "ports", label: "Custom Ports", type: "text", value: "22,80,443", placeholder: "22,80,8000-8010", disabledWhen: function (v) { return v.portset !== "custom" } },
                {
                    key: "scan", label: "Scan Type", type: "select", value: "connect",
                    options: [["connect", "TCP Connect (No Admin)"], ["syn", "TCP SYN (Needs Admin)"], ["udp", "UDP (Needs Admin, Slow)"]],
                },
                {
                    key: "timing", label: "Speed", type: "select", value: "",
                    options: [["", "Normal"], ["2", "Polite (Slower)"], ["4", "Aggressive (Faster)"], ["5", "Insane (Fastest, Noisy)"]],
                },
                { key: "version", label: "Detect Service Versions", type: "checkbox", value: true, help: "Shows what is running on each open port" },
                { key: "os", label: "Detect OS", type: "checkbox", value: false, help: "Needs administrative access" },
                { key: "scripts", label: "Run Default Scripts", type: "checkbox", value: false, help: "nmap's safe default script set" },
                { key: "pn", label: "Skip Host Discovery", type: "checkbox", value: false, help: "For hosts that ignore ping" },
                { key: "nodns", label: "Don't Resolve Names", type: "checkbox", value: false },
                { key: "ipv6", label: "IPv6", type: "checkbox", value: false },
                { key: "openOnly", label: "Show Open Ports Only", type: "checkbox", value: true },
            ],
            build: function (v) {
                var argv = ["nmap", "-v", "--stats-every", "5s"];
                var admin = false;
                if (v.scan === "syn") {
                    argv.push("-sS");
                    admin = true;
                } else if (v.scan === "udp") {
                    argv.push("-sU");
                    admin = true;
                } else {
                    argv.push("-sT");
                }
                if (v.portset === "fast")
                    argv.push("-F");
                else if (v.portset === "all")
                    argv.push("-p-");
                else if (v.portset === "custom")
                    argv.push("-p", ports(v.ports, 65535));
                if (v.timing)
                    argv.push("-T" + v.timing);
                if (v.version)
                    argv.push("-sV");
                if (v.os) {
                    argv.push("-O");
                    admin = true;
                }
                if (v.scripts)
                    argv.push("-sC");
                if (v.pn)
                    argv.push("-Pn");
                if (v.nodns)
                    argv.push("-n");
                if (v.ipv6)
                    argv.push("-6");
                if (v.openOnly)
                    argv.push("--open");
                argv.push(target(v.host));
                return { argv: argv, superuser: admin };
            },
            // Summary, built from nmap's normal output as it streams in.
            stats: [["up", "Hosts Up"], ["open", "Open"], ["filtered", "Filtered"], ["closed", "Closed"], ["hidden", "Not Shown"], ["time", "Duration"]],
            active: function (st) { return !!(st.rows && st.rows.length) || st.up !== undefined },
            parse: function (line, st) {
                st.rows = st.rows || [];
                st.index = st.index || {};
                var m;
                function add(row) {
                    // "name (1.2.3.4)" and the bare "1.2.3.4" of the live hint are the same host.
                    var ip = /\(([^)]+)\)\s*$/.exec(row.host);
                    var key = (ip ? ip[1] : row.host) + "|" + row.port + "/" + row.proto;
                    if (st.index[key])
                        Object.assign(st.index[key], row);
                    else
                        st.rows.push(st.index[key] = row);
                }
                if ((m = /^Nmap scan report for (.+)$/.exec(line))) {
                    st.host = m[1];
                } else if ((m = /^Discovered open port (\d+)\/(\w+) on (\S+)/.exec(line))) {
                    // Live hint; the final table line below fills in service and version.
                    add({ host: st.host || m[3], port: Number(m[1]), proto: m[2], state: "open", service: "", version: "" });
                } else if ((m = /^(\d+)\/(tcp|udp|sctp)\s+(\S+)\s+(.+?)\s*$/.exec(line))) {
                    var rest = m[4].split(/\s+/);
                    add({ host: st.host || "", port: Number(m[1]), proto: m[2], state: m[3], service: rest.shift(), version: rest.join(" ") });
                } else if ((m = /^Not shown: (\d+)/.exec(line)) || (m = /^All (\d+) scanned ports on .* are in ignored states/.exec(line))) {
                    st.hidden = (st.hidden || 0) + Number(m[1]);
                } else if ((m = /^Nmap done: .*\((\d+) hosts? up\) scanned in ([\d.]+) seconds/.exec(line))) {
                    st.up = Number(m[1]);
                    st.time = m[2] + " s";
                }
            },
            format: function (st) {
                var rows = st.rows || [];
                function count(test) { return String(rows.filter(function (r) { return test(r.state) }).length) }
                return {
                    up: st.up === undefined ? "-" : String(st.up),
                    open: count(function (x) { return x === "open" }),
                    filtered: count(function (x) { return x.indexOf("filtered") !== -1 }),
                    closed: count(function (x) { return x === "closed" }),
                    hidden: st.hidden === undefined ? "-" : String(st.hidden),
                    time: st.time || "-",
                };
            },
            table: {
                caption: "Port scan results",
                emptyText: "No ports found yet",
                sort: { key: "port", dir: "asc" },
                columns: [
                    { key: "host", label: "Host" },
                    { key: "port", label: "Port", numeric: true },
                    { key: "proto", label: "Protocol" },
                    {
                        key: "state", label: "State",
                        render: function (v) {
                            return stateLabel(v);
                        },
                    },
                    { key: "service", label: "Service" },
                    { key: "version", label: "Version" },
                ],
            },
            rows: function (st) { return st.rows || [] },
            summaryText: function (st) {
                var shown = this.format(st);
                var lines = ["Hosts up: " + shown.up + "  Open: " + shown.open + "  Filtered: " + shown.filtered +
                             "  Closed: " + shown.closed + "  Not shown: " + shown.hidden + "  Duration: " + shown.time];
                (st.rows || []).forEach(function (r) {
                    lines.push([r.host, r.port + "/" + r.proto, r.state, r.service, r.version].filter(Boolean).join("  "));
                });
                return lines.join("\n");
            },
        },

        dns: {
            id: "dns", bin: "dig",
            fields: [
                { key: "name", label: "Name", type: "text", value: "example.com", placeholder: "example.com, or an IP with Reverse Lookup", span: true },
                {
                    key: "type", label: "Record Type", type: "select", value: "A",
                    options: DNS_TYPES.map(function (t) { return [t, t] }),
                },
                { key: "server", label: "DNS Server", type: "text", value: "", placeholder: "system default resolver", help: "e.g. 1.1.1.1 or dns.google" },
                { key: "port", label: "Server Port", type: "number", value: "53" },
                { key: "timeout", label: "Timeout (s)", type: "number", value: "5" },
                { key: "tries", label: "Tries", type: "number", value: "2" },
                { key: "family", label: "IP Version", type: "select", value: "", options: FAMILY },
                { key: "reverse", label: "Reverse Lookup", type: "checkbox", value: false, help: "Look up the name for an IP address" },
                { key: "short", label: "Short Answer", type: "checkbox", value: false, help: "Only the answer data" },
                { key: "tcp", label: "Use TCP", type: "checkbox", value: false },
                { key: "dnssec", label: "Request DNSSEC", type: "checkbox", value: false },
                { key: "trace", label: "Trace from Root", type: "checkbox", value: false, help: "Follow delegation from the root servers" },
            ],
            build: function (v) {
                var argv = ["dig"];
                if (v.family)
                    argv.push("-" + v.family);
                if (v.server.trim())
                    argv.push("@" + host(v.server));
                var n = num(v.port, "Server port", 1, 65535, true);
                if (n !== null && n !== 53)
                    argv.push("-p", String(n));
                if (v.reverse) {
                    argv.push("-x", host(v.name));
                } else {
                    if (DNS_TYPES.indexOf(v.type) === -1)
                        throw new Error("Unknown record type.");
                    argv.push(host(v.name), v.type);
                }
                if ((n = num(v.timeout, "Timeout", 1, 60, true)) !== null)
                    argv.push("+time=" + n);
                if ((n = num(v.tries, "Tries", 1, 10, true)) !== null)
                    argv.push("+tries=" + n);
                if (v.tcp)
                    argv.push("+tcp");
                if (v.short)
                    argv.push("+short");
                if (v.dnssec)
                    argv.push("+dnssec");
                if (v.trace)
                    argv.push("+trace");
                return { argv: argv };
            },
        },
    };

    // ------------------------------------------------------------------
    // Small persistence helpers. localStorage can be blocked: always optional.
    // ------------------------------------------------------------------

    function loadJSON(key, fallback) {
        try {
            var raw = window.localStorage.getItem(key);
            return raw ? JSON.parse(raw) : fallback;
        } catch (ex) {
            return fallback;
        }
    }

    function saveJSON(key, value) {
        try {
            window.localStorage.setItem(key, JSON.stringify(value));
        } catch (ex) { /* optional */ }
    }

    var MAX_HOSTS = 12;
    var recentHosts = loadJSON("netdebug:hosts", []);

    function renderHosts() {
        var list = document.getElementById("nd-hosts");
        list.replaceChildren.apply(list, recentHosts.map(function (h) { return el("option", { value: h }) }));
    }

    function rememberHost(h) {
        recentHosts = [h].concat(recentHosts.filter(function (x) { return x !== h })).slice(0, MAX_HOSTS);
        saveJSON("netdebug:hosts", recentHosts);
        renderHosts();
    }

    // ------------------------------------------------------------------
    // Form building
    // ------------------------------------------------------------------

    function chevron() {
        var ns = "http://www.w3.org/2000/svg";
        var svg = document.createElementNS(ns, "svg");
        svg.setAttribute("viewBox", "0 0 320 512");
        svg.setAttribute("width", "1em");
        svg.setAttribute("height", "1em");
        svg.setAttribute("fill", "currentColor");
        svg.setAttribute("aria-hidden", "true");
        var path = document.createElementNS(ns, "path");
        path.setAttribute("d", "M31.3 192h257.3c17.8 0 26.7 21.5 14.1 34.1L174.1 354.8c-7.8 7.8-20.5 7.8-28.3 0L17.2 226.1C4.6 213.5 13.5 192 31.3 192z");
        svg.appendChild(path);
        return svg;
    }

    function helper(text) {
        return el("div", { class: "pf-v6-c-helper-text" }, [
            el("div", { class: "pf-v6-c-helper-text__item" }, [
                el("span", { class: "pf-v6-c-helper-text__item-text", text: text }),
            ]),
        ]);
    }

    // Returns { node, input } for one field.
    function buildField(tool, f) {
        var id = "nd-" + tool.id + "-" + f.key;
        var group = el("div", { class: "pf-v6-c-form__group" + (f.span ? " nd-span" : "") + (f.type === "checkbox" ? " nd-check" : "") });
        var input;
        var control;

        if (f.type === "checkbox") {
            input = el("input", { class: "pf-v6-c-check__input", type: "checkbox", id: id });
            control = el("div", { class: "pf-v6-c-check" }, [input, el("label", { class: "pf-v6-c-check__label", for: id, text: f.label })]);
            group.appendChild(el("div", { class: "pf-v6-c-form__group-control" }, [control].concat(f.help ? [helper(f.help)] : [])));
            return { node: group, input: input };
        }

        group.appendChild(el("div", { class: "pf-v6-c-form__group-label" }, [
            el("label", { class: "pf-v6-c-form__label", for: id }, [el("span", { class: "pf-v6-c-form__label-text", text: f.label })]),
        ]));

        if (f.type === "select") {
            input = el("select", { id: id });
            f.options.forEach(function (o) { input.appendChild(el("option", { value: o[0], text: o[1] })) });
            control = el("span", { class: "pf-v6-c-form-control" }, [
                input,
                el("span", { class: "pf-v6-c-form-control__utilities" }, [
                    el("span", { class: "pf-v6-c-form-control__toggle-icon" }, [chevron()]),
                ]),
            ]);
        } else {
            input = el("input", { type: f.type === "number" ? "number" : "text", id: id, autocomplete: "off", spellcheck: "false" });
            if (f.type === "number")
                input.setAttribute("step", "any");
            if (f.placeholder)
                input.setAttribute("placeholder", f.placeholder);
            if (f.key === "host")
                input.setAttribute("list", "nd-hosts");
            control = el("span", { class: "pf-v6-c-form-control" }, [input]);
        }
        group.appendChild(el("div", { class: "pf-v6-c-form__group-control" }, [control].concat(f.help ? [helper(f.help)] : [])));
        return { node: group, input: input };
    }

    // ------------------------------------------------------------------
    // Runner
    // ------------------------------------------------------------------

    var MAX_OUTPUT = 400000; // characters kept on screen (and in Copy)
    var sessions = {};

    function quote(arg) {
        return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : "'" + arg.replace(/'/g, "'\\''") + "'";
    }

    function setLabel(node, text, color) {
        node.replaceChildren(el("span", { class: "pf-v6-c-label" + (color ? " pf-m-" + color : "") }, [
            el("span", { class: "pf-v6-c-label__content" }, [el("span", { class: "pf-v6-c-label__text", text: text })]),
        ]));
    }

    function stateLabel(state) {
        var color = state === "open" ? "green" : state === "closed" ? "red" : "orange";
        return el("span", { class: "pf-v6-c-label pf-m-" + color }, [
            el("span", { class: "pf-v6-c-label__content" }, [el("span", { class: "pf-v6-c-label__text", text: state })]),
        ]);
    }

    // Copies text and flips the button's label to "Copied!" for a moment.
    function copyText(text, button) {
        if (!text) {
            App.alerts.toast("warning", "Nothing to copy yet");
            return;
        }
        App.clipboard.copy(text).then(function () {
            if (!button.dataset.label)
                button.dataset.label = button.textContent;
            button.textContent = "Copied!";
            window.setTimeout(function () { button.textContent = button.dataset.label }, 1500);
        }).catch(function (ex) {
            App.alerts.toast("danger", "Copy failed", { description: ex.message });
        });
    }

    function mountTool(tool) {
        var s = {
            tool: tool, inputs: {}, proc: null, running: false, stopping: false, started: 0, poller: null,
            chunks: [], length: 0, partial: "", stats: {}, dirty: false, frame: 0,
            fieldsEl: document.getElementById("nd-" + tool.id + "-fields"),
            actionsEl: document.getElementById("nd-" + tool.id + "-actions"),
            statusEl: document.getElementById("nd-" + tool.id + "-status"),
            cmdEl: document.getElementById("nd-" + tool.id + "-cmd"),
            cmdCopy: document.getElementById("nd-" + tool.id + "-cmd-copy"),
            cmdText: "",
            outCopy: document.getElementById("nd-" + tool.id + "-copy"),
            summaryEl: document.getElementById("nd-" + tool.id + "-summary"),
            outEl: document.getElementById("nd-" + tool.id + "-out"),
            scrollEl: document.getElementById("nd-" + tool.id + "-scroll"),
            boxEl: document.getElementById("nd-" + tool.id + "-scroll").closest(".nd-output"),
            statsEl: document.getElementById("nd-" + tool.id + "-stats"),
            alertId: "nd-" + tool.id + "-alert",
        };
        sessions[tool.id] = s;

        var grid = el("div", { class: "nd-grid" });
        tool.fields.forEach(function (f) {
            var built = buildField(tool, f);
            s.inputs[f.key] = built.input;
            grid.appendChild(built.node);
        });
        s.fieldsEl.appendChild(grid);

        s.start = el("button", { class: "pf-v6-c-button pf-m-primary", type: "submit", text: "Start" });
        s.stop = el("button", { class: "pf-v6-c-button pf-m-danger", type: "button", text: "Stop" });
        s.stop.disabled = true;
        var follow = el("input", { class: "pf-v6-c-check__input", type: "checkbox", id: "nd-" + tool.id + "-follow" });
        follow.checked = true;
        s.follow = follow;
        var clear = el("button", { class: "pf-v6-c-button pf-m-link", type: "button", text: "Clear" });
        var reset = el("button", { class: "pf-v6-c-button pf-m-link", type: "button", text: "Reset Defaults" });
        s.reset = reset;
        s.actionsEl.appendChild(el("div", { class: "app-btn-group nd-actions__main" }, [s.start, s.stop]));
        s.actionsEl.appendChild(el("div", { class: "nd-actions__side" }, [
            el("div", { class: "pf-v6-c-check" }, [follow, el("label", { class: "pf-v6-c-check__label", for: follow.id, text: "Follow Output" })]),
            clear, reset,
        ]));

        s.statNodes = {};
        if (s.statsEl) {
            tool.stats.forEach(function (st) {
                var value = el("strong", { id: "nd-" + tool.id + "-stat-" + st[0], text: "-" });
                s.statNodes[st[0]] = value;
                s.statsEl.appendChild(el("span", { class: "nd-stat" }, [
                    el("span", { class: "app-muted", text: st[1] + " " }),
                    value,
                ]));
            });
        }

        if (tool.table)
            s.table = App.table.create({
                container: "nd-" + tool.id + "-table",
                caption: tool.table.caption,
                columns: tool.table.columns,
                sort: tool.table.sort,
                emptyText: tool.table.emptyText,
            });
        showStats(s);

        restore(s);
        applyDisables(s);
        updatePreview(s);
        setLabel(s.statusEl, "Idle");

        function changed() {
            applyDisables(s);
            updatePreview(s);
            persist(s);
        }
        s.fieldsEl.addEventListener("input", changed);
        s.fieldsEl.addEventListener("change", changed);
        document.getElementById("nd-" + tool.id + "-form").addEventListener("submit", function (ev) {
            ev.preventDefault();
            if (!s.running)
                start(s);
        });
        s.stop.addEventListener("click", function () { stop(s) });
        clear.addEventListener("click", function () { clearOutput(s) });
        reset.addEventListener("click", function () { defaults(s); changed() });
        s.cmdCopy.addEventListener("click", function () { copyText(s.cmdText, s.cmdCopy) });
        s.outCopy.addEventListener("click", function () { copyText(s.chunks.join(""), s.outCopy) });
        var copySummary = document.getElementById("nd-" + tool.id + "-copysummary");
        if (copySummary)
            copySummary.addEventListener("click", function () { copyText(tool.summaryText(s.stats), copySummary) });
    }

    function defaults(s) {
        s.tool.fields.forEach(function (f) {
            var input = s.inputs[f.key];
            if (f.type === "checkbox")
                input.checked = !!f.value;
            else
                input.value = f.value;
        });
    }

    // "Infinite Test" and friends grey out the fields they make irrelevant.
    function applyDisables(s) {
        var v = values(s);
        s.tool.fields.forEach(function (f) {
            if (f.disables) {
                var on = s.inputs[f.key].checked;
                f.disables.forEach(function (key) { s.inputs[key].disabled = on });
            }
            if (f.disabledWhen)
                s.inputs[f.key].disabled = f.disabledWhen(v);
        });
    }

    function values(s) {
        var v = {};
        s.tool.fields.forEach(function (f) {
            var input = s.inputs[f.key];
            v[f.key] = f.type === "checkbox" ? input.checked : input.value;
        });
        return v;
    }

    function persist(s) {
        saveJSON("netdebug:" + s.tool.id, values(s));
    }

    function restore(s) {
        defaults(s);
        var saved = loadJSON("netdebug:" + s.tool.id, null);
        if (!saved || typeof saved !== "object")
            return;
        s.tool.fields.forEach(function (f) {
            if (!(f.key in saved))
                return;
            if (f.type === "checkbox")
                s.inputs[f.key].checked = !!saved[f.key];
            else
                s.inputs[f.key].value = String(saved[f.key]);
        });
    }

    // The command as you would type it in a terminal ("sudo" where it needs root).
    function updatePreview(s) {
        try {
            var built = s.tool.build(values(s));
            s.cmdText = (built.superuser ? "sudo " : "") + built.argv.map(quote).join(" ");
            s.cmdEl.value = s.cmdText;
            s.cmdEl.classList.remove("nd-cmd--invalid");
            s.cmdCopy.disabled = false;
        } catch (ex) {
            s.cmdText = "";
            s.cmdEl.value = ex.message;
            s.cmdEl.classList.add("nd-cmd--invalid");
            s.cmdCopy.disabled = true;
        }
    }

    function focusHost(id) {
        var s = sessions[id];
        if (s && !s.running && s.inputs.host)
            window.setTimeout(function () { s.inputs.host.focus() }, 0);
    }

    // ---- output ------------------------------------------------------

    // The output box turns red when a run ends in any kind of error.
    function markError(s, failed) {
        s.boxEl.classList.toggle("is-error", !!failed);
    }

    function clearOutput(s) {
        markError(s, false);
        s.outEl.textContent = "";
        s.chunks = [];
        s.length = 0;
        s.partial = "";
        s.stats = {};
        s.dirty = false;
        window.cancelAnimationFrame(s.frame);
        s.frame = 0;
        showStats(s);
    }

    function showStats(s) {
        var tool = s.tool;
        if (!tool.format)
            return;
        var active = tool.active ? tool.active(s.stats) : !!s.stats.n;
        if (s.statsEl)
            s.statsEl.hidden = !active;
        if (s.summaryEl)
            s.summaryEl.hidden = !active;
        var shown = tool.format(s.stats);
        Object.keys(s.statNodes).forEach(function (key) {
            s.statNodes[key].textContent = shown[key];
        });
        if (s.table)
            s.table.setRows(tool.rows(s.stats));
    }

    // Stats, the results table and the scroll position are redrawn at most once per
    // animation frame, however many chunks the process printed in between. Text itself
    // is appended straight away, so nothing is ever held back.
    function flush(s) {
        window.cancelAnimationFrame(s.frame);
        s.frame = 0;
        if (s.dirty) {
            s.dirty = false;
            showStats(s);
        }
        if (s.follow.checked)
            s.scrollEl.scrollTop = s.scrollEl.scrollHeight;
    }

    function append(s, text) {
        if (!text)
            return;
        // A pty turns line ends into CR LF; a lone CR is a progress redraw.
        text = text.replace(/\r\n/g, "\n").replace(/\r/g, "");
        s.chunks.push(text);
        s.length += text.length;
        s.outEl.appendChild(document.createTextNode(text));
        while (s.length > MAX_OUTPUT && s.chunks.length > 1) {
            s.length -= s.chunks.shift().length;
            s.outEl.removeChild(s.outEl.firstChild);
        }

        if (s.tool.parse) {
            var lines = (s.partial + text).split("\n");
            s.partial = lines.pop();
            lines.forEach(function (line) { s.tool.parse(line, s.stats) });
            s.dirty = true;
        }
        if (!s.frame)
            s.frame = window.requestAnimationFrame(function () { flush(s) });
    }

    // ---- lifecycle ----------------------------------------------------

    function setRunning(s, running) {
        s.running = running;
        s.start.disabled = running;
        s.stop.disabled = !running;
        s.fieldsEl.disabled = running;
        s.reset.disabled = running;
    }

    function elapsed(s) {
        return Math.round((Date.now() - s.started) / 1000) + " s";
    }

    function start(s) {
        var built;
        var v = values(s);
        App.alerts.inline(s.alertId);
        try {
            built = s.tool.build(v);
        } catch (ex) {
            App.alerts.inline(s.alertId, "danger", "Check the parameters", ex.message);
            return;
        }
        // Only tools with a "host" field feed the recent-hosts list (DNS has "name").
        if (v.host !== undefined)
            rememberHost(String(v.host).trim());
        persist(s);

        clearOutput(s);
        append(s, "$ " + built.argv.map(quote).join(" ") + "\n");

        s.stopping = false;
        s.stopReason = "";
        s.started = Date.now();
        setRunning(s, true);
        setLabel(s.statusEl, "Running", "blue");
        s.poller = App.poll(function () {
            setLabel(s.statusEl, "Running · " + elapsed(s), "blue");
            return Promise.resolve();
        }, 1000);

        var opts = { pty: true, environ: ["LC_ALL=C"], err: "message" };
        if (built.superuser)
            opts.superuser = "try";
        var proc = cockpit.spawn(built.argv, opts);
        s.proc = proc;
        proc.stream(function (data) { append(s, data) });
        proc.then(function () {
            finish(s, "Finished", "green", "Exit status 0 after " + elapsed(s));
        }, function (ex) {
            if (s.stopping || ex.problem === "terminated")
                return finish(s, "Stopped", "orange", (s.stopReason || "Stopped") + " after " + elapsed(s));
            if (ex.problem === "not-found")
                return fail(s, "`" + s.tool.bin + "` is not installed on the SERVER.");
            if (ex.problem === "access-denied")
                return fail(s, "Administrative access is required for this method. Enable it with the \"Limited access\" button in the header, then try again.");
            if (ex.exit_status !== undefined)
                return finish(s, "Exit " + ex.exit_status, "red", "Exit status " + ex.exit_status + " after " + elapsed(s));
            fail(s, ex.message || ex.problem || "unknown error");
        });
    }

    function stop(s, reason) {
        if (!s.proc || !s.running)
            return;
        s.stopReason = reason || "";
        s.stopping = true;
        s.stop.disabled = true;
        s.proc.close("terminated");
    }

    function end(s) {
        if (s.poller)
            s.poller.stop();
        s.poller = null;
        s.proc = null;
        setRunning(s, false);
    }

    function finish(s, label, color, note) {
        end(s);
        markError(s, color === "red");
        setLabel(s.statusEl, label, color);
        append(s, (s.chunks.length && !/\n$/.test(s.chunks[s.chunks.length - 1]) ? "\n" : "") + "[" + note + "]\n");
        flush(s); // the final numbers must be on screen before the run counts as over
    }

    function fail(s, message) {
        end(s);
        markError(s, true);
        setLabel(s.statusEl, "Failed", "red");
        App.alerts.inline(s.alertId, "danger", "Couldn't run " + s.tool.bin, message);
    }

    // ------------------------------------------------------------------
    // No dangling processes. Cockpit keeps a tool's iframe alive while another page
    // is shown, so closing the channel on unload isn't enough on its own:
    //   - cockpit.hidden (another Cockpit page shown, or a background browser tab)
    //     for longer than HIDDEN_GRACE_MS stops everything that is still running.
    //     The grace period lets a quick tab flip pass without killing a long test.
    //   - leaving for good (reload, closing the tab, logging out) closes the
    //     channels right away. The bridge hangs up their ptys, which ends the tools.
    // Moving between NetDebug's own pages keeps a test running; it is still "here".
    // ------------------------------------------------------------------

    var HIDDEN_GRACE_MS = 15000;
    var hiddenTimer = null;

    function running() {
        return Object.keys(sessions).map(function (id) { return sessions[id] }).filter(function (s) { return s.running });
    }

    function stopAll(reason) {
        running().forEach(function (s) { stop(s, reason) });
    }

    cockpit.addEventListener("visibilitychange", function () {
        window.clearTimeout(hiddenTimer);
        hiddenTimer = null;
        if (!cockpit.hidden || !running().length)
            return;
        hiddenTimer = window.setTimeout(function () {
            hiddenTimer = null;
            if (cockpit.hidden)
                stopAll("Stopped because the page was left");
        }, HIDDEN_GRACE_MS);
    });

    window.addEventListener("pagehide", function () { stopAll("Stopped because the page was closed") });

    // ------------------------------------------------------------------
    // Go
    // ------------------------------------------------------------------

    renderHosts();
    Object.keys(TOOLS).forEach(function (id) { mountTool(TOOLS[id]) });

    App.menu.mount(MENU, {
        nav: "app-menu",
        startExpanded: true,
    });
}());
