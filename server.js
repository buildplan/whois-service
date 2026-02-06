const express = require('express');
const { exec } = require('child_process');
const whois = require('whois');
const path = require('path');
const rateLimit = require('express-rate-limit');
const util = require('util');
const dns = require('dns').promises;

// Force Node.js to use reliable upstream DNS
dns.setServers(['1.1.1.1', "9.9.9.9", "208.67.222.222", "8.8.8.8"]);

const app = express();
const npmLookupPromise = util.promisify(whois.lookup);

// --- CONFIGURATION ---
app.set('json spaces', 2);
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(express.static(path.join(__dirname, 'views'), { index: false }));

// --- HELPERS ---
function isCli(userAgent) {
    const ua = (userAgent || '').toLowerCase();
    return ua.includes('curl') || ua.includes('wget') || ua.includes('httpie') ||
           ua.includes('python') || ua.includes('powershell') || ua.includes('aiohttp') || ua.includes('go-http-client');
}

function detectQueryType(query) {
    const clean = query.replace(/^\[|\]$/g, '').trim();
    if (/^(AS|as)?\d+$/i.test(clean)) return 'asn';
    if (clean.includes(':')) return 'ip'; // IPv6
    if (/^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/.test(clean)) return 'ip'; // IPv4 Regex
    if (clean.includes('.')) return 'domain';
    return 'unknown';
}

// --- EXTERNAL INTEGRATIONS ---
async function getIpIntelligence(ip) {
    try {
        const res = await fetch(`https://ip.wiredalter.com/api/info?ip=${ip}`);
        if (!res.ok) return null;
        return await res.json();
    } catch (e) { return null; }
}

async function getDNS(domain) {
    try {
        const [a, aaaa] = await Promise.allSettled([
            dns.resolve4(domain),
            dns.resolve6(domain)
        ]);
        return {
            v4: a.status === 'fulfilled' ? a.value : [],
            v6: aaaa.status === 'fulfilled' ? aaaa.value : []
        };
    } catch (e) {
        return { v4: [], v6: [] };
    }
}

// --- CORE WHOIS FUNCTIONS ---
function lookupLinux(query, server = null) {
    return new Promise((resolve, reject) => {
        if (!/^[a-zA-Z0-9.:-]+$/.test(query)) return reject(new Error("Invalid characters"));

        const cmd = server ? `whois -h ${server} "${query}"` : `whois "${query}"`;
        console.log(`[DEBUG] Executing: ${cmd}`);

        exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
            const output = (stdout || '') + (stderr || '');

            if (output.includes("Name or service not known") ||
                output.includes("Temporary failure") ||
                output.includes("Connection refused") ||
                output.includes("getaddrinfo")) {
                return reject(new Error("Network/DNS Error"));
            }

            if (!server) {
                const cleanOut = output.trim().toLowerCase();
                const failurePhrases = [
                    "no such domain", "no match for", "not found",
                    "domain not found", "no entries found", "no match"
                ];
                const isTooShort = cleanOut.length < 65;
                const hasFailureText = failurePhrases.some(p => cleanOut.includes(p));

                if (isTooShort || hasFailureText) {
                    console.log(`[DEBUG] Tier 1 Reject: '${query}' (Len: ${cleanOut.length})`);
                    return reject(new Error("Possible false negative - triggering fallback"));
                }
            }

            if (error && output.length < 20) return reject(error);
            resolve(output);
        });
    });
}

// Helper to resolve hostname to IP (Bypasses container DNS)
async function resolveServerIP(hostname) {
    try {
        const ips = await dns.resolve4(hostname);
        return ips[0]; // Return the first IP
    } catch (e) {
        console.log(`[DEBUG] Failed to resolve WHOIS server ${hostname}: ${e.message}`);
        return hostname; // Fallback to hostname if resolution fails
    }
}

async function lookupDeep(query) {
    try {
        const tld = query.split('.').pop().toLowerCase();
        const MANUAL_SERVERS = {
            'uk': 'whois.nic.uk', 'co': 'whois.nic.co', 'io': 'whois.nic.io',
            'ai': 'whois.nic.ai', 'me': 'whois.nic.me', 'gov': 'whois.nic.gov',
            'id': 'whois.pandi.or.id'
        };

        let realServer = MANUAL_SERVERS[tld];

        if (!realServer) {
            console.log(`[DEBUG] No override for .${tld}, asking IANA...`);
            const ianaRaw = await lookupLinux(tld, 'whois.iana.org');
            const match = ianaRaw.match(/refer:\s*([^\s\n]+)/i);

            if (match && match[1]) {
                realServer = match[1];
            } else {
                if (ianaRaw.length > 50) return ianaRaw;
                throw new Error("No referral found in IANA response");
            }
        }

        const serverIP = await resolveServerIP(realServer);

        console.log(`[DEBUG] Deep Lookup for '${query}' at '${realServer}' (${serverIP})`);
        return await lookupLinux(query, serverIP);

    } catch (e) {
        console.log(`[DEBUG] Deep Lookup Failed: ${e.message}`);
        throw e;
    }
}

async function lookupNPM(query) {
    const options = { follow: 2, timeout: 5000 };
    if (query.toLowerCase().endsWith('.eu')) options.server = 'whois.eu';
    return await npmLookupPromise(query, options);
}

// --- MASTER CONTROLLER ---
async function robustLookup(query) {
    let rawData = null;
    let methodUsed = 'Linux Binary';

    try {
        rawData = await lookupLinux(query);
    } catch (err1) {
        try {
            if (detectQueryType(query) === 'domain') {
                rawData = await lookupDeep(query);
                methodUsed = 'Deep Discovery (IANA/Manual)';
            } else { throw new Error(); }
        } catch (err2) {
             try {
                console.log("[DEBUG] Tier 2 failed, trying NPM fallback...");
                rawData = await lookupNPM(query);
                methodUsed = 'NPM Library (Fallback)';
             } catch (err3) {
                return { rawData: null, methodUsed: 'Failed' };
             }
        }
    }
    return { rawData, methodUsed };
}

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'views', 'terms.html')));

app.get('/api/lookup/:query', async (req, res) => {
    const query = req.params.query;
    const ua = req.headers['user-agent'];
    const type = detectQueryType(query);

    if (type === 'unknown') return res.status(400).json({ error: "Invalid format." });

    const start = Date.now();

    const [whoisResult, dnsResult, ipInfoResult] = await Promise.all([
        robustLookup(query),
        (type === 'domain') ? getDNS(query) : Promise.resolve(null),
        (type === 'ip') ? getIpIntelligence(query) : Promise.resolve(null)
    ]);

    const { rawData, methodUsed } = whoisResult;

    // Parsing Logic
    let parsed = { registrar: null, created: null, expires: null, updated: null, nameservers: [] };

    if (rawData) {
        const extract = (regex) => {
            const m = rawData.match(regex);
            return m ? m[1].trim() : null;
        };

        parsed = {
            registrar: extract(/(?:Registrar:|Registrant Organization:|\[Organization\]|org-name:)\s*(.+)/i),
            created: extract(/(?:Creation Date:|Created:|\[Registered Date\]|created:)\s*(.+)/i),
            expires: extract(/(?:Registry Expiry Date:|Expir\w+ Date:|Expiration Date:|\[Expires\]|fh-expiry:)\s*(.+)/i) || extract(/\[State\]\s*Connected \((.+)\)/i),
            updated: extract(/(?:Updated Date:|Last Updated:|\[Last Update\]|changed:)\s*(.+)/i),
            nameservers: (rawData.match(/(?:Name Server:|\[Name Server\]|nserver:)\s*(.+)/gi) || [])
                .map(s => s.replace(/(?:Name Server:|\[Name Server\]|nserver:)\s*/i, '').trim().toLowerCase())
        };
        parsed.nameservers = [...new Set(parsed.nameservers)];
    }

    const response = {
        query, type, method: methodUsed,
        timestamp: new Date().toISOString(),
        latency_ms: Date.now() - start,
        parsed, ips: dnsResult, ip_info: ipInfoResult,
        raw: rawData || "WHOIS Lookup failed or server unreachable."
    };

    if (isCli(ua)) {
        res.header('Content-Type', 'application/json');
        return res.send(JSON.stringify(response, null, 2) + '\n');
    }
    res.json(response);
});

// CLI Text Report
app.get('/:query', async (req, res, next) => {
    if (detectQueryType(req.params.query) === 'unknown') return next();
    const ua = req.headers['user-agent'];
    if (isCli(ua)) {
        const query = req.params.query;
        const [whoisResult, dnsResult, ipInfo] = await Promise.all([
            robustLookup(query),
            (detectQueryType(query) === 'domain') ? getDNS(query) : Promise.resolve(null),
            (detectQueryType(query) === 'ip') ? getIpIntelligence(query) : Promise.resolve(null)
        ]);

        let output = `\n🔎 WHOIS Report: ${query}\n`;
        output += `------------------------------------------------\n`;
        if (ipInfo) {
            output += `Location: ${ipInfo.city}, ${ipInfo.country}\n`;
            output += `Provider: ${ipInfo.org} (${ipInfo.asn})\n`;
            if(ipInfo.is_proxy) output += `SECURITY WARNING: Identified as ${ipInfo.proxy_type}\n`;
            output += `------------------------------------------------\n`;
        }
        if (dnsResult) {
            if (dnsResult.v4.length > 0) output += `IPv4: ${dnsResult.v4.join(', ')}\n`;
            if (dnsResult.v6.length > 0) output += `IPv6: ${dnsResult.v6.join(', ')}\n`;
            output += `------------------------------------------------\n`;
        }
        output += (whoisResult.rawData || "[WHOIS Data Unavailable]");
        output += `\n------------------------------------------------\n`;
        return res.send(output);
    }
    next();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 WHOIS Service running on ${PORT}`));
