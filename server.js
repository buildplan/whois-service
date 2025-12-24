const express = require('express');
const { exec } = require('child_process');
const whois = require('whois');
const path = require('path');
const rateLimit = require('express-rate-limit');
const util = require('util');
const dns = require('dns').promises; // NATIVE DNS MODULE

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

// --- DNS LOOKUP HELPER ---
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

        // Timeout 10s
        const cmd = server ? `whois -h ${server} "${query}"` : `whois "${query}"`;
        console.log(`[DEBUG] Executing: ${cmd}`);

        exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
            const output = (stdout || '') + (stderr || '');

            // STRICT NETWORK ERROR DETECTION
            if (output.includes("Name or service not known") ||
                output.includes("Temporary failure") ||
                output.includes("Connection refused") ||
                output.includes("getaddrinfo")) {
                return reject(new Error("Network/DNS Error"));
            }

            if (error && output.length < 20) return reject(error);
            resolve(output);
        });
    });
}

async function lookupDeep(query) {
    try {
        const tld = query.split('.').pop();
        // 1. Ask IANA
        const ianaRaw = await lookupLinux(tld, 'whois.iana.org');

        // 2. Find Referral
        const match = ianaRaw.match(/refer:\s*([^\s\n]+)/i);

        if (match && match[1]) {
            const realServer = match[1];
            console.log(`[DEBUG] IANA referral for .${tld} -> ${realServer}`);

            // 3. Try Referral (Return IANA data if Referral fails)
            try {
                return await lookupLinux(query, realServer);
            } catch (referralErr) {
                console.warn(`[WARN] Referral ${realServer} failed. Returning IANA data.`);
                return `[WARNING: Registry server ${realServer} is unreachable]\n[Showing IANA Registry Data:]\n\n${ianaRaw}`;
            }
        }

        // 4. Fallback: If IANA has data but no referral, return IANA data
        if (ianaRaw.length > 50) return ianaRaw;

        throw new Error("No referral found");
    } catch (e) {
        throw e;
    }
}

async function lookupNPM(query) {
    const options = { follow: 2, timeout: 5000 };
    if (query.toLowerCase().endsWith('.eu')) options.server = 'whois.eu';
    return await npmLookupPromise(query, options);
}

// --- MASTER CONTROLLER (Graceful) ---
async function robustLookup(query) {
    let rawData = null;
    let methodUsed = 'Linux Binary';

    try {
        // Attempt 1
        rawData = await lookupLinux(query);
    } catch (err1) {
        try {
            // Attempt 2 (Deep) - Only for domains
            if (detectQueryType(query) === 'domain') {
                rawData = await lookupDeep(query);
                methodUsed = 'Deep Discovery (IANA)';
            } else { throw new Error(); }
        } catch (err2) {
             try {
                // Attempt 3 (NPM)
                rawData = await lookupNPM(query);
                methodUsed = 'NPM Library (Fallback)';
             } catch (err3) {
                // FINAL FALLBACK: Don't crash. Return null so we can show DNS data.
                console.error(`[ERROR] All WHOIS methods failed for ${query}`);
                return { rawData: null, methodUsed: 'Failed' };
             }
        }
    }
    return { rawData, methodUsed };
}

// --- ROUTES ---

app.get('/api/lookup/:query', async (req, res) => {
    const query = req.params.query;
    const ua = req.headers['user-agent'];
    const type = detectQueryType(query);

    if (type === 'unknown') return res.status(400).json({ error: "Invalid format." });

    const start = Date.now();

    // PARALLEL EXECUTION: Run WHOIS and DNS at the same time
    const [whoisResult, dnsResult] = await Promise.all([
        robustLookup(query),
        (type === 'domain') ? getDNS(query) : Promise.resolve(null)
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
        query,
        type,
        method: methodUsed,
        timestamp: new Date().toISOString(),
        latency_ms: Date.now() - start,
        // IF WHOIS FAILED, 'parsed' will be nulls, but 'ips' will have data!
        parsed: parsed,
        ips: dnsResult,
        raw: rawData || "WHOIS Lookup failed or server unreachable. See IP/DNS data."
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
        // Parallel Lookup
        const [whoisResult, dnsResult] = await Promise.all([
            robustLookup(query),
            (detectQueryType(query) === 'domain') ? getDNS(query) : Promise.resolve(null)
        ]);

        let output = `\n🔎 WHOIS Report: ${query}\n`;
        output += `------------------------------------------------\n`;

        // SHOW DNS DATA FIRST
        if (dnsResult) {
            if (dnsResult.v4.length > 0) output += `IPv4: ${dnsResult.v4.join(', ')}\n`;
            if (dnsResult.v6.length > 0) output += `IPv6: ${dnsResult.v6.join(', ')}\n`;
            output += `------------------------------------------------\n`;
        }

        output += (whoisResult.rawData || "[WHOIS Data Unavailable - Registry may be offline]");
        output += `\n------------------------------------------------\n`;
        return res.send(output);
    }
    next();
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'views', 'terms.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 WHOIS Service running on ${PORT}`));
