'use strict';
// (0.6.47) WHOIS (port 43), only for the ownership lookups (src/intel/ownership.js): the registrant organization when the
// registry's and the registrar's RDAP records leave it blank. Some registrars blank the organization in RDAP but still
// publish it in WHOIS (Com Laude's sharepoint.com: "Microsoft Corporation"). What is sent: the domain name only, first to
// the registry's WHOIS server (found from IANA's for its ending), then to the registrar's it names. Each answer within
// WAIT_MS; at most MAX_BYTES read. The answers are kept with the ownership answer (60 days), so this is asked rarely.
const net = require('net');

const WAIT_MS = 4000, MAX_BYTES = 64 * 1024;
const REDACTED = /redacted|privacy|protected|withheld|not disclosed|gdpr|data protected|statutory masking|anonymi[sz]ed/i;

// One question to a WHOIS server: the text it answers.
function ask(server, query, { connect = net.connect, waitMs = WAIT_MS } = {}) {
    return new Promise((resolve, reject) => {
        let text = '', done = false;
        const finish = (err) => { if (done) return; done = true; clearTimeout(timer); try { sock.destroy(); } catch (e) { /* closed */ } if (err) reject(err); else resolve(text); };
        const sock = connect({ host: server, port: 43 });
        const timer = setTimeout(() => finish(new Error(`WHOIS ${server}: no answer within ${waitMs / 1000} s`)), waitMs);
        sock.setEncoding && sock.setEncoding('utf8');
        sock.on('connect', () => sock.write(`${query}\r\n`));
        sock.on('data', (chunk) => { text += chunk; if (text.length > MAX_BYTES) finish(); });
        sock.on('end', () => finish());
        sock.on('close', () => finish());
        sock.on('error', (e) => finish(e));
    });
}
// The value of the first line "Key: value" for one of the keys (case-insensitive), or ''.
function field(text, keys) {
    for (const line of String(text || '').split(/\r?\n/)) {
        const m = /^\s*([^:]{2,60}):\s*(.*\S)\s*$/.exec(line);
        if (m && keys.includes(m[1].trim().toLowerCase())) return m[2].trim();
    }
    return '';
}

// The "Organization:" line of a block whose heading is alone on its line ("Registrant", then indented lines: Italy's
// registry and others), or ''.
function blockField(text, heading) {
    const lines = String(text || '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().toLowerCase() !== heading) continue;
        for (let k = i + 1; k < lines.length && /^\s+\S/.test(lines[k]); k++) {
            const m = /^\s+organi[sz]ation:\s*(.*\S)\s*$/i.exec(lines[k]);
            if (m) return m[1].trim();
        }
    }
    return '';
}
// { info(domain) → { org, registrar }, registrantOrg(domain) }: what WHOIS gives for a registrable domain ('' when none or
// hidden): the registrant organization and the registrar.
function createWhois({ connect = net.connect, waitMs = WAIT_MS } = {}) {
    const servers = new Map();      // ending → its registry's WHOIS server
    const q = (server, query) => ask(server, query, { connect, waitMs });
    async function registryServer(tld) {
        if (!servers.has(tld)) servers.set(tld, q('whois.iana.org', tld).then(t => field(t, ['whois', 'refer'])).catch((e) => { servers.delete(tld); throw e; }));
        return servers.get(tld);
    }
    async function info(domain) {
        const d = String(domain || '').toLowerCase();
        const server = await registryServer(d.split('.').pop());
        if (!server) return { org: '', registrar: '' };
        let text = await q(server, d);
        const orgOf = (t) => field(t, ['registrant organization', 'registrant organisation']) || blockField(t, 'registrant');
        let org = orgOf(text);
        let registrar = field(text, ['registrar']) || blockField(text, 'registrar');
        const next = field(text, ['registrar whois server', 'whois server']);
        if (!org && next && next.toLowerCase() !== server.toLowerCase()) {
            text = await q(next.replace(/^whois:\/\//i, ''), d);
            org = orgOf(text);
            registrar = registrar || field(text, ['registrar']);
        }
        const clean = (v) => (v && !REDACTED.test(v) ? v.slice(0, 120) : '');
        return { org: clean(org), registrar: clean(registrar) };
    }
    return { info, registrantOrg: async (domain) => (await info(domain)).org };
}

module.exports = { createWhois, field, blockField, ask };
