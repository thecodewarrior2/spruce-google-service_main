'use strict';
// (0.6.9) The two repositories an installation downloads from, set in deploy/settings.env and changeable on the
// dashboard (Settings → Update → Repositories): RELEASES_REPO, the approved versions (what Settings → Update
// offers, what deploy/update.sh and the update job install), and MODEL_REPO, the AI model's files (each version
// pins the model's commit and every file's SHA-256 in vendor/spruce/VENDOR.json; MODEL_REPO only says where those
// exact files are downloaded from). Neither has a default: each installation names its own.
//
// An address is one of:
//   - a GitHub repository: https://github.com/OWNER/REPO (or OWNER/REPO, as RELEASES_REPO was written before 0.6.9);
//   - a GitLab repository: https://gitlab.com/GROUP/…/REPO, or on a GitLab server whose name starts with "gitlab.";
//   - for MODEL_REPO on another host: an https address under which COMMIT/FILE downloads each file.
// Releases on another host can be installed from Cloud Shell (deploy/update.sh clones any git address), but the
// dashboard can't list their versions: it reads GitHub's and GitLab's own APIs.
const MAX_LEN = 300;

// What's wrong with an address, or '' (an empty one is allowed: "not set").
function problem(input) {
    const s = String(input || '').trim();
    if (!s) return '';
    if (s.length > MAX_LEN) return `It is longer than ${MAX_LEN} characters.`;
    if (/^[\w.-]+\/[\w.-]+$/.test(s)) return '';                                   // OWNER/REPO (GitHub)
    let u;
    try { u = new URL(s); } catch (e) { return 'It isn\'t a web address (https://…).'; }
    if (u.protocol !== 'https:') return 'Only https:// addresses are used.';
    if (u.username || u.password) return 'It has a name or password in it: use a public repository instead (no secret is ever stored here).';
    if (u.search || u.hash) return 'It has a ? or # part: give the repository\'s address alone.';
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(u.hostname)) return 'Its server name isn\'t a public domain.';
    if (!/^\/[\w.~%-]+(\/[\w.~%-]+)*\/?$/.test(u.pathname)) return 'Its path isn\'t a repository\'s (letters, digits, - _ . ~ and /).';
    return '';
}

// { kind: 'github' | 'gitlab' | 'other', url (to clone), path, host } or null (empty or not an address).
function parseRepo(input) {
    const s = String(input || '').trim();
    if (!s || problem(s)) return null;
    if (/^[\w.-]+\/[\w.-]+$/.test(s)) return { kind: 'github', host: 'github.com', path: s.replace(/\.git$/, ''), url: `https://github.com/${s.replace(/\.git$/, '')}.git` };
    const u = new URL(s);
    const path = u.pathname.replace(/^\/+|\/+$/g, '').replace(/\.git$/, '');
    const host = u.hostname.toLowerCase();
    if (host === 'github.com' && /^[\w.-]+\/[\w.-]+$/.test(path)) return { kind: 'github', host, path, url: `https://github.com/${path}.git` };
    if ((host === 'gitlab.com' || host.startsWith('gitlab.')) && path.includes('/')) return { kind: 'gitlab', host, path, url: `https://${host}/${path}.git` };
    return { kind: 'other', host, path, url: `https://${host}/${path}` };
}

// Where a repository's file at a commit downloads from (raw), or null for another host's release repository.
function rawUrl(repo, commit, file) {
    const r = typeof repo === 'string' ? parseRepo(repo) : repo;
    if (!r) return null;
    if (r.kind === 'github') return `https://raw.githubusercontent.com/${r.path}/${commit}/${file}`;
    if (r.kind === 'gitlab') return `https://${r.host}/${r.path}/-/raw/${commit}/${file}`;
    return `https://${r.host}/${r.path}/${commit}/${file}`;
}
// The model's files: the base COMMIT/FILE is appended to (tools/fetch-model.js).
function rawBase(repo) {
    const r = typeof repo === 'string' ? parseRepo(repo) : repo;
    if (!r) return null;
    if (r.kind === 'github') return `https://raw.githubusercontent.com/${r.path}`;
    if (r.kind === 'gitlab') return `https://${r.host}/${r.path}/-/raw`;
    return `https://${r.host}/${r.path}`;
}
// The newest commit on a branch, by the host's own API: { url, sha(json), date(json) } or null (another host).
function newestCommit(repo, branch = 'main') {
    const r = typeof repo === 'string' ? parseRepo(repo) : repo;
    if (!r) return null;
    if (r.kind === 'github') return { url: `https://api.github.com/repos/${r.path}/commits/${branch}`, sha: (j) => j.sha, date: (j) => j.commit && j.commit.committer && j.commit.committer.date };
    if (r.kind === 'gitlab') return { url: `https://${r.host}/api/v4/projects/${encodeURIComponent(r.path)}/repository/commits/${branch}`, sha: (j) => j.id, date: (j) => j.committed_date };
    return null;
}
// How an address is shown: the repository's web address.
function shown(input) {
    const r = parseRepo(input);
    return r ? (r.kind === 'other' ? r.url : r.url.replace(/\.git$/, '')) : '';
}

module.exports = { problem, parseRepo, rawUrl, rawBase, newestCommit, shown, MAX_LEN };
