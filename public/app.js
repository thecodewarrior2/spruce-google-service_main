// S.P.R.U.C.E Mail Protection Service: the admin dashboard page. Plain JavaScript, no libraries, no build step.
// Every value from an email (senders, subjects, reasons) is put on the page as TEXT (textContent,
// createTextNode), never as HTML: email content is written by attackers.
(function () {
    'use strict';
    const $ = (sel, root = document) => root.querySelector(sel);
    const SVG = 'http://www.w3.org/2000/svg';
    const view = () => $('#view');
    let days = 30;
    try { days = Number(localStorage.getItem('spruce.days')) || 30; } catch (e) { /* storage blocked */ }

    // --- Talking to the service (the clickable mockup swaps in window.SPRUCE_API) -------------------
    async function realApi(path, opts = {}) {
        const res = await fetch(path, { method: opts.method || 'GET', credentials: 'same-origin',
            headers: Object.assign({ 'x-requested-with': 'spruce-dashboard' }, opts.body ? { 'content-type': 'application/json' } : {}),
            body: opts.body ? JSON.stringify(opts.body) : undefined });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    }
    // The AI move threshold and suspicious line in force, and whether the Let the AI alone move staff email (every
    // answer says them; 90%, 65% and off until the first one).
    let aiThreshold = 0.9, aiSuspicious = 0.65, aiMovesInside = false, reportedOn = false;
    // (0.6.1) admin, or moderator (MODERATOR_GROUP: the review pages only; the service refuses the rest whatever the page shows).
    let role = 'admin';
    const isModerator = () => role === 'moderator';
    const api = async (path, opts) => {
        const sends = !!(opts && opts.method && opts.method !== 'GET');
        const ticket = sends ? busyStart(busyWordsFor(path)) : null;
        let data;
        try { data = await (window.SPRUCE_API || realApi)(path, opts); } finally { if (ticket) busyEnd(ticket); }
        if (data && typeof data.aiThreshold === 'number') aiThreshold = data.aiThreshold;
        if (data && typeof data.aiSuspicious === 'number') aiSuspicious = data.aiSuspicious;
        if (data && typeof data.aiMovesInside === 'boolean') aiMovesInside = data.aiMovesInside;
        if (data && typeof data.reportedOn === 'boolean') reportedOn = data.reportedOn;   // (0.6.61) Review's Reported tab
        if (data && (data.role === 'admin' || data.role === 'moderator')) role = data.role;
        return data;
    };
    // A POST whose answer is a file (the retraining export): saved by the browser; its headers returned.
    async function downloadPost(path, body) {
        const res = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'x-requested-with': 'spruce-dashboard', 'content-type': 'application/json' }, body: JSON.stringify(body) });
        if (!res.ok) { const data = await res.json().catch(() => ({})); throw new Error(data.error || `HTTP ${res.status}`); }
        const blob = await res.blob();
        const name = (/filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '') || [])[1] || 'download';
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 30000);
        return res.headers;
    }

    // --- Building the page safely ----------------------------------------------------------------
    function h(tag, props, ...kids) {
        const el = document.createElement(tag);
        for (const [k, v] of Object.entries(props || {})) {
            if (v === null || v === undefined || v === false) continue;
            if (k === 'class') el.className = v;
            else if (k === 'text') el.textContent = v;
            else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
            else el.setAttribute(k, v === true ? '' : String(v));
        }
        for (const k of kids.flat(Infinity)) if (k !== null && k !== undefined && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
        return el;
    }
    function s(tag, attrs, ...kids) {
        const el = document.createElementNS(SVG, tag);
        for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, String(v));
        for (const k of kids.flat()) if (k) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
        return el;
    }
    const nf = new Intl.NumberFormat();
    const num = (n) => nf.format(Math.round(n || 0));
    const compact = (n) => (n >= 10000 ? new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n) : num(n));
    const pct = (x, d = 0) => `${(100 * (x || 0)).toFixed(d)}%`;
    const when = (ms) => new Date(ms).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    // (0.6.39) A date without the time, in the same style as when() ("Nov 19").
    const dayOf = (ms) => (ms ? new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '–');
    const dayLabel = (d) => new Date(`${d}T12:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    const A_DAY = 24 * 60 * 60 * 1000;
    const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    // (0.6.39) One wording for what happened to an email, and where it is, on every page.
    const ACTION = { move: ['Moved to the Spam folder', 'moved'], 'would-move': ['Would be moved', 'would'], flag: ['Suspicious (not moved)', 'flag'], promo: ['Promotional (not moved)', 'promo'] };
    const STATE = { moved: ['In the Spam folder', 'moved'], released: ['Moved back to the Inbox', 'released'], inbox: ['In the Inbox', 'inbox'], reported: ['Out of the Inbox: its reader reported it (Gmail)', 'moved'] };
    const stateOf = (m) => (m.state === 'released' && m.releasedByUser ? ['Moved back by its reader', 'released'] : STATE[m.state] || [m.state, '']);
    const pill = ([label, cls]) => h('span', { class: `pill ${cls}`, text: label });
    // (0.6.39) What happened to an email; a move made while the service was in enforce mode says so, so it doesn't seem
    // to contradict a "Monitor mode" badge after switching back.
    const actionPill = (m) => {
        const [label, cls] = ACTION[m.action] || [m.action, ''];
        const old = m.action === 'move' && m.mode === 'enforce' && currentMode && currentMode !== 'enforce';
        return pill([old ? `${label} (in enforce mode)` : label, cls]);
    };
    // (0.6.27) Spam or phishing, plainly: what the service took the email for (its trigger, or an admin's "Spam"
    // answer), as a coloured label beside the subject and at the top of an opened email.
    const kindOf = (m) => (!m ? null : m.kind !== undefined ? m.kind : m.spam || m.trigger === 'spam' ? 'spam' : m.action === 'promo' ? 'promotional' : ['move', 'would-move', 'flag'].includes(m.action) ? 'phishing' : null);
    const KIND = { spam: ['Spam', 'Unwanted bulk or marketing mail, not phishing: moved to Spam as spam'], phishing: ['Phishing', 'Taken for phishing by the rules or the AI'],
        promotional: ['Promotional', 'Marketing or subscribed mail (Gmail\'s Promotions category, or a one-click unsubscribe the sender signed): never moved for that; an admin answers it in Review → Promotional'] };
    const kindTag = (k) => (KIND[k] ? h('span', { class: `kind-tag ${k}`, title: KIND[k][1], text: KIND[k][0] }) : null);
    const asKind = (m) => { const k = kindOf(m), a = (ACTION[m.action] || [m.action])[0]; return k === 'spam' ? `${a}: spam, not phishing` : k === 'phishing' && m.action !== 'flag' ? `${a}: phishing` : a; };
    // Re-checked after delivery (0.5.35): what happened, and the outcomes that mean phishing had been delivered.
    const RECHECK_BAD = ['moved', 'would-move', 'held', 'not-in-inbox'];
    const WHERE = { archived: 'archived by its reader', spam: 'in Spam', trash: 'in the Trash', inbox: 'in the Inbox' };

    // The mode, in the header: set when the page loads, and again whenever Today or Settings is read
    // (the mode can be switched on the dashboard, by this admin or another).
    function showMode(mode) {
        const badge = $('#modeBadge');
        if (!badge || !mode) return;
        badge.hidden = false;
        currentMode = mode;
        badge.className = `mode ${mode}`;
        badge.textContent = mode === 'enforce' ? 'Enforce mode' : 'Monitor mode';
        // (0.6.0) And a card in the menu: what the mode means, and where to go from it.
        const card = $('#modeCard');
        if (!card || card.dataset.mode === mode) return;
        card.dataset.mode = mode;
        card.hidden = false;
        card.className = `mode-card ${mode}`;
        card.textContent = '';
        card.append(...[(mode === 'enforce'
            ? [h('b', { text: 'Enforce mode' }), 'Mail the policy flags is moved to Spam. The brake stops all moving if too much moves in an hour.', isModerator() ? null : [h('br'), h('a', { href: '#/settings', text: 'The policy' })]]
            : [h('b', { text: 'Monitor mode' }), 'Nothing is moved: emails the policy would move are only recorded, so you can measure false alarms first.', isModerator() ? null : [h('br'), h('a', { href: '#/readiness', text: 'Ready for enforce mode?' })]])].flat(Infinity).filter(Boolean));
    }

    // (0.6.5) The loading bar: anything the person started (an action, a page, a download) that takes more than
    // BUSY_AFTER_MS shows a bar across the top, and in the bottom corner what is happening, until it is done. The
    // live refresh in the background never shows it.
    // (0.6.12) Each start is its own entry, and each end takes away exactly its own: busyStart(label) returns a
    // ticket for busyEnd(ticket). busyEnd('the same words') takes away the newest entry with those words, and
    // busyEnd() with nothing the newest entry started with nothing, never another's (before, an action that drew the
    // page again took away the page's entry, and its own stayed: the bar never stopped). The words shown are the
    // newest entry's that has some: every request to the service says what it does (BUSY_WORDS).
    const BUSY_AFTER_MS = 1000;
    let busyEntries = [], busyTimer = null, busyEl = null, busyNext = 0;
    const BUSY_WORDS = {
        '/api/mark': 'Saving your answer…', '/api/unclear': 'Saving your answer…', '/api/bulk': 'Saving your answers…',
        '/api/release': 'Moving it back to the Inbox…', '/api/rescan': 'Checking it again: reading the email from Gmail…',
        '/api/message/context': 'Reading the email from Gmail…', '/api/check': 'Checking the email…',
        '/api/campaign/confirm': 'Confirming the campaign as phishing…', '/api/campaign/release': 'Moving the campaign\'s copies back…',
        '/api/campaign/find': 'Searching the watched mailboxes for copies…', '/api/resume': 'Resuming moving…', '/api/rechecked/seen': 'Marking them as seen…',
        '/api/policy': 'Saving the setting…', '/api/lookalikes/mark': 'Saving the mark…', '/api/digest': 'Saving the weekly summary setting…',
        '/api/digest/send': 'Sending the weekly summary…', '/api/renew-watches': 'Reading the directory again…', '/api/lists/recheck': 'Downloading the phishing lists again…',
        '/api/keys/save': 'Testing and saving the key…', '/api/keys/remove': 'Removing the key…', '/api/safe-browsing/key': 'Testing and saving the key…',
        '/api/safe-browsing/remove': 'Removing the key…', '/api/clicks': 'Saving the link-clicks setting…', '/api/clicks/test': 'Testing with Google…',
        '/api/training-export': 'Reading the emails for the retraining file (up to a minute)…', '/api/training-export/allow': 'Saving the setting…',
        '/api/phish-training/rule': 'Saving the rule…', '/api/phish-training/rule/edit': 'Saving the rule…', '/api/phish-training/rule/remove': 'Removing the rule…',
        '/api/phish-training/domains': 'Saving the domains…', '/api/update': 'Starting the update…', '/api/update/check': 'Asking GitHub for the newest version…'
    };
    const busyWordsFor = (path) => BUSY_WORDS[String(path || '').split('?')[0]] || 'Sending it to the service…';
    function busyLabel() {
        for (let i = busyEntries.length - 1; i >= 0; i--) if (busyEntries[i].label) return busyEntries[i].label;
        return 'Working…';
    }
    function busyShow() {
        busyTimer = null;
        if (!busyEntries.length) return;
        if (!busyEl) {
            busyEl = h('div', { class: 'busy', role: 'status', 'aria-live': 'polite' }, h('div', { class: 'busy-track', 'aria-hidden': 'true' }),
                h('div', { class: 'busy-label' }, h('span', { class: 'busy-spin', 'aria-hidden': 'true' }), h('span', { class: 'busy-words' })));
            document.body.append(busyEl);
        }
        busyEl.querySelector('.busy-words').textContent = busyLabel();
        busyEl.hidden = false;
    }
    function busyStart(label) {
        const ticket = ++busyNext;
        busyEntries.push({ ticket, label: label || null });
        if (busyEl && !busyEl.hidden) busyShow();
        else if (!busyTimer) busyTimer = setTimeout(busyShow, BUSY_AFTER_MS);
        return ticket;
    }
    function busyEnd(which) {
        let i = -1;
        if (typeof which === 'number') i = busyEntries.findIndex(e => e.ticket === which);
        else for (let j = busyEntries.length - 1; j >= 0 && i < 0; j--) if (which ? busyEntries[j].label === which : !busyEntries[j].label) i = j;
        if (i >= 0) busyEntries.splice(i, 1);
        if (busyEntries.length) { if (busyEl && !busyEl.hidden) busyShow(); return; }
        if (busyTimer) { clearTimeout(busyTimer); busyTimer = null; }
        if (busyEl) busyEl.hidden = true;
    }

    // (0.6.39) A message after an action; with undo, an Undo button and 10 seconds to use it. An error stays until closed.
    function toast(msg, { undo = null, error = false } = {}) {
        document.querySelectorAll('.toast').forEach(t => t.remove());
        const t = h('div', { class: `toast${error ? ' error' : ''}${undo ? ' with-undo' : ''}`, role: error ? 'alert' : 'status' }, h('span', { text: msg }));
        const close = () => t.remove();
        if (undo) t.append(h('button', { class: 'toast-btn', type: 'button', onclick: async (e) => {
            e.target.disabled = true;
            try { await undo(); close(); toast('Undone: the answer before is back.'); render(); }
            catch (err) { toast(`Couldn't undo it: ${err.message}`, { error: true }); }
        } }, 'Undo'));
        if (error) t.append(h('button', { class: 'toast-btn', type: 'button', 'aria-label': 'Close', onclick: close }, '✕'));
        document.body.append(t);
        if (!error) setTimeout(close, undo ? 10000 : 4000);
    }

    // --- Popup: an in-page dialog over the page (Escape or Close closes it; the page's keys wait meanwhile) ----
    function popup(title, ...content) {
        const close = h('button', { class: 'linkbtn', type: 'button', text: 'Close' });
        const dlg = h('dialog', { class: 'popup', 'aria-label': title },
            h('div', { class: 'popup-head' }, h('h2', { text: title }), close),
            h('div', { class: 'popup-body' }, ...content));
        close.addEventListener('click', () => dlg.close());
        dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });   // a click outside the box
        dlg.addEventListener('close', () => dlg.remove());
        document.body.append(dlg);
        if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
        return dlg;
    }
    const popupOpen = () => !!document.querySelector('dialog.popup[open]');
    // A list that shows its first two, then "…show more": the rest in a popup.
    // copy: each item is an email address, with its copy button (0.5.72).
    function shortList(items, title, { describe = (n) => `${n} in all`, copy = false } = {}) {
        const one = (x) => (copy ? addr(x) : x);
        const joined = (xs) => xs.flatMap((x, i) => (i ? [', ', one(x)] : [one(x)]));
        if (items.length <= 2) return h('span', {}, joined(items));
        const more = h('button', { class: 'linkbtn', type: 'button', text: `…show more (${items.length - 2})` });
        more.addEventListener('click', () => popup(title, h('p', { class: 'sub', text: describe(items.length) }), h('ul', { class: 'plain-list' }, items.map(x => h('li', {}, one(x))))));
        return h('span', {}, joined(items.slice(0, 2)), ' ', more);
    }

    // --- Tooltip (one, shared; values lead, names follow) ------------------------------------------
    const tip = () => $('#tip');
    function showTip(evt, title, rows) {
        const t = tip();
        t.textContent = '';
        t.append(h('div', { class: 't-title', text: title }));
        for (const r of rows) {
            const key = h('span', { class: 'key' });
            if (r.color) key.style.background = r.color;
            t.append(h('div', { class: 't-row' }, h('span', {}, r.color ? key : null, r.name), h('b', { text: r.value })));
        }
        t.hidden = false;
        const box = evt.target.getBoundingClientRect();
        const x = evt.clientX || box.left + box.width / 2, y = evt.clientY || box.top;
        const w = t.offsetWidth, hgt = t.offsetHeight;
        t.style.left = `${Math.min(window.innerWidth - w - 8, Math.max(8, x + 12))}px`;
        t.style.top = `${Math.max(8, y - hgt - 12)}px`;
    }
    const hideTip = () => { tip().hidden = true; };

    // --- Charts ----------------------------------------------------------------------------------
    // Round axis ticks: a step of 1, 2 or 5 × 10ⁿ, four or five of them.
    function niceAxis(v) {
        const raw = Math.max(1, v) / 4;
        const p = 10 ** Math.floor(Math.log10(raw)), f = raw / p;
        const step = Math.max(1, (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p);
        const n = Math.max(1, Math.ceil(Math.max(1, v) / step));
        return { max: n * step, step, n };
    }
    // Charts are drawn at the width they get, so their text stays 11px on a phone.
    const chartWidth = () => Math.max(320, Math.min(760, (view().clientWidth || 760) - (window.innerWidth < 900 ? 34 : 420)));
    // A column with a 4px rounded top (the data end) and a square base.
    function colPath(x, y, w, hgt, round) {
        const r = round ? Math.min(4, w / 2, hgt) : 0;
        return `M${x},${y + hgt}V${y + r}${r ? `Q${x},${y} ${x + r},${y}` : ''}H${x + w - r}${r ? `Q${x + w},${y} ${x + w},${y + r}` : ''}V${y + hgt}Z`;
    }
    // Stacked columns, one per day; series: [{ key, name, color }]. totals: the tooltip also gives the day's
    // emails checked (first) and moved back (last), when the rows have them (Today's trend).
    // back: a column drawn behind the stack, on the same axis (the emails checked, 0.5.45), unless zoom (the
    // axis fits the stack alone; the back column isn't drawn, never cut). One axis always.
    function stackedColumns(rows, series, { label = 'day', totals = false, back = null, zoom = false } = {}) {
        const W = chartWidth(), H = 230, L = 38, B = 24, T = 10, R = 8;
        const pw = W - L - R, ph = H - B - T;
        const stackMax = Math.max(1, ...rows.map(r => series.reduce((a, se) => a + (r[se.key] || 0), 0)));
        const showBack = !!back && !zoom;
        const ax = niceAxis(showBack ? Math.max(stackMax, ...rows.map(r => r[back.key] || 0)) : stackMax), max = ax.max;
        const band = pw / rows.length, bw = Math.max(3, Math.min(24, band * 0.62));
        const backW = Math.max(bw + 4, Math.min(band - 2, bw + 12));
        const y = (v) => T + ph - (v / max) * ph;
        const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Emails per ${label}${showBack ? ', checked and moved' : ''}, by reason` });
        for (let i = 0; i <= ax.n; i++) {
            const v = ax.step * i, yy = y(v);
            svg.append(s('line', { class: i === 0 ? 'baseline' : 'gridline', x1: L, x2: W - R, y1: yy, y2: yy }));
            svg.append(s('text', { x: L - 6, y: yy + 3.5, 'text-anchor': 'end' }, compact(v)));
        }
        const every = Math.max(1, Math.ceil(rows.length / Math.max(3, Math.floor(pw / 90))));
        // what each column holds: moved, would move, or both (the tooltip and the table say which)
        const split = (r, se) => {
            if (!se.trig) return num(r[se.key] || 0);
            const m = r[se.trig] || 0, w = r[`wm:${se.trig}`] || 0;
            return m && w ? `${num(m)} moved, ${num(w)} would move` : w ? `${num(w)} would move` : m ? `${num(m)} moved` : '0';
        };
        rows.forEach((r, i) => {
            const x = L + i * band + (band - bw) / 2;
            let acc = 0;
            const segs = series.filter(se => (r[se.key] || 0) > 0);
            const checked = (totals || back) && typeof r.scanned === 'number' ? [{ name: 'Emails checked', value: num(r.scanned), color: back ? css(back.color) : undefined }] : [];
            const moved = totals && typeof r.released === 'number' ? [{ name: 'Moved back', value: num(r.released) }] : [];
            const g = s('g', { class: 'bar', tabindex: 0, role: 'img',
                'aria-label': `${dayLabel(r.day)}: ${[...checked, ...series.map(se => ({ name: se.name, value: split(r, se) })), ...moved].map(x => `${x.name} ${x.value}`).join(', ')}` });
            if (showBack && (r[back.key] || 0) > 0) {
                const yb = y(r[back.key]);
                g.append(s('path', { class: 'back-col', d: colPath(L + i * band + (band - backW) / 2, yb, backW, y(0) - yb, true), fill: css(back.color) }));
            }
            segs.forEach((se, j) => {
                const v = r[se.key];
                const y0 = y(acc), y1 = y(acc + v);
                const top = j === segs.length - 1;
                const hgt = Math.max(0, y0 - y1 - (j > 0 ? 2 : 0));           // 2px surface gap between segments
                if (hgt > 0) g.append(s('path', { d: colPath(x, y1, bw, Math.max(hgt, showBack ? 1.5 : 0), top), fill: css(se.color) }));
                acc += v;
            });
            g.append(s('rect', { class: 'hit', x: L + i * band, y: T, width: band, height: ph }));
            const rowsTip = [...checked, ...series.map(se => ({ name: se.name, value: split(r, se), color: css(se.color) })), ...moved];
            g.addEventListener('pointermove', (e) => showTip(e, dayLabel(r.day), rowsTip));
            g.addEventListener('focus', (e) => showTip(e, dayLabel(r.day), rowsTip));
            g.addEventListener('pointerleave', hideTip); g.addEventListener('blur', hideTip);
            svg.append(g);
            if (i % every === 0) svg.append(s('text', { x: L + i * band + band / 2, y: H - 6, 'text-anchor': 'middle' }, dayLabel(r.day)));
        });
        return svg;
    }
    function legend(series) {
        return h('div', { class: 'legend' }, series.map(se => { const i = h('i'); i.style.background = `var(${se.color})`; return h('span', {}, i, se.name); }));
    }
    function hbars(items, fmt = num) {
        const max = Math.max(1, ...items.map(i => i.value));
        return h('div', { class: 'hbars' }, items.map(i => {
            const fill = h('div', { class: 'fill' });
            fill.style.width = `${(100 * i.value) / max}%`;
            return h('div', { class: 'hbar' }, h('div', { class: 'name', text: i.name }), h('div', { class: 'track' }, fill), h('div', { class: 'num', text: fmt(i.value) }));
        }));
    }
    function histogram(buckets, threshold) {
        const W = chartWidth(), H = 220, L = 38, B = 26, T = 16, R = 8, pw = W - L - R, ph = H - B - T;
        const ax = niceAxis(Math.max(1, ...buckets.map(b => b.count))), max = ax.max;
        const band = pw / buckets.length, bw = Math.min(24, band * 0.6);
        const y = (v) => T + ph - (v / max) * ph;
        const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Recorded emails by AI score' });
        for (let i = 0; i <= ax.n; i++) { const v = ax.step * i; svg.append(s('line', { class: i ? 'gridline' : 'baseline', x1: L, x2: W - R, y1: y(v), y2: y(v) })); svg.append(s('text', { x: L - 6, y: y(v) + 3.5, 'text-anchor': 'end' }, compact(v))); }
        buckets.forEach((b, i) => {
            const x = L + i * band + (band - bw) / 2;
            const g = s('g', { class: 'bar', tabindex: 0, role: 'img', 'aria-label': `AI ${b.from}–${b.to}%: ${b.count} emails, ${b.released} moved back` });
            if (b.count) g.append(s('path', { d: colPath(x, y(b.count), bw, y(0) - y(b.count), true), fill: css('--s1') }));
            g.append(s('rect', { class: 'hit', x: L + i * band, y: T, width: band, height: ph }));
            const rows = [{ name: 'Emails', value: num(b.count) }, { name: 'Moved back (false alarm)', value: num(b.released) }];
            g.addEventListener('pointermove', (e) => showTip(e, `AI score ${b.from}–${b.to}%`, rows)); g.addEventListener('focus', (e) => showTip(e, `AI score ${b.from}–${b.to}%`, rows));
            g.addEventListener('pointerleave', hideTip); g.addEventListener('blur', hideTip);
            svg.append(g);
            if (b.count && b.from >= 80) svg.append(s('text', { x: x + bw / 2, y: y(b.count) - 5, 'text-anchor': 'middle' }, num(b.count)));
            if (pw > 500 || i % 2 === 0) svg.append(s('text', { x: L + i * band + band / 2, y: H - 8, 'text-anchor': 'middle' }, `${b.from}%`));
        });
        const tx = L + threshold * pw;
        svg.append(s('line', { class: 'thresh', x1: tx, x2: tx, y1: T - 6, y2: T + ph }));
        svg.append(s('text', { class: 'thresh-label', x: tx - 6, y: T - 2, 'text-anchor': 'end' }, `Moves at ${Math.round(threshold * 100)}%`));
        return svg;
    }
    // (0.6.39) Every table sorts the same way: click a column's heading (again for the other way). A column may give
    // its own value to sort by (c.sort(r): a date's time, a number); otherwise numbers sort as numbers, text as text.
    function sortable(table) {
        let col = -1, dir = 1;
        const key = (td) => { if (!td) return ''; const v = td.dataset.sort !== undefined ? td.dataset.sort : td.textContent.trim().toLowerCase().replace(/[%,]/g, ''); return v !== '' && !isNaN(Number(v)) ? Number(v) : v; };
        table.querySelectorAll('thead th').forEach((th, i) => {
            if (!th.textContent.trim()) return;
            th.setAttribute('aria-sort', 'none'); th.tabIndex = 0;
            const go = () => {
                dir = col === i ? -dir : 1; col = i;
                const tb = table.querySelector('tbody');
                [...tb.children].sort((a, b) => { const x = key(a.children[i]), y = key(b.children[i]); return dir * (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))); }).forEach(r => tb.append(r));
                table.querySelectorAll('thead th').forEach((t, j) => { if (t.hasAttribute('aria-sort')) t.setAttribute('aria-sort', j === i ? (dir > 0 ? 'ascending' : 'descending') : 'none'); });
            };
            th.addEventListener('click', go);
            th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
        });
        return table;
    }
    const cell = (c, r, cls) => h('td', { class: cls, 'data-sort': c.sort ? String(c.sort(r)) : null, 'data-label': c.name || null }, c.get(r));
    // rowClass: a row's class (or ''), for a row that needs attention.
    function dataTable(cols, rows, rowClass = null) {
        return h('div', { class: 'table-wrap' }, sortable(h('table', {},
            h('thead', {}, h('tr', {}, cols.map(c => h('th', { class: c.num ? 'num' : '', text: c.name })))),
            h('tbody', {}, rows.map(r => h('tr', { class: (rowClass && rowClass(r)) || '' }, cols.map(c => cell(c, r, c.num ? 'num' : ''))))))));
    }
    // The red alert icon, beside something that needs an admin (a phishing list that missed its download).
    const alertIcon = (label) => h('span', { class: 'alert-icon', role: 'img', 'aria-label': label, title: label, text: '!' });
    // A service's state beside its page's title (0.5.40): on and working (a green check), on but not working
    // (red), or off (grey). state: 'on' | 'bad' | 'off'.
    function serviceTitle(title, state, text) {
        const icon = { on: '✓', bad: '!', off: '–', info: '•' }[state] || '–';   // info (0.6.39): on, but not a protection (no green)
        return h('div', { class: 'title-row' }, h('h1', { text: title }),
            h('span', { class: `svc-badge ${state}`, role: 'status' }, h('span', { class: 'svc-icon', 'aria-hidden': 'true', text: icon }), text));
    }
    const SERVICE_WORDS = { on: 'Service is on', bad: 'Service is on, but not working', off: 'Service is off' };
    // Phishing found after it was delivered (0.5.35), on Messages until an admin marks it seen (Today lists it
    // under Needs attention since 0.6.0).
    function recheckBanner(rc) {
        if (!rc) return null;
        const one = rc.emails === 1;
        return h('div', { class: 'alert critical recheck-alert', role: 'alert' }, alertIcon('Alert'),
            h('div', { class: 'grow' }, h('b', { text: `${one ? 'An email' : `${num(rc.emails)} emails`} already delivered ${one ? 'was' : 'were'} found to be phishing on a re-check.` }),
                ` ${num(rc.people)} ${rc.people === 1 ? 'person' : 'people'} got ${one ? 'it' : 'them'}: ${num(rc.moved)} moved to Spam since, ${num(rc.opened)} opened before that`,
                rc.clicked ? h('b', { text: `, ${num(rc.clicked)} with a link clicked` }) : null, '. The admins were sent an alert. ',
                h('a', { href: '#/rechecked', text: 'Who got them, and what they did: Threats → Re-checked' }), '.'));
    }
    // (0.6.39) A search box over the table that follows it in the same card: hides the rows without the words.
    function searchRows(what) {
        const input = h('input', { type: 'search', class: 'list-search', placeholder: `Search ${what}`, 'aria-label': `Search ${what}`, autocomplete: 'off', spellcheck: 'false' });
        const count = h('span', { class: 'small muted list-count', 'aria-live': 'polite' });
        input.addEventListener('input', () => {
            const q = input.value.trim().toLowerCase(), card = input.closest('section') || document;
            let shown = 0, total = 0;
            for (const r of card.querySelectorAll('table tbody tr')) { total++; const ok = !q || r.textContent.toLowerCase().includes(q); r.hidden = !ok; if (ok) shown++; }
            count.textContent = q ? `${num(shown)} of ${num(total)} match` : '';
        });
        return h('div', { class: 'list-tools' }, input, count);
    }
    // (0.6.39) A page's long introduction: its first sentence, and the rest folded under "How this works".
    const foldedIntros = new Set();
    function foldIntro(root) {
        const p = [...root.querySelectorAll(':scope > p.sub, :scope .side-page > p.sub')][0];
        if (!p || p.children.length || p.textContent.length < 220) return;
        const text = p.textContent, cut = text.search(/\. [A-Z]/);
        if (cut < 40 || cut > 200) return;
        const key = currentHash().split('?')[0];
        const more = h('details', { class: 'intro-more' }, h('summary', { text: 'How this works' }), h('p', { class: 'sub', text: text.slice(cut + 2) }));
        if (foldedIntros.has(key)) more.open = true;
        more.addEventListener('toggle', () => { if (more.open) foldedIntros.add(key); else foldedIntros.delete(key); });
        p.textContent = text.slice(0, cut + 1);
        p.after(more);
    }
    // A table whose rows open something (mouse or keyboard).
    function clickTable(cols, rows, open, empty = 'Nothing in this period.', rowClass = null) {
        if (!rows.length) return h('div', { class: 'empty', text: empty });
        return h('div', { class: 'table-wrap row-cards' }, sortable(h('table', {},
            h('thead', {}, h('tr', {}, cols.map(c => h('th', { class: c.num ? 'num' : '', text: c.name })), h('th', { class: 'opens', 'aria-label': 'Opens' }))),
            h('tbody', {}, rows.map(r => h('tr', { class: `clickable ${(rowClass && rowClass(r)) || ''}`.trim(), tabindex: 0, onclick: () => open(r), onkeydown: (e) => { if (e.key === 'Enter') open(r); } },
                cols.map(c => cell(c, r, `${c.num ? 'num' : ''} ${c.cls || ''}`.trim())), h('td', { class: 'opens', 'aria-hidden': 'true', text: '›' })))))));
    }
    // Where the page is: the address bar's #/route, or, in the clickable mockup (which runs inside a frame
    // that keeps the address bar to itself), a route kept in the page with its own Back stack.
    const MEMORY = !!window.SPRUCE_MEMORY_ROUTER;
    let memRoute = '#/overview';
    const memStack = [];
    const currentHash = () => (MEMORY ? memRoute : location.hash);
    const go = (hash) => {
        if (!MEMORY) { location.hash = hash; return; }
        memStack.push(memRoute); memRoute = hash; render(); window.scrollTo(0, 0);
    };
    const back = () => { if (!MEMORY) { history.back(); return; } memRoute = memStack.pop() || '#/overview'; render(); };
    const q = (o) => Object.entries(o).filter(([, v]) => v).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

    // --- Views -----------------------------------------------------------------------------------
    // The daily chart's columns (0.5.45): by what triggered the move, moved or (monitor mode, or held by a
    // brake) would be moved; the emails checked behind them, on the same scale.
    const TREND_SERIES = [
        { key: 'by:rules+ai', trig: 'rules+ai', name: 'Rules + AI', color: '--s1' },
        { key: 'by:ai', trig: 'ai', name: 'AI score only', color: '--s2' },
        { key: 'by:rules', trig: 'rules', name: 'Rules only', color: '--s3' },
        { key: 'by:admin', trig: 'admin', name: 'Copies of a campaign an admin marked Phishing', color: '--s4' },
        { key: 'by:spam', trig: 'spam', name: 'Spam (padded list mail)', color: '--s5' }
    ];
    const CHECKED_SERIES = { key: 'scanned', name: 'Emails checked', color: '--total' };

    async function overview() {
        const d = await api(`/api/overview?days=${days}`);
        showMode(d.mode);
        const sm = d.summary;
        const out = [];
        // (0.6.0) What needs an admin, as one list (it was a banner each): the brake, paused campaigns, a phishing list
        // that missed its download, phishing found after delivery, new look-alikes of your domain, and the review queue.
        const need = [];
        const item = (tone, title, body, actions) => need.push({ tone, title, body, actions });
        const link = (href, text) => h('a', { class: 'btn', href, text });
        if (d.brake) {
            const held = d.brake.held || 0;
            const resume = (moveHeld) => postButton('/api/resume', () => ({ moveHeld }), (o) => (moveHeld && o.held && !o.held.monitor ? `Moving resumed: ${num(o.held.moved)} moved to Spam${o.held.left ? `; ${num(o.held.left)} to go, press again` : ''}.` : 'Moving resumed.'),
                moveHeld ? `Resume moving, and move the ${num(held)} emails the brake left in the Inbox to Spam now?` : 'Resume moving, and leave those emails in the Inbox?');
            item('critical', 'Moving is paused (brake).', `${num(d.brake.moves)} emails were moved within an hour (the limit is ${num(d.brake.limit || d.brake.moves)}). Since then, ${num(held)} emails that would have been moved were left in the Inbox, like any other email; resuming can move them now${isModerator() ? ' (an administrator resumes it)' : ''}.`,
                isModerator() ? null : [h('button', { class: 'btn primary', type: 'button', onclick: resume(true) }, `Resume, and move those ${num(held)} to Spam`), h('button', { class: 'btn', type: 'button', onclick: resume(false) }, 'Resume, and leave them in the Inbox')]);
        }
        if (d.heldCampaigns && d.heldCampaigns.length) item('warning', `Moving is paused for ${d.heldCampaigns.length} campaign${d.heldCampaigns.length === 1 ? '' : 's'}, waiting for your decision.`,
            ['Many copies were moved on evidence nothing outside the email confirms, so its other copies are left in the Inbox, like any email not moved. Open one to confirm it as phishing (every copy is moved to Spam) or dismiss it as a false alarm (the moved ones go back to the Inbox).',
                h('ul', { class: 'held-list' }, d.heldCampaigns.slice(0, 5).map(c => h('li', {}, h('a', { href: `#/messages?${q({ campaign: c.campaign })}`, text: c.label }), ` (${num(c.held)} left in the Inbox)`)))], null);
        // A phishing list that missed its download (0.5.22): until it downloads again; the details on About.
        if (d.missedLists && d.missedLists.length) {
            const ml = d.missedLists, one = ml.length === 1;
            item('critical', `${one ? 'A phishing list' : `${num(ml.length)} phishing lists`} missed ${one ? 'its' : 'their'} download: ${ml.map(l => l.name).join(', ')}.`,
                `The checks still use ${one ? 'its' : 'their'} previous copy, and ${one ? 'it is' : 'they are'} tried again every 3 hours; the admins were sent an alert.`, isModerator() ? null : link('#/about?show=lists', 'Details, and Download the lists again'));
        }
        if (d.rechecked) {
            const rc = d.rechecked, one = rc.emails === 1;
            item('critical', `${one ? 'An email' : `${num(rc.emails)} emails`} already delivered ${one ? 'was' : 'were'} found to be phishing on a re-check.`,
                [`${num(rc.people)} ${rc.people === 1 ? 'person' : 'people'} got ${one ? 'it' : 'them'}: ${num(rc.moved)} moved to Spam since, ${num(rc.opened)} opened before that`, rc.clicked ? h('b', { text: `, ${num(rc.clicked)} with a link clicked` }) : null, '. The admins were sent an alert.'],
                link('#/rechecked', 'Who got them, and what they did'));
        }
        // New look-alikes of your domain, until an admin marks them (0.5.36).
        if (d.lookalikes && d.lookalikes.length) item('critical', `${d.lookalikes.length === 1 ? 'A domain that imitates yours was' : `${num(d.lookalikes.length)} domains that imitate yours were`} registered: ${d.lookalikes.slice(0, 5).join(', ')}${d.lookalikes.length > 5 ? '…' : ''}.`,
            'Mail from them counts as a strong sign of phishing. The admins were sent an alert.', isModerator() ? null : link('#/lookalikes', 'Details, and marking one as the district\'s own'));
        // (0.6.30) Allow-list domains the 30-day check flagged, until an admin answers.
        if (d.allowReview && d.allowReview.length) {
            const ar = d.allowReview, sus = ar.filter(x => x.suspended).length;
            item(sus ? 'critical' : 'warning', `${ar.length === 1 ? `${ar[0].domain} on your Sender lists needs` : `${num(ar.length)} domains on your Sender lists need`} review${sus ? ` (${num(sus)} suspended)` : ''}.`,
                `The 30-day check found a change in ${ar.length === 1 ? 'its' : 'their'} registration or reputation: ${ar.length === 1 ? 'it' : 'each'} may have lapsed and been registered by someone else, or been sold. ${sus ? 'A suspended one isn\'t trusted until you answer. ' : ''}The admins were emailed.`,
                isModerator() ? null : link('#/allowlist', 'Review it'));
        }
        if (unreviewed) item('info', `${num(unreviewed)} email${unreviewed === 1 ? '' : 's'} ${unreviewed === 1 ? 'waits' : 'wait'} for review.`, 'Copies of one email are answered together. Every answer helps measure false alarms before enforce mode, and retraining.', h('a', { class: 'btn primary', href: '#/review', text: 'Start reviewing' }));
        const hour = new Date().getHours();
        const urgent = need.filter(n => n.tone !== 'info').length;
        out.push(h('header', { class: 'hello' },
            h('div', { class: 'hello-date', text: new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' }) }),
            h('h1', { text: `${hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'}. ${urgent ? `${num(urgent)} thing${urgent === 1 ? ' needs' : 's need'} you${unreviewed ? `, and ${num(unreviewed)} email${unreviewed === 1 ? ' waits' : 's wait'} for an answer` : ''}.` : unreviewed ? `${num(unreviewed)} email${unreviewed === 1 ? ' waits' : 's wait'} for an answer.` : 'All clear.'}` })));
        if (need.length) out.push(h('section', { class: 'card attention', 'aria-labelledby': 'needs-title' }, h('h2', { id: 'needs-title', text: 'Needs attention' }),
            need.map(n => h('div', { class: `need ${n.tone}`, role: n.tone === 'critical' ? 'alert' : null },
                h('span', { class: 'need-icon', 'aria-hidden': 'true', text: n.tone === 'info' ? num(unreviewed) : '!' }),
                h('div', { class: 'need-text' }, h('b', { text: n.title }), h('div', { class: 'need-body' }, n.body)),
                n.actions ? h('div', { class: 'need-actions' }, n.actions) : null))));
        else out.push(h('div', { class: 'alert good', role: 'status' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '✓' }),
            h('div', { class: 'grow' }, h('b', { text: 'Nothing needs you right now.' }), ' No paused moving, no list behind, nothing found after delivery, and the review queue is empty.')));
        const movedBack = `${num(sm.released)} moved back (${pct(sm.releaseRate, 1)}): ${num(sm.released - (sm.userReleased || 0))} by admins, ${num(sm.userReleased || 0)} by users`;
        const wb = sm.wouldMoveBy || {};
        // (0.6.39) Each count says what it covers: these are this period's emails (the Review tab counts those still to answer).
        const hero = d.mode === 'enforce' ? { label: `Moved to the Spam folder, last ${days} days`, value: sm.moved, note: movedBack }
            : { label: `Would be moved, last ${days} days`, value: sm.wouldMove, note: `monitor mode, nothing moved: ${num(wb['rules+ai'] || 0)} by rules + AI, ${num(wb.ai || 0)} by the AI score alone, ${num(wb.rules || 0)} by the rules alone${wb.spam ? `, ${num(wb.spam)} as spam` : ''}` };
        out.push(h('div', { class: 'grid kpis' },
            h('div', { class: 'card kpi hero' }, h('div', { class: 'label', text: hero.label }), h('div', { class: 'value', text: num(hero.value) }), h('div', { class: 'note', text: hero.note })),
            kpi('Emails checked', compact(sm.scanned), `last ${days} days`),
            kpi('Users affected', num(sm.usersAffected), 'had mail moved or recorded'),
            kpi('Campaigns', num(sm.campaigns), 'same sender and subject')),
            h('div', { class: 'kpi-strip' },
                h('span', {}, h('b', { text: num(d.mode === 'enforce' ? sm.wouldMove : sm.moved) }), ` ${d.mode === 'enforce' ? 'recorded, not moved (monitor phase or brake)' : 'moved'}${d.mode !== 'enforce' && sm.moved ? ` · ${movedBack}` : ''}`),
                h('span', {}, h('b', { text: num(sm.flagged) }), ' suspicious only, below the move rules')));
        // Trend (0.5.45): the emails checked behind, on the same scale; Zoom in fits the axis to the moved ones.
        let zoom = false;
        try { zoom = localStorage.getItem('spruce.trendZoom') === 'on'; } catch (e) { /* not kept */ }
        let asTable = false;
        const chartBox = h('div', { class: 'chart' });
        const draw = () => {
            chartBox.textContent = '';
            chartBox.append(asTable ? dataTable([{ name: 'Day', get: r => dayLabel(r.day) }, { name: 'Checked', num: true, get: r => num(r.scanned) },
                ...TREND_SERIES.flatMap(se => [{ name: `${se.name}: moved`, num: true, get: r => num(r[se.trig] || 0) }, { name: `${se.name}: would move`, num: true, get: r => num(r[`wm:${se.trig}`] || 0) }]),
                { name: 'Moved back', num: true, get: r => num(r.released) }], d.trend.slice().reverse())
                : stackedColumns(d.trend, TREND_SERIES, { totals: true, back: CHECKED_SERIES, zoom }));
        };
        draw();
        const toggle = h('button', { class: 'linkbtn', type: 'button', text: 'Show as table' });
        const zoomBtn = h('button', { class: 'linkbtn', type: 'button', 'aria-pressed': String(zoom), text: zoom ? 'Show emails checked' : 'Zoom in to the moved ones' });
        toggle.addEventListener('click', () => { asTable = !asTable; toggle.textContent = asTable ? 'Show as chart' : 'Show as table'; zoomBtn.hidden = asTable; draw(); });
        zoomBtn.addEventListener('click', () => {
            zoom = !zoom; zoomBtn.setAttribute('aria-pressed', String(zoom)); zoomBtn.textContent = zoom ? 'Show emails checked' : 'Zoom in to the moved ones';
            try { localStorage.setItem('spruce.trendZoom', zoom ? 'on' : 'off'); } catch (e) { /* not kept */ }
            draw();
        });
        // How much each trigger adds (moved or would move), in words.
        const bt = sm.byTrigger || {}, totalBy = (bt['rules+ai'] || 0) + (bt.ai || 0) + (bt.rules || 0) + (bt.spam || 0);
        const share = (n) => (totalBy ? ` (${pct(n / totalBy)})` : '');
        const triggerNote = totalBy ? h('p', { class: 'small muted trigger-note', text: `In these ${days} days, of ${num(totalBy)} emails moved or that would be moved: ${num(bt['rules+ai'] || 0)} by the rules and the AI together${share(bt['rules+ai'] || 0)}, ${num(bt.ai || 0)} by the AI score alone${share(bt.ai || 0)} (the AI score alone moves an email at ${pct(d.aiThreshold || 0.9)}), and ${num(bt.rules || 0)} by the rules alone${share(bt.rules || 0)}${bt.spam ? `; ${num(bt.spam)} were spam (list or marketing mail padded with hidden text, nothing else suspicious)${share(bt.spam)}` : ''}.` }) : null;
        out.push(h('div', { class: 'grid two' },
            h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('div', {}, h('h2', { text: 'Emails checked and moved per day' }),
                h('div', { class: 'sub', text: `Behind: every email checked. In front: the emails moved${d.mode === 'enforce' ? '' : ', or in monitor mode that would be moved,'} by what triggered it. On one scale the moved ones are a small share: zoom in to see them. Hover a day for its numbers.` })),
                h('div', { class: 'chart-actions' }, zoomBtn, toggle)), legend([CHECKED_SERIES, ...TREND_SERIES]), chartBox, triggerNote),
            h('section', { class: 'card' }, h('h2', { text: 'Top reasons' }), h('div', { class: 'sub', text: 'Signs found in moved and would-move emails.' }),
                d.topReasons.length ? hbars(d.topReasons.map(r => ({ name: r.reason, value: r.count }))) : h('div', { class: 'empty', text: 'Nothing moved in this period.' }))));
        out.push(h('div', { class: 'grid two' },
            h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('div', {}, h('h2', { text: 'Largest campaigns' }), h('div', { class: 'sub', text: 'The same email sent to many people.' })), h('a', { href: '#/campaigns', text: 'All campaigns' })),
                campaignTable(d.campaigns)),
            h('section', { class: 'card' }, h('h2', { text: 'Recent activity' }), h('div', { class: 'sub', text: 'Alerts, emails moved back, and changes, last 7 days.' }),
                d.alerts.length ? h('ul', { class: 'events' }, d.alerts.map(a => h('li', {}, h('time', { text: when(a.at) }), a.text))) : h('div', { class: 'empty', text: 'Nothing new.' }))));
        return out;
    }
    // A button's click handler that posts to the service (asking first when ask is set), says the
    // outcome, and redraws the page.
    function postButton(path, body, done, ask) {
        return async (e) => {
            if (ask && !window.confirm(ask)) return;
            const b = e.currentTarget;
            b.disabled = true; acting++; busyStart();
            try { const out = await api(path, { method: 'POST', body: body() }); toast(done(out)); render(); pendingAt = 0; refreshPending(); }
            catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); b.disabled = false; }
            finally { acting--; busyEnd(); }
        };
    }
    // A campaign's state and an admin's decisions for every copy (Messages, filtered to a campaign).
    // (0.6.39) A campaign's box: the same four answers as anywhere else, for every copy (the last 90 days). Phishing
    // ("confirm": later copies are moved too) and Not phishing ("dismiss": moved copies back, later ones not moved)
    // decide the campaign; Spam and Not sure answer its copies, with Undo, until it is decided. "Move" only in enforce mode.
    async function campaignBar(key) {
        let c;
        try { ({ campaign: c } = await api(`/api/campaign?${q({ key })}`)); } catch (e) { return null; }
        const enforce = currentMode === 'enforce';
        const status = c.decision === 'confirmed' ? `Marked Phishing by ${c.decidedBy}: every copy is ${enforce ? 'moved to the Spam folder' : 'marked'}, and later copies too.`
            : c.decision === 'released' ? `Marked safe by ${c.decidedBy}: its copies went back to the Inbox, and later copies aren't moved.`
            : c.held ? `Moving is paused: ${num(c.held)} copies were left in the Inbox, because more than ${num(c.holdAfter)} were moved on weaker evidence (only the email itself looked bad). Mark it Phishing or Mark safe.`
            : `${num(c.copies)} copies: ${num(c.moved)} in the Spam folder, ${num(c.recorded)} in the Inbox, ${num(c.released)} moved back.`;
        const search = h('input', { type: 'checkbox', checked: true });
        const found = (f) => (f ? `; ${num(f.found)} more found in ${num(f.searched)} of ${num(f.of)} mailboxes${f.moved ? `, ${num(f.moved)} moved` : ''}` : '');
        const run = (label, fn) => async (e) => {
            const btn = e.currentTarget; btn.disabled = true; acting++; busyStart(label);
            try { await fn(); } catch (err) { toast(`Couldn't save your answer: ${err.message}`, { error: true }); btn.disabled = false; } finally { acting--; busyEnd(); }
        };
        const answerAll = (action) => run('Answering every copy…', async () => {
            if (!window.confirm(`Mark every copy of "${c.label}" ${ANSWER[action].label}?${action === 'spam' && enforce ? ' Copies in the Inbox are moved to the Spam folder.' : ''} You can undo it for an hour.`)) return;
            const o = await api('/api/campaign/answer', { method: 'POST', body: { key, action, addSender: action === 'spam' && spamAddSender && !isModerator() } });
            toast(answeredText(action, o, Math.max(2, o.done || 0)), { undo: undoKeys((o.keys || []).concat((o.sameSender && o.sameSender.keys) || [])) });
            render();
        });
        const decide = (action) => run('Answering every copy…', async () => {
            const back = action === 'false-alarm';
            if (!window.confirm(back ? `Mark every copy of "${c.label}" safe (not phishing or spam)?${enforce ? ' Copies in the Spam folder go back to the Inbox,' : ''} and later copies aren't moved.`
                : `Mark every copy of "${c.label}" Phishing?${enforce ? ' Every copy is moved to the Spam folder,' : ''} and later copies are treated the same${search.checked ? '. Every watched mailbox is also searched for copies not recorded' : ''}.`)) return;
            const o = await api(back ? '/api/campaign/release' : '/api/campaign/confirm', { method: 'POST', body: back ? { key } : { key, search: search.checked } });
            toast(back ? `Marked safe: every copy${o.released ? `, ${num(o.released)} moved back to the Inbox` : ''}.`
                : `Marked Phishing: every copy${o.moved && !o.moved.monitor && o.moved.moved ? `, ${num(o.moved.moved)} moved to the Spam folder` : ''}${found(o.found)}.`);
            render();
        });
        const label = (action) => `${ANSWER[action].label}${enforce && action === 'phishing' ? ': move every copy to the Spam folder' : enforce && action === 'false-alarm' ? ': move every copy back' : ' (every copy)'}`;
        return h('section', { class: `card campaign-bar${c.held && !c.decision ? ' held' : ''}` },
            h('div', {}, h('b', { text: c.label }), h('div', { class: 'small muted', text: status })),
            h('div', { class: 'actions' },
                c.decision !== 'confirmed' ? h('button', { class: 'btn phish', type: 'button', title: ANSWER.phishing.help, onclick: decide('phishing') }, label('phishing')) : null,
                !c.decision ? h('button', { class: 'btn', type: 'button', title: ANSWER.spam.help, onclick: answerAll('spam') }, label('spam')) : null,
                c.decision !== 'released' ? h('button', { class: 'btn safe', type: 'button', title: ANSWER['false-alarm'].help, onclick: decide('false-alarm') }, label('false-alarm')) : null,
                !c.decision ? h('button', { class: 'btn', type: 'button', title: ANSWER.unclear.help, onclick: answerAll('unclear') }, label('unclear')) : null),
            h('div', { class: 'actions small' },
                c.decision !== 'confirmed' ? h('label', { class: 'small' }, search, ' with Phishing, also search every watched mailbox for copies not recorded') : null,
                !c.decision ? spamSenderBox('its sender\'s') : null,
                c.decision === 'confirmed' ? h('button', { class: 'btn', type: 'button', onclick: postButton('/api/campaign/find', () => ({ key }), (o) => `Searched: ${num(o.found.found)} more found in ${num(o.found.searched)} of ${num(o.found.of)} mailboxes${o.found.moved ? `, ${num(o.found.moved)} moved` : ''}.`) }, 'Search every mailbox for more copies') : null));
    }
    const kpi = (label, value, note) => h('div', { class: 'card kpi' }, h('div', { class: 'label', text: label }), h('div', { class: 'value', text: value }), note ? h('div', { class: 'note', text: note }) : null);

    function campaignTable(list) {
        return clickTable([
            { name: 'Campaign', cls: 'trunc', get: c => h('div', {}, h('div', { text: c.subject || '(subject not stored)' }), h('div', { class: 'muted small', text: c.senderDomain })) },
            { name: 'People', num: true, get: c => num(c.recipients) },
            // (0.6.44) Emails beside people: someone can get the same email twice (sent again, or to an alias too), and Moved
            // and Would move count emails.
            { name: 'Emails', num: true, get: c => num(c.messages) },
            { name: 'Moved', num: true, get: c => num(c.moved) },
            { name: 'Would move', num: true, get: c => num(c.wouldMove) },
            { name: 'Moved back', num: true, get: c => num(c.released) },
            { name: 'Top reason', get: c => c.topReason }
        ], list, c => go(`#/messages?${q({ campaign: c.campaign })}`));
    }

    // Threats → Campaigns (0.6.0): each campaign as a bar from its first copy to its last across the period (the
    // newest 15), one picked out with its numbers, and every campaign in the table below.
    let pickedCampaign = null;
    async function campaigns() {
        const d = await api(`/api/campaigns?days=${days}`);
        const list = d.campaigns || [];
        const head = [h('h1', { text: 'Campaigns' }), h('p', { class: 'sub', text: 'Emails grouped by sender domain and subject (numbers and the recipient\'s name taken out). Open one to see every copy.' })];
        if (!list.length) return [...head, h('section', { class: 'card' }, h('div', { class: 'empty', text: 'No campaigns in this period.' }))];
        const end = Date.now(), start = end - days * A_DAY, span = end - start;
        const at = (ms) => Math.max(0, Math.min(100, ((ms - start) / span) * 100));
        const recent = list.slice().sort((a, b) => b.lastAt - a.lastAt).slice(0, 15);
        let pick = recent.find(c => c.campaign === pickedCampaign) || recent[0];
        const bad = (c) => (c.moved || 0) + (c.wouldMove || 0) > 0;
        const detail = h('aside', { class: 'card tl-detail', 'aria-live': 'polite' });
        const drawDetail = () => {
            const c = pick;
            detail.textContent = '';
            detail.append(h('span', { class: `tl-state ${bad(c) ? 'bad' : ''}`, text: bad(c) ? (c.moved ? 'Moved to Spam' : 'Would move') : 'Suspicious, not moved' }),
                h('h2', { text: c.subject || '(subject not stored)' }), h('div', { class: 'small muted', text: `From ${c.senderDomain || 'an unknown domain'}` }),
                h('div', { class: 'tl-nums' }, [['People', c.recipients], ['Moved', c.moved], ['Would move', c.wouldMove], ['Moved back', c.released]].map(([l, v]) =>
                    h('div', {}, h('b', { text: num(v) }), h('span', { text: l })))),
                h('dl', { class: 'kv' }, kvRow('Highest AI score', pct(c.maxAi)), kvRow('Top reason', c.topReason || '–'), kvRow('First seen', when(c.firstAt)), kvRow('Last seen', when(c.lastAt))),
                h('a', { class: 'btn primary', href: `#/messages?${q({ campaign: c.campaign })}` }, 'Open every copy'));
        };
        const rows = recent.map(c => {
            const left = at(c.firstAt), right = at(c.lastAt);
            const bar = h('span', { class: `tl-bar ${bad(c) ? 'bad' : 'flag'}` });
            bar.style.left = `${left}%`; bar.style.width = `max(10px, ${Math.max(0, right - left)}%)`;
            const row = h('button', { class: 'tl-row', type: 'button', 'aria-pressed': String(c === pick), onclick: () => {
                pick = c; pickedCampaign = c.campaign;
                for (const r of rowsBox.querySelectorAll('.tl-row')) r.setAttribute('aria-pressed', String(r === row));
                drawDetail();
            } },
                h('span', { class: 'tl-name' }, h('span', { class: 'tl-subject', text: c.subject || '(subject not stored)' }), h('span', { class: 'tl-meta', text: `${c.senderDomain || '–'} · ${num(c.recipients)} people` })),
                h('span', { class: 'tl-track' }, bar));
            return row;
        });
        const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => h('span', { text: dayLabel(new Date(start + f * span).toISOString().slice(0, 10)) }));
        const rowsBox = h('div', { class: 'tl-rows' }, rows);
        drawDetail();
        return [...head,
            h('div', { class: 'tl-wrap' },
                h('section', { class: 'card tl-card', 'aria-label': 'Campaigns over time' },
                    h('div', { class: 'card-head' }, h('div', {}, h('h2', { text: `The newest ${num(recent.length)}, over the last ${days} days` }), h('div', { class: 'sub', text: 'Each bar runs from the first copy to the last. Pick one to see its numbers.' })),
                        h('div', { class: 'legend' }, h('span', {}, h('i', { class: 'tl-key bad' }), 'Moved or would move'), h('span', {}, h('i', { class: 'tl-key flag' }), 'Suspicious only'))),
                    h('div', { class: 'tl-axis', 'aria-hidden': 'true' }, h('span'), h('span', { class: 'tl-ticks' }, ticks)),
                    rowsBox),
                detail),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Every campaign' }), searchRows('campaigns'), clickTable([
                { name: 'Campaign', cls: 'trunc', get: c => h('div', {}, h('div', { text: c.subject || '(subject not stored)' }), h('div', { class: 'muted small', text: c.senderDomain })) },
                { name: 'People', num: true, get: c => num(c.recipients) },
            // (0.6.44) Emails beside people: someone can get the same email twice (sent again, or to an alias too), and Moved
            // and Would move count emails.
            { name: 'Emails', num: true, get: c => num(c.messages) },
                { name: 'Moved', num: true, get: c => num(c.moved) },
                { name: 'Would move', num: true, get: c => num(c.wouldMove) },
                { name: 'Moved back', num: true, get: c => num(c.released) },
                { name: 'Highest AI score', num: true, get: c => pct(c.maxAi) },
                { name: 'Top reason', get: c => c.topReason },
                { name: 'First seen', sort: c => c.firstAt || 0, get: c => when(c.firstAt) },
                { name: 'Last seen', sort: c => c.lastAt || 0, get: c => when(c.lastAt) }
            ], list, c => go(`#/messages?${q({ campaign: c.campaign })}`)))];
    }

    async function users() {
        const d = await api(`/api/users?days=${days}`);
        return [h('h1', { text: 'Users' }), h('p', { class: 'sub', text: 'Everyone who had mail moved, would have had mail moved, or got suspicious mail in this period.' }),
            h('section', { class: 'card' }, searchRows('users'), clickTable([
                { name: 'User', get: u => u.user },
                { name: 'Moved', num: true, get: u => num(u.moved) },
                { name: 'Would move', num: true, get: u => num(u.wouldMove) },
                { name: 'Suspicious', num: true, get: u => num(u.flagged) },
                { name: 'Moved back', num: true, get: u => num(u.released) },
                { name: 'Last', sort: u => u.last || 0, get: u => when(u.last) }
            ], d.users, u => go(`#/messages?${q({ user: u.user })}`)))];
    }

    async function messages(params) {
        const filt = { user: params.get('user') || '', campaign: params.get('campaign') || '', action: params.get('action') || '', state: params.get('state') || '', q: params.get('q') || '' };
        const d = await api(`/api/messages?days=${days}&${q(filt)}`);
        const search = h('input', { type: 'search', placeholder: 'Search sender, recipient, subject or Message-ID', value: filt.q, 'aria-label': 'Search' });
        const action = h('select', { 'aria-label': 'Action' }, h('option', { value: '', text: 'Any action' }), Object.entries(ACTION).map(([k, [l]]) => h('option', { value: k, text: l, selected: filt.action === k })));
        const state = h('select', { 'aria-label': 'Where it is' }, h('option', { value: '', text: 'Anywhere' }), Object.entries(STATE).map(([k, [l]]) => h('option', { value: k, text: l, selected: filt.state === k })));
        const apply = () => go(`#/messages?${q(Object.assign({}, filt, { q: search.value.trim(), action: action.value, state: state.value }))}`);
        search.addEventListener('keydown', (e) => { if (e.key === 'Enter') apply(); });
        action.addEventListener('change', apply); state.addEventListener('change', apply);
        const scope = filt.user ? `for ${filt.user}` : filt.campaign ? 'in this campaign' : '';
        const bar = filt.campaign ? await campaignBar(filt.campaign) : null;
        const csv = MEMORY || isModerator() ? null : h('a', { class: 'btn', href: `/api/export.csv?${q(Object.assign({ days: String(days) }, filt))}`, download: '' }, 'Download CSV');
        // Several at once: a checkbox on each row, and a bar with what to do with the selected ones.
        const selected = new Set(), boxes = [];
        const count = h('b', { text: '' });
        const bulkBar = h('div', { class: 'bulk-bar card', hidden: true });
        const changed = () => { bulkBar.hidden = !selected.size; count.textContent = `${num(selected.size)} selected`; };
        pageBusy = () => selected.size > 0;   // (live updates wait while some are selected)
        const box = (m) => {
            const c = h('input', { type: 'checkbox', 'aria-label': `Select the email from ${m.sender.address} to ${m.user}` });
            c.addEventListener('click', (e) => { e.stopPropagation(); if (c.checked) selected.add(m.key); else selected.delete(m.key); changed(); });
            c.addEventListener('keydown', (e) => e.stopPropagation());
            boxes.push([m, c]);
            return c;
        };
        const all = h('input', { type: 'checkbox', 'aria-label': 'Select every email on this page' });
        all.addEventListener('change', () => { for (const [m, c] of boxes) { c.checked = all.checked; if (all.checked) selected.add(m.key); else selected.delete(m.key); } changed(); });
        // (0.6.39) The same four answers as Review, the same message after them, with Undo; asked first when it is many.
        const bulk = (action) => async (ev) => {
            const btnEl = ev.currentTarget; btnEl.disabled = true; acting++; busyStart('Saving your answers…');
            try { const done = await answerKeys([...selected], action); if (done) { toast(done.text, { undo: undoKeys(done.keys) }); selected.clear(); render(); } }
            catch (err) { toast(`Couldn't save your answers: ${err.message}`, { error: true }); } finally { btnEl.disabled = false; acting--; busyEnd(); }
        };
        bulkBar.append(count,
            ...['phishing', 'spam', 'false-alarm', 'unclear'].map(a => h('button', { class: `btn ${ANSWER[a].cls}`, type: 'button', title: ANSWER[a].help, onclick: bulk(a) }, ANSWER[a].label)),
            spamSenderBox('their senders\'') || '',
            h('button', { class: 'linkbtn', type: 'button', onclick: () => { selected.clear(); all.checked = false; for (const [, c] of boxes) c.checked = false; changed(); } }, 'Clear'));
        return [h('h1', { text: `Emails ${scope}`.trim() }),
            h('p', { class: 'sub' }, `${num(d.total)} recorded in the last ${days} days. `, (filt.user || filt.campaign) ? h('a', { href: '#/messages', text: 'Show all' }) : null),
            recheckBanner(d.rechecked),
            bar,
            h('div', { class: 'toolbar' }, search, action, state, h('button', { class: 'btn', type: 'button', onclick: apply }, 'Filter'), csv,
                MEMORY ? null : h('a', { class: 'btn', href: '#/check' }, 'Check an email'),
                d.messages.length ? h('label', { class: 'small select-all' }, all, ' Select all on this page') : null),
            bulkBar,
            h('section', { class: 'card' }, clickTable([
                // (0.6.39) What happened stays in view: the email (subject and sender together), what happened and where it
                // is now, then the scores and when; fewer columns, so nothing hides off to the right.
                { name: '', get: m => box(m) },
                { name: 'Email', cls: 'trunc', sort: m => (m.subject || '').toLowerCase(), get: m => h('div', {}, h('div', { class: 'msg-subject', text: m.subject || '(subject not stored)' }), h('div', { class: 'muted small', text: `${m.sender.name ? `${m.sender.name} · ` : ''}${m.sender.address}` })) },
                { name: 'To', cls: 'trunc', get: m => m.user },
                { name: 'What happened', get: m => h('div', { class: 'what-happened' }, actionPill(m), kindTag(kindOf(m)),
                    m.recheck ? h('span', { class: 'found-later small' }, alertIcon(`Found after it was delivered (checked again ${when(m.recheck.at)})${m.recheck.clicked ? ': a link in it was clicked' : m.recheck.opened ? ': it had been opened' : ''}`), ' found later') : null) },
                { name: 'Now', get: m => pill(stateOf(m)) },
                { name: 'Scores', num: true, sort: m => (m.score || 0) * 1000 + (m.ai || 0), get: m => h('div', { class: 'scores' }, h('div', { text: `AI ${m.ai === null ? '–' : pct(m.ai)}` }), typeof m.aiSpam === 'number' ? h('div', { class: 'muted small', title: 'The AI\'s spam answer: how sure it is that this is a business\'s bulk marketing', text: `spam ${pct(m.aiSpam)}` }) : null, h('div', { class: 'muted small', text: `rules ${m.score === null || m.score === undefined ? '–' : m.score}` })) },
                { name: 'When', sort: m => m.processedAt || 0, get: m => h('span', { class: 'nowrap', text: when(m.processedAt) }) }
            ], d.messages, m => go(`#/message?${q({ key: m.key })}`), 'No messages match.', m => (m.recheck && RECHECK_BAD.includes(m.recheck.outcome) ? 'row-alert' : '')))];
    }

    async function message(params) {
        const key = params.get('key') || '';
        const { message: m, mode } = await api(`/api/message?${q({ key })}`);
        return emailView(m, { mode });
    }
    // Copies text to the clipboard (or, where the browser doesn't allow it, through a hidden field), then says
    // done in a toast. copyButton: a Copy button for an identifier (what: what it is; label: the button's text).
    async function copyText(text, done) {
        try { await navigator.clipboard.writeText(text); }
        catch (e) {
            const t = h('textarea', { 'aria-hidden': 'true' });
            t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
            document.body.append(t); t.select();
            try { document.execCommand('copy'); } finally { t.remove(); }
        }
        toast(done);
    }
    function copyButton(text, what, label = 'Copy') {
        return h('button', { class: 'linkbtn copy', type: 'button', 'aria-label': `Copy the ${what}`, onclick: () => copyText(text, `${what} copied.`) }, label);
    }
    // (0.5.72) An email address with a small copy button after it (the icon: two sheets).
    // shown: the text in place of the address ("Name <address>"); the button still copies the address alone.
    function addr(address, shown = address) {
        const a = String(address || '');
        if (!a) return shown || '';
        const icon = s('svg', { viewBox: '0 0 16 16', width: 13, height: 13, 'aria-hidden': 'true', focusable: 'false' },
            s('rect', { x: 5.5, y: 5.5, width: 8, height: 9, rx: 1.5 }), s('path', { d: 'M3.5 10.5h-.5A1.5 1.5 0 0 1 1.5 9V3A1.5 1.5 0 0 1 3 1.5h6A1.5 1.5 0 0 1 10.5 3v.5' }));
        return h('span', { class: 'addr' }, shown, h('button', { class: 'copy-addr', type: 'button', title: `Copy ${a}`, 'aria-label': `Copy ${a}`,
            onclick: (e) => { e.stopPropagation(); copyText(a, `Copied ${a}.`); } }, icon));
    }
    // A row with an identifier, its Copy button (and any others: extra), and what it is for.
    const idRow = (label, value, note, extra = []) => [h('dt', { text: label }),
        h('dd', {}, value ? [h('code', { class: 'mid', text: value }), ' ', copyButton(value, label), ...extra.flatMap(b => [' ', b]), note ? h('div', { class: 'muted small', text: note }) : null]
            : h('span', { class: 'muted', text: 'not recorded (emails before 0.3.1)' }))];
    // Google Vault's search finds an email by its Message-ID written as rfc822msgid:<id> (no angle brackets).
    const vaultQuery = (id) => `rfc822msgid:${String(id || '').replace(/^<|>$/g, '')}`;
    const PASTED = { move: 'Would be moved to Spam', 'would-move': 'Would be recorded as "would move" (monitor mode: nothing is moved)', flag: 'Would be recorded as suspicious, not moved', none: 'Nothing would happen: the checks find nothing to act on' };

    // Re-scan (Review, an email's page): the email read again from its mailbox and judged now, with today's checks
    // and model; nothing is moved, and the record keeps what happened on arrival beside it.
    const pctOr = (x) => (typeof x === 'number' ? pct(x) : 'none');
    // (0.6.6) An email being re-scanned isn't asked again until it is done (its button is greyed out meanwhile).
    // The service refuses one too (within 30 s of its last re-scan, or while one runs) and says why: the toast shows it.
    const rescanning = new Set();
    async function rescanEmail(key) {
        if (rescanning.has(key)) { toast('This email is being re-scanned now: wait for it to finish.'); return; }
        rescanning.add(key);
        for (const b of document.querySelectorAll('[data-rescan-key]')) if (b.dataset.rescanKey === key) b.disabled = true;
        acting++; busyStart('Checking it again: reading the email from Gmail…');
        try {
            const out = await api('/api/rescan', { method: 'POST', body: { key } });
            const r = out.rescan;
            toast(`Checked again with ${r.model || 'no AI model'}: AI ${pctOr(r.ai)}, rules score ${r.score}. ${PASTED[r.action] || r.action}.`);
            render();
        } catch (e) { toast(`Couldn't re-scan it: ${e.message}`); } finally {
            rescanning.delete(key); acting--; busyEnd('Checking it again: reading the email from Gmail…');
            for (const b of document.querySelectorAll('[data-rescan-key]')) if (b.dataset.rescanKey === key) b.disabled = false;
        }
    }
    function rescanButton(m, cls) {
        if (m.pasted || !m.key || MEMORY) return null;
        return h('button', { class: cls, type: 'button', 'data-rescan-key': m.key, disabled: rescanning.has(m.key), title: 'Read it again from the mailbox and judge it with today\'s checks and AI model. Nothing is moved. Once every 30 seconds per email.', onclick: () => rescanEmail(m.key) },
            cls.includes('review') ? [h('kbd', { text: 'R' }), ' Check again'] : 'Check again');
    }
    function rescanBox(m) {
        const r = m.rescan;
        if (!r) return null;
        // On arrival: kept apart since 0.5.4 (arrival); a record re-scanned by 0.5.3 still has it in ai and score.
        const arr = m.arrival || { ai: m.ai, score: m.score };
        const was = arr.ai && typeof arr.ai.probability === 'number' ? arr.ai.probability : null;
        const other = arr.ai && arr.ai.model && r.model && arr.ai.model !== r.model ? `, ${arr.ai.model}` : '';
        return h('div', { class: 'rescan' },
            h('b', { text: `Checked again ${when(r.at)}${r.by ? ` by ${r.by}` : ''}` }),
            h('div', { text: `With ${r.model || 'no AI model'}: AI ${pctOr(r.ai)} (on arrival ${pctOr(was)}${other}); rules score ${r.score} (on arrival ${arr.score === null || arr.score === undefined ? '–' : arr.score}).` }),
            h('div', { text: `With today's checks and model: ${PASTED[r.action] || r.action}.` }),
            h('div', { class: 'small muted', text: 'The scores, the AI opinion and the signs on this page are the re-scan\'s; what happened to the email stays, and nothing was moved by the re-scan: decide with the buttons. The sender counts as new if it was new on arrival.' }));
    }

    // Found after it was delivered (0.5.35): why, when, where it was, opened, a link clicked.
    function recheckBox(m) {
        const r = m.recheck;
        if (!r) return null;
        const c = r.clicks;
        // (the same words as src/recheck.js foundWords)
        const why = r.source === 'lists' ? `${r.list || 'A phishing list'} listed ${r.site || 'one of its sites'} after it was delivered`
            : r.source === 'lookalike' ? (r.list === 'marked' ? `An admin marked ${r.site || 'a look-alike'} a threat after it was delivered` : `The look-alike watch found ${r.site || 'a domain'} imitating your domain after it was delivered`)
            : r.source === 'update' ? `Version ${r.version || 'a new version'} changed how email is checked after it was delivered`
            : `A second look ${r.round === 2 ? 'a day' : 'an hour'} after it arrived`;
        const did = { moved: `It was moved to Spam ${when(r.movedAt || r.at)}.`, 'would-move': 'Monitor mode: it was recorded as "would move" and left in the Inbox.', held: 'A brake left it in the Inbox.',
            'not-in-inbox': `It had already left the Inbox (${WHERE[r.where] || r.where}), so it wasn't moved.`, flag: 'It is now suspicious, and was left in the Inbox.' }[r.outcome] || '';
        return h('div', { class: `rescan recheck-box${RECHECK_BAD.includes(r.outcome) ? ' bad' : ''}` },
            h('b', {}, RECHECK_BAD.includes(r.outcome) ? alertIcon('Found after delivery') : null, ` Found on a re-check, ${when(r.at)}`),
            h('div', { text: `${why}. ${r.before === 'none' ? 'Nothing was found on arrival' : `On arrival it was ${(ACTION[r.before] || [r.before])[0].toLowerCase()}`}${typeof r.beforeScore === 'number' ? ` (score ${r.beforeScore})` : ''}. ${did}` }),
            h('div', { text: `Delivered ${when(m.receivedAt)}. Opened before the re-check: ${c && c.opened ? `yes${c.openedAt ? `, ${when(c.openedAt)}` : ''}` : r.opened ? 'yes' : 'no'}. Link clicked: ${c ? (c.clicked ? `YES${c.clickedAt ? `, ${when(c.clickedAt)}` : ''}` : `none found in Gmail's logs (checked ${when(c.checkedAt)})`) : 'not checked (Settings → Link clicks)'}.` }),
            h('a', { class: 'small', href: '#/rechecked', text: 'Every copy: Threats → Re-checked' }));
    }

    // The AI's opinion of one email: its score and where that stands against the lines that move or flag
    // mail, what weighed most, and "…show more" (showAiReading: the email itself, then what the model reads of
    // it, sentence by sentence; read from Gmail on demand, the service keeps no email text). No score: why
    // (mail from inside, or a language it doesn't read).
    // (0.6.39) Said first: when the rule checks or a list moved or flagged the email, not the AI, so a low AI number
    // next to a red verdict doesn't read as a contradiction.
    function aiNotTheCause(m) {
        const t = m.trigger;
        if (!['move', 'would-move'].includes(m.action) || !['rules', 'spam', 'admin'].includes(t)) return null;
        const by = t === 'rules' ? 'the rule checks' : t === 'admin' ? 'an admin\'s answer' : m.spamSender ? 'the Spam senders list' : 'the spam check';
        const what = m.action === 'move' ? 'Moved' : 'Would be moved';
        return h('p', { class: 'ai-cause' }, h('b', { text: `${what} because of ${by}, not the AI.` }), ' The AI\'s number below is its own opinion; a low number doesn\'t mean the checks were wrong.');
    }
    function aiOpinion(m, ai, opts = {}) {
        if (ai === null) {
            if (m.ai && m.ai.skipped === 'inside') return h('div', { class: 'ai-none' },
                h('b', { text: 'Not scored: the sender is inside your organization.' }),
                h('div', { text: 'The AI doesn\'t read mail from inside (your domains, Gmail confirmed the sender is real (DMARC)): Settings → Policy, "AI reads staff email", turns it on. The rule checks read it as usual: its links, its headers and the rest.' }));
            if (m.ai && m.ai.skipped === 'bounce') return h('div', { class: 'ai-none' },
                h('b', { text: 'Not scored: a delivery report from a mail provider.' }),
                h('div', { text: 'A "couldn\'t be delivered" report from a mail provider\'s own mail system (its sender check passed): the AI reads its failure wording as a lure, so it gives no opinion. The rule checks read it as usual, the returned copy included.' }));
            if (m.ai && m.ai.skipped === 'language') return h('div', { class: 'ai-none' },
                h('b', { text: 'Not scored: the AI model reads English only.' }),
                h('div', { text: `This email looks like it is in ${m.ai.language || 'another language'}, so the AI gives no opinion of it. The rule checks don't depend on the language and ran as usual; decide from the signs and the email itself.` }));
            return h('div', { class: 'empty', text: m.ai && m.ai.error ? `The model gave no score (${m.ai.error}).` : 'The model gave no score.' });
        }
        const inside = !!m.inside;
        const where = ai >= aiThreshold ? (inside ? (aiMovesInside ? `at or over the move line (${pct(aiThreshold)}): the AI score alone moves it, though the sender is inside your organization ("Let the AI alone move staff email" is on)`
                : `at or over the move line (${pct(aiThreshold)}), but the sender is inside your organization, so the AI score alone doesn't move it ("Let the AI alone move staff email" is off)`) : `at or over the move line (${pct(aiThreshold)}): the AI score alone moves an outside email`)
            : ai >= aiSuspicious ? `over the suspicious line (${pct(aiSuspicious)}), under the move line (${pct(aiThreshold)}): recorded as suspicious, not moved`
            : ai >= 0.5 ? `50% or more, so it leans toward phishing, but under the suspicious line (${pct(aiSuspicious)}): the AI alone does nothing`
            : `under 50%: the AI reads it as genuine`;
        const canRead = !m.pasted && !!m.key;
        const more = canRead ? h('button', { class: 'linkbtn', type: 'button', text: '…show more' }) : null;
        if (more) more.addEventListener('click', () => showAiReading(m));
        return [
            h('div', { class: 'kpi kpi-small' }, h('div', { class: 'value', text: pct(ai) }), h('div', { class: 'note', text: `${m.ai.model}: how likely it is phishing` })),
            m.rescan && m.arrival ? h('div', { class: 'small muted', text: `Checked again ${when(m.rescan.at)}. On arrival: ${m.arrival.ai ? `${pct(m.arrival.ai.probability)}, ${m.arrival.ai.model || 'an unknown model'}` : 'no AI score'}.` }) : null,
            (() => { const mt = h('div', { class: `meter ${ai >= aiThreshold ? 'hot' : ''}`, role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(ai * 100), 'aria-label': 'AI score' }, h('div')); mt.firstChild.style.width = pct(ai); return mt; })(),
            h('div', { class: 'small ai-where', text: `Where it stands: ${pct(ai)} is ${where}.` }),
            aiSpamLine(m),
            m.ai.reasons && m.ai.reasons.length ? [h('div', { class: 'small muted', text: 'What weighed most (each part scored on its own):' }),
                m.ai.reasons.map(r => h('div', { class: 'quote', text: r.facts ? 'Who sent it, the sender check and where its links go' : `“${r.sentence}”` }))]
                : ai >= 0.5 ? h('div', { class: 'small muted', text: 'Which parts weighed most isn\'t kept for this email (STORE_AI_QUOTES=off, or recorded before it was).' }) : null,
            h('div', { class: 'small muted' }, 'The model reads the subject, the sender\'s name and domain, the sender check, where the links go and the text, with addresses and numbers replaced. ',
                more ? [more, ' to see the whole email as the model reads it, sentence by sentence, with what weighed most.'] : null)];
    }
    // (0.6.6) The email itself, as received: who, the subject, all its text (the quoted earlier messages and any text
    // hidden from the reader folded away), every link with where it really goes (not clickable), the attachments.
    // m.links (the record's flagged links) marks the links the checks flagged.
    function emailAsReceived(e, m) {
        const who = (p) => (p.name ? `${p.name} <${p.address}>` : p.address);
        const row = (k, v) => (v ? [h('dt', { text: k }), h('dd', {}, v)] : null);
        const people = (l) => (l && l.length ? l.map((p, i) => [i ? ', ' : '', addr(p.address, who(p))]) : null);
        const flagged = new Set((m.links || []).map(l => l.url));
        const size = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`);
        const fold = (title, text, note) => (text ? h('details', { class: 'email-fold' }, h('summary', { text: title }), note ? h('div', { class: 'small muted', text: note }) : null, h('div', { class: 'email-text', text })) : null);
        return h('section', { class: 'email-received' },
            h('h3', { text: 'The email' }),
            h('dl', { class: 'kv email-head' },
                row('From', e.from.address ? addr(e.from.address, who(e.from)) : e.from.name || 'unknown'), row('To', people(e.to)), row('Cc', people(e.cc)), row('Reply-To', people(e.replyTo)),
                row('Date', e.date ? when(e.date) : ''), row('Subject', e.subject || '(no subject)')),
            e.text ? h('div', { class: 'email-text', text: e.text }) : h('div', { class: 'empty', text: e.pictures || e.attachments.length ? `No text in the email itself: its content is ${[e.pictures ? `${num(e.pictures)} picture${e.pictures === 1 ? '' : 's'}` : '', e.attachments.length ? `${num(e.attachments.length)} attachment${e.attachments.length === 1 ? '' : 's'}` : ''].filter(Boolean).join(' and ')} (below).` : 'No text in the email.' }),
            fold('Earlier messages quoted below it', e.quoted),
            fold('Text hidden from the reader', e.hidden, 'In the email but not shown to its reader (white on white, tiny, or hidden): often filler to fool filters.'),
            e.links.length ? [h('h4', { text: `Links (${num(e.links.length)})` }), h('ul', { class: 'email-links' }, e.links.map(l => h('li', { class: flagged.has(l.href) ? 'flagged' : null },
                h('span', { text: l.text && l.text !== l.href ? `“${l.text}”` : '' }), l.text && l.text !== l.href ? ' → ' : '', h('code', { class: 'mid', text: l.href }),
                l.hidden ? h('span', { class: 'small muted', text: ' (hidden)' }) : null, flagged.has(l.href) ? h('span', { class: 'small flag-note', text: ' flagged' }) : null)))] : null,
            e.attachments.length ? [h('h4', { text: `Attachments (${num(e.attachments.length)})` }), h('ul', { class: 'plain-list' }, e.attachments.map(a => h('li', { text: `${a.name || '(no name)'} · ${a.type || 'unknown type'} · ${size(a.size)}` })))] : null,
            e.pictures ? h('div', { class: 'small muted', text: `${num(e.pictures)} picture${e.pictures === 1 ? '' : 's'} in the email (not loaded here).` }) : null,
            h('div', { class: 'small muted', text: 'Shown as text: nothing in it is opened, loaded or clickable here. Read from Gmail just now; nothing is kept.' }));
    }
    // "…show more" and Show the email: the email as received (0.6.6), then what the model reads of it, read from
    // Gmail now (nothing is kept; Activity notes the look), in a popup.
    async function showAiReading(m) {
        const body = h('div', { class: 'ai-reading' }, h('div', { class: 'empty', text: 'Reading the email from Gmail…' }));
        popup(`The email: ${m.subject || '(no subject)'}`, body);
        try {
            const { language, reading: r, skipped, email } = await api('/api/message/context', { method: 'POST', body: { key: m.key } });
            body.textContent = '';
            if (email) body.append(emailAsReceived(email, m));
            body.append(h('h3', { class: 'ai-part', text: 'What the AI reads' }));
            if (skipped === 'inside') { body.append(h('div', { class: 'ai-none' }, h('b', { text: 'Not scored: the sender is inside your organization.' }), h('div', { text: 'The AI doesn\'t read mail from inside (Settings → Policy, "AI reads staff email").' }))); return; }
            if (skipped === 'bounce') { body.append(h('div', { class: 'ai-none' }, h('b', { text: 'Not scored: a delivery report from a mail provider.' }), h('div', { text: 'The AI doesn\'t score a mail provider\'s own "couldn\'t be delivered" reports; the rule checks read it as usual.' }))); return; }
            body.append(h('p', { class: 'sub', text: 'Read from Gmail just now; nothing is kept, and Activity notes that you looked. Addresses keep only their domain, and phone numbers and long numbers are replaced, as the model sees them. Each part is also scored on its own: how much that part alone reads like phishing.' }));
            if (!r) { body.append(h('div', { class: 'ai-none' }, h('b', { text: 'Not scored: the AI model reads English only.' }), h('div', { text: `This email looks like it is in ${language && language.name || 'another language'}.` }))); return; }
            const lean = (w) => 1 / (1 + Math.exp(-w));
            // The whole email's score is the AI's opinion. A part scored alone, out of context, can read
            // more like phishing than the email does ("click here to accept" is in invitations too): when
            // the whole email reads as genuine (under 50%), nothing is marked or shown in red.
            const calm = r.probability < 0.5;
            const weighed = calm ? new Set() : new Set(r.sentences.map((x, i) => [x.weight, i]).filter(([w]) => w > 0).sort((a, b) => b[0] - a[0]).slice(0, 3).map(([, i]) => i));
            const badge = (w) => (w === null || w === undefined ? null : h('span', { class: `lean ${!calm && lean(w) >= 0.5 ? 'hot' : ''}`, text: `${pct(lean(w))} on its own` }));
            const partsHigher = calm && [r.headWeight, ...r.sentences.map(x => x.weight)].some(w => lean(w) >= 0.5);
            body.append(h('div', { class: 'small' }, h('b', { text: `The AI now: ${pct(r.probability)}${typeof r.spam === 'number' ? `, spam ${pct(r.spam)}` : ''}` }), ` (${r.model} ${r.version}, the whole email${m.ai && typeof m.ai.probability === 'number' && Math.abs(m.ai.probability - r.probability) >= 0.01 ? `; ${pct(m.ai.probability)} when it was checked` : ''}).`));
            if (partsHigher) body.append(h('div', { class: 'alert info' }, h('div', { text: `The whole email reads as genuine to the AI (${pct(r.probability)}): that is its opinion. Some parts score higher on their own, because without the rest of the email a single line (a link, "click here to accept") reads like many phishing emails; together, the AI doesn't find it phishing.` })));
            // What weighed most, each with the nearest sentence of real text before and after it (blank
            // lines, lone punctuation and invisible padding skipped: reading() marks them filler).
            const inContext = calm ? [] : (r.weighed || []).filter(c => r.sentences[c.index]);
            if (inContext.length) body.append(h('h3', { text: 'What weighed most, with the sentence before and after' }),
                ...inContext.map(c => h('div', { class: 'in-context' },
                    h('div', { class: 'ctx muted', text: c.before ? c.before.text : '(the start of the text)' }),
                    h('div', { class: 'ctx weighed' }, h('span', { text: r.sentences[c.index].text }), badge(r.sentences[c.index].weight)),
                    h('div', { class: 'ctx muted', text: c.after ? c.after.text : '(the end of the text)' }))));
            // (0.6.54) With a Copy button: the exact line the AI read, to paste into a report.
            body.append(h('h3', {}, 'About the sender and links ', copyButton(r.head, 'line about the sender and links')), h('div', { class: 'reading-line' }, h('div', { class: 'mono small', text: r.head }), badge(r.headWeight)));
            const shown = r.sentences.map((x, i) => [x, i]).filter(([x]) => !x.filler);
            const left = r.sentences.length - shown.length;
            body.append(...[h('h3', { text: `The whole text, sentence by sentence${weighed.size ? ' (what weighed most is marked)' : ''}` }),
                shown.length ? h('ol', { class: 'reading' }, shown.map(([x, i]) => h('li', { class: `${weighed.has(i) ? 'weighed' : ''}${x.unread ? ' unread' : ''}`.trim() || null }, h('span', { text: x.text }), x.unread ? h('span', { class: 'lean', text: 'not read by the model' }) : badge(x.weight))))
                    : h('div', { class: 'empty', text: 'No text: the model read only the subject, the sender and the links.' }),
                left ? h('div', { class: 'small muted', text: `${num(left)} blank or filler line${left === 1 ? '' : 's'} (spaces, lone punctuation, invisible characters) left out.` }) : null,
                r.scored && r.scored < r.sentences.length ? h('div', { class: 'small muted', text: `The whole email is shown. Its first ${num(r.scored)} sentences are also scored on their own${r.read && r.read < r.sentences.length ? `; the model's input keeps ${num(r.read)} of them (${r.readsEnd ? 'the first 40 and the last 20' : `the first ${num(r.read)}`}), so the others are marked "not read by the model"` : '; the rest are read by the model with the email, not one by one'}.` }) : null,
                r.more ? h('div', { class: 'small muted', text: `…and ${num(r.more)} more sentences the model reads, not scored one by one here.` }) : null].filter(Boolean));
        } catch (e) {
            body.textContent = '';
            body.append(h('div', { class: 'alert warning' }, h('div', { text: `Couldn't read it: ${e.message}` })));
        }
    }

    // (0.6.55) The AI's spam answer (phish-tiny 0.26.0 on): how sure it is that the email is a business's bulk marketing,
    // wanted or not, and what the spam rules do with it. Nothing for a model without one.
    function aiSpamLine(m) {
        const q = m.ai && typeof m.ai.spam === 'number' ? m.ai.spam : null;
        if (q === null) return null;
        const p = m.ai.probability || 0;
        const where = q < 0.5 ? 'it doesn\'t read as bulk marketing'
            : q < aiThreshold || p >= aiSuspicious ? `it reads as a business's bulk marketing, under the line where the spam rules act (${pct(aiThreshold)})`
            : m.inside ? 'it reads as bulk marketing, but the sender is inside your organization, so it is never moved as spam'
            : m.gmailPromotions ? `at or over ${pct(aiThreshold)}, but Gmail put it in its Promotions tab: never moved for this alone`
            : m.verified || (m.auth && m.auth.dmarc === 'pass') ? `at or over ${pct(aiThreshold)}, from a sender Gmail confirmed (DMARC): never moved for this alone; the company's marketing is listed in Review → Promotional for one answer`
            : `at or over ${pct(aiThreshold)}, from a sender Gmail couldn't confirm: moved as spam when nothing else is suspicious (like other spam: moving on the rules on, enforce mode)`;
        return h('div', { class: 'small ai-spam' }, h('b', { text: `Spam: ${pct(q)}` }), ` (${m.ai.model}: how likely it is a business's bulk marketing, wanted or not; not phishing). ${where.replace(/^./, c => c.toUpperCase())}.`);
    }
    // One email's decision: a record (Messages), or a pasted email's answer (Check an email: m.pasted).
    // opts.inReview: the review queue shows its own buttons and title.
    function emailView(m, opts = {}) {
        const pasted = !!m.pasted, quiet = pasted || !!opts.inReview;
        const ai = m.ai && typeof m.ai.probability === 'number' ? m.ai.probability : null;
        // A user took back an email the checks flagged, and no admin has looked yet: worth a look.
        const rescueToCheck = !pasted && m.state === 'released' && m.releasedByUser && !m.markedBy && m.score >= 5 && m.trigger !== 'ai';
        const decisionClass = rescueToCheck ? 'would' : m.state === 'released' ? 'released' : m.action === 'move' ? 'move' : m.action === 'would-move' ? 'would' : m.action === 'none' ? 'released' : 'flag';
        const act = async (path, body, done) => { acting++; busyStart(); try { const out = await api(path, { method: 'POST', body }); toast(typeof done === 'function' ? done(out) : done); render(); } catch (e) { toast(`Couldn't save that: ${e.message}`, { error: true }); } finally { acting--; busyEnd(); } };
        // Suspicious emails weren't moved, so "not phishing" says it better than "false alarm"; in enforce
        // mode, phishing still in the Inbox is moved to Spam when confirmed.
        const notMoved = m.action === 'flag';
        const moves = opts.mode === 'enforce' && m.state === 'inbox' && m.action !== 'move';
        // (0.6.39) The same four answers as Review, worded the same, each shown unless it is already this email's answer
        // (so any answer can be changed); Not phishing also for an email its reader took back, which no admin has
        // looked at yet. None is styled as the page's main button; Undo is in the message after.
        const isPhish = m.falseAlarm === false && !m.spam, isSpam = m.falseAlarm === false && !!m.spam;
        const reviewed = !!m.markedBy;
        const answer = (action) => async () => {
            acting++; busyStart();
            try { const done = await answerKeys([m.key], action); if (done) { toast(done.text, { undo: undoKeys(done.keys) }); render(); } }
            catch (e) { toast(`Couldn't save your answer: ${e.message}`, { error: true }); } finally { acting--; busyEnd(); }
        };
        const btn = (action, label) => h('button', { class: `btn ${ANSWER[action].cls}`, type: 'button', title: ANSWER[action].help, onclick: answer(action) }, label);
        const canSender = m.auth && m.auth.dmarc === 'pass' && !m.inside;
        const actions = quiet ? null : h('div', { class: 'actions answer-actions' },
            !isPhish || moves ? btn('phishing', answerLabel('phishing', moves)) : null,
            !isSpam || moves ? btn('spam', answerLabel('spam', moves)) : null,
            m.falseAlarm !== true || !reviewed ? btn('false-alarm', answerLabel('false-alarm', m.state === 'moved')) : null,
            !(m.unclear && reviewed) ? btn('unclear', ANSWER.unclear.label) : null,
            (!isSpam || moves) && canSender ? spamSenderBox(m.spamKey ? `${m.spamKey}'s` : 'its sender\'s') : null,
            rescanButton(m, 'btn'));
        const verdictText = pasted ? 'Checked from a pasted copy: nothing was stored, moved or counted.'
            : m.userReported && !m.markedBy ? `Its reader reported it as phishing with Gmail's Report phishing${m.userReported.at ? `, ${when(m.userReported.at)}` : ''}. No admin has answered it yet: answer it below (Review → Reported lists it).`
            : m.falseAlarm === true && m.releasedByUser && !m.markedBy ? 'Its reader moved it back to the Inbox, so it counts as safe for now. No admin has looked at it yet: answer it below.'
            : m.falseAlarm === true && m.autoAnswered ? (m.autoAnswered.kind === 'campaign' ? `Marked safe automatically: ${m.markedBy || 'an admin'} dismissed its campaign as a false alarm.` : `Marked safe automatically: ${m.markedBy || 'an admin'} marked an identical email safe (Settings → Sender lists → Remembered answers).`)
            : m.falseAlarm === true ? `Marked safe by ${m.markedBy || 'an admin'}.` : m.falseAlarm === false ? (m.spam ? `Answered Spam by ${m.markedBy || 'an admin'}.` : m.spam === false ? `Answered Phishing by ${m.markedBy || 'an admin'}.` : `Answered Phishing or spam by ${m.markedBy || 'an admin'} (before Spam was its own answer).`)
            : m.unclear && m.markedBy ? `Answered Not sure by ${m.markedBy}: left as it is, and not used to train the AI.` : 'Not answered yet.';
        return [quiet ? null : h('button', { class: 'linkbtn back', type: 'button', onclick: back }, '← Back'),
            h(quiet ? 'h2' : 'h1', { class: quiet ? 'pasted-title' : null, text: m.subject || (pasted ? '(no subject)' : '(subject not stored)') }),
            h('p', { class: 'sub' }, 'From ', m.sender.address ? addr(m.sender.address, m.sender.name ? `${m.sender.name} <${m.sender.address}>` : m.sender.address) : (m.sender.name || 'an unknown sender'),
                ' to ', m.user ? addr(m.user) : '–', m.receivedAt ? `, ${when(m.receivedAt)}` : ''),
            h('div', { class: 'grid detail' },
                h('div', { class: 'grid' },
                    h('section', { class: 'card' }, h('h2', { text: 'What happened' }),
                        h('div', { class: `decision ${decisionClass}` }, h('b', { text: pasted ? (PASTED[m.action] || m.action) : m.state === 'released' ? (m.releasedByUser ? 'Moved back to the Inbox by the user' : `Moved back to the Inbox by ${m.releasedBy}`) : asKind(m) }), pasted || m.state === 'released' ? null : kindTag(kindOf(m)), h('div', { text: m.state === 'released' ? `${when(m.releasedAt)}. It was moved because ${m.why}.` : m.why ? `Because ${m.why}.` : 'No sign of phishing from the checks or the AI.' }),
                            rescueToCheck ? h('div', { text: 'The checks flagged it. Make sure it is safe, or confirm phishing and warn the user.' }) : null),
                        h('div', { class: 'small muted', text: `${verdictText} ${m.markedBy ? `(${m.markedBy})` : ''}`.trim() }),
                        // (0.6.32) A pasted email with a training rule's header the rule didn't match: why.
                        pasted && (m.trainingMiss || []).length ? h('div', { class: 'alert warning' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '!' }),
                            h('div', { class: 'grow' }, h('b', { text: 'Not recognized as a training email. ' }), m.trainingMiss.map(x => `It has the "${x.name}" rule's header, but ${x.why}.`).join(' '), ' Settings → Phishing training: edit the rule.')) : null,
                        pasted ? null : recheckBox(m),
                        pasted ? null : rescanBox(m),
                        // (about moving, so not for an email the service didn't move: suspicious, or moved by an admin's decision)
                        m.evidence && !notMoved && !(m.heldMovedBy && !m.trigger) ? h('div', { class: 'small muted', text: m.evidence === 'strong' ? `Strong evidence: the rules flagged it, and ${(m.confirmedBy || []).join('; ')}. Moving its campaign is never paused for it.`
                            : m.evidence === 'admin' ? 'A copy found by an admin\'s search for a campaign.' : 'Weaker evidence: nothing outside the email confirms it, so moving its campaign\'s copies can pause for your decision (they stay in the Inbox meanwhile).' }) : null,
                        actions),
                    h('section', { class: 'card' }, h('h2', { text: 'Signs found' }), h('div', { class: 'sub', text: `The rule checks: score ${m.score === null || m.score === undefined ? '–' : m.score} (suspicious from 3, moved from 5).` }),
                        m.signals.length ? h('ul', { class: 'signals' }, m.signals.slice().sort((a, b) => b.weight - a.weight).map(sg => h('li', {}, h('span', { class: `weight ${sg.weight >= 3 ? 'high' : ''}`, text: String(sg.weight) }), h('span', { text: sg.text })))) : h('div', { class: 'empty', text: 'No signs.' })),
                    m.links && m.links.length ? h('section', { class: 'card' }, h('h2', { text: 'Links the checks found' }), h('ul', { class: 'signals' }, m.links.map(l => h('li', {}, h('span', { class: `weight ${l.severity === 'danger' ? 'high' : ''}`, text: l.severity === 'danger' ? '!' : '?' }), h('span', {}, h('div', { text: l.reason || '' }), h('div', { class: 'muted small', text: `${l.from ? `${l.from[0].toUpperCase()}${l.from.slice(1)}: ` : ''}${l.finalUrl && l.finalUrl !== l.url ? `${l.url} → ${l.finalUrl}` : l.url}` })))))) : null),
                h('div', { class: 'grid' },
                    h('section', { class: 'card' }, h('h2', { text: 'What the AI thought' }), aiNotTheCause(m), aiOpinion(m, ai, opts)),
                    h('section', { class: 'card' }, h('h2', { text: 'Details' }), h('dl', { class: 'kv' },
                        h('dt', { text: 'Sender check' }), h('dd', { text: m.auth ? `DMARC ${m.auth.dmarc || '–'}${m.auth.derived ? ` (worked out from ${m.auth.derived}: Gmail wrote no DMARC result)` : ''}, SPF ${m.auth.spf || '–'}, DKIM ${m.auth.dkim || '–'}` : 'not recorded' }),
                        h('dt', { text: 'What moved it' }), h('dd', { text: m.trigger ? ({ rules: 'Rules', ai: 'AI score', 'rules+ai': 'Rules and AI', admin: 'An admin marked its campaign Phishing, and the search for its copies found it' })[m.trigger] || m.trigger : m.state === 'moved' && m.heldMovedBy ? `none: ${m.heldMovedBy} confirmed it as phishing` : 'none' }),
                        h('dt', { text: 'Mode when it arrived' }), h('dd', { text: m.mode === 'enforce' ? 'Enforce (moves mail)' : m.mode === 'monitor' ? 'Monitor (moves nothing)' : (m.mode || '–') }),
                        h('dt', { text: 'Looked up' }), h('dd', { text: m.checks ? [m.checks.cloudflare ? `Cloudflare: ${m.checks.cloudflare} site${m.checks.cloudflare === 1 ? '' : 's'}` : '', m.checks.safeBrowsing ? `Safe Browsing: ${m.checks.safeBrowsing} link${m.checks.safeBrowsing === 1 ? '' : 's'}` : '', m.checks.lists ? 'phishing lists' : '', m.checks.ages ? `site age: ${m.checks.ages}` : '', m.checks.notChecked ? `${m.checks.notChecked} not checked` : ''].filter(Boolean).join(' · ') || 'nothing to look up' : 'offline checks only' }),
                        h('dt', { text: 'Attachments' }), h('dd', { text: m.attachments && m.attachments.length ? m.attachments.map(a => a.name || a.type).join(', ') : 'none' }),
                        // What the attachment checks found (0.5.34): a QR code's site, a form, a script…
                        m.attachmentFindings && m.attachmentFindings.length ? [h('dt', { text: 'Found in them' }), h('dd', {}, h('ul', { class: 'plain-list' }, m.attachmentFindings.map(f => h('li', { text: f.what }))))] : null,
                        idRow('Message-ID', m.rfc822MessageId, 'To look it up in Google Workspace: Admin console → Reporting → Email log search (Message ID), or the security investigation tool. Copy for Vault gives Google Vault\'s search for it (rfc822msgid:…).',
                            m.rfc822MessageId ? [copyButton(vaultQuery(m.rfc822MessageId), 'Vault search', 'Copy for Vault')] : []),
                        pasted ? null : idRow('Gmail ID', m.messageId, 'The Gmail API\'s id of this copy, in this mailbox.'),
                        h('dt', { text: 'Checked' }), h('dd', { text: when(m.processedAt) })))))];
    }

    // --- Mail → Check an email: what the service would decide for a reported email -----------------------
    async function check() {
        const area = h('textarea', { class: 'paste', rows: 10, spellcheck: 'false', 'aria-label': 'The email\'s original',
            placeholder: 'In Gmail, open the email, then ⋮ → Show original → Copy to clipboard, and paste it here. Or choose a saved .eml file below.' });
        const file = h('input', { type: 'file', accept: '.eml,message/rfc822,text/plain', 'aria-label': 'An .eml file' });
        const out = h('div', { class: 'check-result', 'aria-live': 'polite' });
        const run = async (raw) => {
            if (!raw.trim()) { toast('Paste the email\'s original first, or choose an .eml file.'); return; }
            acting++; busyStart();
            out.textContent = '';
            out.append(h('div', { class: 'muted', text: 'Checking…' }));
            try {
                const { result } = await api('/api/check', { method: 'POST', body: { raw } });
                out.textContent = '';
                out.append(...[].concat(emailView(result)).flat(Infinity).filter(Boolean));
            } catch (e) {
                out.textContent = '';
                out.append(h('div', { class: 'alert critical', role: 'alert' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '⚠️' }), h('div', {}, h('b', { text: 'Couldn\'t check it. ' }), e.message)));
            } finally { acting--; busyEnd(); }
        };
        file.addEventListener('change', async () => {
            const f = file.files && file.files[0];
            if (!f) return;
            if (f.size > 10 * 1024 * 1024) { toast('That file is over 10 MB.'); return; }
            run(await f.text());
        });
        return [h('h1', { text: 'Check an email' }),
            h('p', { class: 'sub', text: 'What the service would decide for an email someone reported, and why: judged as on arrival, in the current mode, with the same lookups. Nothing is stored, moved or counted; Activity notes that you checked one.' }),
            h('section', { class: 'card' }, area, h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'button', onclick: () => run(area.value) }, 'Check the pasted email'),
                // (0.6.39) The file picker as a plain button that says what it does.
                h('label', { class: 'btn file-btn' }, file, 'Or choose a saved .eml file…'))),
            out];
    }

    // The model in use, and, when others scored some of the period's emails (before an upgrade), which.
    function modelLine(d) {
        const now = d.current || d.model || 'unknown';
        const models = d.models || [];
        if (!models.length || (models.length === 1 && models[0].model === now)) return `Model in use: ${now}.`;
        const total = models.reduce((n, m) => n + m.count, 0);
        return `Model in use: ${now}. The scores above for these ${num(total)} emails came from ${models.map(m => `${m.model} (${num(m.count)})`).join(', ')}: emails are scored on arrival, and keep the score the model in use then gave them.`;
    }
    async function health() {
        const d = await api(`/api/health?days=${days}`);
        const reviewedRate = d.reviewed ? d.falseAlarms / d.reviewed : 0;
        return [h('h1', { text: 'Model health' }), h('p', { class: 'sub', text: 'Whether the move rules are right: how often each kind of move had to be undone. Use this to choose the AI move level (Settings → Policy).' }),
            h('div', { class: 'grid kpis' }, kpi('Moved back by users', num(d.userReleased || 0), 'Not spam, or dragged to the Inbox'), kpi('Reviewed', num(d.reviewed), 'moved back, marked or confirmed'), kpi('Confirmed phishing', num(d.confirmed), ''), kpi('False alarms', num(d.falseAlarms), d.reviewed ? `${pct(reviewedRate, 1)} of reviewed` : ''), kpi('AI move level', pct(d.threshold), 'Settings → Policy')),
            h('div', { class: 'grid' },
                h('section', { class: 'card' }, h('h2', { text: 'Recorded emails by AI score' }), h('div', { class: 'sub', text: 'Each column is a 10-point range of the model\'s score; hover for how many were moved back.' }), h('div', { class: 'chart' }, histogram(d.buckets, d.threshold))),
                h('section', { class: 'card' }, h('h2', { text: 'Moves taken back, by what moved them' }), h('div', { class: 'sub', text: 'Moved back ÷ moved. A high rate for "AI score" alone means the AI move level is too low (Settings → Policy).' }),
                    dataTable([{ name: 'What moved it', get: r => r.label }, { name: 'Moved', num: true, get: r => num(r.moved) }, { name: 'Moved back', num: true, get: r => num(r.released) }, { name: 'By users', num: true, get: r => num(r.byUser || 0) }, { name: 'Rate', num: true, get: r => pct(r.rate, 1) }], d.byTrigger),
                    h('p', { class: 'small muted', text: modelLine(d) }))),
            togetherCard(d),
            h('p', { class: 'small muted' }, 'Examples for retraining the AI model: ', h('a', { href: '#/trainingexport', text: 'Health → Retraining examples' }), '.')];
    }
    // Rules and AI together: measured only. Emails from outside senders that scored in between on both
    // (neither alone moves them), and what admins marked them: whether moving such emails would be worth
    // trying. Nothing is moved because of it.
    function togetherCard(d) {
        const t = d.together;
        if (!t) return null;
        const [lo, hi] = t.ai;
        const marked = t.phishing + t.falseAlarms;
        const verdict = !t.count ? 'None in this period.'
            : marked < 10 ? `Too few marked so far to tell (${num(marked)} of ${num(t.count)}): mark them in Review → Suspicious, not moved.`
            : t.phishing >= 0.8 * marked ? `Most of those marked are phishing (${pct(t.phishing / marked)}): moving such emails could be worth trying, in monitor mode first.`
            : t.falseAlarms >= 0.5 * marked ? `Many of those marked are genuine (${pct(t.falseAlarms / marked)}): moving such emails would make false alarms.`
            : `Mixed so far (${pct(t.phishing / marked)} phishing): keep marking them.`;
        return h('section', { class: 'card spaced' }, h('h2', { text: 'Rules and AI together (measured only)' }),
            h('div', { class: 'sub', text: `Emails from outside senders with a rules score of ${t.rules[0]} to under ${t.rules[1]} and an AI score of ${pct(lo)} to under ${pct(hi)}: each in between, so neither alone moves them, and they are recorded as suspicious. Nothing is moved because of this count.` }),
            h('div', { class: 'grid kpis' }, kpi('In between on both', num(t.count), `last ${days} days`), kpi('Marked phishing', num(t.phishing), 'by an admin'),
                kpi('Marked false alarm', num(t.falseAlarms), 'by an admin'), kpi('Not reviewed', num(t.unreviewed), 'yet')),
            h('p', { class: 'small muted', text: verdict }));
    }

    // --- Health → DMARC & reputation (0.6.1): each of your domains' DMARC and SPF records as published, what they
    // say, and what would make them stronger (src/dashboard/dmarc.js), with its reputation beside them.
    const DMARC_TAGS = [['p', 'Policy', (v) => ({ none: 'none: report only, deliver anyway', quarantine: 'quarantine: to spam', reject: 'reject: refuse it' })[String(v).toLowerCase()] || v],
        ['sp', 'Subdomains', (v) => v || null], ['pct', 'Applies to', (v) => `${v}% of failing mail`], ['adkim', 'DKIM alignment', (v) => (String(v).toLowerCase() === 's' ? 'strict' : 'relaxed')],
        ['aspf', 'SPF alignment', (v) => (String(v).toLowerCase() === 's' ? 'strict' : 'relaxed')], ['rua', 'Aggregate reports to', (v) => v], ['ruf', 'Failure reports to', (v) => v]];
    const LEVEL_WORDS = { good: 'Strong', warn: 'Can be stronger', bad: 'Needs attention' };
    // A domain's reputation (src/dashboard/reputation.js): each blocklist service, and the downloaded lists' entries on it.
    const REP_STATE = { clean: ['Clean', 'good'], listed: ['Listed', 'bad'], off: ['Off', 'off'], unknown: ['Not checked', 'warn'] };
    function reputationPart(r, error) {
        const head = (lvl) => h('h3', {}, 'Reputation and blocklists ', lvl ? h('span', { class: `dns-level ${lvl}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), { good: 'Clean', warn: 'Partly checked', bad: 'Listed' }[lvl]) : null);
        if (!r) return h('div', { class: 'dns-part' }, head(null), h('div', { class: 'small muted', text: error ? `Couldn't check (${error}).` : 'Not checked.' }));
        return h('div', { class: 'dns-part' }, head(r.level),
            h('ul', { class: 'rep-list' }, r.services.map(sv => { const [w, c] = REP_STATE[sv.state] || [sv.state, 'warn'];
                return h('li', {}, h('span', { class: 'rep-name', text: sv.name }), h('span', { class: `dns-level ${c}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), w), h('span', { class: 'rep-detail small muted', text: sv.detail })); })),
            h('h3', {}, 'In the downloaded phishing lists'),
            r.lists.length ? r.lists.map(l => h('div', { class: 'rep-hit' },
                h('div', {}, h('b', { text: l.list }), ` has ${num(l.count)} ${l.kind === 'address' ? 'sender address' : l.kind === 'url' ? 'link' : 'site'}${l.count === 1 ? '' : 's'} on this domain${l.count > l.entries.length ? ` (the first ${num(l.entries.length)} shown)` : ''}:`),
                l.entries.map(e => h('code', { class: 'rep-entry', text: e }))))
                : h('div', { class: 'small muted', text: r.listsChecked ? `Nothing on this domain or under it in the ${num(r.listsChecked)} lists downloaded (Settings → About).` : `Not checked${r.listsError ? ` (${r.listsError})` : ': the phishing lists are off or not downloaded yet'}.` }),
            r.lists.length ? h('p', { class: 'small muted', text: 'A listed site or link on your own domain usually means a hacked page or a compromised account: find and fix it, then ask the list to remove it. Mail is still judged as before: your own domains count only as exact listed links and addresses, never as a whole site.' }) : null);
    }
    async function dmarcPage(params) {
        const fresh = params.get('fresh') ? '?fresh=1' : '';
        const [d, rep] = await Promise.all([api(`/api/dmarc${fresh}`), api(`/api/reputation${fresh}`).catch(e => ({ error: e.message, domains: [] }))]);
        const repOf = (domain) => (rep.domains || []).find(r => r.domain === domain);
        if (params.get('fresh')) { if (MEMORY) memRoute = '#/dmarc'; else history.replaceState(null, '', '#/dmarc'); }
        const recordBox = (text) => h('div', { class: 'dns-record' }, h('code', { text }), copyButton(text, 'DNS record', 'Copy'));
        const level = (x, what = '') => h('span', { class: `dns-level ${x.level}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), `${what}${LEVEL_WORDS[x.level] || x.level}`);
        const notes = (list) => (list && list.length ? h('ul', { class: 'dns-notes' }, list.map(n => h('li', { text: n }))) : null);
        const card = (x) => {
            if (x.error) return h('section', { class: 'card dns-card' }, h('div', { class: 'dns-head' }, h('h2', { text: x.domain }), h('span', { class: 'dns-level bad' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), 'Couldn\'t read')),
                h('p', { class: 'small muted', text: `The DNS lookup failed (${x.error}). Check again in a minute.` }));
            const tags = x.dmarc.tags || (x.dmarc.inherited && x.dmarc.inherited.tags);
            return h('section', { class: 'card dns-card' },
                h('div', { class: 'dns-head' }, h('h2', { text: x.domain }), level(x.dmarc, 'DMARC: ')),
                h('div', { class: 'dns-part' },
                    h('h3', {}, 'DMARC ', h('span', { class: 'small muted', text: `_dmarc.${x.domain}` })),
                    h('div', { class: 'dns-words', text: x.dmarc.words }),
                    x.dmarc.records.length ? x.dmarc.records.map(recordBox) : x.dmarc.inherited ? [h('div', { class: 'small muted', text: `Its parent's record (_dmarc.${x.dmarc.inherited.domain}):` }), recordBox(x.dmarc.inherited.record)] : h('div', { class: 'small muted', text: 'No TXT record starting v=DMARC1 was found.' }),
                    tags ? h('dl', { class: 'kv dns-tags' }, DMARC_TAGS.filter(([k]) => tags[k] !== undefined && tags[k] !== '').map(([k, label, show]) => { const v = show(tags[k]); return v ? kvRow(label, v) : null; })) : null,
                    notes(x.dmarc.notes)),
                h('div', { class: 'dns-part' },
                    h('h3', {}, 'SPF ', h('span', { class: 'small muted', text: x.domain }), ' ', level(x.spf)),
                    h('div', { class: 'dns-words', text: x.spf.words }),
                    x.spf.records.length ? x.spf.records.map(recordBox) : h('div', { class: 'small muted', text: 'No TXT record starting v=spf1 was found.' }),
                    notes(x.spf.notes)),
                reputationPart(repOf(x.domain), rep.error),
                h('div', { class: 'small muted', text: `Read ${when(x.checkedAt)}.` }));
        };
        const counts = { good: 0, warn: 0, bad: 0 };
        for (const x of d.domains) counts[x.error ? 'bad' : x.dmarc.level]++;
        const listed = (rep.domains || []).filter(r => r.level === 'bad').length;
        return [h('div', { class: 'page-head' }, h('div', {}, h('h1', { text: 'DMARC & reputation' }),
                h('p', { class: 'sub', text: 'Your domains: their DMARC and SPF records as published in DNS, what they tell other mail servers to do with mail that pretends to come from you, and what would make them stronger; whether a blocklist lists them; and whether the phishing lists the service downloads have anything on them or under them. Only the domain names are sent (to Cloudflare\'s resolver, and to Safe Browsing and Spamhaus when they are on). Changing the records is done where your domains\' DNS is managed.' })),
                h('a', { class: 'btn', href: '#/dmarc?fresh=1' }, 'Check again')),
            h('div', { class: 'kpi-strip' }, h('span', {}, h('b', { text: num(d.domains.length) }), ` domain${d.domains.length === 1 ? '' : 's'}`),
                h('span', {}, 'DMARC: ', h('b', { text: num(counts.good) }), ' strong, ', h('b', { text: num(counts.warn) }), ' can be stronger, ', h('b', { text: num(counts.bad) }), ' need attention'),
                h('span', {}, h('b', { text: num(listed) }), ` listed on a blocklist or in a downloaded list`)),
            d.domains.length ? h('div', { class: 'dns-grid' }, d.domains.map(card)) : h('div', { class: 'empty', text: 'No domains set up yet (for IT: ORG_DOMAINS).' })];
    }
    // --- Health → Retraining examples (0.6.1, its own page; was on Model health): off until an admin allows it in
    // Settings → Retraining.
    async function trainingPage() {
        const d = await api(`/api/health?days=${days}`);
        return [h('h1', { text: 'Retraining examples' }),
            h('p', { class: 'sub' }, 'The emails admins and moderators marked, as training examples for the AI model. Marking emails doesn\'t train the model by itself: this file, checked by hand (docs/RETRAINING.md), does. ',
                h('a', { href: '#/retraining', text: 'Settings → Retraining' }), ' allows or stops it.'),
            trainingCard(d)];
    }
    function trainingCard(d) {
        const title = h('h2', { text: 'Examples for retraining the model' });
        const intro = h('div', { class: 'sub', text: `The emails an admin or moderator confirmed as phishing in the last ${days} days (and, if you tick it, the false alarms), one per campaign, newest first, up to 100, as training examples for the AI model. Each is read from Gmail when you download, with the people in it taken out. The file is the only copy: nothing is stored, and Activity notes who downloaded it.` });
        const guide = h('p', { class: 'small muted', text: 'Before the file goes anywhere, follow docs/RETRAINING.md: check every example (words marked ⟦like this⟧ may be names), run tools/check-training-file.js, then train.' });
        if (!d.trainingExport) return h('section', { class: 'card spaced' }, title, intro, h('p', { class: 'small muted', text: 'Off. A dashboard admin can allow it in Settings → Retraining.' }));
        if (MEMORY) return h('section', { class: 'card spaced' }, title, intro, h('p', { class: 'small muted', text: 'The clickable mockup has no emails to read: in the real dashboard, the download is here.' }), guide);
        const fa = h('input', { type: 'checkbox', 'aria-label': 'Include false alarms' });
        const warn = h('div', { class: 'alert warning', hidden: true }, h('div', { text: 'False alarms are real people\'s mail: parents, staff, companies. Check each one with care, and leave out any you can\'t make anonymous (anything about a student, health, grades or discipline).' }));
        fa.addEventListener('change', () => { warn.hidden = !fa.checked; });
        const result = h('p', { class: 'small muted', role: 'status' });
        const btn = h('button', { class: 'btn', type: 'button' }, 'Download for retraining');
        btn.addEventListener('click', async () => {
            btn.disabled = true; btn.textContent = 'Reading the emails (up to a minute)…'; acting++; busyStart('Reading the emails for the retraining file (up to a minute)…');
            try {
                const hd = await downloadPost('/api/training-export', { days, falseAlarms: fa.checked });
                const n = (k) => Number(hd.get(`x-spruce-${k}`) || 0);
                const pl = (k, one, many) => `${num(n(k))} ${n(k) === 1 ? one : many}`;
                result.textContent = [`${pl('examples', 'example', 'examples')} in the file: ${num(n('phishing'))} phishing${fa.checked ? `, ${pl('genuine', 'false alarm', 'false alarms')}` : ''}.`,
                    n('gone') ? `${num(n('gone'))} no longer in a mailbox.` : '', n('failed') ? `${num(n('failed'))} couldn't be read.` : '',
                    n('conflicting') ? `${num(n('conflicting'))} campaigns marked both ways left out.` : '',
                    n('not-english') ? `${num(n('not-english'))} not in English left out (the model reads English only).` : '',
                    n('not-reached') ? `${num(n('not-reached'))} more not reached: choose a shorter period for the older ones.` : ''].filter(Boolean).join(' ');
                toast('Downloaded. Check it before it goes anywhere.');
            } catch (e) { result.textContent = `Couldn't make the file: ${e.message}`; }
            finally { btn.disabled = false; btn.textContent = 'Download for retraining'; acting--; busyEnd('Reading the emails for the retraining file (up to a minute)…'); }
        });
        return h('section', { class: 'card spaced' }, title, intro,
            h('label', { class: 'switch' }, fa, h('span', { text: 'Include false alarms' })), warn,
            h('div', { class: 'actions' }, btn), result, guide);
    }

    // --- Settings, in pages (its own menu beside the page, in four groups: SECTIONS.settings below) ------------
    async function settingsData(query = '') { const d = await api(`/api/settings${query}`); showMode(d.mode); return d; }
    const kvRow = (k, v) => [h('dt', { text: k }), v instanceof Node ? h('dd', {}, v) : h('dd', { text: v })];
    async function settings() {   // Policy
        const d = await settingsData();
        const allowed = ((d.policy && d.policy.allowDomains && d.policy.allowDomains.value) || d.allowDomains || []).length;
        const addresses = d.policy && d.policy.allowAddresses ? d.policy.allowAddresses.value.length : d.allowAddresses;
        const card = policyCard(d, POLICY_ROWS, 'Every setting', 'Each change needs the Google Cloud project ID, applies within 30 seconds, and is noted in Health → Activity → What admins did. When deploy/settings.env says something else, deploy/install.sh (and upgrade.sh) asks which to keep, and writes the answer into settings.env.');
        const P = d.policy || {};
        const val = (k) => ((P[k] || {}).value !== undefined ? P[k].value : d[k]);
        const mode = val('mode'), move = val('aiThreshold'), sus = val('aiSuspicious');
        const modeOption = (m, title, text) => h('button', { class: `mode-option${mode === m ? ' current' : ''}`, type: 'button', 'aria-pressed': String(mode === m), disabled: !d.projectKnown && mode !== m,
            onclick: () => { if (mode !== m) card.openRow('mode', m); } },
            h('span', { class: 'mode-option-title' }, title, m === 'monitor' ? h('span', { class: 'safe-badge', text: 'Safe default' }) : null, mode === m ? h('span', { class: 'pol-pill on', text: 'In force' }) : null),
            h('span', { class: 'small', text }));
        const scale = h('div', { class: 'ai-scale', 'aria-hidden': 'true' }, h('span', { class: 'ai-zone sus' }), h('span', { class: 'ai-zone move' }), h('span', { class: 'ai-mark sus' }), h('span', { class: 'ai-mark move' }));
        scale.style.setProperty('--sus', pct(sus, 1)); scale.style.setProperty('--move', pct(move, 1));
        const labels = h('div', { class: 'ai-labels' }, h('span', { class: 'ai-label sus' }, h('b', { text: pct(sus) }), ' the suspicious line'), h('span', { class: 'ai-label move' }, h('b', { text: pct(move) }), ' the move line'));
        return [h('h1', { text: 'Policy' }), h('p', { class: 'sub', text: 'What is moved to Spam, and when. The settings below can be changed here, each change confirmed with the Google Cloud project ID; the rest is set when the service is deployed (deploy/settings.env, docs/DEPLOY.md).' }),
            h('div', { class: 'grid policy-top' },
                h('section', { class: 'card' }, h('h2', { text: 'Mode' }), h('div', { class: 'sub', text: 'Start in Monitor, and switch when Readiness says false alarms are rare. Switching needs the project ID and I agree.' }),
                    h('div', { class: 'mode-options', role: 'group', 'aria-label': 'Mode' },
                        modeOption('monitor', 'Monitor', 'Check and record. Nothing is moved.'),
                        modeOption('enforce', 'Enforce', 'Move the mail the policy flags to Spam.'))),
                h('section', { class: 'card' }, h('h2', { text: 'How sure the AI must be' }),
                    h('div', { class: 'sub', text: `One scale, two lines: from the suspicious line an email is recorded for review; from the move line the AI score alone moves it${val('aiMovesInside') ? ' (inside mail too: "Let the AI alone move staff email" is on)' : ', from outside senders (inside mail never moves on the AI score alone)'}.` }),
                    scale, labels,
                    d.projectKnown ? h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: () => card.openRow('aiSuspicious') }, 'Change the suspicious line'), h('button', { class: 'btn', type: 'button', onclick: () => card.openRow('aiThreshold') }, 'Change the move line')) : null)),
            card,
            h('section', { class: 'card spaced' }, h('h2', { text: 'How it decides' }), h('dl', { class: 'kv' },
                kvRow('Moved: sender outside', d.moveOnRules ? `either one is enough: the AI scores ${pct(d.aiThreshold)} or more, or the rules flag it (a rules score of 5 or more). The AI score needs no rule, link check or other sign to agree.`
                    : `when the AI scores ${pct(d.aiThreshold)} or more (moving on the rule checks is off: the rules alone don't move mail).`),
                kvRow('Moved: sender is staff (inside)', d.aiMovesInside ? (d.moveOnRules ? `as for outside senders, either one is enough: the AI scores ${pct(d.aiThreshold)} or more, or the rules flag it (5 or more). "Let the AI alone move staff email" is on (Settings → Policy): the AI score alone moves a colleague's email too.`
                        : `when the AI scores ${pct(d.aiThreshold)} or more ("Let the AI alone move staff email" is on; MOVE_ON_RULES is off: the rules alone don't move mail).`)
                    : d.moveOnRules ? `only when the rules flag it (a rules score of 5 or more: its links, its headers and the rest), as they do for a staff account taken over. ${d.aiScansInside ? `The AI reads it too (Settings → Policy), but its score alone doesn't move it, even at ${pct(d.aiThreshold)} or more ("Let the AI alone move staff email" is off): it is recorded as suspicious.` : 'The AI doesn\'t read it (Settings → Policy, "AI reads staff email": off).'}`
                    : 'never (the AI score alone doesn\'t move inside mail: "Let the AI alone move staff email" is off; and moving on the rule checks is off).'),
                kvRow('Inside or outside', `inside: the From address is in your own domains (${(d.orgDomains || []).join(', ') || 'none set up yet'}) and Gmail confirmed the sender is real (DMARC) for it. Anything else is outside, a forged staff address too. DMARC only decides this (and whether a Trusted sender counts): an outside sender doesn't have to pass or fail it. A failed DMARC check is also one of the rules' signs (2 or 3 points), never required.`),
                kvRow('Suspicious, not moved', `a rules score of 3 or more (from a sender Gmail confirmed, only when the AI also scores it ${pct(d.aiSuspicious || 0.65)} or more), or an AI score of ${pct(d.aiSuspicious || 0.65)} or more, that doesn't move it${d.aiMovesInside ? '' : ' (an inside sender\'s high AI score included)'}: recorded for review (Review → Suspicious, not moved).`),
                kvRow('Moved as spam', `${d.moveOnRules ? '' : '(moving on the rule checks is off, so nothing is moved as spam) '}list or marketing mail padded with hidden text, or (with an AI model that has a spam answer) mail the AI is ${pct(d.aiThreshold)} or more sure is a business's bulk marketing, from an outside sender Gmail couldn't confirm (DMARC), not in Gmail's Promotions tab, with nothing else suspicious. Never mail from inside. Marketing from a sender Gmail confirmed is never moved for that: it is listed in Review → Promotional, and an admin's Spam answer moves that company's later mail.`),
                kvRow('The rules', 'the rule checks add up signs: dangerous or brand-new links, a look-alike or impersonated sender, forged headers, a failed sender check, requests for passwords, codes or money, a new outside sender. Suspicious from 3, moved from 5. The AI score is separate.'),
                kvRow('Campaign pause', `After ${num(d.campaignHoldAfter)} copies of one campaign are moved on weaker evidence, moving its other copies pauses until you confirm it as phishing or dismiss it as a false alarm; until then they stay in the Inbox, like any email not moved. Strong evidence never pauses (CAMPAIGN_HOLD_AFTER)`),
                kvRow('Alerts', d.alertEmail ? `Emailed to ${d.alertEmail} by Cloud Monitoring` : 'Shown in Health → Activity; not emailed (ALERT_EMAIL, deploy/install.sh)'),
                kvRow('Never moved', allowed || addresses ? `Trusted senders: ${num(allowed)} domain${allowed === 1 ? '' : 's'} and ${num(addresses)} address${addresses === 1 ? '' : 'es'} (Settings → Sender lists)` : 'nobody on Trusted senders (Settings → Sender lists)'),
                kvRow('Label on moved mail', d.movedLabel)))];
    }
    // (0.6.26) Spam people took back: when someone moves mail the service moved as spam back out of Spam, that sender's
    // spam isn't moved for them again (6 months); when 3 or more people did, for no one, until an admin keeps moving it.
    async function spamRescuedCard() {
        let list = [];
        try { list = (await api('/api/spam-rescued')).list || []; } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Spam people took back' }),
            h('p', { class: 'sub', text: 'When someone moves mail the service moved as spam back out of Spam, that sender\'s spam isn\'t moved for them again for 6 months (only from a sender Gmail verified; phishing is never affected: it is still checked and moved). When 3 or more people took back the same sender\'s, it isn\'t moved as spam for anyone; it is listed here. If it is mail your district wants, add it to Trusted senders above; if it is spam after all, keep moving it (each person who took some back still keeps theirs).' }));
        if (!list.length) { card.append(h('p', { class: 'empty', text: 'No sender yet: nobody\'s spam has been taken back by 3 or more people.' })); return card; }
        const draw = (rows) => {
            card.querySelectorAll('table').forEach(t => t.remove());
            card.append(h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Sender', 'People who took it back', 'Last', ''].map(t => h('th', { text: t })))),
                h('tbody', {}, rows.map(r => h('tr', {}, h('td', { text: r.sender }), h('td', { 'data-sort': String(r.people), text: num(r.people) }), h('td', { 'data-sort': String(r.last || 0), text: dayOf(r.last) }),
                    h('td', {}, isModerator() ? null : h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                        e.target.disabled = true;
                        try { const out = await api('/api/spam-rescued', { method: 'POST', body: { sender: r.sender, keep: !r.keep } }); toast(r.keep ? `Spam from ${r.sender} is no longer moved for anyone.` : `Spam from ${r.sender} is moved to Spam again.`); draw(out.list || []); }
                        catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, r.keep ? 'Stop moving it' : 'Keep moving it'),
                        r.keep ? h('span', { class: 'small muted', text: ` Moved again${r.keepBy ? ` (${r.keepBy})` : ''}` }) : null))))));
        };
        draw(list);
        return card;
    }
    // (0.6.52) Promotional senders kept: companies an admin answered Keep in Review → Promotional; an admin removes one (its
    // promotional mail is listed again).
    async function promoKeptCard() {
        let list = [];
        try { list = (await api('/api/promotional-kept')).list || []; } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Promotional senders kept' }),
            h('p', { class: 'sub', text: 'Companies whose promotional mail an admin chose to keep (Review → Promotional → Keep). Each is the sender\'s own domain, never the platform it sends through.' }));
        const draw = (rows) => {
            card.querySelectorAll('table, p.empty').forEach(t => t.remove());
            if (!rows.length) { card.append(h('p', { class: 'empty', text: 'No company yet.' })); return; }
            card.append(h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Company', 'Kept by', 'Since', ''].map(t => h('th', { text: t })))),
                h('tbody', {}, rows.map(r => h('tr', {}, h('td', { text: r.company }), h('td', { text: r.by || '' }), h('td', { 'data-sort': String(r.at || 0), text: dayOf(r.at) }),
                    h('td', {}, isModerator() ? null : h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                        e.target.disabled = true;
                        try { const out = await api('/api/promotional-kept', { method: 'POST', body: { company: r.company } }); toast(`${r.company}'s promotional mail is listed in Review again.`); draw(out.list || []); }
                        catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, 'Remove')))))));
        };
        draw(list);
        return card;
    }
    // (0.6.56) Remembered Not phishing answers: identical emails an admin answered Not phishing (src/remember.js); an admin
    // removes one (its later copies are judged as usual again); moderators see the list.
    async function rememberedCard() {
        let list = [];
        try { list = (await api('/api/remembered')).list || []; } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Remembered answers' }),
            h('p', { class: 'sub', text: 'Emails marked safe (not phishing or spam) in Review, an email\'s page or Mail: their identical copies are marked safe too. "Was" shows what the service had taken the email for. Each is kept as a one-way hash of the email, with its sender and subject line for this list.' }));
        const draw = (rows) => {
            card.querySelectorAll('table, p.empty').forEach(t => t.remove());
            if (!rows.length) { card.append(h('p', { class: 'empty', text: 'No answer remembered yet.' })); return; }
            card.append(h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Sender', 'Subject', 'Was', 'Marked safe by', 'Copies since', 'Until', ''].map(t => h('th', { text: t })))),
                h('tbody', {}, rows.map(r => h('tr', {}, h('td', { text: r.sender }), h('td', { class: 'trunc', text: r.label || '–' }), h('td', {}, h('span', { class: `kind-tag ${/^Phishing/.test(r.was || '') ? 'needs' : ''}`, text: r.was || 'not recorded' })), h('td', { text: r.by || '' }),
                    h('td', { 'data-sort': String(r.hits || 0), text: `${num(r.hits || 0)}${r.last && r.hits ? ` (last ${dayOf(r.last)})` : ''}` }), h('td', { 'data-sort': String(r.until || 0), text: dayOf(r.until) }),
                    h('td', {}, isModerator() ? null : h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                        e.target.disabled = true;
                        try { const out = await api('/api/remembered', { method: 'POST', body: { id: r.id } }); toast('Removed: its later copies are judged as usual again.'); draw(out.list || []); }
                        catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, 'Remove')))))));
        };
        draw(list);
        return card;
    }
    // (0.6.29) Brand senders the reviewers confirmed: a "False alarm" on an email whose only sign was a brand's name from
    // another verified domain. An admin removes one; moderators see the list.
    async function brandSendersCard() {
        let list = [];
        try { list = (await api('/api/brand-senders')).list || []; } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Brand senders' }),
            h('p', { class: 'sub', text: 'A company that sends for a brand from its own domain (Walmart Business\'s invoices from TreviPay, a bank\'s mail about the card it issues in a store\'s name) gets "the sender\'s name says the brand, but the address isn\'t the brand\'s". When a reviewer answers False alarm on such an email, and that was its only sign and Gmail confirmed the sender is real, the brand and the domain are listed here: from then on its verified mail under that brand\'s name isn\'t counted as an imitation, and the AI is told it is the brand\'s sender. Every other check still applies, and a forged copy is judged as before. Remove one to undo it.' }));
        if (!list.length) { card.append(h('p', { class: 'empty', text: 'None yet: no false alarm of this kind has been answered.' })); return card; }
        const draw = (rows) => {
            card.querySelectorAll('table, p.empty').forEach(t => t.remove());
            if (!rows.length) { card.append(h('p', { class: 'empty', text: 'None left.' })); return; }
            card.append(h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Brand', 'Sender domain', 'Confirmed by', 'Last', ''].map(t => h('th', { text: t })))),
                h('tbody', {}, rows.map(r => h('tr', {}, h('td', { text: r.brand }), h('td', { text: r.domain }), h('td', { text: `${r.by || '–'}${r.count > 1 ? ` (${num(r.count)} emails)` : ''}` }), h('td', { 'data-sort': String(r.last || r.at || 0), text: dayOf(r.last || r.at) }),
                    h('td', {}, isModerator() ? null : h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                        e.target.disabled = true;
                        try { const out = await api('/api/brand-senders', { method: 'POST', body: { key: r.key } }); toast(`${r.domain} is no longer a confirmed sender for ${r.brand}.`); draw(out.list || []); }
                        catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, 'Remove')))))));
        };
        draw(list);
        return card;
    }
    // (0.6.30) The allow lists' 30-day check: the domains whose registration or reputation changed. A suspended one isn't
    // trusted until an admin answers "Still trusted" (with the project ID), which can also release the emails it got
    // while suspended (answered as false alarms: those in Spam go back to the Inbox).
    async function allowReviewCard() {
        let d;
        try { d = await api('/api/allow-watch'); } catch (e) { return null; }
        const rows = d.review || [];
        const card = h('section', { class: 'card spaced' + (rows.length ? ' allow-review' : '') }, h('h2', { text: rows.length ? `Needs review: ${num(rows.length)}` : 'The 30-day check' }),
            h('p', { class: 'sub', text: `Every domain on these lists (${num(d.watched || 0)} now) is looked up every 30 days: its registration (when it was registered, when it expires, its registrar and name servers) and its reputation (Cloudflare, the phishing lists, Spamhaus). If it was registered again, expired, or is now blocked or listed, it may have lapsed and been taken by someone else: it is suspended, not trusted until you answer, and its emails are checked like anyone's. A new registrar or new name servers only flag it. Each one found is also emailed to the admins.` }));
        if (!rows.length) { card.append(h('p', { class: 'empty', text: 'Nothing to review: no domain on the lists has changed.' })); return card; }
        // (0.6.39) Each domain's own answer, its project ID (for a suspended one) beside the button it confirms.
        const answer = (r, release, idBox) => async (e) => {
            e.target.disabled = true;
            try {
                const out = await api('/api/allow-watch', { method: 'POST', body: { domain: r.domain, release, projectId: idBox ? idBox.value.trim() : '' } });
                toast(`${r.domain} stays on its list${r.suspended ? ' and is no longer suspended' : ''}${release ? `: ${num(out.answered)} email${out.answered === 1 ? '' : 's'} marked safe, ${num(out.released)} moved back to the Inbox` : ''}.`);
                render();
            } catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; }
        };
        for (const r of rows) {
            const idBox = r.suspended && !isModerator() ? h('input', { type: 'text', class: 'project-input', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': `Google Cloud project ID, to keep ${r.domain} on its list` }) : null;
            card.append(h('div', { class: `review-row ${r.suspended ? 'suspended' : ''}` },
                h('div', { class: 'review-head' }, h('b', { text: r.domain }), h('span', { class: `kind-tag ${r.suspended ? 'needs' : 'changed'}`, text: r.suspended ? 'Suspended' : 'Changed' }),
                    h('span', { class: 'small muted', text: ` on ${r.lists.join(', ')} · found ${when(r.at)}` })),
                h('ul', { class: 'small' }, r.changes.map(c => h('li', { text: `${c.text[0].toUpperCase()}${c.text.slice(1)}.` }))),
                r.emails ? h('p', { class: 'small' }, `${num(r.emails)} email${r.emails === 1 ? '' : 's'} from it ${r.suspended ? 'were checked like anyone\'s while it was suspended' : 'were recorded since'}${r.moved ? ` (${num(r.moved)} moved to the Spam folder)` : ''}: `, h('a', { href: `#/messages?${q({ q: `@${r.domain}` })}`, text: 'see them' }), '.') : null,
                isModerator() ? null : h('div', { class: 'review-actions' },
                    idBox ? h('label', { class: 'project inline' }, h('span', { text: 'Project ID, to confirm' }), idBox) : null,
                    h('button', { class: 'btn', type: 'button', onclick: answer(r, false, idBox) }, 'Keep it on the list'),
                    r.emails ? h('button', { class: 'btn', type: 'button', onclick: answer(r, true, idBox) }, `Keep it, and mark its ${num(r.emails)} email${r.emails === 1 ? '' : 's'} safe`) : null,
                    h('span', { class: 'small muted', text: ' Not wanted any more? Remove it from its list below.' }))));
        }
        return card;
    }
    // (0.6.35) Settings → Sender lists (was Allowlist): one card per list, each with a label for what it does.
    const LIST_LABELS = {
        trusted: ['Never moved', 'trusted', 'Its mail is never moved or marked suspicious, whatever the checks find, as long as Gmail confirms the sender is real (DMARC) for it (a forged address is judged like any other).'],
        spam: ['Always to Spam', 'spam', 'Its verified mail goes straight to Spam, as spam, whatever the other checks find (monitor mode: recorded as "would move"). A forged copy, mail from inside, and a person who took its spam back are judged as usual.'],
        brand: ['Brand\'s own sender', 'brand', 'Its verified mail under the brand\'s name isn\'t counted as an imitation; every other check still applies.'],
        link: ['Link site allowed', 'link', 'Not a sender: a phishing list\'s listing of the whole domain doesn\'t flag links to it (the other link checks still apply).'],
        kept: ['Not moved for some people', 'kept', 'People took its spam back out of Spam: not moved as spam for them (for anyone once 3 did).'],
        promo: ['Promotional, kept', 'promo-kept', 'An admin answered Keep in Review → Promotional: its promotional mail isn\'t listed there again. It is still checked as usual, and moved if it is phishing or spam.'],
        remembered: ['Marked safe', 'remembered', 'An identical email (the same sender, subject, text, links and attachments) was marked safe (not phishing or spam): its later copies to anyone are answered the same way and left alone, for 90 days, when Gmail confirms the sender (DMARC) and nothing outside the email says otherwise. Only a hash of the email is kept.'],
        company: ['A company\'s own domain', 'company', 'Its mail under the company\'s name isn\'t counted as an imitation, and links between it and the company\'s other domains aren\'t counted as disguised; every other check still applies.']
    };
    const listHead = (k) => h('div', { class: 'list-head' }, h('span', { class: `list-label ${LIST_LABELS[k][1]}`, text: LIST_LABELS[k][0] }), h('span', { class: 'small muted', text: LIST_LABELS[k][2] }));
    // (0.6.49) Settings → Sender lists → Company domains: the domains public records proved a company's (learned by the
    // service, read-only here), and those an admin confirmed from a registry's own web page, for registries the service
    // can't read (EURid's .eu). A confirmed one needs where it was checked; it can be removed.
    async function companyDomainsCard() {
        let d;
        try { d = await api('/api/company-domains'); } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Company domains' }), listHead('company'),
            h('p', { class: 'sub', text: 'The service proves which domains belong to a well-known company from public records (name servers, DMARC reporting, the registrant in RDAP or WHOIS, a corporate registrar) and keeps the answers for 60 days. Some registries show the owner only on their own website, which the service can\'t read (EURid\'s, for .eu). When you have checked such a page yourself, confirm the domain here and say where you checked it.' }));
        const draw = (data) => {
            card.querySelectorAll('table, p.empty').forEach(t => t.remove());
            const at = card.querySelector('.company-add');
            const rows = [...(data.confirmed || []), ...(data.proven || [])];
            const tbl = rows.length ? h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Domain', 'Company', 'How it is known', 'When', ''].map(t => h('th', { text: t })))),
                h('tbody', {}, rows.map(r => h('tr', {}, h('td', {}, h('b', { text: r.domain })), h('td', { text: r.name }),
                    h('td', {}, r.by ? h('span', { class: 'kind-tag changed', text: 'Confirmed' }) : r.state === 'likely' ? h('span', { class: 'kind-tag needs', text: 'Likely' }) : h('span', { class: 'kind-tag', text: 'Proven' }), ' ', h('span', { class: 'small', text: r.by ? `${r.note} · by ${r.by}` : r.how || (r.state === 'likely' ? 'a corporate registrar and a link to the company (counts for links only)' : '') })),
                    h('td', { class: 'nowrap', 'data-sort': String(r.at || 0), text: dayOf(r.at) }),
                    h('td', {}, r.by && !isModerator() ? h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                        e.target.disabled = true;
                        try { const out = await api('/api/company-domains', { method: 'POST', body: { domain: r.domain, remove: true } }); toast(`${r.domain} is no longer confirmed: public records decide again.`); draw(out); }
                        catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, 'Remove') : null))))) : h('p', { class: 'empty', text: 'None yet: domains appear here as the service proves them.' });
            card.insertBefore(tbl, at);
        };
        if (!isModerator()) {
            const domain = h('input', { type: 'text', class: 'project-input', placeholder: 'amzn.eu', 'aria-label': 'Domain to confirm', autocomplete: 'off', spellcheck: 'false' });
            const name = h('select', { 'aria-label': 'The company it belongs to' }, h('option', { value: '', text: 'Company…' }), (d.brands || []).map(b => h('option', { value: b, text: b })));
            const note = h('input', { type: 'text', class: 'project-input wide', placeholder: 'Where you checked it, and what it showed (EURid WHOIS page: Amazon Europe Core S.à r.l.)', 'aria-label': 'Where you checked it', autocomplete: 'off' });
            const add = h('button', { class: 'btn', type: 'button' }, 'Confirm');
            add.addEventListener('click', async () => {
                add.disabled = true;
                try {
                    const out = await api('/api/company-domains', { method: 'POST', body: { domain: domain.value.trim(), name: name.value, note: note.value.trim() } });
                    toast(`${out.domain} is confirmed as ${name.value}'s.`); domain.value = ''; note.value = ''; name.value = ''; draw(out);
                } catch (err) { toast(`Couldn't confirm it: ${err.message}`, { error: true }); }
                finally { add.disabled = false; }
            });
            card.append(h('div', { class: 'company-add toolbar' }, domain, name, note, add));
        } else card.append(h('div', { class: 'company-add' }));
        draw(d);
        return card;
    }
    // (0.6.59) Spam learning: for the days an admin chooses, promotional mail and mail the AI is sure is spam, from senders Gmail
    // confirms, go to Spam and the senders to Spam senders; someone taking its mail back out of Spam trusts a sender again.
    async function spamLearningCard() {
        let info = null;
        try { info = (await api('/api/spam-learning')).info; } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Spam learning' }),
            h('p', { class: 'sub', text: 'For the days you choose, promotional mail (Gmail\'s Promotions tab, a one-click unsubscribe, the AI\'s spam answer) and mail the AI is at least 99% sure is spam, from senders Gmail confirms (DMARC) outside your organization, go to Spam, and each sender is added to Spam senders ("by Spam learning"), so its later mail goes there too. A sender stays trusted only when someone takes its mail back out of Spam: for that person at once, for everyone once 3 people did. Never mail from inside, Trusted senders, or a platform\'s notification. Monitor mode: recorded as "would move", nothing moved.' }));
        const body = h('div');
        card.append(body);
        const draw = (i) => {
            body.textContent = '';
            const status = !i || !i.startedAt ? 'Never run.'
                : i.active ? `Running: started ${dayOf(i.startedAt)} by ${i.by}, ends ${dayOf(i.endsAt)} (${num(i.days)} day${i.days === 1 ? '' : 's'}). ${num(i.learned)} sender${i.learned === 1 ? '' : 's'} learned so far.`
                : `Last ran ${dayOf(i.startedAt)} to ${dayOf(i.endedAt)}${i.stoppedBy ? ` (stopped early by ${i.stoppedBy})` : ''}, started by ${i.by}: ${num(i.learned)} sender${i.learned === 1 ? '' : 's'} learned.`;
            body.append(h('p', {}, h('span', { class: `pol-pill ${i && i.active ? 'on' : 'off'}`, text: i && i.active ? 'On' : 'Off' }), ' ', status));
            if (isModerator()) return;
            if (i && i.active) {
                body.append(h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                    e.target.disabled = true;
                    try { const out = await api('/api/spam-learning', { method: 'POST', body: { stop: true } }); toast('Spam learning stopped. The senders it learned stay on Spam senders.'); draw(out.info); }
                    catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, 'Stop now'));
                return;
            }
            const days = h('input', { type: 'number', min: 1, max: (i && i.maxDays) || 30, step: 1, value: '7', class: 'num-input', 'aria-label': 'Days to run' });
            const agree = h('input', { type: 'checkbox' });
            const start = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Start');
            agree.addEventListener('change', () => { start.disabled = !agree.checked; });
            start.addEventListener('click', async () => {
                start.disabled = true;
                try { const out = await api('/api/spam-learning', { method: 'POST', body: { days: Number(days.value), agree: agree.checked } }); toast(`Spam learning runs until ${dayOf(out.info.endsAt)}.`); draw(out.info); }
                catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); start.disabled = false; }
            });
            body.append(h('div', { class: 'inline-form' }, h('label', { class: 'inline' }, h('span', { text: 'Run for ' }), days, h('span', { text: ` days (1 to ${(i && i.maxDays) || 30})` }))),
                h('label', { class: 'choice' }, agree, h('span', { text: 'I agree: promotional mail, including newsletters people signed up for, will be moved to Spam until they take it back out.' })), start);
        };
        draw(info);
        return card;
    }
    async function spamSendersCard() {
        let list = [];
        try { list = (await api('/api/spam-senders')).list || []; } catch (e) { return null; }
        const card = h('section', { class: 'card spaced' }, h('h2', { text: 'Spam senders' }), listHead('spam'),
            h('p', { class: 'sub', text: 'Add one when answering Spam ("also send future mail … straight to Spam"), or here. A Spam answer adds the sending subdomain when the mail comes from one (em.store.example: a company\'s mailing host), else the address itself (deals@store.example: the company\'s main domain also sends receipts and support replies, which stay checked as usual). Here you can also add a whole domain (store.example), which covers all its addresses and subdomains. The 30-day check looks at each domain too.' }));
        const draw = (rows) => {
            card.querySelectorAll('table, p.empty').forEach(t => t.remove());
            const at = card.querySelector('.spam-add');
            const tbl = rows.length ? h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, ['Sender', 'Added', 'By', ''].map(t => h('th', { text: t })))),
                h('tbody', {}, rows.map(r => h('tr', {}, h('td', {}, h('span', { class: 'list-label spam small-label', text: 'Always to Spam' }), ' ', h('b', { text: r.key })),
                    h('td', { 'data-sort': String(r.at || 0), text: `${dayOf(r.at)}${r.from === 'review' ? ', from a Spam answer' : r.from === 'learning' ? ', by Spam learning' : ''}` }), h('td', { text: r.by || '–' }),
                    h('td', {}, isModerator() ? null : h('button', { class: 'btn', type: 'button', onclick: async (e) => {
                        e.target.disabled = true;
                        try { const out = await api('/api/spam-senders', { method: 'POST', body: { key: r.key, remove: true } }); toast(`${r.key} is checked as usual again.`); draw(out.list || []); }
                        catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); e.target.disabled = false; } } }, 'Remove')))))) : h('p', { class: 'empty', text: 'None yet.' });
            card.insertBefore(tbl, at);
        };
        const input = h('input', { type: 'text', placeholder: 'newsletter.example', 'aria-label': 'Spam sender to add', autocomplete: 'off', spellcheck: 'false' });
        const add = h('button', { class: 'btn', type: 'button' }, 'Add');
        add.addEventListener('click', async () => {
            if (!input.value.trim()) return;
            add.disabled = true;
            try { const out = await api('/api/spam-senders', { method: 'POST', body: { sender: input.value.trim() } }); toast(`${out.key} added: its verified mail goes straight to Spam.`); input.value = ''; draw(out.list || []); }
            catch (err) { toast(`Couldn't add it: ${err.message}`); }
            finally { add.disabled = false; }
        });
        card.append(isModerator() ? h('div', { class: 'spam-add' }) : h('div', { class: 'spam-add toolbar' }, input, add));
        draw(list);
        return card;
    }
    // (0.6.36) Each list's own search and sorting (a table's headers sort by their column; a list of entries A–Z or as
    // kept), and the page's search across every list. Rows are found again whenever a list is drawn again.
    // (0.6.45) How many entries a Sender list shows on the page; the rest open in a popup (Show all).
    const LIST_ROWS = 8;
    function listTools(card, name) {
        if (!card) return null;
        // (0.6.45) On the page, a list shows its first LIST_ROWS entries (or matches); "Show all" opens the whole list, the
        // same card with its search, sorting and buttons, in a popup over the page (full), and puts it back on close.
        const st = { q: '', col: -1, dir: 1, az: 0, full: false };
        const input = h('input', { type: 'search', class: 'list-search', placeholder: `Search ${name}`, 'aria-label': `Search ${name}`, autocomplete: 'off', spellcheck: 'false' });
        const count = h('span', { class: 'small muted list-count', 'aria-live': 'polite' });
        const az = h('button', { class: 'btn small-btn', type: 'button', title: 'Sort the entries' }, 'Sort A–Z');
        const all = h('button', { class: 'linkbtn list-all', type: 'button', hidden: true });
        const bar = h('div', { class: 'list-tools' }, input, card.querySelector('ul.entries') ? az : null, count, all);
        all.addEventListener('click', () => {
            const here = document.createComment('list');
            card.before(here);
            st.full = true; apply();
            const title = (card.querySelector('h2') || {}).textContent || name;
            const dlg = popup(title, card);
            dlg.classList.add('popup-wide');
            dlg.addEventListener('close', () => { here.replaceWith(card); st.full = false; apply(); });
            setTimeout(() => input.focus(), 0);
        });
        (card.querySelector('.list-head') || card.querySelector('h2')).after(bar);
        const sortKey = (td) => { const v = td && (td.dataset.sort !== undefined ? td.dataset.sort : td.textContent.trim().toLowerCase()); return v !== '' && !isNaN(Number(v)) ? Number(v) : v || ''; };
        const cmp = (a, b) => (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b)));
        let busy = false;
        const apply = () => {
            busy = true;
            const q = st.q.trim().toLowerCase();
            // (0.6.51) The limit is each list's own: a card with two lists (Trusted senders' domains and addresses) shows
            // the first entries of each (before, the first list's filled it and the second showed none).
            let shown = 0, total = 0, visible = 0, here = 0;
            const room = () => st.full || here < LIST_ROWS;
            for (const tb of card.querySelectorAll('table tbody')) {
                here = 0;
                const rows = [...tb.children];
                if (st.col >= 0) rows.sort((a, b) => st.dir * cmp(sortKey(a.children[st.col]), sortKey(b.children[st.col]))).forEach(r => tb.append(r));
                for (const r of rows) { total++; const ok = !q || r.textContent.toLowerCase().includes(q); const show = ok && room(); r.hidden = !show; if (ok) shown++; if (show) { visible++; here++; } }
            }
            for (const ul of card.querySelectorAll('ul.entries')) {
                const lis = [...ul.children];
                if (!ul.dataset.order) lis.forEach((li, i) => { li.dataset.i = String(i); });
                ul.dataset.order = '1';
                lis.sort((a, b) => (st.az ? st.az * a.textContent.localeCompare(b.textContent) : Number(a.dataset.i) - Number(b.dataset.i))).forEach(li => ul.append(li));
                here = 0;
                [...ul.children].forEach((li) => { total++; const ok = !q || li.textContent.toLowerCase().includes(q); const show = ok && room(); li.hidden = !show; if (ok) shown++; if (show) { visible++; here++; } });
            }
            card.querySelectorAll('.entries-more').forEach(m => { m.hidden = true; });
            all.hidden = st.full || shown <= visible;
            all.textContent = q ? `Show all ${num(shown)} matches` : `Show all ${num(total)}`;
            card.querySelectorAll('table thead th').forEach((th, i) => { if (th.textContent.trim()) th.setAttribute('aria-sort', i === st.col ? (st.dir > 0 ? 'ascending' : 'descending') : 'none'); });
            count.textContent = (q ? `${num(shown)} of ${num(total)} match` : `${num(total)} entr${total === 1 ? 'y' : 'ies'}`) + (shown > visible ? ` · ${num(visible)} shown here` : '');
            card.classList.toggle('no-match', !!q && !shown);
            // (0.6.39) Nothing to search in an empty list: no search box.
            bar.hidden = !total && !q;
            if (observer) observer.takeRecords();   // (its own moves of rows are no new rows: never applied again for them)
            busy = false;
            return shown;
        };
        let observer = null;
        input.addEventListener('input', () => { st.q = input.value; apply(); });
        az.addEventListener('click', () => { st.az = st.az === 1 ? -1 : st.az === -1 ? 0 : 1; az.textContent = st.az === 1 ? 'Sort Z–A' : st.az === -1 ? 'As kept' : 'Sort A–Z'; apply(); });
        card.addEventListener('click', (e) => {
            const th = e.target.closest('thead th');
            if (!th || !th.textContent.trim() || !card.contains(th)) return;
            const i = [...th.parentElement.children].indexOf(th);
            st.dir = st.col === i ? -st.dir : 1; st.col = i;
            apply();
        });
        observer = new MutationObserver(() => { if (!busy) apply(); });
        observer.observe(card, { childList: true, subtree: true });
        apply();
        return { name, card, query(q) { input.value = q; st.q = q; return apply(); } };
    }
    async function allowlist() {
        const d = await settingsData();
        const TRUSTED_ROWS = ALLOW_ROWS.filter(r => r.key !== 'allowLinkDomains'), LINK_ROWS = ALLOW_ROWS.filter(r => r.key === 'allowLinkDomains');
        const brand = await brandSendersCard(), kept = await spamRescuedCard(), promoKept = await promoKeptCard(), remembered = await rememberedCard();
        if (remembered) remembered.insertBefore(listHead('remembered'), remembered.children[1]);
        if (brand) brand.insertBefore(listHead('brand'), brand.children[1]);
        if (kept) kept.insertBefore(listHead('kept'), kept.children[1]);
        if (promoKept) promoKept.insertBefore(listHead('promo'), promoKept.children[1]);
        const trusted = policyCard(d, TRUSTED_ROWS, 'Trusted senders', 'A change needs the Google Cloud project ID, applies within 30 seconds and is noted in Health → Activity. When deploy/settings.env (ALLOW_DOMAINS, ALLOW_ADDRESSES) says something else, deploy/install.sh asks which to keep, and writes the answer into settings.env.');
        const linkPrev = pageBusy;
        const links = policyCard(d, LINK_ROWS, 'Link sites', 'For a link site a phishing list flagged by mistake (a newsletter\'s click tracker). A list naming the exact page still flags it. Emails already checked keep their verdict: Use Check again on one to judge it again. ALLOW_LINK_DOMAINS only in the services\' environment.');
        const linkBusy = pageBusy; pageBusy = () => linkPrev() || linkBusy();
        for (const [card, k] of [[trusted, 'trusted'], [links, 'link']]) { const h2 = card.querySelector('h2'); if (h2) h2.after(listHead(k)); }
        const spam = await spamSendersCard();
        const learning = await spamLearningCard();
        const companies = await companyDomainsCard();
        const tools = [[trusted, 'Trusted senders'], [spam, 'Spam senders'], [brand, 'Brand senders'], [companies, 'Company domains'], [links, 'Link sites'], [kept, 'Spam people took back'], [remembered, 'Remembered answers'], [promoKept, 'Promotional senders kept']]
            .map(([c, n]) => listTools(c, n)).filter(Boolean);
        // (0.6.36) One search across every list: each list shows its matches; a list with none is hidden meanwhile.
        const all = h('input', { type: 'search', class: 'list-search global', placeholder: 'Search every sender list (a domain, an address, a brand)', 'aria-label': 'Search every sender list', autocomplete: 'off', spellcheck: 'false' });
        const found = h('div', { class: 'small muted', 'aria-live': 'polite' });
        all.addEventListener('input', () => {
            const q = all.value.trim();
            const hits = tools.map(t => [t, t.query(q)]);
            for (const [t, n] of hits) t.card.classList.toggle('search-hidden', !!q && !n);
            const where = hits.filter(([, n]) => n);
            found.textContent = !q ? '' : where.length ? `Found in ${where.map(([t, n]) => `${t.name} (${num(n)})`).join(', ')}.` : 'On no list.';
        });
        return [h('h1', { text: 'Sender lists' }), h('p', { class: 'sub', text: 'The senders and sites the checks treat differently, each list labeled with what it does. Every domain on them is checked again every 30 days. Changes are noted in Health → Activity → What admins did.' }),
            h('div', { class: 'card list-search-card' }, all, found),
            h('div', { class: 'alert warning' }, h('div', {}, h('b', { text: 'Add only senders you trust to Trusted senders. ' }), 'If one of their accounts is taken over, the phishing it sends isn\'t caught. Your own domains can\'t be added: a staff account taken over would never be moved. Single addresses in them can.')),
            await allowReviewCard(),
            trusted,
            spam,
            learning,
            brand,
            companies,
            links,
            kept,
            remembered,
            promoKept];
    }
    // Settings → Mailboxes (0.5.53): who is checked (the pilot, the default, or the whole domain, switched here with
    // a ticked box, the project ID and the admin's own address), and the mailboxes watched, a page of 100 at a time
    // with a search by address (a whole district has 10,000).
    async function mailboxes() {
        const d = await settingsData();
        const first = await api('/api/mailboxes');
        const domainScope = d.watchScope === 'domain';
        const pilotWhat = [...(d.pilotGroups || []).map(g => `group ${g}`), d.pilotOu ? `unit ${d.pilotOu}` : '', d.pilotUsers ? `${num(d.pilotUsers)} address${d.pilotUsers === 1 ? '' : 'es'} from PILOT_USERS` : ''].filter(Boolean).join(', ') || 'nothing set (deploy/settings.env)';
        const domains = (d.orgDomains || []).join(', ') || 'your domains';
        return [h('h1', { text: 'Mailboxes' }),
            h('p', { class: 'sub', text: 'Who is checked, and whether Gmail\'s notifications arrive for each mailbox. The service starts with the pilot; it checks the whole domain only once an admin switches it here.' }),
            h('section', { class: 'card' }, h('h2', { text: 'Who is checked' }), h('dl', { class: 'kv' },
                kvRow('Organization', domains),
                kvRow('Now', domainScope ? `The whole domain: every active mailbox of ${domains}` : `The pilot: ${pilotWhat}`),
                kvRow('Mailboxes watched', `${num(first.watched)}${first.left ? `; ${num(first.left)} more being ${domainScope ? 'added' : 'stopped or added'} over the next hours (each hourly run continues)` : ''}`),
                kvRow('Watches ending within a day', first.ending == null ? '–' : `${num(first.ending)} (each is renewed before it ends; a watch lasts 7 days)`)),
                scopeForm(d, domainScope, pilotWhat, domains)),
            mailboxList(first, d)];
    }
    function scopeForm(d, domainScope, pilotWhat, domains) {
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const radio = (v, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'watch-scope', value: v, checked: (v === 'domain') === domainScope }), h('span', { text: label }));
        const choices = h('div', { class: 'choices' }, radio('pilot', `The pilot (the default): ${pilotWhat}`), radio('domain', `The whole domain: every active mailbox of ${domains}`));
        const counts = h('div', { class: 'small muted', text: 'Reading the directory…' });
        const warn = h('div', { class: 'alert warning', hidden: true });
        const agree = h('input', { type: 'checkbox' });
        const agreeText = h('span');
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        const email = h('input', { type: 'email', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'you@district', 'aria-label': 'Your admin address' });
        const go = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Switch');
        let preview = null;
        const choice = () => choices.querySelector('input:checked').value;
        const update = () => {
            const v = choice(), changing = (v === 'domain') !== domainScope;
            warn.hidden = !changing;
            warn.textContent = '';
            if (changing && v === 'domain') warn.append(h('div', {}, h('b', { text: `Every active mailbox of ${domains} will be checked${preview && preview.domain != null ? `: ${num(preview.domain)} mailboxes` : ''}. ` }),
                `They are watched from the directory's next read (started when you switch; a large domain takes a few hours), and checked in ${d.mode === 'enforce' ? 'enforce mode: emails the policy flags are moved to Spam' : 'monitor mode: nothing is moved, only recorded'}, with the brake. Processing and Firestore costs grow with the number of mailboxes (Help → Costs).`));
            if (changing && v === 'pilot') warn.append(h('div', {}, h('b', { text: `Only the pilot will be checked${preview && preview.pilot != null ? ` (${num(preview.pilot)} mailboxes)` : ''}. ` }), 'The other mailboxes\' watches are stopped from the directory\'s next read (started when you switch): their mail is no longer checked or moved.'));
            agreeText.textContent = v === 'domain' ? `I understand: every active mailbox of ${domains}${preview && preview.domain != null ? ` (${num(preview.domain)})` : ''} will be checked.` : 'I understand: only the pilot\'s mailboxes will be checked from now on.';
            go.disabled = !changing || !agree.checked || !project.value.trim() || !email.value.trim() || (v === 'domain' && preview && preview.domain === null && !preview.demo);
        };
        [agree, project, email].forEach(e => e.addEventListener('input', update));
        agree.addEventListener('change', update);
        choices.addEventListener('change', () => { agree.checked = false; update(); });
        const box = h('div', { class: 'policy-form sb-form', hidden: true }, choices, counts, warn,
            h('label', { class: 'choice' }, agree, agreeText),
            h('label', { class: 'project' }, h('span', { text: 'Google Cloud project ID, to confirm' }), project),
            h('label', { class: 'project' }, h('span', { text: 'Your admin address (the one you are signed in with), to confirm' }), email),
            d.demo ? h('div', { class: 'small muted', text: 'Demo mode: the project ID is demo-project, and you are signed in as demo-admin@example.org.' }) : null,
            h('div', { class: 'actions' }, go, h('button', { class: 'btn', type: 'button', onclick: () => { box.hidden = true; opener.hidden = false; } }, 'Cancel')), err);
        const opener = h('button', { class: 'btn', type: 'button', onclick: async () => {
            box.hidden = false; opener.hidden = true; update();
            try {
                preview = await api('/api/scope-preview');
                counts.textContent = `The directory now: the pilot, ${preview.pilot != null ? `${num(preview.pilot)} mailboxes` : `couldn't be read (${preview.pilotError})`}; the whole domain, ${preview.domain != null ? `${num(preview.domain)} active mailboxes` : `couldn't be read: ${preview.domainError}`}. Watched now: ${num(preview.watched)}.`;
            } catch (e) { counts.textContent = `Couldn't read the directory: ${e.message}`; }
            update();
        } }, 'Change who is checked');
        go.addEventListener('click', async () => {
            err.textContent = ''; go.disabled = true; acting++; busyStart();
            try {
                const v = choice();
                await api('/api/policy', { method: 'POST', body: { key: 'watchScope', value: v, projectId: project.value, adminEmail: email.value, agree: agree.checked } });
                toast(v === 'domain' ? 'Switched to the whole domain: the directory is being read again; mailboxes are added over the next hours.' : 'Switched to the pilot: the other mailboxes\' watches are being stopped.');
                render();
            } catch (e) { err.textContent = e.message; update(); }
            finally { acting--; busyEnd(); }
        });
        return h('div', { class: 'spaced' }, opener, box);
    }
    function mailboxList(first, d) {
        const body = h('div');
        const search = h('input', { type: 'search', placeholder: 'Search by address (its beginning)', 'aria-label': 'Search mailboxes by address', class: 'mailbox-search' });
        const back = [];                            // the cursors of the pages before
        let cur = '', timer = null;
        const draw = (r) => {
            body.textContent = '';
            if (!r.mailboxes.length) { body.append(h('div', { class: 'empty', text: search.value.trim() ? 'No watched mailbox starts with that.' : 'None: run the spruce-renew-watches job (docs/INSTALL.md, step 7).' })); return; }
            body.append(dataTable([{ name: 'Mailbox', get: m => m.email }, { name: 'Last notification', get: m => (m.lastNotification ? when(m.lastNotification) : 'None yet') }, { name: 'Watch renews by', get: m => (m.watchExpiration ? when(m.watchExpiration) : '–') }], r.mailboxes),
                h('div', { class: 'actions pager' },
                    back.length ? h('button', { class: 'btn', type: 'button', onclick: () => load(back.pop(), false) }, `Previous ${r.mailboxes.length}`) : null,
                    h('span', { class: 'small muted', text: `${num(back.length * 100 + 1)}–${num(back.length * 100 + r.mailboxes.length)}${search.value.trim() ? '' : ` of ${num(r.watched)}`}` }),
                    r.next ? h('button', { class: 'btn', type: 'button', onclick: () => { back.push(cur); load(r.next, false); } }, 'Next 100') : null));
        };
        const load = async (after, reset = true) => {
            if (reset) back.length = 0;
            cur = after || '';
            try { draw(await api(`/api/mailboxes?after=${encodeURIComponent(cur)}&q=${encodeURIComponent(search.value.trim().toLowerCase())}`)); }
            catch (e) { body.textContent = `Couldn't read the mailboxes: ${e.message}`; }
        };
        search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => load(''), 300); });
        draw(first);
        return h('section', { class: 'card spaced' }, h('h2', { text: 'Mailboxes watched' }),
            renewBar(d.renew),
            h('div', { class: 'sub', text: 'When Gmail last said each mailbox changed, 100 at a time, by address. "None yet" for a mailbox that does get mail means its notifications don\'t arrive. Health → Activity says, after each read of the directory, how many were found and why any were left out.' }),
            search, body);
    }
    async function summary() {
        const d = await settingsData();
        const on = !!(d.digest && d.digest.enabled);
        return [serviceTitle('Weekly summary', on ? 'on' : 'off', on ? 'On: emailed every week' : 'Off: not sent'), digestCard(d)];
    }
    async function retraining() {
        const d = await settingsData();
        const on = !!(d.trainingExport && d.trainingExport.enabled);
        return [serviceTitle('Retraining', on ? 'info' : 'off', on ? 'Allowed: examples can be downloaded' : 'Off: nothing can be downloaded'), trainingSettingCard(d)];
    }
    // --- Settings → Safe Browsing (0.5.23): the API key (tested, kept in Secret Manager, never shown again),
    // and on or off. Each change needs the project ID, as the policy does.
    // A small form under a button (on every Settings page that turns something on or off): the project ID, then
    // confirm; posts body() with it to path.
    function confirmForm(label, path, body, done, note = null) {
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        const go = h('button', { class: 'btn primary', type: 'button', disabled: true }, label);
        const box = h('div', { class: 'policy-form sb-form', hidden: true }, note,
            h('label', { class: 'project' }, h('span', { text: 'Google Cloud project ID, to confirm' }), project),
            h('div', { class: 'actions' }, go, h('button', { class: 'btn', type: 'button', onclick: () => { box.hidden = true; opener.hidden = false; } }, 'Cancel')), err);
        const opener = h('button', { class: 'btn', type: 'button', onclick: () => { box.hidden = false; opener.hidden = true; project.focus(); } }, label);
        project.addEventListener('input', () => { go.disabled = !project.value.trim(); });
        go.addEventListener('click', async () => {
            err.textContent = ''; go.disabled = true; acting++; busyStart();
            try { const out = await api(path, { method: 'POST', body: Object.assign(body(), { projectId: project.value }) }); toast(done(out)); render(); }
            catch (e) { err.textContent = e.message; go.disabled = false; }
            finally { acting--; busyEnd(); }
        });
        return h('div', {}, opener, box);
    }
    async function safeBrowsingPage() {
        const d = await settingsData();
        const sb = d.safeBrowsing || {};
        const hl = sb.health;
        const keyText = sb.saved ? `Saved by ${sb.saved.by}, ${when(sb.saved.at)}. It is kept in Secret Manager and never shown here again.`
            : !sb.available ? (sb.envKey ? 'From the service\'s settings (SAFE_BROWSING_KEY). Upgrade from Cloud Shell once (bash deploy/update.sh (or, from an unzipped new version, bash deploy/upgrade.sh)) to manage the key here instead.' : 'Can\'t be saved here yet: upgrade from Cloud Shell once (bash deploy/update.sh (or, from an unzipped new version, bash deploy/upgrade.sh)); it sets up Secret Manager for the key.')
            : sb.envKey ? 'None saved here; the key from the service\'s settings (SAFE_BROWSING_KEY) is used.' : 'None saved.';
        const lookups = !sb.on ? 'Off: links aren\'t sent to Google.'
            : !sb.working ? 'On, but no key can be used: links aren\'t looked up with Google.'
            : hl && !hl.ok ? `Google refused the last lookup (${when(hl.at)}): ${hl.error}. Links aren't looked up with Google until the key works again.`
            : hl ? `Working: Google answered at ${when(hl.at)}.` : 'On: no lookup yet.';
        const bad = sb.on && (!sb.working || (hl && !hl.ok));
        const switchForm = sb.on
            ? confirmForm('Turn off', '/api/policy', () => ({ key: 'safeBrowsing', value: false }), () => 'Safe Browsing is off: links are no longer sent to Google (within 30 seconds everywhere).')
            : sb.saved || sb.envKey ? confirmForm('Turn on', '/api/policy', () => ({ key: 'safeBrowsing', value: true }), () => 'Safe Browsing is on: links are looked up with Google too (within 30 seconds everywhere).') : h('div', { class: 'small muted', text: 'Save a key below first.' });
        // The key: a password field (never kept, never shown back); tested with Google, then saved.
        const keyInput = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'AIza…', 'aria-label': 'Safe Browsing API key', 'data-lpignore': 'true', 'data-1p-ignore': 'true' });
        const turnOn = h('input', { type: 'checkbox', checked: !sb.on });
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const save = h('button', { class: 'btn primary', type: 'button', disabled: true }, sb.saved ? 'Test and replace the key' : 'Test and save the key');
        const ready = () => { save.disabled = !keyInput.value.trim() || !project.value.trim(); };
        keyInput.addEventListener('input', ready); project.addEventListener('input', ready);
        save.addEventListener('click', async () => {
            err.textContent = ''; save.disabled = true; acting++; busyStart();
            const apiKey = keyInput.value;
            keyInput.value = '';                                  // (not left in the page)
            try {
                const out = await api('/api/safe-browsing/key', { method: 'POST', body: { apiKey, projectId: project.value, turnOn: !sb.on && turnOn.checked } });
                toast(`${out.tested ? 'Google accepted the key. ' : ''}It is saved in Secret Manager${out.turnedOn ? ', and Safe Browsing is on' : ''}.`);
                render();
            } catch (e) { err.textContent = e.message; ready(); }
            finally { acting--; busyEnd(); }
        });
        const keyCard = sb.available ? h('section', { class: 'card spaced' }, h('h2', { text: sb.saved ? 'Replace the API key' : 'Add the API key' }),
            h('div', { class: 'sub', text: 'Paste the key. It is tried with Google first (a lookup of Google\'s own test address, nothing from anyone\'s mail); only a key that works is saved, in Secret Manager. It is never kept in the dashboard\'s records, shown here again, or written to the logs. Saving a new key destroys the old one.' }),
            h('div', { class: 'policy-form sb-form' },
                h('label', { class: 'project' }, h('span', { text: 'API key' }), keyInput),
                sb.on ? null : h('label', { class: 'choice' }, turnOn, h('span', { text: 'Turn Safe Browsing on once the key works' })),
                h('label', { class: 'project' }, h('span', { text: 'Google Cloud project ID, to confirm' }), project),
                d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}; any well-formed key is accepted, and nothing is sent to Google.` }) : null,
                h('div', { class: 'actions' }, save), err),
            sb.saved ? h('div', { class: 'spaced-top' }, h('h3', { text: 'Remove the key' }),
                h('div', { class: 'small muted', text: 'Turns Safe Browsing off and destroys every copy of the key in Secret Manager. Delete the key in the Google Cloud console too (APIs & Services → Credentials) if it isn\'t used anywhere else.' }),
                confirmForm('Remove the key', '/api/safe-browsing/remove', () => ({}), () => 'The key was removed, and Safe Browsing is off.')) : null) : null;
        const link = (text, href) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
        const sbState = !sb.on ? 'off' : bad ? 'bad' : 'on';
        return [serviceTitle('Google Safe Browsing', sbState, SERVICE_WORDS[sbState]),
            h('p', { class: 'sub', text: 'An extra check of the links in each email against Google\'s list of phishing, malware and unwanted-software pages, the list Chrome and Gmail use. Off by default. It needs a free API key from your Google Cloud project.' }),
            bad ? h('div', { class: 'alert critical', role: 'alert' }, alertIcon('Alert'), h('div', { class: 'grow' }, h('b', { text: 'Safe Browsing is on, but it isn\'t working. ' }), lookups)) : null,
            // Optional, and what it adds (0.5.23).
            h('section', { class: 'card optional-note' }, h('h2', { text: 'Optional: the service works without it' }),
                h('div', { class: 'sub', text: 'S.P.R.U.C.E doesn\'t need Safe Browsing to protect your mail. Without it, every email still gets the rule checks, the AI model, Cloudflare\'s security check of each link\'s site and the sender\'s domain, the five phishing lists downloaded daily, and the site-age check. Turned on, it adds:' }),
                h('ul', { class: 'benefits' },
                    h('li', {}, h('b', { text: 'Google\'s own list. ' }), 'The phishing, malware and unwanted-software pages Chrome and Gmail warn about, updated continuously by Google, far larger than the free lists.'),
                    h('li', {}, h('b', { text: 'Single pages on good sites. ' }), 'It checks each link\'s full address, so it can flag one phishing page on a hacked school or business website, or on a free page builder (Google Sites, Weebly, Firebase…), without condemning the whole site. A check of the site alone can\'t do that.'),
                    h('li', {}, h('b', { text: 'Malware downloads. ' }), 'Links to infected files and fake updates, which the phishing lists mostly don\'t cover.'),
                    h('li', {}, h('b', { text: 'A second opinion. ' }), 'A link Google lists is dangerous (it counts toward moving the email); when Cloudflare and the lists miss a brand-new page, Google may already have it.')),
                h('div', { class: 'small muted', text: 'What it doesn\'t change: phishing through real Google Docs, Drive, Classroom or DocuSign links, which the sender, Reply-To and directory checks catch. Costs: none (free for non-commercial use); each link\'s address is sent to Google (below).' })),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Status' }), h('dl', { class: 'kv' },
                kvRow('Safe Browsing', sb.on ? 'On: the links in each email are also looked up with Google' : 'Off'),
                kvRow('API key', keyText),
                kvRow('Lookups', lookups),
                kvRow('Changes', 'Each needs the Google Cloud project ID, applies everywhere within 30 seconds, and is noted in Health → Activity → What admins did. Google refusing the key is an alert: the admins are emailed.')),
                h('div', { class: 'actions' }, switchForm)),
            keyCard,
            h('section', { class: 'card spaced' }, h('h2', { text: 'Getting a key' }),
                h('ol', { class: 'steps' },
                    h('li', {}, 'In the ', link('Google Cloud console', 'https://console.cloud.google.com/'), ', choose this service\'s project (the project ID you type here).'),
                    h('li', {}, 'Enable the ', link('Safe Browsing API', 'https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com'), ' (deploy/install.sh does it from 0.5.23 on).'),
                    h('li', {}, 'In ', link('APIs & Services → Credentials', 'https://console.cloud.google.com/apis/credentials'), ', click Create credentials → API key.'),
                    h('li', {}, 'Edit the new key: name it "SPRUCE Safe Browsing"; Application restrictions: None (the service has no fixed address); API restrictions: Restrict key → Safe Browsing API. Save.'),
                    h('li', {}, 'Click Show key, copy it, and paste it above.'))),
            h('section', { class: 'card spaced' }, h('h2', { text: 'What is sent to Google' }), h('dl', { class: 'kv' },
                kvRow('Sent', 'The address of each link in an email (up to 500 per lookup), without the part after "#"; for one-time links (password resets, sign-in and unsubscribe links), without the query either, so their codes never leave the district.'),
                kvRow('Not sent', 'The email\'s text, subject, sender, recipients or attachments, and nothing about who received it.'),
                kvRow('Remembered', 'Google\'s answers, 30 minutes for a clean link and a day for a listed one, so a campaign\'s copies cost one lookup.'),
                kvRow('What it decides', 'A link Google lists is dangerous. One it doesn\'t list isn\'t "safe" by that alone, and a lookup that fails leaves the link "not checked", never safe.'),
                kvRow('Terms', 'The Safe Browsing API (v4 Lookup) is free for non-commercial use, as a school district protecting its own mail is. Google\'s terms apply to the key\'s project.')))];
    }
    async function about(q) {
        const d = await settingsData();
        const yes = (b) => (b ? 'Yes' : 'No');
        const lists = d.lists || [];
        const missed = lists.filter(l => l.missed);
        // A list's name, with the red alert icon and what happened when it missed its download.
        const listName = (l) => {
            if (!l.missed) return l.name;
            const what = l.missed === 'failed'
                ? `Missed its download${l.failures > 1 ? ` ${num(l.failures)} times` : ''} since ${when(l.failedSince)}: ${l.error}. ${l.updated ? `The copy from ${when(l.updated)} is still used.` : 'It has no copy yet, so it isn\'t used.'}`
                : `Not updated since ${when(l.updated)}: the daily download isn't happening (Health → Service status shows the hourly job). Its copy is still used.`;
            return h('div', {}, h('div', { class: 'list-name' }, alertIcon(`Alert: ${l.name} missed its download`), h('b', { text: l.name })), h('div', { class: 'small list-problem', text: what }));
        };
        const recheck = h('button', { class: missed.length ? 'btn primary' : 'btn', type: 'button',
            onclick: postButton('/api/lists/recheck', () => ({}), (o) => {
                const f = o.feeds || [], got = f.filter(r => r.count != null).length, bad = f.filter(r => r.error);
                return bad.length ? `Still missing: ${bad.map(r => `${r.name} (${r.error})`).join('; ')}.` : got ? `Downloaded ${num(got)} list${got === 1 ? '' : 's'}; every list is up to date.` : 'Every list is up to date (downloaded within the day).';
            }) }, 'Download the lists again');
        const listsCard = h('section', { class: `card spaced${missed.length ? ' has-alert' : ''}`, id: 'lists' },
            h('div', { class: 'card-head' }, h('div', {}, h('h2', { text: 'Phishing lists' }),
                h('div', { class: 'sub', text: 'Downloaded once a day for the whole organization and matched here; nothing about an email is sent. A list that misses its download keeps its previous copy and is tried again every 3 hours.' })), d.checks && d.checks.phishingLists ? recheck : null),
            missed.length ? h('div', { class: 'alert critical', role: 'alert' }, alertIcon('Alert'), h('div', { class: 'grow' }, h('b', { text: `${missed.length === 1 ? '1 list' : `${num(missed.length)} lists`} missed ${missed.length === 1 ? 'its' : 'their'} download (highlighted below).` }),
                ' Re-check downloads them again now; the alert was emailed to the admins.')) : null,
            lists.length ? dataTable([{ name: 'List', get: listName }, { name: 'Kind', get: l => (({ url: 'phishing links', domain: 'phishing sites', address: 'scam senders' })[l.kind] || l.kind) + (l.confidence === 'report' ? ' (reports: a caution)' : '') },
                { name: 'Entries', num: true, get: l => (l.off ? '–' : num(l.count)) }, { name: 'Updated', get: l => (l.off ? 'not used' : l.updated ? when(l.updated) : 'not yet') },
                // (abuse.ch's lists, 0.5.37: used only when turned on with a key)
                { name: 'Last download', get: l => (l.off ? h('a', { href: '#/abusech', text: 'Off (Settings → abuse.ch)' }) : l.lastAttempt ? `${when(l.lastAttempt)}: ${l.error ? 'failed' : 'OK'}` : '—') }], lists, l => (l.missed ? 'row-alert' : ''))
                : h('div', { class: 'empty', text: d.checks && d.checks.phishingLists ? 'Not downloaded yet: the hourly job downloads them within the hour.' : 'The phishing lists are off (PHISHING_LISTS=off).' }));
        if (q && q.get && q.get('show') === 'lists') setTimeout(() => { if (listsCard.isConnected) listsCard.scrollIntoView({ block: 'start' }); }, 0);
        return [h('h1', { text: 'About' }), h('p', { class: 'sub', text: 'What this service runs, what it keeps, and what it looks up.' }),
            h('section', { class: 'card' }, h('h2', { text: 'Version and records' }), h('dl', { class: 'kv' },
                kvRow('Version', d.version || ''),
                kvRow('Model', `${d.model.name} ${d.model.version}`),
                kvRow('Engine', d.engine && d.engine.extensionVersion ? `S.P.R.U.C.E+ ${d.engine.extensionVersion} (${d.engine.commit || ''})` : 'bundled'),
                kvRow('Records kept', `${d.retentionDays} days`),
                kvRow('Subjects stored', yes(d.storeSubjects)),
                kvRow('AI quotes stored', yes(d.storeAiQuotes)))),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Network checks' }), h('div', { class: 'sub', text: 'Lookups made for every email, besides the offline checks. A lookup that fails leaves a link "not checked", never "safe".' }),
                h('dl', { class: 'kv' },
                    kvRow('Cloudflare Security', d.checks && d.checks.cloudflare ? 'On: link sites and sender domains' : 'Off'),
                    kvRow('Google Safe Browsing', h('span', {}, d.checks && d.checks.safeBrowsing ? 'On: links (no #part; one-time links without their query)' : d.safeBrowsing && d.safeBrowsing.on ? 'On, but no key can be used' : 'Off', ' (', h('a', { href: '#/safebrowsing', text: 'Settings → Safe Browsing' }), ')')),
                    kvRow('Phishing lists', d.checks && d.checks.phishingLists ? (missed.length ? h('span', {}, alertIcon('Alert'), ` On; ${num(missed.length)} missed ${missed.length === 1 ? 'its' : 'their'} download (below)`) : 'On: downloaded once a day, matched here (below)') : 'Off'),
                    kvRow('Site age', d.checks && d.checks.siteAge ? 'On: up to 3 unfamiliar link sites and the sender\'s domain' : 'Off'),
                    kvRow('Short links', 'Not looked up (no outside unshortening service)'))),
            listsCard];
    }

    // --- Keeping the page up to date --------------------------------------------------------------
    // While the tab is visible, the page shown is fetched again every LIVE_MS (liveTick looks every 5 s), quietly. A round is skipped
    // while someone is using the page (typing in a field, focus on something in it, a tooltip open, text
    // selected, an action under way), and taken as soon as they stop. Pausing is remembered per browser.
    const LIVE_MS = Number(window.SPRUCE_LIVE_MS) || 30000;   // (a test page may set it shorter)
    let live = true, updatedAt = 0, liveError = null, acting = 0;
    // (0.6.7) Pages whose content changes only when someone changes it (Help, Settings but Mailboxes, About,
    // Update): updated every STILL_MS, not every LIVE_MS. And after IDLE_MS with no key, click, touch or scroll,
    // nothing is fetched (a dashboard left open on a screen or overnight) until the person is back.
    const STILL_MS = 5 * 60 * 1000, IDLE_MS = 15 * 60 * 1000;
    const STILL_PAGES = /^#\/?(help\w*|credits|about|update|settings|allowlist|safebrowsing|spamhaus|abusech|summary|clicks|phishtraining|retraining)(\?|$)/;
    let lastInput = Date.now();
    const away = () => Date.now() - lastInput > IDLE_MS;
    for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
        window.addEventListener(ev, () => {
            const was = away();
            lastInput = Date.now();
            if (was && live && !document.hidden) { showLive(); refreshPending(); if (!inUse() && !/^#\/?(check|review)/.test(currentHash())) render({ quiet: true }); }
        }, { passive: true, capture: true });
    }
    try { live = localStorage.getItem('spruce.live') !== 'off'; } catch (e) { /* storage blocked */ }
    const clock = (ms) => new Date(ms).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' });
    function inUse() {
        const v = view(), a = document.activeElement, sel = window.getSelection && window.getSelection();
        return acting > 0 || pageBusy() || popupOpen() || !tip().hidden || (a && a !== v && v.contains(a))
            || [...v.querySelectorAll('input, textarea')].some(i => i.value !== i.defaultValue)
            || !!(sel && !sel.isCollapsed && sel.anchorNode && v.contains(sel.anchorNode));
    }
    function showLive() {
        const box = $('#live');
        if (!box) return;
        box.classList.toggle('paused', !live);
        box.classList.toggle('stale', live && !!liveError);
        $('#liveState').textContent = !live ? 'Updates paused'
            : away() ? 'Updates paused while you are away: back as soon as you click or press a key'
            : liveError ? `Couldn't update (${liveError.message}); trying again`
            : updatedAt ? `Live · updated ${clock(updatedAt)}` : 'Live';
        const b = $('#liveToggle');
        b.textContent = live ? 'Pause updates' : 'Resume updates';
        b.setAttribute('aria-pressed', String(live));
    }
    function liveDone(err) { liveError = err; updatedAt = Date.now(); showLive(); }
    function liveTick() {
        // (not on Check an email, whose answer isn't fetched again, nor on Review, which keeps its list while it is
        // answered; the badges and the brake banner still update there)
        if (away()) { showLive(); return; }
        if (!document.hidden) refreshPending();
        const every = STILL_PAGES.test(currentHash()) ? STILL_MS : LIVE_MS;
        if (live && !document.hidden && Date.now() - updatedAt >= every && !inUse() && !/^#\/?(check|review)/.test(currentHash())) render({ quiet: true });
    }

    // --- Health → Activity: alerts, what admins did, errors, the watching of mailboxes ------------
    // Activity (0.5.29): its own period, up to how long it is kept (AUDIT_DAYS, a year by default), a kind,
    // words to look for, and all of it as CSV for an audit (recorded under What admins did).
    async function activity(params) {
        const kind = params.get('kind') || '', words = params.get('q') || '';
        const period = Number(params.get('days')) || 30;
        const d = await api(`/api/activity?${q({ days: String(period), kind, q: words })}`);
        const nav = (patch) => go(`#/activity?${q(Object.assign({ days: String(period), kind, q: words }, patch))}`);
        const sel = h('select', { 'aria-label': 'Kind' }, [['', 'Everything'], ['alert', 'Alerts (problems, emailed)'], ['admin', 'What admins did'], ['error', 'Errors and gaps'], ['watch', 'Watching mailboxes']]
            .map(([v, l]) => h('option', { value: v, text: l, selected: v === kind })));
        sel.addEventListener('change', () => nav({ kind: sel.value }));
        const spans = [7, 30, 90, 180, 365, d.maxDays].filter((x, i, a) => x && x <= d.maxDays && a.indexOf(x) === i);
        const per = h('select', { 'aria-label': 'Period' }, spans.map(x => h('option', { value: String(x), text: x === d.maxDays && x !== 365 ? `Last ${x} days (all kept)` : `Last ${x} days`, selected: x === d.days })));
        per.addEventListener('change', () => nav({ days: per.value }));
        const find = h('input', { type: 'search', value: words, placeholder: 'Look for an admin, a mailbox, a word…', 'aria-label': 'Look for', autocomplete: 'off', spellcheck: 'false' });
        find.addEventListener('keydown', (e) => { if (e.key === 'Enter') nav({ q: find.value.trim() }); });
        const csv = MEMORY ? null : h('a', { class: 'btn', href: `/api/activity.csv?${q({ days: String(d.days), kind, q: words })}`, download: '' }, 'Download CSV');
        return [h('h1', { text: 'Activity' }), h('p', { class: 'sub', text: `Alerts, what admins did, errors and the watching of mailboxes, newest first. Kept ${d.maxDays} days (AUDIT_DAYS); the email records themselves are kept as long as Settings → Policy says.` }),
            h('div', { class: 'toolbar' }, sel, per, find, csv),
            d.total > d.events.length ? h('div', { class: 'small muted', text: `The newest ${num(d.events.length)} of ${num(d.total)} shown; Download CSV has them all (downloading it is noted under What admins did).` }) : null,
            // An alert (a problem the admins were emailed about) in red; an admin's own change is never one (0.5.28).
            h('section', { class: 'card' }, d.events.length ? h('ul', { class: 'events' }, d.events.map(e => {
                const alerted = e.alert && !e.adminAction;
                return h('li', { class: alerted ? 'alerted' : '' }, h('time', { text: `${when(e.at)}${alerted ? ' · alert, emailed to the admins' : ''}` }), ' ', e.text);
            }))
                : h('div', { class: 'empty', text: 'Nothing in this period.' }))];
    }

    // --- Health → Readiness: ready for enforce mode? ------------------------------------------------
    async function readiness() {
        const { readiness: r } = await api(`/api/readiness?days=${days}`);
        const todo = r.checks.filter(c => !c.ok).length;
        return [h('h1', { text: 'Ready for enforce mode?' }),
            h('p', { class: 'sub', text: r.mode === 'enforce' ? 'Enforce mode is on. The checks still show how the policy is doing.'
                : `What monitor mode has shown in the last ${days} days. When every check is green: set MODE=enforce in deploy/settings.env and run deploy/install.sh (docs/INSTALL.md, step 7).` }),
            h('div', { class: `alert ${r.ready ? 'good' : 'warning'}`, role: 'status' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: r.ready ? '✅' : '⏳' }),
                h('div', { class: 'grow' }, h('b', { text: r.ready ? 'Ready.' : `Not yet: ${todo} of ${r.checks.length} checks to look at.` }))),
            h('section', { class: 'card' }, h('ul', { class: 'checks' }, r.checks.map(c => h('li', { class: c.ok ? 'ok' : 'todo' },
                h('span', { class: 'mark', 'aria-hidden': 'true', text: c.ok ? '✓' : '!' }), h('span', { class: 'sr-only', text: c.ok ? 'Done: ' : 'To look at: ' }), h('span', { text: c.text }))))),
            h('div', { class: 'grid kpis' },
                kpi('Would be moved', num(r.wouldMove), r.strongShare === null ? '' : `${pct(r.strongShare)} on strong evidence`),
                kpi('Reviewed', num(r.reviewed), `${num(r.falseAlarms)} false alarms`),
                kpi('Busiest hour', num(r.peakHour), `the brake stops at ${num(r.brakeLimit)}`),
                kpi('Days so far', num(r.monitorDays), 'since the install')),
            r.campaignsOverHold.length ? h('section', { class: 'card spaced' }, h('h2', { text: 'Campaigns whose moving would have paused' }),
                h('div', { class: 'sub', text: `More than ${r.holdAfter} copies on weaker evidence: in enforce mode, moving the rest would pause for your decision (they'd stay in the Inbox meanwhile).` }),
                dataTable([{ name: 'Campaign', get: c => h('a', { href: `#/messages?${q({ campaign: c.campaign })}`, text: c.label }) }, { name: 'Copies', num: true, get: c => num(c.count) }], r.campaignsOverHold)) : null];
    }

    // --- Review (0.6.0): every item in one list; open one to weigh the evidence and answer ----------------------
    // Two queues: moved or "would move" (oldest first), and suspicious emails that weren't moved (newest first:
    // still in the Inbox). Each item is one email with all its copies (a campaign: the same email to many people),
    // answered at once: P phishing, S spam (0.6.26), F false alarm (not phishing), I ignore (unclear: left as it is, out of the
    // queue, never used for retraining), N skip (stays in the queue, undecided), R re-scan. Several items can be
    // ticked and answered together. In enforce mode, Phishing also moves an email still in the Inbox to Spam.
    let reviewStates = {}, reviewKeys = null;
    // (0.6.39) R only where the Check again button is shown (not in the demo's clickable mockup).
    const canRescanReview = (g) => !!(g && g.keys && g.keys[0]) && !MEMORY;
    const QUEUES = {
        moved: { label: 'Moved, or would be moved', short: 'Moved', what: 'moved, or would-be-moved, emails', order: 'oldest first' },
        suspicious: { label: 'Suspicious (not moved)', short: 'Suspicious', what: 'suspicious emails (not moved)', order: 'newest first' },
        // (0.6.52) Admins only: its answers change Spam senders and Promotional senders kept.
        promotional: { label: 'Promotional (never moved; one answer per company)', short: 'Promotional', what: 'promotional emails', order: 'most emails first', admin: true },
        // (0.6.60) Settings → User reports: what readers reported with Gmail's own "Report phishing".
        reported: { label: 'Reported by their readers (Gmail\'s Report phishing)', short: 'Reported', what: 'emails their readers reported as phishing', order: 'newest report first' }
    };
    const queueOf = (params) => (['suspicious', 'promotional', 'reported'].includes(params.get('queue')) ? params.get('queue') : 'moved');
    const shownQueues = () => Object.entries(QUEUES).filter(([, x]) => !x.admin || !isModerator());
    // (0.6.39) The four answers, worded the same everywhere (Review, Mail, an email's page, a campaign's box). When the
    // click moves mail (enforce mode), the button says where to.
    const ANSWER = {
        phishing: { label: 'Phishing', moved: 'Phishing: move to the Spam folder', cls: 'phish', help: 'A scam or an attack: it tries to trick the reader.' },
        spam: { label: 'Spam', moved: 'Spam: move to the Spam folder', cls: '', help: 'Unwanted bulk mail (ads, newsletters nobody asked for, political mail): annoying, not dangerous.' },
        'false-alarm': { label: 'Mark safe', moved: 'Mark safe: move back to the Inbox', cls: 'safe', help: 'Not phishing or spam: a genuine email, nothing wrong with it.' },
        unclear: { label: 'Not sure', moved: 'Not sure', cls: '', help: 'You can\'t tell: it is left as it is, and not used to train the AI.' }
    };
    const answerLabel = (action, moves) => (moves ? ANSWER[action].moved : ANSWER[action].label);
    let currentMode = null;   // (set by showMode)
    // What happened, in one sentence: for one email (o from /api/mark) or several (o from /api/bulk, n emails).
    function answeredText(action, o, n) {
        const one = n === 1, a = ANSWER[action].label;
        let t = one ? `Marked ${a}` : `Marked ${a}: ${num(o.done || 0)} email${o.done === 1 ? '' : 's'}`;
        if (action === 'phishing' || action === 'spam') {
            if (one) t += o.moved === 'moved' ? ', and moved to the Spam folder' : o.moved === 'gone' ? '. It isn\'t in the Inbox any more, so nothing was moved' : '';
            else if (o.moved) t += `, ${num(o.moved)} moved to the Spam folder`;
        }
        if (action === 'false-alarm' && o.released) t += one ? ', and moved back to the Inbox' : `, ${num(o.released)} moved back to the Inbox`;
        if (action === 'unclear') t += one ? ': left as it is, and not used to train the AI' : ', left as they are and not used to train the AI';
        t += '.';
        const added = one ? (o.spamSenderAdded ? [o.spamSenderAdded] : []) : (o.spamSendersAdded || []);
        if (added.length) t += ` ${added.join(', ')} ${added.length === 1 ? 'is' : 'are'} now on Spam senders: future mail goes straight to the Spam folder.`;
        // (0.6.40) A Spam answer also answers the same address's other emails waiting for review.
        const same = o.sameSender;
        if (same && same.done) t += ` Also answered Spam: ${num(same.done)} other email${same.done === 1 ? '' : 's'} from the same address waiting for review${same.moved ? ` (${num(same.moved)} moved to the Spam folder)` : ''}.`;
        if (!one && o.failed) t += ` ${num(o.failed)} couldn't be saved (Gmail didn't answer in time, or they changed meanwhile): answer them again.`;
        if (!one && o.skipped) t += ` ${num(o.skipped)} weren't found.`;
        return t;
    }
    // Answers emails (one: its own call, so Activity names it; several: in batches of 500), asking first when it is many
    // or moves several back to the Inbox. Returns { text, keys } for the message and its Undo, or null when cancelled.
    async function answerKeys(keys, action, { addSender = action === 'spam' && spamAddSender && !isModerator() } = {}) {
        const n = keys.length;
        if (!n) return null;
        const enforce = currentMode === 'enforce';
        if (n > 50 || (n > 1 && action === 'false-alarm' && enforce)) {
            const effect = !enforce ? '' : action === 'false-alarm' ? ' Those in the Spam folder go back to the Inbox.' : action === 'unclear' ? '' : ' Those still in the Inbox are moved to the Spam folder.';
            if (!window.confirm(`Mark ${num(n)} emails ${ANSWER[action].label}?${effect} You can undo it for an hour.`)) return null;
        }
        let o;
        if (n === 1) {
            o = action === 'unclear' ? await api('/api/unclear', { method: 'POST', body: { key: keys[0] } })
                : await api('/api/mark', { method: 'POST', body: { key: keys[0], falseAlarm: action === 'false-alarm', spam: action === 'spam', move: (action === 'phishing' || action === 'spam') && enforce, addSender } });
        } else {
            o = { done: 0, moved: 0, released: 0, failed: 0, skipped: 0, spamSendersAdded: [], sameSender: { done: 0, moved: 0, keys: [] } };
            // (0.6.44) In batches of 50, saying how far it got: a long wait shows progress, and a slow batch delays only itself.
            let ticket = null;
            try {
            for (let i = 0; i < n; i += 50) {
                if (n > 50) { if (ticket) busyEnd(ticket); ticket = busyStart(`Saving your answers: ${num(i)} of ${num(n)} done…`); }
                const r = await api('/api/bulk', { method: 'POST', body: { keys: keys.slice(i, i + 50), action, addSender } });
                for (const k of ['done', 'moved', 'released', 'failed', 'skipped']) o[k] += r[k] || 0;
                for (const x of r.spamSendersAdded || []) if (!o.spamSendersAdded.includes(x)) o.spamSendersAdded.push(x);
                if (r.sameSender) { o.sameSender.done += r.sameSender.done || 0; o.sameSender.moved += r.sameSender.moved || 0; o.sameSender.keys.push(...(r.sameSender.keys || [])); }
            }
            } finally { if (ticket) busyEnd(ticket); }
        }
        return { text: answeredText(action, o, n), keys: keys.concat((o.sameSender && o.sameSender.keys) || []) };
    }
    // Undo, in batches of 500.
    const undoKeys = (keys) => async () => {
        if (keys.length === 1) return api('/api/undo', { method: 'POST', body: { key: keys[0] } });
        for (let i = 0; i < keys.length; i += 500) await api('/api/undo', { method: 'POST', body: { keys: keys.slice(i, i + 500) } });
    };
    // (0.6.42) A sign as a heat box, like a heat index: its points inside (the AI's score for the AI), its color how strong
    // it is: pale yellow (weak) to red (strong) for phishing or spam, pale to deep blue for safe.
    const heatLevel = (w) => { const a = Math.abs(w); return a >= 5 ? 5 : a >= 3 ? 4 : a >= 2 ? 3 : a >= 1 ? 2 : 1; };
    const HEAT_WORDS = ['', 'Very weak', 'Weak', 'Medium', 'Strong', 'Very strong'];
    // The key under the evidence: what a box's number and color mean.
    function heatLegend() {
        return h('div', { class: 'heat-legend small muted' }, 'Each box: the sign\'s points toward the rules score (the AI\'s own score for the AI). Color: how strong ',
            h('span', { class: 'heat-scale', 'aria-hidden': 'true' }, [1, 2, 3, 4, 5].map(n => h('span', { class: `heat hot h${n} mini` }))), ' weak to strong; blue points to safe.');
    }
    function heatBox(w, tone, label) {
        const n = heatLevel(w);
        return h('span', { class: `heat ${tone === 'safe' ? 'cool' : 'hot'} h${n}`, role: 'img', 'aria-label': `${HEAT_WORDS[n]} sign${label ? `, ${label}` : ''}` }, label || '');
    }
    // (0.6.35) "Also send future mail from this sender straight to Spam", under Review's buttons: ticked by default for
    // admins, remembered while the page is open; a Spam answer adds the sender (verified, outside) to Spam senders.
    let spamAddSender = true;
    // (0.6.37) The same choice where several emails are answered at once (Mail's selection, a campaign's copies).
    const spamSenderBox = (whose) => {
        if (isModerator()) return null;
        const box = h('input', { type: 'checkbox', checked: spamAddSender });
        box.addEventListener('change', () => { spamAddSender = box.checked; });
        return h('label', { class: 'small spam-sender-opt', title: 'Only senders Gmail verified, from outside, are added (Settings → Sender lists → Spam senders); it skips the other checks for them.' },
            box, ` with Spam, also send ${whose} future mail straight to Spam`);
    };
    // Answers every copy of the items given (one copy: its own endpoint, so Activity names it; more: in batches of 500).
    async function answerGroups(st, groups, action) {
        const keys = groups.flatMap(g => g.keys);
        const done = await answerKeys(keys, action);
        if (!done) return null;
        const openGroup = st.groups[st.open];
        st.groups = st.groups.filter(g => !groups.includes(g));
        for (const g of groups) st.picked.delete(g);
        st.done += keys.length;
        // The item that was open stays open unless it was answered; then the next one opens.
        if (openGroup && !groups.includes(openGroup)) st.open = st.groups.indexOf(openGroup);
        else st.open = Math.min(st.open, st.groups.length - 1);
        return done;
    }
    // The tabs above Review's lists, each with how many emails it holds (left: the queue's count).
    // (0.6.61) Reported only while Settings → User reports is on, or while reports from before still wait (or it is open).
    const reviewTabs = (queue, left) => h('nav', { class: 'segmented', 'aria-label': 'Which emails to review' }, shownQueues().filter(([k]) => k !== 'reported' || reportedOn || left(k) > 0 || queue === k).map(([k, x]) =>
        h('a', { href: k === 'moved' ? '#/review' : `#/review?queue=${k}`, 'aria-current': k === queue ? 'page' : null, title: x.label }, `${x.short} · ${num(left(k))}`)));
    // (0.6.52) Review → Promotional: marketing and subscribed mail (Gmail's Promotions category, or a one-click unsubscribe the
    // sender signed) from senders Gmail verified, that the checks found nothing wrong with. Never moved for that. One row per
    // company (the From address's organization, never the platform that sent it), answered once: Spam (each waiting email
    // answered Spam, moved to the Spam folder in enforce mode; with the box ticked, its senders on Spam senders) or Keep
    // (left in the Inbox; the company on Promotional senders kept, so its later mail isn't listed). Each answer can be undone.
    async function promotionalReview(params) {
        const plain = '#/review?queue=promotional';
        let st = reviewStates.promotional;
        if (!st || params.get('restart') || st.days !== days) {
            const d = await api(`/api/review?${q({ days: String(days), queue: 'promotional' })}`);
            st = reviewStates.promotional = { queue: 'promotional', companies: d.companies || [], days, counts: d.counts || {}, mode: d.mode, done: 0, shown: 50 };
            for (const [k, other] of Object.entries(reviewStates)) if (k !== 'promotional' && other && other.days === days && d.counts) other.counts = d.counts;
            if (params.get('restart')) { if (MEMORY) memRoute = plain; else history.replaceState(null, '', plain); }
        }
        reviewKeys = null;
        const emails = (o) => (o.companies || o.groups || []).reduce((a, g) => a + g.keys.length, 0);
        const left = (k) => { const o = reviewStates[k]; return o && o.days === days && (o.companies || o.groups) ? emails(o) : (st.counts[k] || 0); };
        const enforce = st.mode === 'enforce';
        const answer = async (c, what) => {
            acting++; busyStart();
            try {
                const n = c.keys.length;
                const o = await api('/api/promotional', { method: 'POST', body: { company: c.company, answer: what, addSender: what === 'spam' && spamAddSender && !isModerator() } });
                st.companies = st.companies.filter(x => x !== c);
                st.done += n;
                const text = what === 'spam' ? answeredText('spam', o, Math.max(2, n))
                    : `Kept ${c.company}: ${num(o.done || 0)} email${o.done === 1 ? '' : 's'} left in the Inbox. Its later promotional mail isn't listed here (Settings → Sender lists → Promotional senders kept).`;
                const undo = what === 'spam' ? undoKeys(o.keys || []) : () => api('/api/promotional', { method: 'POST', body: { company: c.company, undo: 'keep', keys: o.keys || [] } });
                toast(text, { undo: async () => { await undo(); reviewStates.promotional = null; pendingAt = 0; refreshPending(); render(); } });
                render(); pendingAt = 0; refreshPending();
            } catch (e) { toast(`Couldn't save your answer: ${e.message}`, { error: true }); } finally { acting--; busyEnd(); }
        };
        const head = [h('div', { class: 'page-head' },
            h('div', {}, h('h1', { text: 'Review' }),
                h('p', { class: 'sub' }, st.companies.length ? [`${num(emails(st))} promotional emails from `, h('b', { text: `${num(st.companies.length)} compan${st.companies.length === 1 ? 'y' : 'ies'}` }), `, last ${days} days, most emails first. One answer covers all of a company's waiting emails.`]
                    : `No promotional email from the last ${days} days is waiting for an answer.`)),
            h('span', { class: 'mode-note', text: enforce ? 'Enforce mode: Spam moves the company\'s waiting emails to the Spam folder; Keep leaves them in the Inbox. Each answer can be undone.' : 'Monitor mode: answers move nothing' })),
            h('div', { class: 'review-tools' }, reviewTabs('promotional', left)),
            h('p', { class: 'sub', text: 'Promotional: marketing and subscribed mail from senders Gmail verified, that the checks found nothing wrong with. It is told by what Gmail and the sender say (Gmail put it in its Promotions category, or the sender signed a one-click unsubscribe, which bulk senders must add to marketing mail), not by a list of platforms, and it is never moved for that. Each row is one company (the sender\'s own domain, never the platform it was sent through). Mail from your own domains and Trusted senders is never listed.' })];
        if (isModerator()) return [...head, h('div', { class: 'alert', role: 'status' }, h('div', { class: 'grow', text: 'Only admins answer promotional mail: its answers change Settings → Sender lists.' }))];
        if (!st.companies.length) {
            return [...head, h('div', { class: 'alert good', role: 'status' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '✓' }),
                h('div', { class: 'grow' }, h('b', { text: 'Nothing left to review.' }), st.done ? ` ${num(st.done)} answered just now.` : '')),
                h('div', { class: 'actions' }, h('a', { class: 'btn', href: '#/review?queue=promotional&restart=1' }, 'Look again'))];
        }
        const shown = st.companies.slice(0, st.shown);
        const row = (c) => h('section', { class: 'card promo-row' },
            h('div', { class: 'promo-main' },
                h('h2', {}, kindTag('promotional'), c.company),
                h('p', { class: 'small muted', text: `${num(c.count)} email${c.count === 1 ? '' : 's'} to ${num(c.users.length)} ${c.users.length === 1 ? 'person' : 'people'}, ${dayOf(c.firstAt)}${c.lastAt && dayOf(c.lastAt) !== dayOf(c.firstAt) ? ` to ${dayOf(c.lastAt)}` : ''}. From ${c.senders.slice(0, 3).join(', ')}${c.senders.length > 3 ? ` and ${num(c.senders.length - 3)} more` : ''}.` }),
                // (0.6.55) The emails themselves (each opens its page: the whole email as the AI reads it, under "…show more",
                // read from the mailbox), the sender check, and the AI's answers.
                (c.emails || []).length ? h('ul', { class: 'promo-subjects small' }, c.emails.map(e => h('li', {},
                    h('a', { href: `#/message?${q({ key: e.key })}`, title: 'Open this email: who sent it, the checks, and the whole email as the AI reads it (…show more)', text: e.subject || '(subject not stored)' }),
                    typeof e.spam === 'number' ? h('span', { class: 'muted', text: ` · spam ${pct(e.spam)}` }) : null)))
                    : c.subjects.length ? h('ul', { class: 'promo-subjects small' }, c.subjects.map(t => h('li', { text: t }))) : null,
                h('p', { class: 'small', text: `Sender check: ${c.dmarcPass === c.count ? `Gmail confirmed the sender (DMARC passed) for ${c.count === 1 ? 'it' : `all ${num(c.count)}`}` : `DMARC passed for ${num(c.dmarcPass || 0)} of ${num(c.count)}`}.` }),
                h('p', { class: 'small', text: typeof c.spamMax === 'number' ? `AI: spam ${c.spamMin === c.spamMax ? pct(c.spamMax) : `${pct(c.spamMin)} to ${pct(c.spamMax)}`}${typeof c.phishMax === 'number' ? `, phishing ${c.phishMax < 0.005 ? 'under 1%' : c.count === 1 ? pct(c.phishMax) : `at most ${pct(c.phishMax)}`}` : ''}.`
                    : typeof c.phishMax === 'number' ? `AI: phishing ${c.count === 1 ? pct(c.phishMax) : `at most ${pct(c.phishMax)}`} (this model has no spam answer).` : 'AI: no score.' }),
                h('p', { class: 'small muted', text: `Why: ${c.signs.join('; ')}.` })),
            h('div', { class: 'actions promo-actions' },
                h('button', { class: 'btn', type: 'button', title: ANSWER.spam.help, onclick: () => answer(c, 'spam') }, enforce ? 'Spam: move to the Spam folder' : 'Spam'),
                h('button', { class: 'btn safe', type: 'button', title: 'Wanted mail: leave it in the Inbox, and stop listing this company here.', onclick: () => answer(c, 'keep') }, 'Keep: not spam')));
        return [...head, h('div', { class: 'card promo-opts' }, spamSenderBox('its senders\'')),
            ...shown.map(row),
            st.companies.length > shown.length ? h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: () => { st.shown += 50; render(); } }, `Show ${num(Math.min(50, st.companies.length - shown.length))} more companies`)) : null,
            h('div', { class: 'actions' }, h('a', { class: 'btn', href: '#/review?queue=promotional&restart=1' }, 'Look again'))];
    }
    async function review(params) {
        if (queueOf(params) === 'promotional') return promotionalReview(params);
        const queue = queueOf(params), Q = QUEUES[queue];
        const plain = queue === 'moved' ? '#/review' : `#/review?queue=${queue}`;
        // A queue is read once and kept while it is answered (answered items leave it here; live updates skip
        // Review); read again for Look again (restart) or another period.
        let st = reviewStates[queue];
        if (!st || params.get('restart') || st.days !== days) {
            const d = await api(`/api/review?${q({ days: String(days), queue })}`);
            const groups = d.groups || (d.keys || []).map(k => ({ keys: [k], users: [], senders: [], count: 1 }));
            st = reviewStates[queue] = { queue, groups, open: groups.length ? 0 : -1, done: 0, days, counts: d.counts || {}, mode: d.mode, picked: new Set(), shown: 100 };
            for (const [k, other] of Object.entries(reviewStates)) if (k !== queue && other.days === days && d.counts) other.counts = d.counts;
            if (params.get('restart')) { if (MEMORY) memRoute = plain; else history.replaceState(null, '', plain); }
        }
        reviewKeys = null;
        const emails = (o) => (o.companies || o.groups).reduce((a, g) => a + g.keys.length, 0);
        const left = (k) => { const o = reviewStates[k]; return o && o.days === days && (o.companies || o.groups) ? emails(o) : (st.counts[k] || 0); };
        const act = async (groups, action) => {
            acting++; busyStart();
            try {
                const done = await answerGroups(st, groups, action);
                if (done) { toast(done.text, { undo: async () => { await undoKeys(done.keys)(); reviewStates[queue] = null; pendingAt = 0; refreshPending(); } }); render(); pendingAt = 0; refreshPending(); }
            } catch (e) { toast(`Couldn't save your answer: ${e.message}`, { error: true }); } finally { acting--; busyEnd(); }
        };
        const head = [h('div', { class: 'page-head' },
            h('div', {}, h('h1', { text: 'Review' }),
                h('p', { class: 'sub' }, st.groups.length ? [`${num(emails(st))} ${Q.what} in `, h('b', { text: `${num(st.groups.length)} item${st.groups.length === 1 ? '' : 's'}` }), `, last ${days} days, ${Q.order}. One answer covers every copy of an email. Open one to weigh the evidence.`] : `Every email in this tab from the last ${days} days has an answer.`)),
            // (0.6.39) What an answer moves, said once above the list (the quick buttons are short).
            h('span', { class: 'mode-note', text: st.mode !== 'enforce' ? 'Monitor mode: answers move nothing' : 'Enforce mode: Phishing and Spam move emails to the Spam folder; Mark safe moves them back to the Inbox. Each answer can be undone.' })),
            h('div', { class: 'review-tools' },
                reviewTabs(queue, left),
                h('span', { class: 'keys-hint' }, h('kbd', { text: 'P' }), ' phishing ', h('kbd', { text: 'S' }), ' spam ', h('kbd', { text: 'F' }), ' mark safe ', h('kbd', { text: 'I' }), ' not sure ', h('kbd', { text: 'N' }), ' skip ', h('kbd', { text: 'R' }), ' check again', ' (the open email)')),
            queue === 'reported' ? h('p', { class: 'sub', text: 'Reported: someone clicked Gmail\'s own "Report phishing" on it (Settings → User reports). Gmail already moved it out of their Inbox, so no answer here moves it: Phishing or Spam confirms the report (and trains the AI); Mark safe records a false report and leaves the email where its reader put it (tell them if they need it back). The why says what the checks had made of it.' }) : null,
            queue === 'suspicious' ? h('p', { class: 'sub', text: 'Suspicious: the checks found signs (a rules score of 3 or more; from a sender Gmail confirmed, only when the AI agrees) or the AI scored it at least the suspicious line, but not enough to move it, so it is still in the Inbox. Marking them is the best way to see what the move rules miss, and what retraining needs (Health → Model health).' }) : null];
        if (!st.groups.length) {
            return [...head, h('div', { class: 'alert good', role: 'status' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '✓' }),
                h('div', { class: 'grow' }, h('b', { text: 'Nothing left to review.' }), ` ${st.done ? `${num(st.done)} answered just now; e` : 'E'}very email in this tab from the last ${days} days has an answer.`)),
                // (0.6.50) Emails still waiting from before the period shown: say so, and one click shows them.
                (() => {
                    const longest = Math.max(...[...document.querySelectorAll('.range')].filter(b => !b.hidden).map(b => Number(b.dataset.days) || 0), days);
                    if (!olderWaiting || days >= longest) return null;
                    return h('div', { class: 'alert warning' }, h('div', { class: 'grow' }, h('b', { text: `${num(olderWaiting)} email${olderWaiting === 1 ? '' : 's'} from before the last ${days} days still wait${olderWaiting === 1 ? 's' : ''} for an answer.` }), ' The menu counts the period you pick.'),
                        h('button', { class: 'btn', type: 'button', onclick: () => { days = longest; try { localStorage.setItem('spruce.days', String(longest)); } catch (e) { /* not kept */ } reviewStates = {}; pendingAt = 0; pendingSeen = false; refreshPending(); go(olderMovedWaiting || !olderWaiting ? '#/review' : '#/review?queue=suspicious'); render(); } }, `Show the last ${longest} days`));
                })(),
                h('div', { class: 'actions' }, queue === 'moved' ? h('a', { class: 'btn', href: '#/readiness' }, 'See Readiness') : h('a', { class: 'btn', href: '#/health' }, 'See Model health'),
                    h('a', { class: 'btn', href: `#/review?${q(queue === 'moved' ? { restart: '1' } : { queue, restart: '1' })}` }, 'Look again'))];
        }
        // The open item: its first copy nobody has reviewed meanwhile (another admin, or Messages).
        // (0.6.44) The filter bar: words (sender, domain, name, subject), the sender check, the AI score, the kind. Kept while
        // answering; the open item and the keys follow what is shown.
        const F = st.filter = st.filter || { q: '', dmarc: 'any', ai: 'any', kind: 'any' };
        const words = F.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
        const filtering = !!(words.length || F.dmarc !== 'any' || F.ai !== 'any' || F.kind !== 'any');
        const matches = (x) => {
            if (words.length) {
                const text = [x.subject, x.label, x.sender && x.sender.name, x.sender && x.sender.address, ...(x.senders || [])].filter(Boolean).join(' ').toLowerCase();
                if (!words.every(w => text.includes(w))) return false;
            }
            if (F.dmarc !== 'any' && (x.dmarc || 'none') !== F.dmarc) return false;
            const a = typeof x.ai === 'number' ? x.ai : null;
            if (F.ai === 'low' && !(a !== null && a < 0.5)) return false;
            if (F.ai === 'mid' && !(a !== null && a >= 0.5 && a < aiThreshold)) return false;
            if (F.ai === 'high' && !(a !== null && a >= aiThreshold)) return false;
            if (F.kind !== 'any' && x.kind !== F.kind) return false;
            return true;
        };
        const visible = st.groups.filter(matches);
        if (st.open >= 0 && !matches(st.groups[st.open])) st.open = visible.length ? st.groups.indexOf(visible[0]) : -1;
        let m = null, mode = st.mode;
        const g = st.open >= 0 ? st.groups[st.open] : null;
        if (g) {
            while (g.keys.length) {
                try { ({ message: m, mode } = await api(`/api/message?${q({ key: g.keys[0] })}`)); } catch (e) { g.keys.shift(); m = null; continue; }
                if (m.markedBy) { g.keys.shift(); m = null; continue; }
                break;
            }
            if (!m) { st.groups.splice(st.open, 1); st.open = Math.min(st.open, st.groups.length - 1); return review(new URLSearchParams(queue === 'moved' ? {} : { queue })); }
            if (mode) st.mode = mode;
        }
        const skip = () => { const next = st.groups.findIndex((x, i) => i > st.open && matches(x)); st.open = next; render(); };
        if (g) reviewKeys = { p: () => act([g], 'phishing'), s: () => act([g], 'spam'), f: () => act([g], 'false-alarm'), i: () => act([g], 'unclear'), n: skip, ...(canRescanReview(g) ? { r: () => rescanEmail(g.keys[0]) } : {}) };
        // Several at once: the ticked items.
        const bar = h('div', { class: 'bulk-review', role: 'region', 'aria-label': 'Ticked items', hidden: !st.picked.size });
        const drawBar = () => {
            const picked = st.groups.filter(x => st.picked.has(x));
            bar.hidden = !picked.length;
            bar.textContent = '';
            if (!picked.length) return;
            const n = picked.reduce((a, x) => a + x.keys.length, 0);
            bar.append(h('span', { class: 'grow', text: `${num(picked.length)} item${picked.length === 1 ? '' : 's'} ticked · ${num(n)} email${n === 1 ? '' : 's'}` }),
                // (0.6.39) The same four answers for every ticked item, and the Spam-senders choice shown here too.
                ...['phishing', 'spam', 'false-alarm', 'unclear'].map(a => h('button', { class: `btn ${ANSWER[a].cls}`, type: 'button', title: ANSWER[a].help, onclick: () => act(picked, a) }, `All: ${ANSWER[a].label}`)),
                spamSenderBox('their senders\'') || '',
                h('button', { class: 'linkbtn', type: 'button', onclick: () => { st.picked.clear(); for (const c of document.querySelectorAll('.rv-pick')) c.checked = false; drawBar(); } }, 'Clear'));
        };
        drawBar();
        const openAt = st.open >= 0 ? visible.indexOf(st.groups[st.open]) : -1;
        const rows = visible.slice(0, Math.max(st.shown, openAt + 1)).map((x) => { const i = st.groups.indexOf(x); return reviewRow(st, x, i, i === st.open && m ? reviewEvidence(st, x, m, act, skip) : null, act, drawBar); });
        const more = visible.length > rows.length ? h('button', { class: 'btn', type: 'button', onclick: () => { st.shown += 200; render(); } }, `Show ${num(Math.min(200, visible.length - rows.length))} more (${num(visible.length - rows.length)} not shown)`) : null;
        const filters = reviewFilterBar(st, visible, filtering, drawBar);
        const list = rows.length ? h('section', { class: 'card rv-list', 'aria-label': 'Items to review' }, rows)
            : h('section', { class: 'card' }, h('div', { class: 'empty', text: 'Nothing here matches the filter.' }));
        return [...head, filters, bar, list, more,
            st.open === -1 ? h('p', { class: 'small muted', text: 'You skipped to the end of the list. The items you skipped are still here, undecided: open one to answer it.' }) : null];
    }
    // (0.6.44) Review's filter bar. Typing filters as you type (the box keeps its place); "Tick all shown" ticks every item
    // the filter shows (only those); Clear shows everything again.
    let reviewSearchFocus = null;
    function reviewFilterBar(st, visible, filtering, drawBar) {
        const F = st.filter;
        const box = h('input', { type: 'search', class: 'list-search', id: 'rvSearch', value: F.q, placeholder: 'Search sender, domain or subject', 'aria-label': 'Search the emails to review', autocomplete: 'off', spellcheck: 'false' });
        let timer = null;
        box.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(() => { F.q = box.value; reviewSearchFocus = box.selectionStart; st.open = -1; render({ quiet: true }); }, 250);
        });
        if (reviewSearchFocus !== null) setTimeout(() => { const b = $('#rvSearch'); if (b) { b.focus(); try { b.setSelectionRange(reviewSearchFocus, reviewSearchFocus); } catch (e) { /* not a text box */ } } reviewSearchFocus = null; }, 0);
        const chips = (label, key, options) => h('div', { class: 'rv-chips', role: 'group', 'aria-label': label }, h('span', { class: 'rv-chips-label', text: `${label}:` }),
            options.map(([v, text]) => h('button', { class: `chip${F[key] === v ? ' on' : ''}`, type: 'button', 'aria-pressed': String(F[key] === v),
                onclick: () => { F[key] = v; st.open = -1; render({ quiet: true }); } }, text)));
        const emails = visible.reduce((n, x) => n + x.keys.length, 0);
        const allTicked = visible.length && visible.every(x => st.picked.has(x));
        const tickAll = h('button', { class: 'btn', type: 'button', disabled: !visible.length, onclick: () => {
            if (allTicked) for (const x of visible) st.picked.delete(x); else for (const x of visible) st.picked.add(x);
            render({ quiet: true });
        } }, allTicked ? 'Untick all shown' : `Tick all ${num(visible.length)} shown`);
        const clear = filtering ? h('button', { class: 'linkbtn', type: 'button', onclick: () => { Object.assign(F, { q: '', dmarc: 'any', ai: 'any', kind: 'any' }); render({ quiet: true }); } }, 'Clear the filter') : null;
        return h('section', { class: 'card rv-filter', 'aria-label': 'Filter' },
            box,
            chips('Sender check', 'dmarc', [['any', 'Any'], ['pass', 'Passed ✓'], ['fail', 'Failed ✗'], ['none', 'None']]),
            chips('AI score', 'ai', [['any', 'Any'], ['low', 'Under 50%'], ['mid', `50–${Math.round(aiThreshold * 100) - 1}%`], ['high', `${pct(aiThreshold)}+`]]),
            chips('Kind', 'kind', [['any', 'Any'], ['phishing', 'Phishing'], ['spam', 'Spam']]),
            h('div', { class: 'rv-filter-foot' },
                h('span', { class: 'grow small', text: filtering ? `Showing ${num(emails)} email${emails === 1 ? '' : 's'} in ${num(visible.length)} item${visible.length === 1 ? '' : 's'}${F.q.trim() ? ` matching "${F.q.trim()}"` : ''}, of ${num(st.groups.length)}.` : `${num(st.groups.length)} item${st.groups.length === 1 ? '' : 's'}. Click a sender's ⌕ to see only their mail.` }),
                tickAll, clear));
    }
    // The sender check of an item's copies, as a tag on its row.
    const dmarcTag = (d) => (d === 'pass' ? h('span', { class: 'dm-tag pass', title: 'Gmail confirmed the sender is real (DMARC passed)', text: '✓ DMARC' })
        : d === 'fail' ? h('span', { class: 'dm-tag fail', title: 'The sender check failed (DMARC): the sender may be forged', text: '✗ DMARC failed' })
        : h('span', { class: 'dm-tag none', title: 'No sender check result (the domain publishes no DMARC policy, or Gmail wrote none)', text: '– no DMARC' }));
    // One row of the review list: tick, AI score, subject (opens it), sender and how many, its heaviest sign, quick answers.
    function reviewRow(st, g, i, evidence, act, drawBar) {
        const Q = QUEUES[st.queue], open = !!evidence;
        const ai = typeof g.ai === 'number' ? g.ai : null;
        const toggle = () => { st.open = open ? -1 : i; render(); };
        const pick = h('input', { type: 'checkbox', class: 'rv-pick', 'aria-label': `Tick "${g.subject || 'this email'}"`, checked: st.picked.has(g) });
        pick.addEventListener('change', () => { if (pick.checked) st.picked.add(g); else st.picked.delete(g); drawBar(); });
        const people = g.users.length || g.count || g.keys.length;
        const meta = [g.sender ? (g.sender.name || g.sender.address) : null, g.keys.length > 1 ? `${num(g.keys.length)} copies, ${num(people)} people` : g.users[0] || null, g.firstAt ? when(g.firstAt) : null].filter(Boolean).join(' · ');
        const ring = h('span', { class: `rv-ai ${ai === null ? '' : ai >= aiThreshold ? 'hot' : ai >= aiSuspicious ? 'warm' : ''}`, title: ai === null ? 'No AI score' : `AI score ${pct(ai)}` }, ai === null ? '–' : String(Math.round(ai * 100)));
        const sign = g.signs && g.signs[0] ? h('span', { class: 'rv-sign', title: g.signs[0].text, text: g.signs[0].text }) : null;
        return h('div', { class: `rv-item${open ? ' open' : ''}` },
            h('div', { class: 'rv-row' }, pick, ring,
                h('button', { class: 'rv-title', type: 'button', 'aria-expanded': String(open), onclick: toggle },
                    h('span', { class: 'rv-subject' }, kindTag(g.kind), h('span', { text: g.subject || g.label || '(subject not stored)' })), h('span', { class: 'rv-meta', text: meta })),
                dmarcTag(g.dmarc),
                g.sender && g.sender.address ? h('button', { class: 'rv-only', type: 'button', title: `Show only mail from ${g.sender.address}`, 'aria-label': `Show only mail from ${g.sender.address}`,
                    onclick: () => { st.filter = Object.assign(st.filter || {}, { q: g.sender.address }); st.open = -1; render({ quiet: true }); } }, '⌕') : null,
                sign,
                open ? null : h('div', { class: 'rv-quick', role: 'group', 'aria-label': 'Quick answer' },
                    // (0.6.39) The four answers, as on the open item (Spam too); what they move is said above the list.
                    ['phishing', 'spam', 'false-alarm', 'unclear'].map(a => h('button', { class: `btn sm ${ANSWER[a].cls}`, type: 'button', title: ANSWER[a].help, onclick: () => act([g], a) }, ANSWER[a].label))),
                h('button', { class: 'rv-chevron', type: 'button', 'aria-label': open ? 'Close' : 'Open and weigh the evidence', 'aria-expanded': String(open), onclick: toggle },
                    s('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }, s('path', { d: 'm6 9 6 6 6-6' })))),
            evidence);
    }
    // The open item: who sent it to whom, where the scores stand, the signs for and against, what the AI weighed
    // most, and the five answers.
    function reviewEvidence(st, g, m, act, skip) {
        const Q = QUEUES[st.queue];
        const ai = m.ai && typeof m.ai.probability === 'number' ? m.ai.probability : null;
        const moves = st.mode === 'enforce' && m.state === 'inbox' && m.action !== 'move';
        // (0.6.41) A rule sign carries its points (they add up to the rules score); the others (the AI, a link's verdict, the
        // sender check) are shown by strength only.
        const against = (m.signals || []).filter(x => x.weight > 0).sort((a, b) => b.weight - a.weight).map(x => [x.weight, x.text, `+${x.weight}`]);
        // (0.6.27) Taken for spam: the column says spam, not phishing, and starts with what made it spam (the hidden
        // filler in list mail counts for no rules score, so it isn't among the weighted signs).
        const spamItem = kindOf(m) === 'spam';
        if (spamItem && ((m.trigger === 'spam' && /hides a block/.test(m.why || '')) || (m.signals || []).some(x => x && x.kind === 'hidden-filler'))) against.unshift([3, 'It is list or marketing mail that hides a block of unrelated text below the message: a spam trick.', 'spam']);
        // (0.6.55) The AI's spam answer, where it reads as bulk marketing.
        const aiSpam = m.ai && typeof m.ai.spam === 'number' ? m.ai.spam : null;
        if (aiSpam !== null && aiSpam >= 0.5) against.unshift([aiSpam >= aiThreshold ? 4 : 2, `The AI scores it ${pct(aiSpam)} spam: it reads as a business's bulk marketing`, `spam ${pct(aiSpam)}`]);
        const againstTitle = spamItem ? 'Points to spam' : 'Points to phishing';
        for (const l of m.links || []) against.push([l.severity === 'danger' ? 5 : 2, `Link: ${l.reason || l.url}`, 'link']);
        if (ai !== null && ai >= 0.5) against.unshift([ai >= aiThreshold ? 5 : ai >= aiSuspicious ? 3 : 1.5, `The AI scores it ${pct(ai)}: it reads like phishing`, `AI ${pct(ai)}`]);
        const pro = (m.signals || []).filter(x => x.weight < 0).map(x => [x.weight, x.text, `−${Math.abs(x.weight)}`]);
        if (ai !== null && ai < 0.5) pro.unshift([ai < 0.2 ? 5 : 2, `The AI scores it ${pct(ai)}: it reads as genuine`, `AI ${pct(ai)}`]);
        if (m.auth && m.auth.dmarc === 'pass') pro.push([2, 'Gmail confirmed the sender is real (DMARC)', '✓']);
        if (m.inside) pro.push([2, 'It comes from inside your organization', '✓']);
        // (0.6.3) A sender check that neither passed nor failed: said beside the evidence, not counted either way.
        const dm = m.auth ? m.auth.dmarc : undefined;
        const dmarcNote = !m.auth ? 'Sender check (DMARC): not recorded for this email. Not counted either way.'
            : !dm ? 'Sender check (DMARC): Gmail wrote no result for this email. Not counted either way.'
            : dm === 'none' ? 'Sender check (DMARC): none. The sender\'s domain publishes no DMARC policy, so nothing confirms who sent it. Not counted either way.'
            : dm !== 'pass' && dm !== 'fail' ? `Sender check (DMARC): ${dm} (neither a pass nor a failure). Not counted either way.` : '';
        const list = (items, tone, none) => (items.length ? h('ul', { class: 'ev-list' }, items.map(([w, t, label]) => h('li', {}, heatBox(w, tone, label), h('span', { text: t }))))
            : h('p', { class: 'small muted', text: none }));
        const lean = ai === null ? null : h('div', { class: 'lean-box' },
            h('div', { class: 'lean-ends', 'aria-hidden': 'true' }, h('span', { text: 'Reads as genuine' }), h('span', { text: 'Reads like phishing' })),
            (() => { const b = h('div', { class: 'lean-bar', role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(ai * 100), 'aria-label': 'AI score' }, h('span', { class: 'lean-mark' })); b.firstChild.style.left = pct(ai, 1); return b; })(),
            h('div', { class: 'small', text: `AI ${pct(ai)} (moves at ${pct(aiThreshold)}) · rules score ${m.score === null || m.score === undefined ? '–' : m.score} (suspicious from 3, moved from 5) · ${num(against.length)} sign${against.length === 1 ? '' : 's'} against, ${num(pro.length)} for` }));
        const users = g.users.length ? g.users : [m.user].filter(Boolean);
        const quotes = m.ai && m.ai.reasons && m.ai.reasons.length ? m.ai.reasons.slice(0, 3).map(r => h('div', { class: 'quote', text: r.facts ? 'Who sent it, the sender check and where its links go' : `“${r.sentence}”` })) : null;
        const canRead = !!m.key && !m.pasted;
        return h('div', { class: 'rv-open' },
            h('div', { class: 'rv-head' },
                h('div', { class: 'rv-who' }, 'From ', m.sender.address ? addr(m.sender.address, m.sender.name ? `${m.sender.name} <${m.sender.address}>` : m.sender.address) : (m.sender.name || 'an unknown sender'),
                    // (0.6.35) The sender's list, beside its address.
                    m.spamSender ? [' ', h('a', { class: 'list-label spam small-label', href: '#/allowlist', title: `${m.spamSender} is on Settings → Sender lists → Spam senders`, text: 'Always to Spam' })] : null,
                    h('br'), 'To ', shortList(users, `Who received "${m.subject || 'this email'}"`, { copy: true, describe: (k) => `${num(k)} people in your organization received a copy${g.keys.length > 1 ? `; ${num(g.keys.length)} copies wait for review` : ''}.` }),
                    g.senders.length > 1 ? [h('br'), `From ${num(g.senders.length)} addresses: `, shortList(g.senders, 'Who sent it', { copy: true, describe: (k) => `The copies came from ${num(k)} sender addresses.` })] : null,
                    h('div', { class: 'rv-verdict' }, kindTag(kindOf(m)), h('b', { text: asKind(m) })),
                    h('div', { class: 'small muted', text: m.why ? `Because ${m.why}.` : '' })),
                lean),
            recheckBox(m), rescanBox(m),
            h('div', { class: 'ev-cols' },
                h('section', { class: `ev against${spamItem ? ' spam' : ''}`, 'aria-label': againstTitle }, h('h3', { text: againstTitle }), list(against, spamItem ? 'spam' : 'phish', `Nothing found that ${againstTitle.toLowerCase()}.`)),
                h('section', { class: 'ev for', 'aria-label': 'Points to safe' }, h('h3', { text: 'Points to safe' }), list(pro, 'safe', 'Nothing found that points to safe.'),
                    quotes ? h('div', { class: 'ev-quotes' }, h('div', { class: 'small muted', text: 'What the AI weighed most:' }), quotes) : null)),
            heatLegend(),
            dmarcNote ? h('p', { class: 'small muted rv-note', text: dmarcNote }) : null,
            h('div', { class: 'rv-actions' },
                h('button', { class: 'btn big phish', type: 'button', title: ANSWER.phishing.help, onclick: () => act([g], 'phishing') }, answerLabel('phishing', moves), h('kbd', { text: 'P' })),
                h('button', { class: 'btn big', type: 'button', title: ANSWER.spam.help, onclick: () => act([g], 'spam') }, answerLabel('spam', moves), h('kbd', { text: 'S' })),
                h('button', { class: 'btn big safe', type: 'button', title: ANSWER['false-alarm'].help, onclick: () => act([g], 'false-alarm') }, answerLabel('false-alarm', st.mode === 'enforce' && m.state === 'moved'), h('kbd', { text: 'F' })),
                h('button', { class: 'btn big', type: 'button', title: ANSWER.unclear.help, onclick: () => act([g], 'unclear') }, ANSWER.unclear.label, h('kbd', { text: 'I' })),
                h('button', { class: 'btn big ghost', type: 'button', onclick: skip, title: 'Go to the next one; this one stays here, unanswered' }, 'Skip for now (answer later)', h('kbd', { text: 'N' })),
                h('span', { class: 'grow' }),
                h('a', { class: 'rv-link', href: `#/message?${q({ key: m.key })}` }, 'More details'),
                canRead ? h('button', { class: 'rv-link', type: 'button', onclick: () => showAiReading(m), title: 'Read from Gmail now: the whole email as received, and what the AI reads of it (nothing is kept)' }, 'Show the email') : null,
                rescanButton(m, 'rv-link review-rescan'),
                g.campaign ? h('a', { class: 'rv-link', href: `#/messages?${q({ campaign: g.campaign })}` }, 'Every copy') : null),
            // (0.6.35) The Spam answer can add the sender to Spam senders (admins; a verified outside sender only).
            isModerator() ? null : (() => {
                const can = m.auth && m.auth.dmarc === 'pass' && !m.inside && m.sender && m.sender.address;
                if (!can) return h('p', { class: 'small muted spam-sender-opt', text: 'Spam here labels this email only: its sender can\'t be added to Spam senders, as Gmail couldn\'t confirm the sender is real (or it is from inside).' });
                const box = h('input', { type: 'checkbox', checked: spamAddSender });
                box.addEventListener('change', () => { spamAddSender = box.checked; });
                return h('label', { class: 'choice spam-sender-opt' }, box, h('span', {}, 'With Spam, also send future mail from ', h('b', { text: m.spamKey || m.sender.address }), ' straight to Spam (Settings → Sender lists → Spam senders; it skips the other checks).'));
            })(),
            h('p', { class: 'small muted rv-help', text: `${g.keys.length > 1 ? `One answer covers all ${num(g.keys.length)} copies. ` : ''}Spam also answers this address's other emails waiting here. Not sure takes it out of the queue and keeps it out of AI training; Skip leaves it here, undecided.${canRead ? ' Show the email reads it from Gmail now, the whole email and what the AI reads of it: nothing is kept.' : ''}${st.mode === 'enforce' ? '' : ' Monitor mode: nothing is moved.'}` }));
    }

    // --- Health → Service status (0.6.0, as a status page): one line on how it is, each check with what to do,
    // and beside them whether it is ready for enforce mode and how the AI model is doing (each card links on).
    async function status() {
        const [d, rd, md] = await Promise.all([api('/api/status'), api(`/api/readiness?days=${days}`).catch(() => null), api(`/api/health?days=${days}`).catch(() => null)]);
        const bad = d.checks.filter(c => c.ok === false).length, unknown = d.checks.filter(c => c.ok === null).length, ok = d.checks.length - bad - unknown;
        const tone = bad ? 'critical' : unknown ? 'warning' : 'good';
        const r = rd && rd.readiness;
        const passed = r ? r.checks.filter(c => c.ok).length : 0;
        return [h('h1', { text: 'Service status' }),
            h('p', { class: 'sub', text: 'Whether the service works end to end, checked from here. In Cloud Shell, bash deploy/doctor.sh checks more (the subscription, Gmail\'s permission to publish, the alert policies) and says what to run.' }),
            h('div', { class: `status-hero ${tone}`, role: 'status' }, h('span', { class: 'status-icon', 'aria-hidden': 'true', text: bad ? '!' : unknown ? '?' : '✓' }),
                h('div', {}, h('b', { text: bad ? `${bad} problem${bad === 1 ? '' : 's'} to fix.` : unknown ? 'No problem found, but not everything could be checked.' : 'Everything checked works.' }),
                    h('div', { class: 'small', text: `${num(ok)} working${bad ? ` · ${num(bad)} not working` : ''}${unknown ? ` · ${num(unknown)} not checked` : ''}` }))),
            h('div', { class: 'status-grid' },
                h('section', { class: 'card', 'aria-label': 'Checks' }, h('ul', { class: 'svc-list' }, d.checks.map(c => {
                    const st = c.ok === true ? 'ok' : c.ok === false ? 'todo' : 'unknown';
                    return h('li', { class: st },
                        h('span', { class: 'sr-only', text: c.ok === true ? 'Works: ' : c.ok === false ? 'Problem: ' : 'Not checked: ' }),
                        // (0.6.54) A check whose fix is a page here links straight to it.
                        h('div', { class: 'svc-text' }, h('div', { text: c.text }), c.fix ? h('div', { class: 'muted small' }, 'What to do: ', c.link ? h('a', { href: c.link, text: c.fix }) : c.fix) : null),
                        h('span', { class: `svc-state ${st}` }, h('span', { class: 'dot', 'aria-hidden': 'true' }), c.ok === true ? 'Working' : c.ok === false ? 'Problem' : 'Not checked'));
                }))),
                h('div', { class: 'status-side' },
                    r ? h('section', { class: 'card' }, h('h2', { text: r.mode === 'enforce' ? 'Enforce mode is on' : 'Ready for enforce mode?' }),
                        h('div', { class: 'sub', text: `${num(passed)} of ${num(r.checks.length)} checks pass, last ${days} days.` }),
                        h('ul', { class: 'checks' }, r.checks.map(c => h('li', { class: c.ok ? 'ok' : 'todo' },
                            h('span', { class: 'mark', 'aria-hidden': 'true', text: c.ok ? '✓' : '!' }), h('span', { class: 'sr-only', text: c.ok ? 'Done: ' : 'To look at: ' }), h('span', { text: c.text })))),
                        h('a', { class: 'btn', href: '#/readiness' }, 'Readiness in full')) : null,
                    md ? h('section', { class: 'card' }, h('h2', { text: 'AI model' }), h('dl', { class: 'kv' },
                        kvRow('In use', md.current || md.model || 'unknown'),
                        kvRow('Reviewed', `${num(md.reviewed)} (${num(md.confirmed)} phishing)`),
                        kvRow('False alarms', md.reviewed ? `${num(md.falseAlarms)}, ${pct(md.falseAlarms / md.reviewed, 1)} of reviewed` : num(md.falseAlarms)),
                        kvRow('Moves at', pct(md.threshold))),
                        h('a', { class: 'btn spaced-btn', href: '#/health' }, 'Model health')) : null))];
    }

    // --- Settings → Weekly summary: the weekly summary email (off by default) ----------------------------
    function digestCard(d) {
        const g = d.digest || { enabled: false };
        const preview = h('pre', { class: 'digest-preview', hidden: true });
        const toggle = h('input', { type: 'checkbox', role: 'switch', checked: !!g.enabled, 'aria-label': 'Send the weekly summary email' });
        toggle.addEventListener('change', async () => {
            acting++; busyStart();
            try { await api('/api/digest', { method: 'POST', body: { enabled: toggle.checked } }); toast(toggle.checked ? 'The weekly summary is on.' : 'The weekly summary is off.'); render(); }
            catch (e) { toggle.checked = !toggle.checked; toast(`Couldn't change it: ${e.message}`, { error: true }); } finally { acting--; busyEnd(); }
        });
        const show = async () => {
            try { const { preview: p } = await api('/api/digest/preview'); preview.textContent = `Subject: ${p.subject}\n\n${p.text}`; preview.hidden = false; }
            catch (e) { toast(`Couldn't make the preview: ${e.message}`); }
        };
        const facts = [g.updatedBy ? `Turned ${g.enabled ? 'on' : 'off'} by ${g.updatedBy}, ${when(g.updatedAt)}.` : 'Off: nobody has turned it on.', g.lastSentAt ? `Last sent ${when(g.lastSentAt)}.` : ''].filter(Boolean).join(' ');
        return h('section', { class: 'card spaced' }, h('h2', { text: 'Weekly summary email' }),
            h('div', { class: 'sub', text: `Every Monday from 7 AM (${d.timeZone || 'UTC'}), a summary of the week goes into the Inbox of each dashboard admin (ADMIN_EMAILS, and the members of ADMIN_GROUP): what was checked and moved, false alarms, what waits for you, the largest campaigns.` }),
            h('label', { class: 'switch' }, toggle, h('span', { text: 'Send the weekly summary' })),
            h('div', { class: 'small muted', text: facts }),
            h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: show }, 'Preview'),
                MEMORY ? null : h('button', { class: 'btn', type: 'button', onclick: postButton('/api/digest/send', () => ({}), (o) => (o.demo ? 'Demo mode: nothing sent.' : `Put in ${num(o.sent)} admin Inbox${o.sent === 1 ? '' : 'es'}${o.failed && o.failed.length ? `; ${o.failed.length} couldn't be reached` : ''}.`),
                    'Put this week\'s summary in every dashboard admin\'s Inbox now?') }, 'Send one now')),
            preview);
    }

    // --- Settings → Update: the approved versions (from the release repository), their changes, the button, and
    // (0.6.9) the two repositories this installation downloads from ----
    // The button needs the agreement, the project ID and the admin's own email address; it asks the
    // spruce-update job to rebuild and redeploy both services (src/update.js, deploy/cloud-update.sh).
    // (0.6.31) An update under way is followed wherever the admin is: the loading bar and, in the bottom corner, what is
    // happening, the whole time Cloud Build builds and deploys it; asked every UPDATE_POLL_MS (an error while the new
    // version takes over is tried again). When it is done the dashboard reloads by itself (its pages come from the new
    // version); when it failed or stalled, the Update page says why.
    const UPDATE_POLL_MS = Number(window.SPRUCE_UPDATE_POLL_MS) || 15000;
    let updateWatch = null;
    function followUpdate(d) {
        const st = d && d.progress;
        const running = !!(st && ['requested', 'building'].includes(st.phase) && d.running);
        if (running) {
            const label = `Updating to ${st.version}: ${st.phase === 'requested' ? 'Cloud Build is starting' : 'Cloud Build is building and deploying it'} (about 10 minutes). The dashboard reloads by itself when it is done.`;
            if (!updateWatch) {
                updateWatch = { version: st.version, from: d.installed && d.installed.version, ticket: busyStart(label), label };
                updateWatch.timer = setInterval(async () => {
                    if (document.hidden) return;
                    try {
                        followUpdate(await api('/api/update'));
                        if (updateWatch && /^#\/?update/.test(currentHash()) && !inUse()) render({ quiet: true });   // its status box, starting → building
                    } catch (e) { /* the new version is taking over: asked again */ }
                }, UPDATE_POLL_MS);
            } else if (updateWatch.label !== label) { busyEnd(updateWatch.ticket); updateWatch.ticket = busyStart(label); updateWatch.label = label; }
            return;
        }
        if (!updateWatch) return;
        const w = updateWatch;
        updateWatch = null;
        clearInterval(w.timer); busyEnd(w.ticket);
        const installed = d && d.installed && d.installed.version;
        if ((st && st.phase === 'done') || (installed && installed !== w.from)) {
            toast(`Updated to ${installed || w.version}: reloading the dashboard…`);
            setTimeout(() => location.reload(), 1500);
        } else {
            toast(`The update to ${w.version} didn't finish: Settings → Update says why.`);
            if (/^#\/?update/.test(currentHash())) render({ quiet: true });
        }
    }
    async function updatePage(q) {
        const demoManual = !!(q && q.get && q.get('manual'));
        const d = await api(`/api/update${demoManual ? '?manual=1' : ''}`);
        followUpdate(d);
        const n = d.newest;
        const out = [h('h1', { text: 'Update' }), h('p', { class: 'sub', text: 'The approved versions, from your release repository (Repositories, below), and what changed in them. A version that changes only the service is installed from here; one that changes the installation itself (permissions, jobs, settings) from Cloud Shell, with bash deploy/update.sh. Each version names its AI model: the update downloads that model from TinyPhishLLM, the model\'s own repository, and uses it only if every file matches.' })];
        // The AI model: each version pins one commit of TinyPhishLLM (its own public repository), which the
        // image build downloads and checks (SHA-256).
        // The repositories are links (a new tab): the model's to TinyPhishLLM (its commit to that commit), the
        // approved versions' to spruce-google-service_main. Only GitHub addresses of the expected shape are linked.
        const ghLink = (url, text) => (/^https:\/\/(github\.com|gitlab\.[\w.-]+)\/[\w.\/-]+?(\/(-\/)?commit\/[0-9a-f]{40})?$/.test(String(url || ''))
            ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text }) : text);
        const modelText = (v) => {
            if (!v || !v.model) return 'unknown';
            const s = v.modelSource;
            if (!s) return `phish-tiny ${v.model}`;
            return [ghLink(s.repository, `phish-tiny ${v.model}, from ${s.repository.replace(/^https:\/\/github\.com\//, '')}`),
                ' (commit ', ghLink(`${s.repository}/commit/${s.commit}`, s.commit.slice(0, 7)), ')'];
        };
        const kvNode = (k, v) => [h('dt', { text: k }), h('dd', {}, v)];
        out.push(h('section', { class: 'card' }, h('dl', { class: 'kv' },
            kvRow('Installed', d.installed.version),
            kvNode('Its AI model', modelText(d.installed)),
            kvRow('Installation level', `${d.installed.installLevel}${d.installed.levelFrom === 'cloud-run' ? ' (read from Cloud Run)' : ''}: what deploy/install.sh last set up. A version with a higher level is installed from Cloud Shell.`),
            kvRow('Newest approved', n ? `${n.version}${n.date ? `, approved ${when(Date.parse(n.date))}` : ''}` : 'unknown'),
            kvNode('Its AI model', n ? modelText(n) : '–'),
            kvNode('From', n && n.repo ? ghLink(n.repo, n.repo) : '–'),
            kvNode('Last checked', checkAgain(d, demoManual)))));
        const st = d.progress;
        if (st && st.phase) {
            const at = st.at ? when(st.at) : '';
            const box = { requested: ['warning', '⏳', `An update to ${st.version} was asked for by ${st.by}, ${at}.`, 'Cloud Build starts within a minute; building and deploying takes about 10 minutes. This page shows the new version when it is done (reload it if it doesn\'t).'],
                building: ['warning', '⏳', `Updating to ${st.version} (asked for by ${st.by}, ${at}).`, 'Building and deploying takes about 10 minutes. Mail keeps being checked meanwhile.'],
                done: ['good', '✅', `Updated from ${st.from} to ${st.version}, ${at} (asked for by ${st.by}).`, ''],
                failed: ['critical', '⛔', `The update to ${st.version} failed, ${at}.`, `${st.message || ''}. Cloud Build's history (tag spruce-update) has the log.`],
                stalled: ['critical', '⛔', `The update to ${st.version} asked for ${at} didn't finish.`, 'Cloud Build\'s history (tag spruce-update) says why. Nothing changed unless a deploy stopped half-way (then bash deploy/rollback.sh goes back).'] }[
                ['requested', 'building'].includes(st.phase) && !d.running ? 'stalled' : st.phase];
            if (box) out.push(h('div', { class: `alert ${box[0]}`, role: 'status' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: box[1] }),
                h('div', { class: 'grow' }, h('b', { text: box[2] }), box[3] ? ` ${box[3]}` : '')));
        }
        // A manual install waiting (0.5.24): what and why, the steps, and the form shown with the button off.
        const m = d.manualInstall;
        if (m) {
            const link = (text, href) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
            out.push(h('section', { class: 'card spaced manual-install', role: 'alert' },
                h('div', { class: 'manual-head' }, alertIcon('Manual install required'), h('h2', { text: `Manual install required: ${m.version}` })),
                h('p', { text: `${m.version} changes the installation itself (new permissions, jobs or settings): it needs installation level ${m.needs}, and this installation is at level ${m.installedLevel}. The dashboard can't make those changes, so it can't install it.` }),
                h('p', {}, h('b', { text: 'Until it is installed from Cloud Shell, no update is installed from this page: ' }), `not ${m.version}, and not any version after it. The Update button stays off, and the service keeps running ${d.installed.version} meanwhile.`),
                h('ol', { class: 'steps' },
                    h('li', {}, 'Open ', link('Cloud Shell', 'https://shell.cloud.google.com/?show=terminal'), ', signed in as a project owner.'),
                    h('li', {}, 'Go to the folder you installed or last upgraded from (the one with deploy/settings.env).'),
                    h('li', {}, 'Run ', h('code', { text: m.command }), ' ', copyButton(m.command, 'command', 'Copy'), '. It downloads the newest approved version, shows what changes and asks before changing anything, then runs deploy/install.sh.'),
                    h('li', {}, 'When it is done, this page installs updates again (within 10 minutes, or at once with Check again).')),
                h('div', { class: 'small muted', text: `${m.since ? `Waiting since ${when(m.since)}. ` : ''}The admins were sent an alert. Read what's new below first: the entry for ${m.version} says what it sets up.` })));
            out.push(updateForm(d, { locked: true }));
        } else if (d.canUpdate) out.push(updateForm(d));
        else if (d.why) out.push(h('div', { class: `alert ${n && !d.newer.length ? 'good' : 'warning'}` }, h('div', { text: d.why })));
        if (d.demo) out.push(h('div', { class: 'small muted' }, 'Demo mode: ', demoManual ? h('a', { href: '#/update', text: 'show the made-up version that installs from here' }) : h('a', { href: '#/update?manual=1', text: 'show a made-up version that needs a manual install' }), '.'));
        if (d.repos) out.push(reposCard(d));
        const entry = (c) => h('article', { class: 'release' }, h('h3', { text: `${c.version}: ${c.title}` }), markdown(c.body));
        out.push(h('section', { class: 'card spaced' }, h('h2', { text: d.newer.length ? `What's new since ${d.installed.version}` : 'What\'s new' }),
            d.newer.length ? d.newer.map(entry) : h('div', { class: 'empty', text: n ? 'Nothing newer than the version installed.' : 'The approved versions couldn\'t be read.' }),
            d.changelog.length ? h('details', { class: 'changelog' }, h('summary', { text: `The whole changelog (the last ${d.changelog.length} versions)` }), d.changelog.map(entry)) : null));
        return out;
    }
    // When GitHub was last asked, and Check again (0.5.38): GitHub asked now. The service allows it once a minute
    // for the whole dashboard (and 10 times an hour per admin); the button counts down until then.
    function checkAgain(d, demoManual) {
        const kept = Math.round((d.keptMs || 600000) / 60000);
        const text = h('span', { text: d.checkedAt ? `GitHub was asked ${when(d.checkedAt)}. The answer is kept ${kept} minutes, then asked again by itself. ` : 'GitHub couldn\'t be asked. ' });
        const btn = h('button', { class: 'btn small-btn', type: 'button' }, 'Check again');
        let until = Number(d.nextCheckAt) || 0, timer = null;
        const tick = () => {
            if (!document.body.contains(btn) && timer) { clearInterval(timer); timer = null; return; }
            const left = Math.ceil((until - Date.now()) / 1000);
            btn.disabled = left > 0 || acting > 0;
            btn.textContent = left > 0 ? `Check again (in ${left} s)` : 'Check again';
            if (left <= 0 && timer) { clearInterval(timer); timer = null; }
        };
        const start = () => { tick(); if (!timer && until > Date.now()) timer = setInterval(tick, 1000); };
        btn.addEventListener('click', async () => {
            btn.disabled = true; acting++; busyStart();
            try {
                const o = await api('/api/update/check', { method: 'POST', body: { manual: demoManual || undefined } });
                toast(o.newest ? `Asked GitHub just now: the newest approved version is ${o.newest.version}.` : `Asked GitHub just now: ${o.why || 'no answer'}`);
                render();
            } catch (e) {
                // A press too soon: the service's refusal says in how many seconds; the button counts down to it.
                const m = /in (\d+) seconds/.exec(e.message);
                if (m) until = Date.now() + Number(m[1]) * 1000;
                toast(e.message);
            } finally { acting--; busyEnd(); start(); }
        });
        start();
        return h('span', { class: 'check-again' }, text, btn);
    }
    // locked: a manual install is waiting (0.5.24): the form is shown, everything in it off, saying why.
    // (0.6.9) Settings → Update → Repositories: where this installation downloads from, each with Change. A change
    // needs the project ID, a ticked box and the admin's own address, is noted in Activity and emailed as an alert:
    // whoever controls the release repository decides what code an update installs. No default: the maintainer's are
    // shown only as examples.
    const REPOS = [
        { key: 'releasesRepo', env: 'RELEASES_REPO', label: 'Release repository', what: 'The approved versions: what this page offers, and what an update installs',
          example: 'https://github.com/thecodewarrior2/spruce-google-service_main' },
        { key: 'modelRepo', env: 'MODEL_REPO', label: 'Model repository', what: 'The AI model\'s files (each version pins their commit and SHA-256: only those exact files are used)',
          example: 'https://github.com/thecodewarrior2/tinyphishllm' }];
    function reposCard(d) {
        let open = null;
        const body = h('dl', { class: 'kv' });
        const draw = () => {
            body.textContent = '';
            for (const r of REPOS) {
                const p = d.repos[r.key] || {};
                const v = String(p.value || '').trim();
                const src = p.changed ? `Changed here by ${p.changed.by}, ${when(p.changed.at)}. settings.env (${r.env}) says ${String(p.env || '').trim() || 'nothing'}.`
                    : v ? `From settings.env (${r.env}).` : `Not set: nothing in settings.env (${r.env}) or here.`;
                const change = h('button', { class: 'btn small', type: 'button', text: v ? 'Change' : 'Set', onclick: () => { open = open === r.key ? null : r.key; draw(); } });
                body.append(h('dt', { text: r.label }), h('dd', {}, h('div', {}, v ? h('code', { class: 'mid', text: v }) : h('b', { text: 'Not set' }), ' ', change),
                    h('div', { class: 'small muted', text: `${r.what}. ${src}` }), open === r.key ? repoForm(d, r, v, () => { open = null; draw(); }) : null));
            }
            pageBusy = () => !!open;
        };
        draw();
        return h('section', { class: 'card spaced' }, h('h2', { text: 'Repositories' }),
            h('p', { class: 'sub', text: 'Where this installation downloads from. Neither has a default: use your own copies (a fork of the maintainer\'s, say), public so installations download without a password. A change applies at once, everywhere; deploy/settings.env keeps its own value for the next install from Cloud Shell.' }),
            body);
    }
    function repoForm(d, r, current, close) {
        const input = h('input', { type: 'url', value: current, placeholder: r.example, spellcheck: 'false', autocapitalize: 'off', 'aria-label': r.label, class: 'wide-input' });
        const agree = h('input', { type: 'checkbox' });
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'Google Cloud project ID', 'aria-label': 'Google Cloud project ID' });
        const email = h('input', { type: 'email', autocomplete: 'off', placeholder: 'Your admin address', 'aria-label': 'Your admin address' });
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const save = h('button', { class: 'btn primary', type: 'button', text: 'Save', onclick: async () => {
            err.textContent = ''; save.disabled = true; acting++; busyStart('Saving the repository…');
            try { await api('/api/policy', { method: 'POST', body: { key: r.key, value: input.value.trim(), projectId: project.value, adminEmail: email.value, agree: agree.checked } }); toast(`${r.label} saved. The admins are alerted, and Activity notes it.`); close(); render(); }
            catch (e) { err.textContent = e.message; save.disabled = false; }
            finally { acting--; busyEnd('Saving the repository…'); }
        } });
        return h('div', { class: 'repo-form' },
            input,
            h('div', { class: 'small muted', text: `A GitHub address (https://github.com/OWNER/REPO) or a GitLab one (https://gitlab.com/GROUP/REPO)${r.key === 'modelRepo' ? ', or an https address under which COMMIT/FILE downloads each file' : ''}. The maintainer's, as an example: ${r.example}. Empty: not set.` }),
            h('label', { class: 'choice' }, agree, h('span', { text: r.key === 'releasesRepo'
                ? 'I understand: whoever controls this repository decides what code an update installs in our project, and that code reads and moves mail. It is ours, or one we trust.'
                : 'I understand: the AI model is downloaded from here at the next build (only the files each version pins, checked by SHA-256). It is ours, or one we trust.' })),
            h('div', { class: 'inline-fields' }, project, email),
            err,
            h('div', { class: 'actions' }, save, h('button', { class: 'btn', type: 'button', text: 'Cancel', onclick: close })));
    }
    function updateForm(d, { locked = false } = {}) {
        const to = d.newest.version;
        const agree = h('input', { type: 'checkbox' });
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        const email = h('input', { type: 'email', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'you@your-domain', 'aria-label': 'Your email address' });
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const go = h('button', { class: 'btn primary', type: 'button' }, `Update to ${to}`);
        const ready = () => { go.disabled = locked || !(agree.checked && project.value.trim() && email.value.trim()); };
        for (const el of [agree, project, email]) { el.addEventListener('input', ready); el.addEventListener('change', ready); }
        if (locked) { for (const el of [agree, project, email]) el.disabled = true; go.textContent = `Update to ${to}: manual install required`; go.title = 'Install it from Cloud Shell first (above).'; }
        ready();
        pageBusy = () => !locked && (agree.checked || !!project.value || !!email.value);
        go.addEventListener('click', async () => {
            err.textContent = ''; go.disabled = true; acting++; busyStart();
            try {
                const o = await api('/api/update', { method: 'POST', body: { agree: agree.checked, projectId: project.value, email: email.value, version: to } });
                toast(o.started && o.started.demo ? 'Demo mode: nothing was updated.' : `Update to ${to} started: about 10 minutes.`);
                pageBusy = () => false; render();
            } catch (e) { err.textContent = e.message; ready(); }
            finally { acting--; busyEnd(); }
        });
        return h('section', { class: `card spaced${locked ? ' locked' : ''}`, 'aria-disabled': locked ? 'true' : null }, h('h2', { text: `Update to ${to}` }),
            locked ? h('div', { class: 'alert warning' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '🔒' }), h('div', { class: 'grow', text: `Off until ${to} is installed from Cloud Shell (Manual install required, above).` })) : null,
            h('div', { class: 'policy-form update-form' },
                h('label', { class: 'choice' }, agree, h('span', { text: `I agree: both services are rebuilt from ${to} and redeployed, with their settings as they are. Mail keeps being checked meanwhile (about 10 minutes). In Cloud Shell, bash deploy/rollback.sh goes back to the version before.` })),
                h('label', { class: 'project' }, h('span', { text: 'Google Cloud project ID, to confirm' }), project),
                h('label', { class: 'project' }, h('span', { text: 'Your email address (the one you are signed in with), to confirm' }), email),
                d.demo ? h('div', { class: 'small muted', text: 'Demo mode: the project ID is demo-project, and you are signed in as demo-admin@example.org.' }) : null,
                h('div', { class: 'actions' }, go), err));
    }
    // A changelog entry's Markdown, as page elements (text only, never HTML): paragraphs, lists (nested by
    // indentation), tables, code blocks, **bold** and `code`.
    // (0.5.46) Links too: a web address opens in a new tab; a link to one of the docs the Help tab shows opens it
    // there; any other is its text.
    const HELP_FILES = { 'README.md': 'help', 'ALERTS.md': 'helpalerts', 'PRIVACY.md': 'helpprivacy', 'WORKSPACE.md': 'helpworkspace', 'INSTALL.md': 'helpinstall', 'DEPLOY.md': 'helpsettings', 'COSTS.md': 'helpcosts', 'ARCHITECTURE.md': 'helparchitecture' };
    function mdLink(label, href) {
        if (/^https:\/\/[^\s]+$/i.test(href)) return h('a', { href, target: '_blank', rel: 'noopener noreferrer', text: label });
        const file = (/([A-Z]+\.md)(#.*)?$/.exec(href) || [])[1];
        if (file && HELP_FILES[file]) return h('a', { href: `#/${HELP_FILES[file]}`, text: label });
        return document.createTextNode(label);
    }
    // One line's **bold**, `code` and [links](…), as elements; the rest stays text.
    function inlineMd(text) {
        const out = [], re = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)\s]+\))/g;
        let last = 0, m;
        while ((m = re.exec(text))) {
            if (m.index > last) out.push(text.slice(last, m.index));
            if (m[0].startsWith('[')) { const lm = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(m[0]); out.push(mdLink(lm[1], lm[2])); }
            else out.push(m[0].startsWith('**') ? h('b', { text: m[0].slice(2, -2) }) : h('code', { text: m[0].slice(1, -1) }));
            last = re.lastIndex;
        }
        if (last < text.length) out.push(text.slice(last));
        return out;
    }
    // A paragraph's or list item's wrapped lines joined first (0.5.46: **bold** and links can wrap in the docs).
    function joinWrapped(text) {
        const out = [];
        let code = false;
        const block = (l) => /^\s*(```|\||#{1,4}\s|- |\d+\. )/.test(l);
        for (const line of String(text || '').split('\n')) {
            if (/^\s*```/.test(line)) { code = !code; out.push(line); continue; }
            const prev = out.length ? out[out.length - 1] : '';
            if (!code && line.trim() && prev.trim() && !block(line) && !/^\s*(```|\|)/.test(prev) && !/^#{1,4}\s/.test(prev.trim())) { out[out.length - 1] = `${prev} ${line.trim()}`; continue; }
            out.push(line);
        }
        return out;
    }
    function markdown(text) {
        const root = h('div', { class: 'md' }), lines = joinWrapped(text);
        let stack = [], para = null, i = 0;
        const lastLi = () => (stack.length ? stack[stack.length - 1].last : null);
        while (i < lines.length) {
            const line = lines[i], indent = /^ */.exec(line)[0].length;
            if (!line.trim()) { para = null; i++; continue; }
            if (/^\s*```/.test(line)) {
                const code = []; i++;
                while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
                i++; ((indent && lastLi()) || root).append(h('pre', { text: code.join('\n') })); para = null; continue;
            }
            if (/^\s*\|/.test(line)) {
                const rows = [];
                while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(lines[i++]);
                const cells = (l) => l.trim().replace(/^\||\|$/g, '').split('|').map(c => c.trim());
                const body = rows.filter(r => !/^\s*\|[\s:|-]+\|\s*$/.test(r)).map(cells);
                const t = h('table', { class: 'md-table' }, h('thead', {}, h('tr', {}, (body[0] || []).map(c => h('th', {}, inlineMd(c))))),
                    h('tbody', {}, body.slice(1).map(r => h('tr', {}, r.map(c => h('td', {}, inlineMd(c)))))));
                ((indent && lastLi()) || root).append(h('div', { class: 'table-wrap' }, t)); para = null; continue;
            }
            // (0.5.46) headings: #… → h2 to h5 (the page's own h1 is the title)
            const hd = /^(#{1,4})\s+(.*)$/.exec(line);
            if (hd && !indent) { stack = []; para = null; root.append(h(`h${Math.min(5, hd[1].length + 1)}`, { class: 'md-h' }, inlineMd(hd[2]))); i++; continue; }
            const li = /^( *)(- |\d+\. )(.*)$/.exec(line);
            if (li) {
                const ordered = li[2] !== '- ';
                while (stack.length && stack[stack.length - 1].indent > indent) stack.pop();
                let top = stack[stack.length - 1];
                if (top && top.indent === indent && top.ordered !== ordered) { stack.pop(); top = stack[stack.length - 1]; }
                if (!top || top.indent < indent) { const ul = h(ordered ? 'ol' : 'ul'); ((top && top.last) || root).append(ul); top = { indent, ul, last: null, ordered }; stack.push(top); }
                top.last = h('li', {}, inlineMd(li[3])); top.ul.append(top.last); para = null; i++; continue;
            }
            if (indent && lastLi()) { lastLi().append(' ', ...inlineMd(line.trim())); i++; continue; }
            stack = [];
            if (!para) { para = h('p'); root.append(para); para.append(...inlineMd(line.trim())); } else para.append(' ', ...inlineMd(line.trim()));
            i++;
        }
        return root;
    }

    // --- Settings → Policy and Settings → Sender lists: the policy, changed here with the project ID ---------------
    // POLICY_ROWS (the mode, the AI lines and switches, the label, re-checking, the brake, the time zone, how long
    // records are kept) and ALLOW_ROWS (the allowlists). Each Change opens a form under its row; it
    // needs the project ID, and switching to enforce mode the agreement too. Live updates wait while a form
    // is open. deploy/install.sh asks which to keep when settings.env says otherwise (deploy/dashboard-policy.sh).
    const POLICY_ROWS = [
        { key: 'mode', label: 'Mode', show: (v) => (v === 'enforce' ? 'Enforce: emails the policy flags are moved to Spam' : 'Monitor: emails are checked and recorded, nothing is moved') },
        { key: 'aiThreshold', label: 'AI move level', show: (v, d) => (d.aiMovesInside ? `${pct(v)}: an email the AI scores this high or higher is moved on the AI score alone, whatever the rules find, from any sender, inside the organization too ("Let the AI alone move staff email" is on)`
            : `${pct(v)}: an email from outside the organization that the AI scores this high or higher is moved on the AI score alone, whatever the rules find. From inside (your domains, DMARC passing), the AI score alone doesn't move it ("Let the AI alone move staff email" is off): it is recorded as suspicious, and only the rules can move it`) },
        { key: 'aiSuspicious', label: 'AI suspicious line', show: (v) => `${pct(v)}: an email the AI scores this high or higher, but not moved, is recorded as suspicious for review` },
        { key: 'aiScansInside', label: 'AI reads staff email', show: (v, d) => (v || d.aiMovesInside ? `On: the AI also reads mail from inside the organization (your domains, Gmail confirming the sender is real (DMARC))${d.aiMovesInside && !v ? ', because "Let the AI alone move staff email" is on and needs it' : d.aiMovesInside ? '; its score alone can move it ("Let the AI alone move staff email" is on)' : '; its score can make it suspicious, never move it on its own'}`
            : 'Off: mail from inside the organization (your domains, Gmail confirming the sender is real (DMARC)) isn\'t read by the AI. The rule checks read it as any email: its links, its headers and the rest; a forged inside address (DMARC not passing) is outside mail, and the AI reads it') },
        { key: 'aiMovesInside', label: 'Let the AI alone move staff email', show: (v, d) => (v ? `On: an email from inside the organization that the AI scores ${pct(d.aiThreshold)} or more is ${d.mode === 'enforce' ? 'moved to Spam' : 'recorded as "would move" (monitor mode)'} on the AI score alone, as outside mail is, whatever the rules find. The AI reads inside mail for it`
            : 'Off: the AI score alone never moves mail from inside the organization (your domains, Gmail confirming the sender is real (DMARC)); the rules still can (a staff account taken over), and a forged inside address is outside mail') },
        // (0.6.59) Off by default: the signs that move outside mail to Spam without review (policy.js strictWhy).
        { key: 'strictSpam', label: 'Straight to Spam', show: (v) => ((v || []).length ? `On for: ${(v || []).map(k => STRICT_LABELS[k] || k).join('; ')}. Such an email from outside the organization is moved to Spam without review (monitor mode: recorded as "would move"); Trusted senders Gmail confirms and mail from inside never are`
            : 'Off: these signs count with the other checks, and a reviewer decides what isn\'t moved') },
        { key: 'suspiciousLabel', label: 'Suspicious label', show: (v, d) => (v ? `On: an email that is suspicious but not moved gets the label ${d.suspiciousLabelName || 'SPRUCE/Suspicious'} in its mailbox, so its reader sees it (in monitor mode too). Nothing is moved by it`
            : 'Off: suspicious emails that aren\'t moved stay in the Inbox unmarked; only the dashboard lists them (Review)') },
        { key: 'recheck', label: 'Re-check delivered mail', show: (v, d) => (v ? `On: when a phishing list adds a site or sender that an email of the last ${num(d.recheckDays || 7)} days has, every copy still in an Inbox is checked again in full and ${d.mode === 'enforce' ? 'moved to Spam' : 'recorded as "would move" (monitor mode)'} if the checks now say so; suspicious mail is also looked at again an hour and a day after it arrived; so is mail from, replying to or linking to a look-alike of your domain once it is found or marked a threat${d.recheckAfterUpdateHours ? `, and the mail of the last ${num(d.recheckAfterUpdateHours)} hours still in the Inbox after an update that changes how email is checked (not one that only changes the dashboard or wording)` : ''}. Threats → Re-checked lists what was found`
            : 'Off: mail is checked once, when it arrives. Nothing is kept to find it again') },
        { key: 'brakePerHour', label: 'Brake (whole domain)', show: (v, d) => (v ? `${num(v)} moves an hour, then moving stops everywhere until an admin resumes` : `Automatic: ${num(d.brakeLimit)} moves an hour now (half the watched mailboxes, at least 100), then moving stops until an admin resumes`) },
        { key: 'timeZone', label: 'Time zone', show: (v) => `${v || 'UTC'}: the dashboard's days (the charts and daily counts), the weekly summary, and the nightly jobs` },
        { key: 'retentionDays', label: 'Records kept', show: (v) => `${num(v)} days: each email's record is deleted ${num(v)} days after it arrived, the oldest first` }
    ];
    const STRICT_LABELS = { 'dmarc-fail': 'Gmail\'s DMARC check failed', 'dmarc-missing': 'no DMARC policy confirms the sender', 'forged-id': 'a forged message ID', listed: 'the sender or a link is on a list (phishing lists, Spamhaus, abuse.ch, Safe Browsing)' };
    // Each setting's default, and how the page names it when it is in force (0.6.0).
    const POLICY_DEFAULTS = { mode: ['monitor', 'Safe default'], aiMovesInside: [false, 'Safe default'], aiScansInside: [false, 'Default'], suspiciousLabel: [false, 'Default'], recheck: [true, 'Default'], brakePerHour: [0, 'Safe default'] };
    const entries = (l, none) => {
        const list = l || [];
        if (!list.length) return h('div', { text: none });
        // (0.6.36) Every entry is on the page (past the 30th hidden until a search finds it), so Sender lists can search them.
        return h('div', {}, h('ul', { class: 'entries' }, list.map((x, i) => h('li', { text: x, hidden: i >= 30 }))), list.length > 30 ? h('div', { class: 'small muted entries-more', text: `and ${num(list.length - 30)} more (search, or Change, shows them all)` }) : null);
    };
    const ALLOW_ROWS = [
        { key: 'allowDomains', label: 'Domains', show: (v) => entries(v, 'None. Mail from any domain is checked.') },
        { key: 'allowAddresses', label: 'Addresses', show: (v) => entries(v, 'None.') },
        // (0.5.73) Not a sender: link sites a phishing list's listing of the whole domain doesn't flag.
        { key: 'allowLinkDomains', label: 'Link domains', show: (v) => entries(v, 'None. Every phishing list counts for every link.') }
    ];
    const ENV_NAME = { mode: 'MODE', aiThreshold: 'AI_MOVE_THRESHOLD', aiSuspicious: 'AI_SUSPICIOUS_THRESHOLD', aiScansInside: 'AI_SCANS_INSIDE', aiMovesInside: 'AI_MOVES_INSIDE', strictSpam: 'STRICT_SPAM', safeBrowsing: 'SAFE_BROWSING', suspiciousLabel: 'SUSPICIOUS_LABEL', recheck: 'RECHECK', brakePerHour: 'BRAKE_PER_HOUR', timeZone: 'TIME_ZONE', allowDomains: 'ALLOW_DOMAINS', allowAddresses: 'ALLOW_ADDRESSES', allowLinkDomains: 'ALLOW_LINK_DOMAINS', retentionDays: 'RETENTION_DAYS' };
    function policyCard(d, ROWS, title, sub) {
        const P = d.policy || {};
        let openKey = null;
        pageBusy = () => !!openKey;
        const short = (key, v) => (Array.isArray(v) ? (v.length ? `${num(v.length)} entr${v.length === 1 ? 'y' : 'ies'}` : 'none')
            : key === 'strictSpam' ? ((v || []).length ? (v || []).join(', ') : 'off') : key === 'mode' ? v : key === 'aiScansInside' || key === 'aiMovesInside' || key === 'suspiciousLabel' || key === 'recheck' ? (v ? 'on' : 'off') : key === 'aiThreshold' || key === 'aiSuspicious' ? pct(v) : key === 'brakePerHour' ? (v ? `${num(v)} an hour` : 'automatic') : key === 'retentionDays' ? `${num(v)} days` : v);
        const source = (key) => {
            const p = P[key] || {};
            if (p.changed && key === 'allowLinkDomains') return `Changed here by ${p.changed.by}, ${when(p.changed.at)}.`;
            if (p.changed) return `Changed here by ${p.changed.by}, ${when(p.changed.at)}. settings.env (${ENV_NAME[key]}) says ${short(key, p.env)}.`;
            if (p.replaced) return `From settings.env (${ENV_NAME[key]}). It replaced ${short(key, p.replaced.value)}, set here by ${p.replaced.by}.`;
            // (install.sh doesn't pass these: off, or for recheck on, unless changed here or set in the services' environment)
            if (key === 'aiScansInside' || key === 'aiMovesInside' || key === 'suspiciousLabel') return p.env ? `On in the services' environment (${ENV_NAME[key]}).` : `Off: the default (${ENV_NAME[key]}).`;
            if (key === 'strictSpam') return (p.env || []).length ? `From the services' environment (${ENV_NAME[key]}).` : `Off: the default (${ENV_NAME[key]}).`;
            if (key === 'recheck') return p.env ? `On: the default (${ENV_NAME[key]}).` : `Off in the services' environment (${ENV_NAME[key]}=false).`;
            if (key === 'allowLinkDomains') return (p.env || []).length ? `From the services' environment (${ENV_NAME[key]}).` : 'None: the default. Added here.';
            return `From settings.env (${ENV_NAME[key]}).`;
        };
        const buttons = {};
        const rows = ROWS.map(r => {
            const value = (P[r.key] || {}).value !== undefined ? P[r.key].value : d[r.key];
            const slot = h('div', { class: 'policy-form-slot' });
            const button = h('button', { class: 'btn', type: 'button', 'aria-expanded': 'false' }, 'Change');
            button.addEventListener('click', () => {
                for (const el of box.querySelectorAll('.policy-form-slot')) el.textContent = '';
                for (const b of box.querySelectorAll('button[aria-expanded]')) b.setAttribute('aria-expanded', 'false');
                if (openKey === r.key) { openKey = null; return; }
                openKey = r.key; button.setAttribute('aria-expanded', 'true');
                slot.append(policyForm(r.key, value, d, () => { openKey = null; slot.textContent = ''; button.setAttribute('aria-expanded', 'false'); }));
                const first = slot.querySelector('input, select'); if (first) first.focus();
            });
            buttons[r.key] = button;
            // (0.6.0) On or off at a glance, and whether it is the default (the safe one, for the mode, the AI alone and the brake).
            const flag = typeof value === 'boolean' ? h('span', { class: `pol-pill ${value ? 'on' : 'off'}`, text: value ? 'On' : 'Off' }) : null;
            const dflt = Object.prototype.hasOwnProperty.call(POLICY_DEFAULTS, r.key) && POLICY_DEFAULTS[r.key][0] === value ? h('span', { class: 'safe-badge', text: POLICY_DEFAULTS[r.key][1] }) : null;
            return h('div', { class: 'policy-row' },
                h('div', { class: 'policy-head' }, h('div', { class: 'policy-label' }, h('div', { text: r.label }), flag || dflt ? h('div', { class: 'pol-badges' }, flag, dflt) : null),
                    h('div', { class: 'policy-value' }, (() => { const v = r.show(value, d); return v instanceof Node ? v : h('div', { text: v }); })(), h('div', { class: 'small muted', text: source(r.key) })),
                    d.projectKnown ? button : null),
                slot);
        });
        const box = h('section', { class: 'card spaced' }, h('h2', { text: title }),
            h('div', { class: 'sub', text: sub }),
            d.projectKnown ? null : h('div', { class: 'alert warning' }, h('div', { text: 'This dashboard doesn\'t know its Google Cloud project (GOOGLE_CLOUD_PROJECT), so these can\'t be changed here yet. Run bash deploy/install.sh once.' })),
            rows);
        // (0.6.0) The Policy page's mode and AI-line cards open a row's form from above.
        box.openRow = (key, pick) => { const b = buttons[key]; if (!b) return; if (b.getAttribute('aria-expanded') !== 'true') b.click(); b.scrollIntoView({ block: 'center', behavior: 'smooth' });
            // (0.6.39) The card clicked (Settings → Policy, Mode) is already chosen in the form it opens.
            const r = pick !== undefined && box.querySelector(`input[type=radio][value="${pick}"]`);
            if (r && !r.checked) { r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); } };
        return box;
    }
    function policyForm(key, value, d, close) {
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        const save = h('button', { class: 'btn primary', type: 'button' }, 'Save');
        const cancel = h('button', { class: 'btn', type: 'button', onclick: close }, 'Cancel');
        let read = () => value, extra = [], agreeBox = null;
        const update = () => { save.disabled = !project.value.trim() || (agreeBox && !agreeBox.hidden && !agreeBox.querySelector('input').checked); };
        if (key === 'mode') {
            const radio = (v, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'policy-mode', value: v, checked: v === value }), h('span', { text: label }));
            const choices = h('div', { class: 'choices' }, radio('monitor', 'Monitor: record only, move nothing'), radio('enforce', 'Enforce: move what the policy flags to Spam'));
            const ready = h('div', { class: 'small muted' });
            agreeBox = h('div', { class: 'agree', hidden: true },
                h('div', { class: 'alert warning' }, h('div', {}, h('b', { text: 'Enforce mode moves mail. ' }), 'From the moment you save, emails the rules flag, or the AI scores at the threshold or higher, are moved to Spam in every watched mailbox (the brake still apply; emails already recorded as "would move" stay where they are).', ready)),
                h('label', { class: 'choice' }, h('input', { type: 'checkbox', onchange: update }), h('span', { text: 'I agree: I have looked at Health → Readiness, and I want emails moved to Spam from now on.' })));
            const sync = async () => {
                const v = choices.querySelector('input:checked').value;
                agreeBox.hidden = !(v === 'enforce' && value !== 'enforce'); update();
                if (!agreeBox.hidden && !ready.textContent) {
                    try { const { readiness: r } = await api(`/api/readiness?days=${days}`); const ok = r.checks.filter(c => c.ok).length; ready.textContent = ` Readiness: ${ok} of ${r.checks.length} checks pass.`; }
                    catch (e) { ready.textContent = ' (Couldn\'t read Readiness.)'; }
                }
            };
            choices.addEventListener('change', sync);
            read = () => choices.querySelector('input:checked').value;
            extra = [choices, agreeBox, value === 'enforce' ? h('div', { class: 'small muted', text: 'Monitor mode: nothing is moved from then on; emails already moved stay in Spam.' }) : null];
        } else if (key === 'aiThreshold') {
            const floor = Math.max(51, Math.round((d.aiSuspicious || 0.65) * 100));
            const input = h('input', { type: 'number', min: floor, max: 100, step: 1, value: String(Math.round(value * 100)), 'aria-label': 'AI move level in percent', class: 'num-input' });
            read = () => Number(input.value) / 100;
            extra = [h('label', { class: 'inline' }, input, h('span', { text: '%' })), h('div', { class: 'small muted', text: `From the suspicious line (${floor}%) to 100%. Higher moves fewer emails on the AI score alone. Health → Model health shows how often moves on the AI score were undone.` })];
        } else if (key === 'aiSuspicious') {
            const ceiling = Math.round((d.aiThreshold || 0.9) * 100);
            const input = h('input', { type: 'number', min: 50, max: ceiling, step: 1, value: String(Math.round(value * 100)), 'aria-label': 'AI suspicious line in percent', class: 'num-input' });
            read = () => Number(input.value) / 100;
            extra = [h('label', { class: 'inline' }, input, h('span', { text: '%' })), h('div', { class: 'small muted', text: `From 50% to the move threshold (${ceiling}%). Lower records more emails for review (Review), higher fewer; nothing more or less is moved. Below the line, and with a rules score under 3, an email isn't recorded at all.` })];
        } else if (key === 'aiScansInside') {
            const radio = (v, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'policy-inside', value: v ? 'on' : 'off', checked: !!value === v }), h('span', { text: label }));
            const choices = h('div', { class: 'choices' }, radio(false, 'Off: the rule checks alone read inside mail (links, headers, the rest)'), radio(true, 'On: the AI reads inside mail too'));
            read = () => choices.querySelector('input:checked').value === 'on';
            extra = [choices, h('div', { class: 'small muted', text: `Inside: your domains, with Gmail confirming the sender is real (DMARC). On, the AI's score of an inside email is shown and can make it suspicious; ${d.aiMovesInside ? 'and it can move it ("Let the AI alone move staff email" is on). Off has no effect while that is on: it needs the AI to read inside mail' : 'it doesn\'t move it on its own ("Let the AI alone move staff email", below, is off)'}.` })];
        } else if (key === 'aiMovesInside') {
            const radio = (v, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'policy-moves-inside', value: v ? 'on' : 'off', checked: !!value === v }), h('span', { text: label }));
            const choices = h('div', { class: 'choices' }, radio(false, 'Off: only the rules move mail from inside (the cautious default)'), radio(true, `On: the AI score alone (${pct(d.aiThreshold)} or more) moves mail from inside too`));
            agreeBox = h('div', { class: 'agree', hidden: true },
                h('div', { class: 'alert warning' }, h('div', {}, h('b', { text: 'The AI alone would move your colleagues\' email. ' }), `From the moment you save, an email from inside the organization that the AI scores ${pct(d.aiThreshold)} or more is ${d.mode === 'enforce' ? 'moved to Spam' : 'recorded as "would move" (monitor mode: moved once you switch to enforce)'}, even when no rule, link check or other sign agrees. A false alarm by the AI on genuine staff mail (a payroll notice, a password reminder from IT) moves it out of the Inbox. The rules already move inside mail that shows real signs (a staff account taken over). The AI reads inside mail for this.`)),
                h('label', { class: 'choice' }, h('input', { type: 'checkbox', onchange: update }), h('span', { text: 'I agree: let the AI score alone move mail from inside the organization.' })));
            choices.addEventListener('change', () => { agreeBox.hidden = !(choices.querySelector('input:checked').value === 'on' && !value); update(); });
            read = () => choices.querySelector('input:checked').value === 'on';
            extra = [choices, agreeBox, h('div', { class: 'small muted', text: 'Inside: your domains, with Gmail confirming the sender is real (DMARC); a forged staff address is outside mail, and the AI can move it either way. Off by default (AI_MOVES_INSIDE).' })];
        } else if (key === 'strictSpam') {
            // (0.6.59) Each sign on its own; none chosen is off.
            const box = (k, help) => h('label', { class: 'choice' }, h('input', { type: 'checkbox', value: k, checked: (value || []).includes(k) }), h('span', {}, h('b', { text: `${STRICT_LABELS[k][0].toUpperCase()}${STRICT_LABELS[k].slice(1)}.` }), ` ${help}`));
            const choices = h('div', { class: 'choices' },
                box('dmarc-fail', 'The From address is forged, or the sender\'s own mail setup is broken. A mailing list or forwarder that rewrites mail can break it too.'),
                box('dmarc-missing', 'Many small businesses, vendors and parents\' providers have no DMARC policy: this moves all their mail. Try it in monitor mode first.'),
                box('forged-id', 'Its message ID claims a mail program that nothing else in the email shows: written by a bulk sender or a phishing kit.'),
                box('listed', 'A link is blocked or on a phishing list, or the sender is on a list or blocked.'));
            read = () => [...choices.querySelectorAll('input:checked')].map(x => x.value);
            extra = [choices, h('div', { class: 'small muted', text: 'An email from outside with any sign ticked is moved to Spam without review (monitor mode: recorded as "would move"). Trusted senders that Gmail confirms, and mail from inside (your domains, DMARC passing), never are. The brake and a campaign\'s hold still apply. Its reader can take it back out of Spam.' })];
        } else if (key === 'suspiciousLabel') {
            // (0.5.33) Off by default; visible to the email's reader, never moves anything.
            const radio = (v, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'policy-suspicious-label', value: v ? 'on' : 'off', checked: !!value === v }), h('span', { text: label }));
            const choices = h('div', { class: 'choices' }, radio(false, 'Off: suspicious emails stay in the Inbox as they arrived (the default)'), radio(true, `On: they get the label ${d.suspiciousLabelName || 'SPRUCE/Suspicious'}, which their reader sees`));
            read = () => choices.querySelector('input:checked').value === 'on';
            extra = [choices, h('div', { class: 'small muted', text: 'Only emails that are suspicious but not moved (Review → Suspicious, not moved) get it, in monitor mode too; nothing is moved by it. Marking one a false alarm takes the label off. Turning it off labels no more; the ones labeled keep it.' })];
        } else if (key === 'recheck') {
            // (0.5.35) On by default; follows the mode and the brake like any move.
            const radio = (v, label) => h('label', { class: 'choice' }, h('input', { type: 'radio', name: 'policy-recheck', value: v ? 'on' : 'off', checked: !!value === v }), h('span', { text: label }));
            const choices = h('div', { class: 'choices' }, radio(true, 'On: delivered mail is checked again when a phishing list adds one of its sites or senders, when a look-alike of your domain is found or marked a threat, and after an update that changes how email is checked (the default)'), radio(false, 'Off: mail is checked once, when it arrives'));
            read = () => choices.querySelector('input:checked').value === 'on';
            extra = [choices, h('div', { class: 'small muted', text: `Each email left in the Inbox keeps short one-way hashes of its link sites, its sender, and its sender's and Reply-To domains (never readable, never shown) for ${num(d.recheckDays || 7)} days of looking (RECHECK_DAYS): a list's new entry or a look-alike found or marked a threat finds the emails that have it. Suspicious mail is also looked at again an hour and a day after it arrived. After an update that changes how email is checked${d.recheckAfterUpdateHours ? `, the mail of the last ${num(d.recheckAfterUpdateHours)} hours still in the Inbox is checked again, newest first (for IT: RECHECK_AFTER_UPDATE_HOURS); an update that only changes the dashboard, wording or documentation checks nothing again` : ' (turned off: nothing is checked again after updates)'}. A re-check is a full check, with the mode and the brake as on arrival; an email its reader already archived or deleted, or one an admin released or marked, is never moved. Turning it off keeps no more hashes.` })];
        } else if (key === 'brakePerHour') {
            const auto = h('input', { type: 'radio', name: 'policy-brake', value: 'auto', checked: !value });
            const fixed = h('input', { type: 'radio', name: 'policy-brake', value: 'fixed', checked: !!value });
            const n = h('input', { type: 'number', min: 10, max: 100000, step: 1, value: String(value || d.brakeLimit || 100), 'aria-label': 'Moves an hour', class: 'num-input' });
            n.addEventListener('focus', () => { fixed.checked = true; });
            read = () => (auto.checked ? 0 : Number(n.value));
            extra = [h('div', { class: 'choices' }, h('label', { class: 'choice' }, auto, h('span', { text: 'Automatic: half the watched mailboxes, at least 100' })),
                h('label', { class: 'choice inline-choice' }, fixed, h('span', { text: 'A fixed limit:' }), n, h('span', { text: 'moves an hour' }))),
                h('div', { class: 'small muted', text: 'After this many moves in one hour, moving stops everywhere until an admin resumes (Today). Strong evidence still counts toward it.' })];
        } else if (key === 'allowDomains' || key === 'allowAddresses' || key === 'allowLinkDomains') {
            const ta = h('textarea', { rows: 8, spellcheck: 'false', autocapitalize: 'off', 'aria-label': key === 'allowDomains' ? 'Trusted senders: domains, one per line' : key === 'allowLinkDomains' ? 'Allowed link domains, one per line' : 'Trusted senders: addresses, one per line' });
            ta.value = (value || []).join('\n');
            read = () => ta.value;
            extra = [ta, h('div', { class: 'small muted', text: key === 'allowDomains' ? 'One domain per line, for example vendor.example; its subdomains count too. Not your own domains.'
                : key === 'allowLinkDomains' ? 'One link site per line, as narrow as you can (l.vendor.example rather than vendor.example); its subdomains count too. A phishing list\'s listing of its whole domain then doesn\'t flag its links, in anyone\'s mail; a listing of the exact page still does. Not sites where anyone can put up a page, link shorteners or your own domains.'
                : 'One address per line, for example billing@vendor.example. Addresses in your own domains can be added.' })];
        } else if (key === 'retentionDays') {
            const input = h('input', { type: 'number', min: 14, max: 365, step: 1, value: String(value), 'aria-label': 'Days records are kept', class: 'num-input' });
            const note = h('div', { class: 'small muted' });
            const say = () => {
                const n = Math.round(Number(input.value));
                note.textContent = !(n >= 14 && n <= 365) ? 'From 14 to 365 days.'
                    : n < value ? `Records older than ${n} days are deleted over the next hours, the oldest first. They can't be brought back.`
                    : n > value ? `Records saved from now on are kept ${n} days. Those already saved keep their date (${value} days after they arrived).`
                    : 'Each record is deleted on its own date, that many days after its email arrived: the oldest go first, never all at once.';
            };
            input.addEventListener('input', say); say();
            read = () => Number(input.value);
            extra = [h('label', { class: 'inline' }, input, h('span', { text: 'days' })), note,
                h('div', { class: 'small muted', text: 'From 14 to 365. The dashboard shows up to 90 days. Keeping longer costs a little more storage: at 10,000 mailboxes, about $0.50 a month for 35 days and $6–7 for a year (docs/COSTS.md).' })];
        } else if (key === 'timeZone') {
            let zones = [];
            try { zones = Intl.supportedValuesOf('timeZone'); } catch (e) { /* an older browser: typed in */ }
            const input = zones.length ? h('select', { 'aria-label': 'Time zone' }, (zones.includes(value) ? zones : [value, ...zones]).map(z => h('option', { value: z, selected: z === value, text: z })))
                : h('input', { type: 'text', value, 'aria-label': 'Time zone', placeholder: 'America/New_York' });
            read = () => input.value;
            extra = [input, h('div', { class: 'small muted', text: 'The dashboard\'s days and the weekly summary use it at once (days already counted keep the day they were counted on). The nightly jobs move to it the next time deploy/install.sh runs.' })];
        }
        project.addEventListener('input', update); update();
        save.addEventListener('click', async () => {
            err.textContent = ''; save.disabled = true; acting++; busyStart();
            try {
                const out = await api('/api/policy', { method: 'POST', body: { key, value: read(), projectId: project.value, agree: !!(agreeBox && agreeBox.querySelector('input').checked) } });
                toast(out.changed && out.changed.unchanged ? 'That is already the setting: nothing changed.' : 'Changed. It applies everywhere within 30 seconds.');
                if (key === 'retentionDays' && out.changed) { fitRanges(out.changed.value); $('#foot').textContent = $('#foot').textContent.replace(/deleted after \d+ days/, `deleted after ${out.changed.value} days`); }
                close(); render();
            } catch (e) { err.textContent = e.message; update(); }
            finally { acting--; busyEnd(); }
        });
        return h('div', { class: 'policy-form' }, extra,
            h('label', { class: 'project' }, h('span', { text: 'Google Cloud project ID, to confirm' }), project),
            d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}.` }) : null,
            h('div', { class: 'actions' }, save, cancel), err);
    }

    // --- Settings → Retraining: the retraining export (off by default) ----------------------------------
    function trainingSettingCard(d) {
        const g = d.trainingExport || { enabled: false };
        const toggle = h('input', { type: 'checkbox', role: 'switch', checked: !!g.enabled, 'aria-label': 'Allow the retraining export' });
        toggle.addEventListener('change', async () => {
            acting++; busyStart();
            try { await api('/api/training-export/allow', { method: 'POST', body: { enabled: toggle.checked } }); toast(toggle.checked ? 'The retraining export is allowed (Health → Retraining examples).' : 'The retraining export is off.'); render(); }
            catch (e) { toggle.checked = !toggle.checked; toast(`Couldn't change it: ${e.message}`, { error: true }); } finally { acting--; busyEnd(); }
        });
        const facts = g.updatedBy ? `${g.enabled ? 'Allowed' : 'Turned off'} by ${g.updatedBy}, ${when(g.updatedAt)}.` : 'Off: nobody has allowed it.';
        return h('section', { class: 'card spaced' }, h('h2', { text: 'Retraining export' }),
            h('div', { class: 'sub', text: 'Lets dashboard admins download the emails an admin marked, with the people in them taken out, to retrain the AI model (Health → Retraining examples → Download for retraining; docs/RETRAINING.md). Each download reads those emails from Gmail at that moment: the file is the only copy, and Activity notes who downloaded it. Turn it on only while someone is preparing training examples.' }),
            h('label', { class: 'switch' }, toggle, h('span', { text: 'Allow the retraining export' })),
            h('div', { class: 'small muted', text: facts }));
    }

    // The tab's title shows how many things need you (the brake, held campaigns, users who took flagged
    // mail back); the Review item in the menu (and in the phone's tab bar), how many emails wait for review.
    // Read at most every 25 s, from the live updates' tick (paused or not, but not while the person is away) and
    // after an action.
    let pendingAt = 0, unreviewed = 0, suspiciousWaiting = 0, pendingSeen = false, olderWaiting = 0, olderMovedWaiting = 0;
    function showUnreviewed() {
        for (const badge of [$('#reviewCount'), $('#reviewCountTab')]) {
            if (!badge) continue;
            badge.hidden = !unreviewed; badge.textContent = num(unreviewed);
            badge.title = `${num(unreviewed)} email${unreviewed === 1 ? '' : 's'} to review`;
        }
    }
    // (0.6.1) The brake, across the top of every page, for admins and moderators alike, until an admin resumes moving.
    function showBrake(on) {
        const b = $('#brakeBanner');
        if (!b || (b.hidden === !on && b.dataset.role === role)) return;
        b.hidden = !on;
        b.dataset.role = role;
        b.textContent = '';
        if (!on) return;
        b.append(h('span', { class: 'brake-icon', 'aria-hidden': 'true', text: '!' }),
            h('div', { class: 'grow' }, h('b', { text: 'Moving is paused by the brake. ' }),
                'Too many emails were moved within an hour, so emails the checks flag are not being moved to Spam: they stay in the Inbox. ',
                isModerator() ? h('b', { text: 'Contact an administrator.' }) : ['Contact an administrator; an administrator resumes moving on ', h('a', { href: '#/overview', text: 'Today' }), '.']));
    }
    // (0.6.40) New emails to review while Review is open: an empty queue reads them at once (no "Look again"), and a queue
    // being answered gets them added at its end, without moving the email open now.
    async function reviewArrived() {
        const m = /^#\/?review(?:\?(.*))?$/.exec(currentHash());
        if (!m || acting > 0 || popupOpen()) return;
        const queue = queueOf(new URLSearchParams(m[1] || ''));
        if (queue === 'promotional') return;
        const st = reviewStates[queue];
        if (!st || st.days !== days || !st.groups.length) { reviewStates[queue] = null; render({ quiet: true }); return; }
        try {
            const d = await api(`/api/review?${q({ days: String(days), queue })}`);
            const have = new Set(st.groups.flatMap(g => g.keys));
            const fresh = (d.groups || []).filter(g => !g.keys.some(k => have.has(k)));
            st.counts = d.counts || st.counts;
            if (fresh.length && reviewStates[queue] === st && !acting) { st.groups.push(...fresh); render({ quiet: true }); }
        } catch (e) { /* the next tick tries again */ }
    }
    async function refreshPending() {
        if (Date.now() - pendingAt < 25000) return;
        pendingAt = Date.now();
        try {
            const p = await api(`/api/pending?days=${days}`);
            const olderWas = olderWaiting;
            olderWaiting = p.older || 0; olderMovedWaiting = p.olderMoved || 0;
            if (olderWas !== olderWaiting && pendingSeen) reviewArrived();   // (0.6.50) an empty Review says so
            document.title = p.total ? `(${p.total}) S.P.R.U.C.E Mail Protection Service` : 'S.P.R.U.C.E Mail Protection Service';
            const was = unreviewed, wasSusp = suspiciousWaiting;
            unreviewed = p.unreviewed || 0; suspiciousWaiting = p.suspicious || 0;
            showUnreviewed();
            if (pendingSeen && (was !== unreviewed || wasSusp !== suspiciousWaiting)) reviewArrived();
            else if (!pendingSeen && olderWaiting && /^#\/?review/.test(currentHash())) reviewArrived();
            pendingSeen = true;
            showBrake(!!p.brake);
        } catch (e) { /* the next tick tries again */ }
    }

    // "Read the directory again now" (Settings → Mailboxes; "Update group membership now" before 0.5.53): runs the
    // daily re-read of who is checked at once (the spruce-renew-watches job), and says when the directory was last
    // read and whether that reached the service.
    function renewBar(r) {
        if (!r) return null;
        const last = r.last;
        const status = !last ? null
            : last.error ? h('span', { class: 'muted small', text: `Couldn't read when the directory was last read: ${last.error}` })
            : !last.at ? h('span', { class: 'muted small', text: 'The directory hasn\'t been read yet.' })
            : last.code ? h('span', { class: 'renew-bad', text: `Directory last read ${when(last.at)}, but that didn't reach the service (Cloud Scheduler status ${last.code}): no mailbox is watched or checked. docs/INSTALL.md, Troubleshooting, "The jobs and notifications are refused".` })
            : h('span', { class: 'muted small', text: `Directory (who is checked) last read ${when(last.at)}: it reached the service.` });
        const button = r.available ? h('button', { class: 'btn', type: 'button', onclick: async (e) => {
            const b = e.currentTarget;
            b.disabled = true; acting++; busyStart();
            try {
                await api('/api/renew-watches', { method: 'POST', body: {} });
                toast('Asked: the group is read again within a minute. This page updates by itself.');
                setTimeout(() => { if (/mailboxes/.test(currentHash())) render({ quiet: true }); }, 10000);
            } catch (err) { toast(`Couldn't save that: ${err.message}`, { error: true }); b.disabled = false; }
            finally { acting--; busyEnd(); }
        } }, 'Read the directory again now') : null;
        return h('div', { class: 'renew' }, button, status);
    }

    // --- Threats → Re-checked (0.5.35) -----------------------------------------------------------------
    // Emails already delivered and found to be phishing (or suspicious) later: when a phishing list added one
    // of their sites or senders, or on a second look an hour or a day after they arrived. One card per
    // campaign, with every copy: who got it, when, whether they had opened it, a link clicked (Link clicks),
    // and what was done.
    async function rechecked() {
        const d = await api(`/api/rechecked?days=${days}`);
        const cl = d.clickLogs || {};
        const outcomeOf = (c) => {
            if (c.released) return ['Moved back to the Inbox', 'released'];
            if (c.rechecked) return {
                moved: ['Moved to Spam', 'moved'], 'would-move': ['Would be moved (monitor mode)', 'would'],
                held: ['Left in the Inbox (a brake)', 'would'], 'not-in-inbox': [`Had already left the Inbox (${WHERE[c.where] || c.where})`, 'inbox'], flag: ['Suspicious, left in the Inbox', 'flag']
            }[c.outcome] || [c.outcome, ''];
            return c.state === 'moved' ? ['Moved to Spam on arrival', 'moved'] : c.action === 'would-move' ? ['Would move (on arrival)', 'would'] : ['Suspicious on arrival', 'flag'];
        };
        // (0.6.39) Short: the answer, and its time on a line of its own.
        const at = (ms, plain) => h('div', { class: plain ? 'nowrap' : 'small muted nowrap', text: `${dayOf(ms)}, ${new Date(ms).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}` });
        const openedOf = (c) => (c.opened === true ? (c.openedAt ? ['Yes', at(c.openedAt)] : 'Yes') : c.opened === false ? 'No' : c.rechecked ? '–' : 'Not known (moved on arrival)');
        const clickedOf = (c) => (c.clicked === true ? [h('b', { class: 'bad-text', text: 'Yes' }), c.clickedAt ? at(c.clickedAt) : null]
            : c.clicksCheckedAt ? h('span', { title: `Gmail's logs checked ${when(c.clicksCheckedAt)}`, text: 'None found' }) : !c.rechecked ? '–' : cl.on ? 'Not checked yet' : h('a', { href: '#/clicks', text: 'Not checked (Link clicks is off)' }));
        const group = (g) => h('section', { class: `card recheck-group${g.phishing ? ' bad' : ''}` },
            h('div', { class: 'card-head' },
                h('div', {}, h('h2', {}, g.phishing ? alertIcon('Phishing found after delivery') : null, ` ${g.subject || g.label || '(subject not stored)'}`),
                    h('div', { class: 'sub', text: `From ${g.sender && g.sender.name ? `${g.sender.name} <${g.sender.address}>` : (g.sender && g.sender.address) || 'an unknown sender'}` })),
                h('div', { class: 'actions' },
                    !g.seen && !isModerator() ? h('button', { class: 'btn small-btn', type: 'button', onclick: postButton('/api/rechecked/seen', () => ({ campaign: g.campaign }), () => 'Marked as seen: it is off this list until something new is found in it.') }, 'Mark as seen') : null,
                    g.seen ? h('span', { class: 'pill', title: 'It leaves this page 7 days after it was seen.', text: `${g.seenBy === 'answered' ? 'Answered' : 'Seen'} ${dayOf(g.seenAt)} · clears ${dayOf(g.seenAt + 7 * 86400000)}` }) : null,
                    h('a', { href: `#/messages?${q({ campaign: g.campaign })}`, text: 'Open the campaign' }))),
            h('p', { class: 'small' }, h('b', { text: `${g.reasons.join('; ')}. ` }), `First delivered ${when(g.firstReceived)}; re-checked ${when(g.lastRecheck)}.`),
            h('div', { class: 'grid kpis recheck-kpis' },
                kpi('People', num(g.people), `${num(g.rechecked)} re-checked`),
                kpi('Moved to Spam', num(g.moved), !g.moved && d.mode !== 'enforce' ? 'monitor mode: nothing moved' : ''),
                kpi('Opened', num(g.opened), 'before it was moved'),
                kpi('Link clicked', cl.on ? num(g.clicked) : '–', cl.on ? `Gmail's logs, ${num(g.clicksChecked)} checked` : 'Link clicks is off')),
            clickTable([
                { name: 'Recipient', get: c => c.user },
                { name: 'Delivered', get: c => at(c.receivedAt, true), sort: c => c.receivedAt || 0 },
                { name: 'Opened', get: c => openedOf(c) },
                { name: 'Link clicked', get: c => clickedOf(c) },
                { name: 'What happened', get: c => [pill(outcomeOf(c)), c.movedAt ? at(c.movedAt) : null] }
            ], g.copies, c => go(`#/message?${q({ key: c.key })}`), 'No copies.', c => (c.clicked ? 'row-alert' : '')));
        // (0.6.17) Listings marked as seen leave the page (a link shows them again) until something new is found in them.
        // (0.6.43) An answered email counts as seen; a seen listing is gone 7 days later (the service leaves it out).
        const fresh = d.groups.filter(g => !g.seen), seenGroups = d.groups.filter(g => g.seen);
        const seen = fresh.length && !isModerator() ? postButton('/api/rechecked/seen', () => ({}), () => 'Marked as seen: they are off this list, and the banners on Today and Messages are gone, until something new is found.') : null;
        const shown = h('div', {}, fresh.map(group));
        const more = seenGroups.length ? h('button', { class: 'linkbtn', type: 'button', text: `Show the ${num(seenGroups.length)} seen (answered or marked seen; each clears 7 days later)` }) : null;
        if (more) more.addEventListener('click', () => { more.remove(); seenGroups.forEach(g => shown.appendChild(group(g))); });
        return [h('h1', { text: 'Re-checked mail' }),
            h('p', { class: 'sub', text: 'Emails already delivered to an Inbox and found later to be phishing or suspicious: when a phishing list added one of their sites or senders, when the look-alike watch found a domain imitating yours that they came from, reply to or link to (or an admin marked one a threat), after an update that changed how email is checked, or on a second look an hour and a day after they arrived. Each is checked again in full, and moved as it would have been on arrival.' }),
            h('section', { class: 'card' }, h('dl', { class: 'kv' },
                kvRow('Re-checking', d.recheck ? `On (Settings → Policy): emails of the last ${num(d.recheckDays)} days are looked for when a phishing list adds one of their sites or senders, or a look-alike of your domain is found or marked a threat (Threats → Look-alikes); suspicious mail is looked at again an hour and a day after it arrived.` : 'Off (Settings → Policy): mail is checked once, when it arrives.'),
                d.recheck ? kvRow('After updates', d.afterUpdateHours ? `An update that changes how email is checked re-checks the mail of the last ${num(d.afterUpdateHours)} hours still in the Inbox, newest first (at most ${num(d.afterUpdateMax)}); one that only changes the dashboard, wording or documentation re-checks nothing.`
                    + (d.updateSweep ? ` Last: version ${d.updateSweep.version}, ${when(d.updateSweep.startedAt)}: ${num(d.updateSweep.queued)} emails ${d.updateSweep.doneAt ? 'checked again' : 'queued so far, more each hour'}.` : '') : 'Off: updates check nothing again (for IT: RECHECK_AFTER_UPDATE_HOURS is 0).') : null,
                kvRow('Link clicks', h('span', {}, cl.on ? `On: Gmail's logs are read (as ${cl.admin || 'DIRECTORY_ADMIN'}) for who opened each email and clicked a link in it. ` : 'Off: whether each email had been opened comes from Gmail\'s unread mark when it was re-checked; clicks aren\'t known. ', h('a', { href: '#/clicks', text: 'Settings → Link clicks' }))),
                d.queued ? kvRow('Waiting', `${num(d.queued)} emails to be checked again at the next hourly run.`) : null,
                d.seenAt ? kvRow('Last marked seen', when(d.seenAt)) : null),
                seen ? h('div', { class: 'actions' }, h('button', { class: 'btn', type: 'button', onclick: seen }, 'Mark all as seen')) : null),
            fresh.length ? shown : h('section', { class: 'card' }, h('div', { class: 'empty', text: d.groups.length ? 'Nothing new: everything found after delivery has been answered or marked as seen.' : `Nothing was found after delivery in the last ${days} days.` })),
            fresh.length ? null : shown, more ? h('p', {}, more) : null];
    }

    // --- Threats → Look-alikes (0.5.36) -----------------------------------------------------------------
    // Domains made to pass for yours, found by the look-alike watch, and an admin's mark on each.
    const changingLookalikes = new Set();   // (0.5.63) marked domains whose mark is being changed
    async function lookalikes() {
        const d = await api('/api/lookalikes');
        const STATUS = { new: ['New: a strong sign in mail', 'moved'], threat: ['A threat: a strong sign', 'moved'], baseline: ['There before the watch: a small sign', 'would'],
            ours: ['The district\'s own: no sign', 'inbox'], harmless: ['Someone else\'s, harmless: no sign', 'inbox'] };
        // (0.5.63) A domain an admin marked shows a Change button; the choices come back only when it is clicked.
        const mark = (e) => {
            if (e.by && !changingLookalikes.has(e.domain)) {
                return h('button', { class: 'btn', type: 'button', 'aria-label': `Change how ${e.domain} counts`, onclick: () => { changingLookalikes.add(e.domain); render(); } }, 'Change');
            }
            const cancel = e.by ? h('button', { class: 'btn', type: 'button', onclick: () => { changingLookalikes.delete(e.domain); render(); } }, 'Cancel') : null;
            const choices = [['ours', 'It\'s ours'], ['harmless', 'Harmless'], ['threat', 'A threat'], ['watch', 'Watch as found']].filter(([k]) => k !== e.status && !(k === 'watch' && (e.status === 'new' || e.status === 'baseline')));
            const sel = h('select', { 'aria-label': `Mark ${e.domain}` }, choices.map(([k, l]) => h('option', { value: k, text: l })));
            return h('div', { class: 'mark-lookalike' }, sel, confirmForm('Mark', '/api/lookalikes/mark', () => ({ domain: e.domain, status: sel.value }), (o) => { changingLookalikes.delete(e.domain); return `${o.entry.domain}: ${(STATUS[o.entry.status] || [o.entry.status])[0]}.${o.recheck && o.recheck.queued ? ` ${o.recheck.queued} delivered ${o.recheck.queued === 1 ? 'email' : 'emails'} from it, replying to it or linking to it will be checked again within the hour.` : ''}`; }), cancel);
        };
        const pass = !d.on ? 'Off (LOOKALIKE_WATCH=off).' : !d.candidates ? 'Starting: the first names are asked at the next hourly run.'
            : `${num(d.candidates)} look-alike names of ${d.orgDomains.join(', ')} are asked of Cloudflare's public DNS once a day, about 80 an hour. ${d.cursor < d.candidates ? `This pass: ${num(d.cursor)} of ${num(d.candidates)} asked.` : `Last full pass ${when(d.lastPassAt)}.`}${d.baselineDone ? '' : ' The first pass takes stock: what exists already is listed without an alert.'}`;
        const fresh = d.found.filter(e => e.status === 'new' && !e.gone);
        const laState = d.on ? 'on' : 'off';
        return [serviceTitle('Look-alike domains', laState, d.on ? 'Watch is on' : 'Watch is off'),
            h('p', { class: 'sub', text: 'Domains made to pass for yours (a letter left out or swapped, another ending, "-k12" or "schools" added…), found when they are registered: payroll and vendor fraud start with one. Mail from them, replies to them and links to them count as signs.' }),
            fresh.length ? h('div', { class: 'alert critical', role: 'alert' }, alertIcon('Alert'), h('div', { class: 'grow' }, h('b', { text: `${fresh.length === 1 ? 'A new look-alike was' : `${num(fresh.length)} new look-alikes were`} registered: ${fresh.map(e => e.domain).join(', ')}.` }),
                ` Mail from ${fresh.length === 1 ? 'it' : 'them'} is a strong sign. If the district registered ${fresh.length === 1 ? 'it' : 'one'} itself, mark it "It's ours".`)) : null,
            h('section', { class: 'card' }, h('dl', { class: 'kv' },
                kvRow('The watch', pass),
                kvRow('How it counts', 'New (registered since the watch began, or in the last 30 days) or marked a threat: the sender\'s domain 5, the reply address 5, a link 4 (strong evidence). There before the watch: 3, 3, 2. The district\'s own, or harmless: nothing.'),
                kvRow('What is sent', 'Only the look-alike names, to Cloudflare\'s public resolver (cloudflare-dns.com); a registry\'s date for each one found (RDAP). Nothing about any email.'))),
            h('section', { class: 'card' }, h('h2', { text: `Found (${num(d.found.length)})` }),
                d.found.length ? dataTable([
                    { name: 'Domain', get: e => h('span', { class: 'list-name' }, e.status === 'new' && !e.gone ? alertIcon('New') : null, e.domain) },
                    { name: 'Found', get: e => h('span', { class: 'nowrap', text: dayOf(e.first) }), sort: e => e.first || 0 },
                    { name: 'Registered', get: e => (typeof e.ageDays === 'number' ? `${num(e.ageDays)} day${e.ageDays === 1 ? '' : 's'} before` : 'not known'), sort: e => (typeof e.ageDays === 'number' ? e.ageDays : -1) },
                    { name: 'Has', get: e => [e.mx ? 'Mail' : '', e.web ? 'Website' : ''].filter(Boolean).join(', ') || 'Nothing yet' },
                    { name: 'Counts as', get: e => (e.gone ? `Gone (no longer registered, ${when(e.gone)})` : h('div', {}, pill(STATUS[e.status] || [e.status, '']), e.by ? h('div', { class: 'small muted', text: `marked by ${e.by}, ${when(e.at)}` }) : null)) },
                    { name: '', get: e => (e.gone ? null : h('div', { class: 'row-action' }, mark(e))) }
                ], d.found, e => (e.status === 'new' && !e.gone ? 'row-alert' : '')) : h('div', { class: 'empty', text: d.candidates ? 'None of the look-alike names exists.' : 'Nothing asked yet.' })),
            d.demoProjectId ? h('p', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}.` }) : null];
    }

    // --- Settings → Spamhaus, Settings → abuse.ch (0.5.37; optional, off by default) ---------------------
    const OPTIONAL = {
        spamhaus: {
            title: 'Spamhaus', label: 'Spamhaus',
            sub: 'Spamhaus\'s free Data Query Service: its Domain Blocklist (DBL) and Zero Reputation Domains (ZRD), looked up for each email\'s sender domain and link sites. Off by default. It needs a free DQS key from Spamhaus.',
            benefits: [
                ['The Domain Blocklist. ', 'Domains Spamhaus has seen in phishing, malware, botnet control and spam, kept up to date around the clock: a link to a phishing or malware domain is dangerous, and a sender domain on it is strong evidence.'],
                ['Brand-new domains. ', 'Zero Reputation Domains: a domain first seen on the internet in the last 24 hours. Phishing sites are usually that new; a sender or link domain that new is a sign.'],
                ['Hacked real sites. ', 'The DBL marks legitimate domains being abused for phishing or malware right now, which the age and look-alike checks can\'t tell.']],
            costs: (o) => `Costs: none. Spamhaus's free use is for non-commercial small organizations, at most 100,000 lookups a day; the service stops for the day at ${num(o.dailyMax || 90000)} (SPAMHAUS_DAILY_MAX), and each name is looked up once an hour at most (a campaign's copies share it; each costs 2 lookups, DBL and ZRD). Spamhaus works on a "know your client" basis: confirm with them that your district qualifies, with its own key. Each lookup sends the site's name, with the key, to Spamhaus's DNS servers through Google's resolver; nothing else about the email.`,
            steps: [['Ask for a ', ['free Spamhaus Data Query Service account', 'https://www.spamhaus.com/data-access/free-data-query-service/'], ' with the district\'s name and a work address, and read its ', ['fair use policy', 'https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service/'], '. Spamhaus checks who you are before it approves the account.'],
                ['Once approved, sign in to Spamhaus\'s portal and open Blocklists via DNS Query → Datasets and access. Under Access, the Query Key (26 letters and digits) must say Enabled; if there is none, press Generate.'],
                ['Wait up to an hour. A new key takes that long to sync across all of Spamhaus\'s servers; until then some of them refuse it, and Test and save the key (above) may say "Spamhaus refused the lookup: its servers don\'t know this key yet". That is expected: try again later.'],
                ['Copy the key and paste it in Add the key, above, with the Google Cloud project ID; leave "Turn Spamhaus on once the key works" ticked; press Test and save the key. It is tried with Spamhaus first (a lookup of Spamhaus\'s own test entry, dbltest.com; a refusal is asked again a few times, in case one server doesn\'t know the key yet). Only a key that works is saved.'],
                ['The badge beside the title turns green: "Service is on". The Lookups line says when Spamhaus last answered.'],
                ['Paste the key only here: never in email or chat. If it ever was, press Generate in Spamhaus\'s portal for a new one, wait up to an hour, and save the new one here (the old one stops working).']],
            keyNote: 'A new Spamhaus key can take up to an hour to sync across Spamhaus\'s servers. Until then, Test and save may say "Spamhaus refused the lookup: its servers don\'t know this key yet": that is expected. Wait, then try again. A refused lookup is asked again a few times, so a key that has reached some of the servers often works sooner.',
            placeholder: 'DQS key'
        },
        abusech: {
            title: 'abuse.ch', label: 'abuse.ch',
            sub: 'abuse.ch\'s URLhaus (links spreading malware) and ThreatFox (malware sites and control servers), downloaded with your free abuse.ch key and matched like the phishing lists. Off by default.',
            benefits: [
                ['Malware links. ', 'URLhaus lists the links spreading malware right now (fake invoices, "view document" downloads), which the phishing lists mostly don\'t cover.'],
                ['Malware sites. ', 'ThreatFox lists domains and links of malware campaigns reported by security researchers.'],
                ['Delivered mail too. ', 'Like the phishing lists, what a download adds is looked for in mail already delivered (Threats → Re-checked).']],
            costs: () => 'Costs: none (abuse.ch\'s data is free for non-commercial use with a key). The lists are downloaded once a day for the whole district, with the key; nothing about any email is sent to abuse.ch.',
            steps: [['Sign in at ', ['abuse.ch\'s authentication portal', 'https://auth.abuse.ch/'], ' (with a Google, Microsoft, GitHub or LinkedIn account) and copy your Auth-Key from your profile.'],
                ['Paste it below with the project ID: it is tried with abuse.ch first (one small download).']],
            placeholder: 'Auth-Key'
        }
    };
    async function optionalPage(id) {
        const d = await settingsData();
        const def = OPTIONAL[id], o = (d.optional || {})[id] || {}, hl = o.health;
        const link = (text, href) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
        const keyText = o.saved ? `Saved by ${o.saved.by}, ${when(o.saved.at)}. It is kept in Secret Manager and never shown here again.`
            : !o.available ? 'Can\'t be saved here yet: this installation needs bash deploy/upgrade.sh from Cloud Shell once (it sets up Secret Manager for the key).' : 'None saved.';
        const working = !o.on ? 'Off.' : !o.saved ? 'On, but no key is saved.' : hl && !hl.ok ? `${def.label} refused (${when(hl.at)}): ${hl.error}` : hl ? `Working: last answer ${when(hl.at)}.` : 'On: nothing asked yet.';
        const bad = o.on && (!o.saved || (hl && !hl.ok));
        const sw = o.on ? confirmForm('Turn off', '/api/policy', () => ({ key: id, value: false }), () => `${def.label} is off (within 30 seconds everywhere).`)
            : o.saved ? confirmForm('Turn on', '/api/policy', () => ({ key: id, value: true }), () => `${def.label} is on (within 30 seconds everywhere).`) : h('div', { class: 'small muted', text: 'Save a key below first.' });
        const keyInput = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: def.placeholder, 'aria-label': `${def.label} key`, 'data-lpignore': 'true', 'data-1p-ignore': 'true' });
        const turnOn = h('input', { type: 'checkbox', checked: !o.on });
        const project = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const save = h('button', { class: 'btn primary', type: 'button', disabled: true }, o.saved ? 'Test and replace the key' : 'Test and save the key');
        const ready = () => { save.disabled = !keyInput.value.trim() || !project.value.trim(); };
        keyInput.addEventListener('input', ready); project.addEventListener('input', ready);
        save.addEventListener('click', async () => {
            err.textContent = ''; save.disabled = true; acting++; busyStart();
            const apiKey = keyInput.value;
            keyInput.value = '';                                  // (not left in the page)
            try {
                const out = await api('/api/keys/save', { method: 'POST', body: { id, apiKey, projectId: project.value, turnOn: !o.on && turnOn.checked } });
                toast(`${out.tested ? `${def.label} accepted the key. ` : ''}It is saved in Secret Manager${out.turnedOn ? `, and ${def.label} is on` : ''}.`);
                render();
            } catch (e) { err.textContent = e.message; ready(); }
            finally { acting--; busyEnd(); }
        });
        const quota = id === 'spamhaus' && o.quota ? kvRow('Lookups today', `${num(o.quota.today)} of ${num(o.quota.max)} (${o.quota.stopped ? 'stopped for the day: the rest of today\'s mail isn\'t looked up with Spamhaus' : 'the day\'s limit'}).`)
            : id === 'abusech' && (o.lists || []).length ? kvRow('Lists', h('ul', { class: 'plain-list' }, o.lists.map(l => h('li', {}, l.missed ? alertIcon('Missed its download') : null,
                `${l.name}: ${l.off ? 'not used (off)' : l.error ? `last download failed (${l.error})` : l.updated ? `${num(l.count)} entries, downloaded ${when(l.updated)}` : 'not downloaded yet'}`))))
            : null;
        // (abuse.ch: also one of its lists that missed its download)
        const listBad = id === 'abusech' && (o.lists || []).some(l => !l.off && l.missed);
        const optState = !o.on ? 'off' : bad || listBad ? 'bad' : 'on';
        return [serviceTitle(def.title, optState, SERVICE_WORDS[optState]), h('p', { class: 'sub', text: def.sub }),
            bad ? h('div', { class: 'alert critical', role: 'alert' }, alertIcon('Alert'), h('div', { class: 'grow' }, h('b', { text: `${def.label} is on, but it isn't working. ` }), working)) : null,
            h('section', { class: 'card optional-note' }, h('h2', { text: 'Optional: the service works without it' }),
                h('div', { class: 'sub', text: `S.P.R.U.C.E doesn't need ${def.label} to protect your mail: every email still gets the rule checks, the AI model, Cloudflare's check, the phishing lists, the site-age check and the look-alike watch. Turned on, it adds:` }),
                h('ul', { class: 'benefits' }, def.benefits.map(([b, t]) => h('li', {}, h('b', { text: b }), t))),
                h('div', { class: 'small muted', text: def.costs(o) })),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Status' }), h('dl', { class: 'kv' },
                kvRow(def.label, o.on ? 'On' : 'Off'), kvRow('Key', keyText), kvRow('Lookups', working), quota,
                kvRow('Changes', 'Each needs the Google Cloud project ID, applies everywhere within 30 seconds, and is noted in Health → Activity → What admins did. The key refused is an alert: the admins are emailed.')),
                h('div', { class: 'actions' }, sw)),
            o.available ? h('section', { class: 'card spaced' }, h('h2', { text: o.saved ? 'Replace the key' : 'Add the key' }),
                h('div', { class: 'sub', text: `Paste the key. It is tried with ${def.label} first; only a key that works is saved, in Secret Manager. It is never kept in the dashboard's records, shown here again, or written to the logs. Saving a new key destroys the old one.` }),
                def.keyNote ? h('div', { class: 'alert warning key-note', role: 'note' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '⏳' }), h('div', { class: 'grow', text: def.keyNote })) : null,
                h('div', { class: 'policy-form sb-form' },
                    h('label', { class: 'project' }, h('span', { text: 'Key' }), keyInput),
                    o.on ? null : h('label', { class: 'choice' }, turnOn, h('span', { text: `Turn ${def.label} on once the key works` })),
                    h('label', { class: 'project' }, h('span', { text: 'Google Cloud project ID, to confirm' }), project),
                    d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}; any well-formed key is accepted, and nothing is sent anywhere.` }) : null,
                    h('div', { class: 'actions' }, save), err),
                o.saved ? h('div', { class: 'spaced-top' }, h('h3', { text: 'Remove the key' }),
                    h('div', { class: 'small muted', text: `Turns ${def.label} off and destroys every copy of the key in Secret Manager.` }),
                    confirmForm('Remove the key', '/api/keys/remove', () => ({ id }), () => `The key was removed, and ${def.label} is off.`)) : null) : null,
            h('section', { class: 'card spaced' }, h('h2', { text: 'Getting a key' }),
                h('ol', { class: 'steps' }, def.steps.map(parts => h('li', {}, parts.map(x => (Array.isArray(x) ? link(x[0], x[1]) : x))))))];
    }
    const spamhausPage = () => optionalPage('spamhaus');
    const abusechPage = () => optionalPage('abusech');

    // --- Settings → Phishing training (0.5.44) ------------------------------------------------------------
    // Training emails (KnowBe4, Wizer…) let through unchecked: header rules (a secret value and/or the vendor's
    // sending addresses) and the vendor's link domains; with instructions.
    let editingRule = null;   // (0.5.61) the rule being edited (its id), or null
    async function phishTrainingPage() {
        const d = await api('/api/phish-training');
        if (editingRule && !d.rules.some(r => r.id === editingRule)) editingRule = null;
        const on = d.rules.length > 0 || d.domains.length > 0;
        const link = (text, href) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
        const field = (label, input, note) => h('label', { class: 'project' }, h('span', { text: label }), input, note ? h('span', { class: 'small muted', text: note }) : null);
        const projectInput = () => h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'project-id', 'aria-label': 'Google Cloud project ID' });
        // Add a rule.
        const preset = h('select', { 'aria-label': 'Vendor' }, d.presets.map(p => h('option', { value: p.id, text: p.name })));
        const name = h('input', { type: 'text', autocomplete: 'off', placeholder: 'KnowBe4', 'aria-label': 'Name' });
        const header = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'X-KB4TOKEN', 'aria-label': 'Header' });
        const value = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: 'the vendor\'s secret token', 'aria-label': 'Secret value', 'data-lpignore': 'true', 'data-1p-ignore': 'true' });
        const ips = h('textarea', { rows: 3, spellcheck: 'false', placeholder: '192.0.2.10\n198.51.100.0/26', 'aria-label': 'Sending addresses' });
        const hint = h('div', { class: 'small muted' });
        const usePreset = () => { const p = d.presets.find(x => x.id === preset.value) || {}; header.value = p.header || ''; name.value = p.id === 'custom' ? '' : p.name.replace(/ \(.*$/, ''); hint.textContent = p.help || ''; };
        preset.addEventListener('change', usePreset); usePreset();
        const project = projectInput();
        const err = h('div', { class: 'policy-error', role: 'alert' });
        const add = h('button', { class: 'btn primary', type: 'button' }, 'Add the rule');
        add.addEventListener('click', async () => {
            err.textContent = ''; add.disabled = true; acting++; busyStart();
            const secret = value.value; value.value = '';            // (not left in the page)
            try { await api('/api/phish-training/rule', { method: 'POST', body: { name: name.value, header: header.value, value: secret, ips: ips.value, projectId: project.value } }); toast('Rule added: emails it matches are let through unchecked (within a minute everywhere).'); render(); }
            catch (e) { err.textContent = e.message; }
            finally { add.disabled = false; acting--; busyEnd(); }
        });
        // (0.5.61) Edit a rule: its fields filled in; the secret value is kept unless a new one is typed or it is removed.
        const editing = d.rules.find(r => r.id === editingRule) || null;
        let editForm = null, editBusy = () => false;
        if (editing) {
            const eName = h('input', { type: 'text', autocomplete: 'off', value: editing.name, 'aria-label': 'Name' });
            const eHeader = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', value: editing.header, 'aria-label': 'Header' });
            const eValue = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: editing.hasValue ? 'unchanged (hidden): type a new one to replace it' : 'none: type one to add it', 'aria-label': 'Secret value', 'data-lpignore': 'true', 'data-1p-ignore': 'true' });
            const eClear = h('input', { type: 'checkbox', 'aria-label': 'Remove the secret value' });
            const eIps = h('textarea', { rows: 3, spellcheck: 'false', 'aria-label': 'Sending addresses' });
            eIps.value = editing.ips.join('\n');
            const eProject = projectInput();
            const eErr = h('div', { class: 'policy-error', role: 'alert' });
            const save = h('button', { class: 'btn primary', type: 'button' }, 'Save the rule');
            const cancel = h('button', { class: 'btn', type: 'button', onclick: () => { editingRule = null; render(); } }, 'Cancel');
            save.addEventListener('click', async () => {
                eErr.textContent = ''; save.disabled = true; acting++; busyStart();
                const secret = eValue.value; eValue.value = '';           // (not left in the page)
                try {
                    await api('/api/phish-training/rule/edit', { method: 'POST', body: { id: editing.id, name: eName.value, header: eHeader.value, value: secret, clearValue: eClear.checked, ips: eIps.value, projectId: eProject.value } });
                    editingRule = null; toast('Rule saved (within a minute everywhere).'); render();
                } catch (e) { eErr.textContent = e.message; }
                finally { save.disabled = false; acting--; busyEnd(); }
            });
            editBusy = () => !!(eValue.value || eProject.value || eName.value !== editing.name || eHeader.value !== editing.header || eIps.value !== editing.ips.join('\n') || eClear.checked);
            editForm = h('div', { class: 'policy-form sb-form', id: 'edit-rule' },
                field('Name (for the counts and Activity)', eName), field('Header', eHeader),
                field('Secret value', eValue, editing.hasValue ? 'Kept as it is unless you type a new one. With a new header it has to be typed again: it is kept only as a one-way hash of both.' : 'The token or custom value the vendor puts in that header.'),
                editing.hasValue ? h('label', { class: 'small' }, eClear, ' Remove the secret value (then the sending addresses are needed)') : null,
                field('Sending addresses (one per line; ranges allowed)', eIps, 'Gmail must have received the email from one of these. Leave empty if the vendor puts emails in the mailboxes directly: then a secret value is needed.'),
                field('Google Cloud project ID, to confirm', eProject),
                d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}.` }) : null,
                h('div', { class: 'actions' }, save, cancel), eErr);
        }
        // The link domains.
        const domains = h('textarea', { rows: 6, spellcheck: 'false', placeholder: 'phish-vendor-domain.example\nanother-training-domain.example', 'aria-label': 'Training link domains' });
        domains.value = d.domains.join('\n');
        const project2 = projectInput();
        const err2 = h('div', { class: 'policy-error', role: 'alert' });
        const saveDomains = h('button', { class: 'btn primary', type: 'button' }, 'Save the domains');
        saveDomains.addEventListener('click', async () => {
            err2.textContent = ''; saveDomains.disabled = true; acting++; busyStart();
            try { await api('/api/phish-training/domains', { method: 'POST', body: { domains: domains.value, projectId: project2.value } }); toast('Saved: an email whose links all go to these domains is let through unchecked.'); render(); }
            catch (e) { err2.textContent = e.message; }
            finally { saveDomains.disabled = false; acting--; busyEnd(); }
        });
        pageBusy = () => !!(value.value || ips.value || project.value || project2.value || domains.value !== d.domains.join('\n') || editBusy());
        const seen = (n) => (d.seen[n] ? when(d.seen[n]) : 'not yet');
        return [serviceTitle('Phishing training', on ? 'info' : 'off', on ? 'On: training emails are let through' : 'Off: training emails are checked like any email'),
            h('p', { class: 'sub', text: 'Your phishing-training service\'s test emails (KnowBe4, Wizer and the like) are let through: not checked, not moved, not recorded, only counted, so a training test measures whether people spot phishing without help. Off until you add a rule or domains.' }),
            h('section', { class: 'card' }, h('dl', { class: 'kv' },
                kvRow('Let through', `${num(d.today)} today, ${num(d.week)} in the last 7 days.`),
                kvRow('Recognized by', on ? `${num(d.rules.length)} header rule${d.rules.length === 1 ? '' : 's'}, ${num(d.domains.length)} link domain${d.domains.length === 1 ? '' : 's'}.` : 'Nothing yet.'),
                d.by ? kvRow('Last changed', `By ${d.by}, ${when(d.at)}. Changes are noted in Health → Activity → What admins did.`) : null)),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Header rules' }),
                h('div', { class: 'sub', text: 'The vendor adds a header to its training emails. A header name alone is public, so a real phishing email could copy it: each rule also needs the vendor\'s secret token (or your own custom header\'s value), or the vendor\'s sending addresses, or both. A secret value is kept only as a one-way hash and never shown again.' }),
                d.rules.length ? dataTable([
                    { name: 'Name', get: r => r.name }, { name: 'Header', get: r => h('code', { text: r.header }) },
                    { name: 'Secret value', get: r => (r.hasValue ? 'set (hidden)' : 'none') },
                    { name: 'Sending addresses', get: r => (r.ips.length ? r.ips.slice(0, 3).join(', ') + (r.ips.length > 3 ? ` +${r.ips.length - 3}` : '') : 'any (direct injection works)') },
                    { name: 'Last matched', get: r => {
                        // (0.6.32) Its header seen in an email the rule didn't match, and why: an address the rule doesn't list, say.
                        const miss = (d.missed || {})[r.id];
                        return miss ? h('div', {}, seen(r.name), h('div', { class: 'small training-miss' }, alertIcon('Header seen, not matched'),
                            ` Header seen ${num(miss.count)} time${miss.count === 1 ? '' : 's'} without a match (last ${when(miss.last)}): ${miss.why}. ${miss.ip && /sending addresses/.test(miss.why) ? `If ${miss.ip} is the vendor's, add it to the rule (Edit).` : 'Check the rule (Edit).'}`)) : seen(r.name);
                    } },
                    { name: '', get: r => h('div', { class: 'actions' },
                        h('button', { class: 'btn', type: 'button', 'aria-label': `Edit the rule ${r.name}`, onclick: () => { editingRule = r.id; render(); } }, 'Edit'),
                        confirmForm('Remove', '/api/phish-training/rule/remove', () => ({ id: r.id }), () => `Rule "${r.name}" removed.`)) }], d.rules) : h('div', { class: 'empty', text: 'No rule yet.' }),
                editForm ? h('h3', { text: `Edit the rule "${editing.name}"` }) : null, editForm,
                h('h3', { text: 'Add a rule' }),
                h('div', { class: 'policy-form sb-form' },
                    field('Vendor', preset), hint, field('Name (for the counts and Activity)', name), field('Header', header),
                    field('Secret value', value, 'The token or custom value the vendor puts in that header. Leave empty only if you give sending addresses.'),
                    field('Sending addresses (one per line; ranges allowed)', ips, 'Gmail must have received the email from one of these. Leave empty if the vendor puts emails in the mailboxes directly (KnowBe4 DMI, Wizer DED): then use the secret value.'),
                    field('Google Cloud project ID, to confirm', project),
                    d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}.` }) : null,
                    h('div', { class: 'actions' }, add), err)),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Training link domains' }),
                h('div', { class: 'sub', text: 'An email is a training email when it has links and every one of them goes to these domains or their subdomains (a security gateway\'s rewrite unwrapped first). One link anywhere else and it is checked as usual, so a phishing email can\'t hide behind a training link. Root domains, one per line. Shared platforms, link shorteners, personal email and well-known companies\' domains are refused: anyone can host pages there.' }),
                h('div', { class: 'policy-form sb-form' }, domains, field('Google Cloud project ID, to confirm', project2), h('div', { class: 'actions' }, saveDomains), err2)),
            h('section', { class: 'card spaced' }, h('h2', { text: 'How to set it up' }),
                h('ol', { class: 'steps' },
                    h('li', {}, h('b', { text: 'Use both identifiers when you can. ' }), 'A header rule with a secret value catches every training email, also those without links; the link domains keep working if the vendor changes its header.'),
                    h('li', {}, h('b', { text: 'KnowBe4: ' }), 'in KSAT, Account Settings → Phishing, turn on ', h('b', { text: 'Enable PST Header Token' }), ' (or Add Custom Header) and copy it; choose "KnowBe4 (PST header token)" above and paste it as the secret value. Copy the root domains from ', h('b', { text: 'Phishing → Domains' }), ' into the link domains. KnowBe4 adds new domains hidden: list each before you show it. ', link('KnowBe4: Account Settings, Phishing', 'https://support.knowbe4.com/hc/en-us/articles/12732930359699-KnowBe4-Console-Account-Settings-Phishing'), ' · ', link('Manage Phish Link Domains', 'https://support.knowbe4.com/hc/en-us/articles/360061705153-Manage-Phish-Link-Domains'), '.'),
                    h('li', {}, h('b', { text: 'Wizer: ' }), 'its header (X-TestPhish) is public: choose "Wizer" above and paste its sending addresses, and copy all its phishing domains into the link domains. With Direct Email Delivery, skip the header rule and rely on the domains. ', link('Wizer IPs and domains', 'https://learn.wizer-training.com/knowledge/wizer-ips-and-domains'), '.'),
                    h('li', {}, h('b', { text: 'Another vendor: ' }), 'its Google Workspace allow-listing guide names the header (use a secret value if it offers one), its sending addresses and its phishing domains.'),
                    h('li', {}, h('b', { text: 'Gmail too: ' }), 'this setting only keeps S.P.R.U.C.E from checking training emails. Gmail\'s own filters need the vendor\'s allow-listing as well (its Google Workspace guide: a content compliance rule on the header, or its addresses in the inbound gateway or allowlist).'),
                    h('li', {}, h('b', { text: 'Test: ' }), 'send a training test to yourself. The count above goes up, and Mail → Messages shows nothing for it. Mail → Check an email says so for a pasted training email.'),
                    h('li', {}, h('b', { text: 'Tell your staff ' }), 'that training emails get no help from S.P.R.U.C.E: that is the point of the test. Keep the secret token private; if it leaks, make a new one in the vendor\'s console and replace the rule.')))];
    }

    // --- Settings → Link clicks (0.5.35; optional, off by default) ---------------------------------------
    async function clicksPage() {
        const d = await api('/api/clicks');
        const cl = d.clickLogs || {}, hl = d.health, t = d.test;
        // (0.6.62) Always DIRECTORY_ADMIN (deploy/settings.env): the account the service already acts as.
        const reader = d.directoryAdmin || '';
        const testOut = h('div', { class: 'small', role: 'status' });
        const testBtn = h('button', { class: 'btn', type: 'button' }, 'Test');
        testBtn.addEventListener('click', async () => {
            testBtn.disabled = true; testOut.textContent = 'Reading the last day of this admin\'s own Gmail log…';
            try {
                const o = await api('/api/clicks/test', { method: 'POST', body: {} });
                if (!o.ok && o.why) { testOut.textContent = ''; testOut.append(h('b', { class: 'bad-text', text: `${o.why} ` }), h('span', { text: o.fix || '' })); return; }
                testOut.textContent = !o.ok ? `Google refused: ${o.error}` : !o.events ? 'Google answered, with no events for the last day (no mail read, or this edition has no Gmail logs in the Reports API).'
                    : o.named ? `Working: ${num(o.events)} events in the last day, ${num(o.named)} naming their email. Clicks can be matched to emails.` : `Google answered with ${num(o.events)} events, but none names its email: clicks can't be matched to emails in this domain.`;
            } catch (e) { testOut.textContent = `Couldn't test: ${e.message}`; }
            finally { testBtn.disabled = false; }
        });
        const status = !cl.on ? 'Off' : hl && !hl.ok ? `On, but Gmail's logs couldn't be read (${when(hl.at)}): ${hl.error}` : hl ? `On: last read ${when(hl.at)} (${num(hl.checked)} emails).` : 'On: nothing to read yet (no re-checked mail).';
        const sw = cl.on ? confirmForm('Turn off', '/api/clicks', () => ({ on: false }), () => 'Link clicks is off: Gmail\'s logs are no longer read.')
            : confirmForm('Turn on', '/api/clicks', () => ({ on: true }), () => 'Link clicks is on: Gmail\'s logs are read for the re-checked mail.', h('div', { class: 'small muted', text: `Gmail's logs are read as ${reader || 'DIRECTORY_ADMIN'} (DIRECTORY_ADMIN in deploy/settings.env).` }));
        const clState = !cl.on ? 'off' : hl && !hl.ok ? 'bad' : 'on';
        return [serviceTitle('Link clicks', clState, SERVICE_WORDS[clState]),
            h('p', { class: 'sub', text: 'Who opened an email found to be phishing after it was delivered, and who clicked a link in it, from Gmail\'s own logs. Off by default.' }),
            (cl.on && hl && !hl.ok) ? h('div', { class: 'alert critical', role: 'alert' }, alertIcon('Alert'), h('div', { class: 'grow' }, h('b', { text: 'Link clicks is on, but Gmail\'s logs can\'t be read. ' }), hl.error)) : null,
            h('section', { class: 'card optional-note' }, h('h2', { text: 'Optional: the service works without it' }),
                h('div', { class: 'sub', text: 'Re-checking delivered mail doesn\'t need it. Without it, Threats → Re-checked still lists who got each email and whether it had been opened (Gmail\'s unread mark when it was re-checked). Turned on, it adds, for each re-checked email:' }),
                h('ul', { class: 'benefits' },
                    h('li', {}, h('b', { text: 'A link clicked. ' }), 'Whether each person clicked a link in it (or in an attachment\'s preview), and when: the people whose password may have been given away. A click found is an alert: the admins are emailed.'),
                    h('li', {}, h('b', { text: 'When it was opened. ' }), 'The time each person first opened it, not only whether it was read.')),
                h('div', { class: 'small muted', text: 'Gmail\'s logs can take a few hours to show a click: each email is looked at again every 3 hours, 4 times. Nothing is sent outside Google; only the re-checked emails\' own events are kept on their records.' })),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Status' }), h('dl', { class: 'kv' },
                kvRow('Link clicks', status),
                kvRow('Logs read as', reader ? `${reader} (DIRECTORY_ADMIN in deploy/settings.env, the account the service acts as for the directory)` : 'DIRECTORY_ADMIN isn\'t set in deploy/settings.env'),
                t ? kvRow('Last test', t.ok ? `${when(t.at)} by ${t.by}: ${num(t.events)} events, ${num(t.named)} naming their email.` : `${when(t.at)} by ${t.by}: refused (${t.error}).`) : null,
                cl.by ? kvRow('Changed', `${cl.on ? 'Turned on' : 'Turned off'} by ${cl.by}, ${when(cl.at)}.`) : null),
                h('div', { class: 'policy-form sb-form' },
                    h('div', { class: 'actions' }, testBtn), testOut,
                    d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}; made-up logs are read.` }) : null),
                h('div', { class: 'actions' }, sw)),
            h('section', { class: 'card spaced' }, h('h2', { text: 'What it needs' }),
                h('ol', { class: 'steps' },
                    h('li', {}, h('b', { text: 'A Google Workspace edition with Gmail logs in the Reports API ' }), '(Gmail log events, not in every edition). To check: Admin console → Reporting → Audit and investigation → Gmail log events; if it is there and shows events, the logs exist. The Test button above says what Google answers.'),
                    h('li', {}, h('b', { text: 'One more scope on the service\'s domain-wide delegation: ' }), h('code', { text: 'https://www.googleapis.com/auth/admin.reports.audit.readonly' }), '. Admin console → Security → Access and data control → API controls → Manage Domain Wide Delegation → the service\'s client ID → Edit, add it to the line, Authorize (docs/INSTALL.md, "Link clicks").'),
                    h('li', {}, h('b', { text: 'The Reports privilege on the directory admin\'s role: ' }), `Admin console → Account → Admin roles → SPRUCE group reader (the role ${reader || 'DIRECTORY_ADMIN'} has) → Privileges → Admin console privileges → tick Reports → Save. The service reads the logs with it; nothing is changed.`),
                    h('li', {}, 'Test, then Turn on (with the project ID). Changes are noted in Health → Activity → What admins did.')))];
    }

    // (0.6.60) Settings → User reports (off by default): Gmail's own "Report phishing" reports, read from Google's Alert
    // Center as an admin, go to Review → Reported.
    async function userReportsPage() {
        const d = await api('/api/user-reports');
        const ur = d.userReports || {}, hl = d.health, t = d.test;
        // (0.6.62) Always DIRECTORY_ADMIN (deploy/settings.env): the account the service already acts as.
        const reader = d.directoryAdmin || '';
        const testOut = h('div', { class: 'small', role: 'status' });
        const testBtn = h('button', { class: 'btn', type: 'button' }, 'Test');
        testBtn.addEventListener('click', async () => {
            testBtn.disabled = true; testOut.textContent = 'Reading the last 7 days of "User reported phishing" alerts…';
            try {
                const o = await api('/api/user-reports/test', { method: 'POST', body: {} });
                if (!o.ok && o.why) { testOut.textContent = ''; testOut.append(h('b', { class: 'bad-text', text: `${o.why} ` }), h('span', { text: o.fix || '' })); return; }
                testOut.textContent = !o.ok ? `Google refused: ${o.error}` : o.alerts ? `Working: ${num(o.alerts)} "User reported phishing" alert${o.alerts === 1 ? '' : 's'} in the last 7 days, naming ${num(o.emails)} email${o.emails === 1 ? '' : 's'}.` : 'Working: Google answered, with no "User reported phishing" alerts in the last 7 days.';
            } catch (e) { testOut.textContent = `Couldn't test: ${e.message}`; }
            finally { testBtn.disabled = false; }
        });
        const f = (hl && hl.found) || {};
        const status = !ur.on ? 'Off' : hl && !hl.ok ? `On, but the Alert Center couldn't be read (${when(hl.at)}): ${hl.error}` : hl ? `On: last read ${when(hl.at)}: ${num(hl.alerts)} new alert${hl.alerts === 1 ? '' : 's'}, ${num((f.added || 0) + (f.marked || 0))} email${(f.added || 0) + (f.marked || 0) === 1 ? '' : 's'} put in Review → Reported${f.notWatched ? ` (${num(f.notWatched)} in mailboxes the service doesn't check)` : ''}${f.notFound ? ` (${num(f.notFound)} no longer in the mailbox)` : ''}.` : 'On: read at the next hourly run.';
        const sw = ur.on ? confirmForm('Turn off', '/api/user-reports', () => ({ on: false }), () => 'User reports is off: the Alert Center is no longer read.')
            : confirmForm('Turn on', '/api/user-reports', () => ({ on: true }), () => 'User reports is on: reports are read every hour (the last day\'s too) into Review → Reported.', h('div', { class: 'small muted', text: `The Alert Center is read as ${reader || 'DIRECTORY_ADMIN'} (DIRECTORY_ADMIN in deploy/settings.env). Nothing is moved or changed there.` }));
        const urState = !ur.on ? 'off' : hl && !hl.ok ? 'bad' : 'on';
        return [serviceTitle('User reports', urState, SERVICE_WORDS[urState]),
            h('p', { class: 'sub', text: 'When someone clicks Gmail\'s own "Report phishing" on an email, it goes to Review → Reported, so an admin sees what people report. Off by default.' }),
            (ur.on && hl && !hl.ok) ? h('div', { class: 'alert critical', role: 'alert' }, alertIcon('Alert'), h('div', { class: 'grow' }, h('b', { text: 'User reports is on, but the Alert Center can\'t be read. ' }), hl.error)) : null,
            h('section', { class: 'card optional-note' }, h('h2', { text: 'How it works' }),
                h('ul', { class: 'benefits' },
                    h('li', {}, h('b', { text: 'No new button. ' }), 'People use the "Report phishing" Gmail already has (the ⋮ menu of an open email). Gmail moves the email to their Spam folder and tells Google, as always.'),
                    h('li', {}, h('b', { text: 'Every report, reviewed. ' }), 'Google raises a "User reported phishing" alert in its Alert Center. Every hour the service reads the new ones and puts each reported email of a mailbox it checks in Review → Reported, with what the checks made of it (an email the checks had let through is read and checked again, and recorded).'),
                    h('li', {}, h('b', { text: 'Your answer counts as usual. ' }), 'Phishing or Spam confirms it and trains the AI; Mark safe records a false report. Nothing is moved by a report or its answer: Gmail already moved it.')),
                h('div', { class: 'small muted', text: 'The Alert Center can take a few minutes to raise an alert, and the service reads it at the next hourly run. Only the reported emails\' Message-IDs and recipients are read from the alerts.' })),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Status' }), h('dl', { class: 'kv' },
                kvRow('User reports', status),
                kvRow('Read as', reader ? `${reader} (DIRECTORY_ADMIN in deploy/settings.env, the account the service acts as for the directory)` : 'DIRECTORY_ADMIN isn\'t set in deploy/settings.env'),
                t ? kvRow('Last test', t.ok ? `${when(t.at)} by ${t.by}: ${num(t.alerts)} alerts in 7 days, ${num(t.emails)} emails.` : `${when(t.at)} by ${t.by}: refused (${t.error}).`) : null,
                ur.by ? kvRow('Changed', `${ur.on ? 'Turned on' : 'Turned off'} by ${ur.by}, ${when(ur.at)}.`) : null),
                h('div', { class: 'policy-form sb-form' },
                    h('div', { class: 'actions' }, testBtn), testOut,
                    d.demoProjectId ? h('div', { class: 'small muted', text: `Demo mode: the project ID is ${d.demoProjectId}; nothing is read from Google.` }) : null),
                h('div', { class: 'actions' }, sw)),
            h('section', { class: 'card spaced' }, h('h2', { text: 'What it needs' }),
                h('ol', { class: 'steps' },
                    h('li', {}, h('b', { text: 'The Alert Center API turned on in the service\'s project: ' }), 'deploy/install.sh does it (version 0.6.60 or later). Settings → Update can\'t, so run install.sh once from Cloud Shell.'),
                    h('li', {}, h('b', { text: 'One more scope on the service\'s domain-wide delegation: ' }), h('code', { text: 'https://www.googleapis.com/auth/apps.alerts' }), '. Admin console → Security → Access and data control → API controls → Manage Domain Wide Delegation → the service\'s client ID → Edit: add it to the line, then Authorize.'),
                    h('li', {}, h('b', { text: 'The Alert Center privilege on the directory admin\'s role: ' }), `Admin console → Account → Admin roles → SPRUCE group reader (the role ${reader || 'DIRECTORY_ADMIN'} has) → Privileges → Admin console privileges → Security → Alert Center → tick View access → Save. The service reads the alerts with it, and changes nothing there.`),
                    h('li', {}, 'Test, then Turn on (with the project ID). Changes are noted in Health → Activity → What admins did.')))];
    }

    // --- Help (0.5.46) -------------------------------------------------------------------------------------
    // The installed version's own docs (the server reads them from the image: /api/help), and About & credits.
    async function helpDocPage(id) {
        const d = await api(`/api/help?doc=${encodeURIComponent(id)}`);
        return [h('h1', { text: d.title }),
            h('p', { class: 'sub' }, `This version's own ${d.source}. `, h('a', { href: '#/help', text: 'How it works' }), ' · ', h('a', { href: '#/helparchitecture', text: 'Architecture deep dive' }), ' · ', h('a', { href: '#/credits', text: 'About & credits' })),
            h('section', { class: 'card help-doc' }, markdown(d.markdown))];
    }
    const DONATE_URL = 'https://www.paypal.com/donate/?hosted_button_id=NA8SK5RBLWGW6';
    async function creditsPage() {
        const d = await api('/api/session');
        const link = (text, href) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text });
        const item = (name, href, what) => h('li', {}, link(name, href), ` ${what}`);
        return [h('h1', { text: 'About & credits' }),
            h('section', { class: 'card' },
                h('p', {}, h('b', { text: 'S.P.R.U.C.E Mail Protection Service' }), ` for Google Workspace · version ${d.version}. The checks and the AI model (${d.model.name} ${d.model.version}) come from the S.P.R.U.C.E+ browser extension (Spam & Phishing Risk URL Checker Extension+).`),
                h('p', { class: 'credits' },
                    h('b', { text: 'Lead developer & author: ' }), 'the S.P.R.U.C.E+ project (', link('thecodewarrior2', 'https://github.com/thecodewarrior2'), ')', h('br'),
                    h('b', { text: 'Design, code, review and security hardening of the service: ' }), 'Claude (Anthropic)', h('br'),
                    h('b', { text: 'The extension it grew from: ' }), 'AI assisted with Google Gemini; reviewed and redesigned with Claude (Anthropic); inspired by ', link('Trocker', 'https://github.com/trockerapp/trocker'), ' and the open-source privacy community.'),
                h('p', { class: 'small muted', text: 'Provided as is, as a best-effort layer of protection, without any warranty. It works with your Google Workspace\'s own email security and your people\'s care, never instead of them.' }),
                d.donateButton !== false ? h('p', { class: 'donate-row' }, link('♥ Donate', DONATE_URL), h('span', { class: 'small muted', text: ' S.P.R.U.C.E is free, with no ads and no tracking. Donations support its development.' })) : null),
            h('section', { class: 'card spaced' }, h('h2', { text: 'Built on' }),
                h('p', { class: 'small muted', text: 'Open-source libraries, used under their licenses (each package\'s own license file):' }),
                h('ul', { class: 'plain-list' },
                    item('ONNX Runtime', 'https://onnxruntime.ai', '(MIT): runs the AI model.'),
                    item('pdf.js', 'https://mozilla.github.io/pdf.js/', 'by Mozilla (Apache-2.0): PDF attachments.'),
                    item('jsQR', 'https://github.com/cozmo/jsQR', '(Apache-2.0), pngjs (MIT) and jpeg-js (BSD-3-Clause): QR codes in pictures.'),
                    item('fflate', 'https://github.com/101arrowz/fflate', '(MIT): Office files and archives.'),
                    item('mailparser', 'https://github.com/nodemailer/mailparser', '(MIT) and htmlparser2 (MIT): reading emails and web pages.'),
                    item('Google Cloud client libraries', 'https://github.com/googleapis/google-cloud-node', '(Apache-2.0): Firestore and Google sign-in.')),
                h('p', { class: 'small muted', text: 'Data, used under their publishers\' terms (Settings → About shows each list\'s state):' }),
                h('ul', { class: 'plain-list' },
                    item('OpenPhish', 'https://openphish.com', 'community phishing feed (OpenPhish Terms of Use).'),
                    item('Phishing Army', 'https://phishing.army', 'blocklist (CC BY-NC 4.0).'),
                    item('HaGeZi DNS Blocklists', 'https://github.com/hagezi/dns-blocklists', 'Threat Intelligence Feeds (GPL-3.0; used, not redistributed).'),
                    item('TweetFeed', 'https://tweetfeed.live', 'by Daniel López, researchers\' reports (CC0 1.0).'),
                    item('Sefinek Blacklisted-Emails', 'https://github.com/sefinek/Blacklisted-Emails', '(MIT): scam sender addresses.'),
                    item('Cloudflare Security DNS', 'https://developers.cloudflare.com/1.1.1.1/', 'and Cloudflare\'s public resolver: blocked sites; the look-alike watch.'),
                    item('Google Safe Browsing', 'https://safebrowsing.google.com', '(optional, your key).'),
                    item('Spamhaus', 'https://www.spamhaus.com', 'Data Query Service (optional, your key; no AI training on its data).'),
                    item('abuse.ch', 'https://abuse.ch', 'URLhaus and ThreatFox (optional, your key; not-for-profit use; no AI training on its data).'),
                    item('IANA', 'https://www.iana.org/domains/root/db', 'registry directory (RDAP): when domains were registered.'),
                    item('TinyPhishLLM', 'https://github.com/thecodewarrior2/TinyPhishLLM', 'holds the phish-tiny AI model (its own public repository; each version of the service pins one commit).')),
                h('p', { class: 'small muted', text: 'Phishing-technique research from public reports by security researchers (SANS ISC, Barracuda, Trustwave, Hoxhunt, KnowBe4, Malware on Tap and others).' })),
            h('section', { class: 'card spaced' }, h('h2', { text: 'License' }),
                h('p', { class: 'small', text: 'The service\'s own code has no open-source license yet (package.json: UNLICENSED). Its third-party components keep their own licenses, listed above.' }),
                h('p', { class: 'small muted', text: 'Google Workspace, Gmail and Google Cloud are trademarks of Google LLC. Other product names are trademarks of their owners. This service is not affiliated with or endorsed by any of them.' }))];
    }

    // --- Routing ---------------------------------------------------------------------------------
    const PERIOD_PAGES = new Set(['overview', 'review', 'campaigns', 'users', 'messages', 'rechecked', 'health', 'readiness', 'status', 'trainingexport']);
    const ROUTES = { dmarc: dmarcPage, trainingexport: trainingPage, overview, review, campaigns, users, messages, message, check, rechecked, lookalikes, health, readiness, activity, status, settings, allowlist, mailboxes, summary, retraining, safebrowsing: safeBrowsingPage, spamhaus: spamhausPage, abusech: abusechPage, clicks: clicksPage, userreports: userReportsPage, phishtraining: phishTrainingPage, update: updatePage, about,
        // Help (0.5.46)
        help: () => helpDocPage('howitworks'), helpdashboard: () => helpDocPage('dashboard'), helpalerts: () => helpDocPage('alerts'), helpprivacy: () => helpDocPage('privacy'),
        helpworkspace: () => helpDocPage('workspace'), helpinstall: () => helpDocPage('install'), helpsettings: () => helpDocPage('settings'), helpcosts: () => helpDocPage('costs'),
        helparchitecture: () => helpDocPage('architecture'), credits: creditsPage };
    // (0.6.0) The menu on the left: Today, Review, Threats, Mail, Health, Settings, and Help at its foot. Threats,
    // Mail, Health, Settings and Help each have their pages in a menu beside the page (Settings' in four groups).
    // The pages keep their own addresses (#/review, #/health…), so links to them still work; an email's page
    // belongs to Mail → Messages. The classic tabs: docs/DASHBOARD-ROLLBACK.md.
    const SECTIONS = {
        threats: { label: 'Threats', groups: [[null, [['campaigns', 'Campaigns'], ['rechecked', 'Re-checked'], ['lookalikes', 'Look-alikes']]]] },
        mail: { label: 'Mail', groups: [[null, [['messages', 'Emails'], ['check', 'Check an email'], ['users', 'Users']]]] },
        health: { label: 'Health', groups: [[null, [['status', 'Service status'], ['readiness', 'Ready for enforce mode?'], ['health', 'Model health'], ['dmarc', 'DMARC & reputation'], ['trainingexport', 'Retraining examples'], ['activity', 'Activity']]]] },
        settings: { label: 'Settings', groups: [['Protection', [['settings', 'Policy'], ['allowlist', 'Sender lists']]],
            ['Threat feeds', [['safebrowsing', 'Safe Browsing'], ['spamhaus', 'Spamhaus'], ['abusech', 'abuse.ch']]],
            ['Organization', [['mailboxes', 'Mailboxes'], ['summary', 'Weekly summary'], ['clicks', 'Link clicks'], ['userreports', 'User reports'], ['phishtraining', 'Phishing training']]],
            ['System', [['retraining', 'Retraining'], ['update', 'Update'], ['about', 'About']]]] },
        help: { label: 'Help', groups: [[null, [['help', 'How it works'], ['helpdashboard', 'The dashboard'], ['helpalerts', 'Alerts'], ['helpprivacy', 'Your privacy'], ['helpworkspace', 'Google Workspace settings'],
            ['helpinstall', 'Install & troubleshooting'], ['helpsettings', 'Settings reference'], ['helpcosts', 'Costs'], ['helparchitecture', 'Architecture deep dive'], ['credits', 'About & credits']]]] }
    };
    const pagesOf = (section) => SECTIONS[section].groups.flatMap(([, pages]) => pages);
    // (0.6.1) What a moderator doesn't see: Health and Settings, and Threats → Look-alikes (the service refuses them too).
    const ADMIN_ONLY_SECTIONS = ['health', 'settings'], ADMIN_ONLY_PAGES = ['lookalikes'];
    const adminOnly = (place) => ADMIN_ONLY_SECTIONS.includes(place.section) || ADMIN_ONLY_PAGES.includes(place.page);
    function applyRole() {
        const mod = isModerator();
        for (const a of document.querySelectorAll('.nav a, .tabbar a')) if (ADMIN_ONLY_SECTIONS.includes(a.dataset.tab)) a.hidden = mod;
        document.body.classList.toggle('moderator', mod);
    }
    const PAGE_OF = { message: 'messages' };
    function placeOf(name) {
        const page = PAGE_OF[name] || name;
        const section = Object.keys(SECTIONS).find(k => pagesOf(k).some(([p]) => p === page));
        return { page, section, tab: section || page };
    }
    function withSideMenu(section, page, nodes) {
        const s = SECTIONS[section];
        const menu = h('nav', { class: 'side', 'aria-label': s.label },
            s.groups.map(([title, pages]) => [title ? h('div', { class: 'side-group', text: title }) : null,
                pages.filter(([p]) => !(isModerator() && ADMIN_ONLY_PAGES.includes(p))).map(([p, label]) => h('a', { href: `#/${p}`, 'data-page': p, 'aria-current': p === page ? 'page' : null, text: label }))]));
        return h('div', { class: 'with-side' }, menu, h('div', { class: 'side-page' }, nodes));
    }
    // The phone's menu: a drawer over the page (the menu button, or More in the tab bar), closed by a choice,
    // a tap outside or Escape.
    function setDrawer(open) {
        const side = $('#sidebar');
        if (!side) return;
        side.classList.toggle('open', open);
        $('#scrim').hidden = !open;
        for (const b of [$('#menuBtn'), $('#moreBtn')]) if (b) b.setAttribute('aria-expanded', String(open));
        if (open) { const a = side.querySelector('a'); if (a) a.focus(); }
    }
    let pageBusy = () => false;   // a page sets it when live updates should wait (emails ticked on Messages, a form being filled in)
    let rendering = 0;
    // quiet: a live update (no loading fade, the scroll position kept, and on failure the page stays).
    async function render(opts = {}) {
        if (opts.quiet) return renderPage(opts);
        busyStart('Loading the page…');
        try { return await renderPage(opts); } finally { busyEnd('Loading the page…'); }
    }
    async function renderPage({ quiet = false } = {}) {
        const [path, query] = (currentHash().replace(/^#\/?/, '') || 'overview').split('?');
        const name = ROUTES[path] ? path : 'overview';
        const place = placeOf(name);
        for (const a of document.querySelectorAll('.nav a, .tabbar a, .help-link')) { if (a.dataset.tab === place.tab) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }
        setDrawer(false);
        for (const b of document.querySelectorAll('.range')) b.setAttribute('aria-pressed', String(Number(b.dataset.days) === days));
        // (0.6.39) The period buttons only on the pages they change (Activity has its own).
        const filters = $('.top .filters'); if (filters) filters.hidden = !PERIOD_PAGES.has(name);
        const id = ++rendering;
        if (!quiet) { view().classList.add('loading'); hideTip(); }
        pageBusy = () => false;
        const scrollY = window.scrollY;
        try {
            let nodes = isModerator() && adminOnly(place)
                ? [h('h1', { text: 'For administrators' }), h('div', { class: 'alert warning', role: 'status' }, h('span', { class: 'icon', 'aria-hidden': 'true', text: '!' }),
                    h('div', { class: 'grow' }, h('b', { text: 'This page is for the service\'s administrators.' }), ' As a moderator you can review emails: ', h('a', { href: '#/review', text: 'go to Review' }), '.'))]
                : [].concat(await ROUTES[name](new URLSearchParams(query || ''))).flat(Infinity).filter(Boolean);
            if (id !== rendering) return;
            if (place.section) nodes = [withSideMenu(place.section, place.page, nodes)];
            view().textContent = '';
            view().append(...nodes);
            foldIntro(view());
            if (quiet) window.scrollTo(0, scrollY);
            liveDone(null);
        } catch (e) {
            if (id !== rendering) return;
            if (quiet) { liveDone(e); return; }
            view().textContent = '';
            view().append(h('div', { class: 'alert critical', role: 'alert' }, h('span', { class: 'icon', text: '⚠️' }), h('div', {}, h('b', { text: 'Couldn\'t load this page. ' }), e.message)));
        } finally { if (id === rendering) view().classList.remove('loading'); }
    }

    // The period buttons, within how long records are kept (Settings → Policy): with 35 days, Last 90 days
    // becomes Last 35 days. The first button at or over the period is capped to it, the longer ones are hidden,
    // and a period no longer offered moves to the longest one left at or under it (else the shortest).
    function fitRanges(keep) {
        const k = Math.round(Number(keep));
        if (!(k > 0)) return;
        const buttons = [...document.querySelectorAll('.range')];
        buttons.forEach(b => { if (!b.dataset.wanted) b.dataset.wanted = b.dataset.days; });
        let shown = false;
        for (const b of buttons) {
            const want = Number(b.dataset.wanted);
            b.hidden = shown && want > k;
            if (!b.hidden) { b.dataset.days = String(Math.min(want, k)); b.textContent = `Last ${Math.min(want, k)} days`; }
            if (want >= k) shown = true;
        }
        const allowed = buttons.filter(b => !b.hidden).map(b => Number(b.dataset.days));
        if (!allowed.includes(days)) days = allowed.filter(n => n <= days).pop() || allowed[0];
        for (const b of buttons) b.setAttribute('aria-pressed', String(Number(b.dataset.days) === days));
    }
    // (0.6.11) Light, dark, or the system's setting: chosen with the switcher in the menu, kept in this browser
    // (theme.js applies it before the page is drawn). Charts read their colors when drawn, so the page is drawn again.
    const THEMES = ['system', 'light', 'dark'];
    function themeNow() { const t = document.documentElement.getAttribute('data-theme'); return t === 'light' || t === 'dark' ? t : 'system'; }
    function showTheme() { for (const b of document.querySelectorAll('[data-theme-choice]')) b.setAttribute('aria-pressed', String(b.dataset.themeChoice === themeNow())); }
    function setTheme(t) {
        if (!THEMES.includes(t)) return;
        if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t);
        try { if (t === 'system') localStorage.removeItem('spruce.theme'); else localStorage.setItem('spruce.theme', t); } catch (e) { /* not kept: this page only */ }
        showTheme();
        render({ quiet: true });
    }
    async function boot() {
        for (const b of document.querySelectorAll('.range')) b.addEventListener('click', () => { days = Number(b.dataset.days); try { localStorage.setItem('spruce.days', String(days)); } catch (e) { /* not kept */ } pendingAt = 0; pendingSeen = false; refreshPending(); render(); });   // (0.6.50) the count follows the period
        if (MEMORY) document.addEventListener('click', (e) => { const a = e.target.closest && e.target.closest('a[href^="#/"]'); if (a) { e.preventDefault(); go(a.getAttribute('href')); } });
        else window.addEventListener('hashchange', render);
        window.addEventListener('scroll', hideTip, { passive: true });
        for (const b of document.querySelectorAll('[data-theme-choice]')) b.addEventListener('click', () => setTheme(b.dataset.themeChoice));
        showTheme();
        // Following the system: its change redraws the charts in the new colors.
        if (window.matchMedia) { const mq = window.matchMedia('(prefers-color-scheme: dark)'); const redraw = () => { if (themeNow() === 'system') render({ quiet: true }); }; if (mq.addEventListener) mq.addEventListener('change', redraw); }
        for (const b of [$('#menuBtn'), $('#moreBtn')]) if (b) b.addEventListener('click', () => setDrawer(!$('#sidebar').classList.contains('open')));
        if ($('#scrim')) $('#scrim').addEventListener('click', () => setDrawer(false));
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#sidebar') && $('#sidebar').classList.contains('open')) setDrawer(false); });
        // The review queue's keys (not while typing, nor with Ctrl, Alt or Cmd).
        document.addEventListener('keydown', (e) => {
            if (!reviewKeys || !/^#\/?review/.test(currentHash()) || e.ctrlKey || e.metaKey || e.altKey || acting || popupOpen()) return;
            // (0.6.39) A ticked box keeps the keys working (only typing in a field stops them).
            if (e.target && (/^(TEXTAREA|SELECT)$/.test(e.target.tagName) || (e.target.tagName === 'INPUT' && !/^(checkbox|radio)$/.test(e.target.type)))) return;
            const f = reviewKeys[String(e.key).toLowerCase()];
            if (f) { e.preventDefault(); f(); }
        });
        refreshPending();
        // Live updates (not in the clickable mockup, whose data never changes).
        if (!MEMORY && $('#live')) {
            $('#live').hidden = false;
            $('#liveToggle').addEventListener('click', () => {
                live = !live;
                try { localStorage.setItem('spruce.live', live ? 'on' : 'off'); } catch (e) { /* not kept */ }
                showLive();
                if (live) liveTick();
            });
            document.addEventListener('visibilitychange', liveTick);
            setInterval(liveTick, 5000);
            showLive();
        }
        try {
            const st = await api('/api/session');
            applyRole();
            $('#who').textContent = st.admin || '';
            showMode(st.mode);
            fitRanges(st.retentionDays);
            if (st.demo) $('.top-right').prepend(h('span', { class: 'demo-flag', text: 'DEMO · made-up data' }));
            $('#foot').textContent = `Checks and AI model from S.P.R.U.C.E+ (${st.model.name} ${st.model.version}). Records keep the sender, subject and the checks' findings, never email bodies, and are deleted after ${st.retentionDays} days.`;
        } catch (e) { /* the view shows the error */ }
        render();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
