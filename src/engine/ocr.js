'use strict';
// (0.6.85) The words in a picture (OCR, tesseract.js with its English data from the @tesseract.js-data/eng package:
// nothing is downloaded, and the picture never leaves the service). For the AI's next input format: a lure sent as a
// picture ("Your mailbox is full", a fake invoice) has no text for a model to read otherwise.
//
// One worker per instance, made when first needed and stopped after IDLE_MS unused; one picture at a time; each read
// gives up after the time it is given. The text is never stored: the retraining export reads it, cleans it and hands it to
// the training computer like an email's own text.
const path = require('path');

const IDLE_MS = 5 * 60 * 1000;
const MAX_CHARS = 2000;
let worker = null, idleTimer = null, chain = Promise.resolve();

function langPath() {
    return path.join(path.dirname(require.resolve('@tesseract.js-data/eng/package.json')), '4.0.0_best_int');
}
async function getWorker() {
    if (!worker) {
        const T = require('tesseract.js');
        worker = T.createWorker('eng', 1, { langPath: langPath(), gzip: true, cacheMethod: 'none', logger: () => {}, errorHandler: () => {} })
            .catch((e) => { worker = null; throw e; });
    }
    return worker;
}
function idleLater() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => { stop().catch(() => {}); }, IDLE_MS);
    if (idleTimer.unref) idleTimer.unref();
}
async function stop() {
    clearTimeout(idleTimer);
    const w = worker;
    worker = null;
    if (w) { try { await (await w).terminate(); } catch (e) { /* gone */ } }
}

// The text in one picture (a PNG or JPEG buffer), at most MAX_CHARS, spaces tidied; '' when none or on time out.
function textIn(buf, { timeoutMs = 4000 } = {}) {
    const run = chain.then(async () => {
        const w = await getWorker();
        let timer;
        const late = new Promise((res) => { timer = setTimeout(() => res(null), timeoutMs); });
        const r = await Promise.race([w.recognize(buf).catch(() => null), late]).finally(() => clearTimeout(timer));
        idleLater();
        if (!r) { await stop(); return ''; }   // a picture that took too long: the worker may still be busy with it
        return tidy(r.data && r.data.text);
    });
    chain = run.catch(() => '');
    return run.catch(() => '');
}
function tidy(t) {
    const words = String(t || '').replace(/[^\S\n]+/g, ' ').split('\n').map(l => l.trim())
        // a line of OCR noise: fewer than two real words
        .filter(l => (l.match(/[A-Za-z]{2,}/g) || []).length >= 2);
    return words.join('\n').slice(0, MAX_CHARS);
}

module.exports = { textIn, stop, tidy, MAX_CHARS };
