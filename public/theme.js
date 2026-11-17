// S.P.R.U.C.E Mail Protection Service: the theme chosen on this browser (System, Light or Dark; app.js's switcher),
// applied before the page is drawn, so a dark page never flashes light. Kept in this browser only.
(function () {
    'use strict';
    try {
        var t = localStorage.getItem('spruce.theme');
        if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
    } catch (e) { /* storage blocked: follow the system */ }
})();
