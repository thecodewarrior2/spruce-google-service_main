'use strict';
// (0.6.53) For tests of the rules and the service's own logic (not of the AI model): the AI's answer for the made-up
// emails whose subject matches is fixed, so a new model's score for them doesn't change what those tests check. Every
// other email still gets the model's own answer. The model itself is tested in engine.test.js and model-source.test.js
// (its answers on the published references). Returns a function that puts the model back.
const spruce = require('../../src/engine/spruce');

function pinAi(pins) {
    const model = spruce.load().model;
    const real = model.analyze;
    model.analyze = async function (facts) {
        const pin = pins.find(([re]) => re.test(String((facts && facts.subject) || '')));
        if (!pin) return real.call(this, facts);
        return { probability: pin[1], reasons: [], model: 'phish-tiny', version: 'pinned by the test' };
    };
    return () => { model.analyze = real; };
}

module.exports = { pinAi };
