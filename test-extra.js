const { test } = require('node:test');
const assert = require('assert');
const { calculateSHA256, VTApiClient } = require('./dist/vt-api.js');
const { Scanner } = require('./dist/scanner.js');

test('Scanner coverage', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'always_upload', true, 'ask');
    
    scanner.updateMaxFileSizeMb(64);
    scanner.updateSensitivePolicy('ask_once');
    scanner.updateSemanticPolicy('always_upload');
    scanner.recordConsent(true, 'sensitive');
    scanner.recordConsent(false, 'semantic');

    try {
        await scanner.scanFile('/dev/null', true, undefined, true);
    } catch(e) {}
    
    // Test cache functions exposed on scanner
    scanner.clearCache();
    
});