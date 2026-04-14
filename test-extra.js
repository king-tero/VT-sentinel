const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { calculateSHA256, VTApiClient } = require('./dist/vt-api.js');
const { Scanner } = require('./dist/scanner.js');

const dummyTxt = path.join(__dirname, 'dummy.txt');
const dummyPdf = path.join(__dirname, 'dummy.pdf');
const dummySkill = path.join(__dirname, 'SKILL.md');
const dummyLarge = path.join(__dirname, 'dummy-large.txt');
const dummySmall = path.join(__dirname, 'dummy-small.txt');

test('Setup temp files for tests', () => {
    fs.writeFileSync(dummyTxt, 'dummy content');
    fs.writeFileSync(dummyPdf, '%PDF-1.4 dummy pdf content for testing magic bytes');
    fs.writeFileSync(dummySkill, '# Skill metadata');
    fs.writeFileSync(dummySmall, 'hello world');
    fs.writeFileSync(dummyLarge, Buffer.alloc(33 * 1024 * 1024, '0'));
});

// === Config & Policy Coverage ===

test('Scanner privacy_first (hash_only) policy avoids upload', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'hash_only', false, 'hash_only');
    scanner.api.checkHash = async () => null;
    scanner.api.uploadFile = async () => { throw new Error('Should not upload in hash_only'); };
    const resPdf = await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(resPdf.verdict, 'unknown');
});

test('Scanner always_upload policy triggers upload', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'always_upload', false, 'always_upload');
    scanner.api.checkHash = async () => null;
    let uploaded = false;
    scanner.api.uploadFile = async () => { uploaded = true; return { analysisId: '123' }; };
    await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(uploaded, true);
});

test('Scanner ask policy requires consent', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'ask', false, 'ask');
    scanner.api.checkHash = async () => null;
    const resPdf = await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(resPdf.verdict, 'needs_consent');
});

test('Scanner ask_once policy tracks consent states', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'ask_once', false, 'ask_once');
    scanner.api.checkHash = async () => null;
    let uploaded = 0;
    scanner.api.uploadFile = async () => { uploaded++; return { analysisId: '123' }; };
    
    await scanner.scanFile(dummyPdf, true);
    scanner.recordConsent(true, 'sensitive');
    await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(uploaded, 1);
    
    await scanner.scanFile(dummySkill, true);
    scanner.recordConsent(false, 'semantic');
    const resSkill2 = await scanner.scanFile(dummySkill, true);
    assert.strictEqual(resSkill2.verdict, 'unknown');
});

// === Parsing and Fetch Coverage ===

test('Scanner fromReport parses varying verdicts', () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'always_upload', false, 'ask');
    const reportMalicious = { hash: 'abc', vtLink: '...', stats: { malicious: 2, suspicious: 0, harmless: 10, undetected: 50 } };
    assert.strictEqual(scanner.fromReport('test.txt', 'abc', 'SAFE', reportMalicious).verdict, 'malicious');
    
    const reportAiSuspicious = {
        hash: 'abc', vtLink: '...', stats: { malicious: 0, suspicious: 0, harmless: 10, undetected: 50 },
        crowdsourcedAiResults: [{ source: 'Code Insight', analysis: 'looks bad', verdict: 'SUSPICIOUS' }]
    };
    assert.strictEqual(scanner.fromReport('test.txt', 'abc', 'SAFE', reportAiSuspicious).verdict, 'suspicious');
});

test('VTApiClient parses standard and vtai reports', async () => {
    const originalFetch = global.fetch;
    global.fetch = async (url) => ({
        ok: true, status: 200,
        json: async () => ({
            data: { id: '123', attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 }, meaningful_name: 'test.exe' } }
        })
    });
    const apiStd = new VTApiClient('key', false);
    const rep1 = await apiStd.checkHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.strictEqual(rep1.hash, '123');

    global.fetch = async (url) => ({
        ok: true, status: 200,
        json: async () => ({
            data: { id: '456', type_description: 'script' }
        })
    });
    const apiVtai = new VTApiClient('key', true);
    const rep2 = await apiVtai.checkHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.strictEqual(rep2.hash, '456');
    global.fetch = originalFetch;
});

test('VTApiClient uploadFile correctly routes', async () => {
    const originalFetch = global.fetch;
    let requests = [];
    global.fetch = async (url, opts) => {
        requests.push(url);
        return { ok: true, status: 200, json: async () => ({ data: { id: 'analysis-123', data: 'http://upload-url.local/large' } }) };
    };

    const apiStd = new VTApiClient('key', false);
    await apiStd.uploadFile(dummySmall);
    await apiStd.uploadFile(dummyLarge);
    
    const apiVtai = new VTApiClient('key', true);
    await apiVtai.uploadFile(dummySmall);
    await assert.rejects(async () => { await apiVtai.uploadFile(dummyLarge); });

    global.fetch = originalFetch;
});

test('Cleanup temp files', () => {
    [dummyTxt, dummyPdf, dummySkill, dummySmall, dummyLarge].forEach(f => {
        if (fs.existsSync(f)) fs.unlinkSync(f);
    });
});