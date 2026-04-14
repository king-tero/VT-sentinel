const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { Scanner } = require('./dist/scanner.js');

const dummyTxt = path.join(__dirname, 'dummy.txt');
const dummyPdf = path.join(__dirname, 'dummy.pdf');
const dummySkill = path.join(__dirname, 'SKILL.md');

test('Setup dummy files', () => {
    fs.writeFileSync(dummyTxt, 'dummy content');
    fs.writeFileSync(dummyPdf, '%PDF-1.4 dummy pdf content for testing magic bytes');
    fs.writeFileSync(dummySkill, '# Skill metadata');
});

test('Scanner privacy_first (hash_only) policy avoids upload', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const scanner = new Scanner('dummy_key', logger, 32, 'hash_only', false, 'hash_only');
    
    // Mock VT API
    scanner.api.checkHash = async () => null; // Unknown hash
    scanner.api.uploadFile = async () => { throw new Error('Should not upload in hash_only'); };

    const resPdf = await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(resPdf.verdict, 'unknown');
    
    const resSkill = await scanner.scanFile(dummySkill, true);
    assert.strictEqual(resSkill.verdict, 'unknown');
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

    // 1. Initial scan: no consent recorded -> needs_consent
    const res1 = await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(res1.verdict, 'needs_consent');
    
    // 2. User consents to sensitive
    scanner.recordConsent(true, 'sensitive');
    await scanner.scanFile(dummyPdf, true);
    assert.strictEqual(uploaded, 1);
    
    // 3. Semantic file should still need consent
    const resSkill1 = await scanner.scanFile(dummySkill, true);
    assert.strictEqual(resSkill1.verdict, 'needs_consent');
    
    // 4. User denies semantic consent
    scanner.recordConsent(false, 'semantic');
    const resSkill2 = await scanner.scanFile(dummySkill, true);
    assert.strictEqual(resSkill2.verdict, 'unknown');
    assert.strictEqual(uploaded, 1); // No new upload
});

test('Cleanup dummy files', () => {
    if (fs.existsSync(dummyTxt)) fs.unlinkSync(dummyTxt);
    if (fs.existsSync(dummyPdf)) fs.unlinkSync(dummyPdf);
    if (fs.existsSync(dummySkill)) fs.unlinkSync(dummySkill);
});
