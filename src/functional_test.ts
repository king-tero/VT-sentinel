/**
 * Functional test for VT Sentinel — real API calls against VirusTotal.
 * Tests all 3 tools end-to-end with real files and hashes.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Scanner, ScanResult } from './scanner';
import { FileClassifier, FileCategory } from './classifier';
import { VTApiClient, calculateSHA256, registerAgent, loadAgentCredentials, saveAgentCredentials, AgentCredentials } from './vt-api';

// ── Config ──────────────────────────────────────────────────────────────

let API_KEY = process.env.VT_API_KEY || '';
let USE_VTAI = false;

if (!API_KEY) {
    // Try VTAI credentials as fallback
    const creds = loadAgentCredentials();
    if (creds) {
        API_KEY = creds.agentToken;
        USE_VTAI = true;
        console.log(`  No VT_API_KEY — using VTAI agent: ${creds.publicHandle}`);
    } else {
        console.error('ERROR: Set VT_API_KEY or have cached VTAI credentials');
        process.exit(1);
    }
}

const logger = {
    info: (msg: string) => console.log(`  [INFO] ${msg}`),
    warn: (msg: string) => console.log(`  [WARN] ${msg}`),
    error: (msg: string) => console.log(`  [ERROR] ${msg}`),
};

let passed = 0;
let failed = 0;
let skipped = 0;

function assert(condition: boolean, name: string) {
    if (condition) {
        console.log(`  PASS: ${name}`);
        passed++;
    } else {
        console.error(`  FAIL: ${name}`);
        failed++;
    }
}

function skip(name: string, reason: string) {
    console.log(`  SKIP: ${name} — ${reason}`);
    skipped++;
}

function printResult(r: ScanResult) {
    console.log(`    ├─ File: ${r.fileName}`);
    console.log(`    ├─ Category: ${r.category}`);
    console.log(`    ├─ Verdict: ${r.verdict}`);
    if (r.detections) {
        console.log(`    ├─ Detections: ${r.detections.malicious}M / ${r.detections.suspicious}S / ${r.detections.total} total`);
    }
    if (r.codeInsight) {
        console.log(`    ├─ Code Insight: ${r.codeInsight.verdict} (${r.codeInsight.source})`);
        console.log(`    │  ${r.codeInsight.analysis?.substring(0, 150)}...`);
    }
    if (r.vtLink) {
        console.log(`    ├─ VT Link: ${r.vtLink}`);
    }
    console.log(`    └─ Message: ${r.message}`);
}

function writeFile(dir: string, name: string, content: Buffer | string): string {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content);
    return p;
}

// Delay to respect rate limits (4 req/min)
function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ═══════════════════════════════════════════════════════════════════════
// Test 1: VT API Client — Direct hash lookups
// ═══════════════════════════════════════════════════════════════════════

async function testApiClient() {
    console.log('\n=== Test 1: VT API Client — Direct Hash Lookups ===\n');

    const api = new VTApiClient(API_KEY, USE_VTAI);

    // EICAR test file hash — universally detected as test malware
    const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    console.log('  Testing EICAR hash lookup...');
    const eicarReport = await api.checkHash(EICAR_SHA256);
    assert(eicarReport !== null, 'EICAR hash found in VT database');
    if (eicarReport) {
        assert(eicarReport.stats.malicious > 0, `EICAR detected as malicious (${eicarReport.stats.malicious} engines)`);
        assert(eicarReport.vtLink !== undefined, 'EICAR has VT link');
        console.log(`    → ${eicarReport.stats.malicious} malicious / ${eicarReport.stats.malicious + eicarReport.stats.harmless + eicarReport.stats.undetected} total`);
        console.log(`    → VT Link: ${eicarReport.vtLink}`);
    }

    await delay(16000); // Rate limit: wait before next request

    // Known clean file: empty file hash (sha256 of zero bytes)
    const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    console.log('\n  Testing empty file hash lookup...');
    const emptyReport = await api.checkHash(EMPTY_SHA256);
    if (emptyReport) {
        assert(emptyReport.stats.malicious === 0, `Empty file hash: 0 malicious detections`);
        console.log(`    → ${emptyReport.stats.malicious} malicious / ${emptyReport.stats.harmless + emptyReport.stats.undetected} total`);
    } else {
        skip('Empty file hash check', 'Hash not in VT database');
    }

    await delay(16000);

    // Non-existent hash
    const FAKE_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
    console.log('\n  Testing non-existent hash lookup...');
    const fakeReport = await api.checkHash(FAKE_HASH);
    assert(fakeReport === null, 'Non-existent hash returns null (404)');
}

// ═══════════════════════════════════════════════════════════════════════
// Test 2: Scanner — Full file scan (HIGH_RISK binary)
// ═══════════════════════════════════════════════════════════════════════

async function testScanBinary() {
    console.log('\n=== Test 2: Scanner — ELF Binary Scan ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-func-'));

    // Create a minimal ELF binary (just header, not a real executable)
    const elfHeader = Buffer.alloc(64);
    elfHeader[0] = 0x7F; elfHeader[1] = 0x45; elfHeader[2] = 0x4C; elfHeader[3] = 0x46; // .ELF
    elfHeader[4] = 0x02; // 64-bit
    elfHeader[5] = 0x01; // Little endian
    elfHeader[6] = 0x01; // ELF version
    const elfPath = writeFile(tmp, 'test_binary.elf', elfHeader);

    // Verify classification
    const cat = FileClassifier.classify(elfPath);
    assert(cat === FileCategory.HIGH_RISK, `ELF classified as HIGH_RISK (got ${cat})`);

    // Scan it
    console.log('  Scanning ELF binary...');
    const result = await scanner.scanFile(elfPath);
    printResult(result);

    assert(result.category === FileCategory.HIGH_RISK, 'Scan result has HIGH_RISK category');
    assert(result.sha256.length === 64, 'SHA-256 hash is 64 chars');
    assert(['clean', 'malicious', 'suspicious', 'unknown', 'pending'].includes(result.verdict),
        `Verdict is valid: ${result.verdict}`);

    fs.rmSync(tmp, { recursive: true });
    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 3: Scanner — EICAR test file (known malicious)
// ═══════════════════════════════════════════════════════════════════════

async function testScanEicar() {
    console.log('\n=== Test 3: Scanner — EICAR Test File (Known Malicious) ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-eicar-'));

    // EICAR test string — standard antivirus test pattern
    const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarPath = writeFile(tmp, 'eicar_test.com', EICAR);

    const sha256 = await calculateSHA256(eicarPath);
    console.log(`  EICAR SHA-256: ${sha256}`);

    console.log('  Scanning EICAR test file (force=true, simulating vt_scan_file tool)...');
    const result = await scanner.scanFile(eicarPath, true);
    printResult(result);

    assert(result.verdict === 'malicious', `EICAR detected as malicious (got ${result.verdict})`);
    if (result.detections) {
        assert(result.detections.malicious > 50, `EICAR: ${result.detections.malicious} engines detected (expected >50)`);
    }

    fs.rmSync(tmp, { recursive: true });
    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 4: Scanner — Script file with Code Insight (SEMANTIC_RISK)
// ═══════════════════════════════════════════════════════════════════════

async function testScanScript() {
    console.log('\n=== Test 4: Scanner — Script File (Semantic Analysis) ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-script-'));

    // Create a suspicious-looking script (harmless but looks bad)
    const script = `#!/bin/bash
# This is a test script for VT Sentinel functional testing
echo "VT Sentinel test $(date)"
curl -s https://example.com/test > /dev/null
echo "Test complete"
`;
    const scriptPath = writeFile(tmp, 'test_script.sh', script);

    const cat = FileClassifier.classify(scriptPath);
    assert(cat === FileCategory.HIGH_RISK, `Script with shebang classified as HIGH_RISK (got ${cat})`);

    console.log('  Scanning shell script...');
    const result = await scanner.scanFile(scriptPath);
    printResult(result);

    assert(result.sha256.length === 64, 'SHA-256 hash computed');
    assert(['clean', 'malicious', 'suspicious', 'unknown', 'pending'].includes(result.verdict),
        `Script verdict is valid: ${result.verdict}`);

    fs.rmSync(tmp, { recursive: true });
    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 5: Scanner — SKILL.md (SEMANTIC_RISK + Code Insight)
// ═══════════════════════════════════════════════════════════════════════

async function testScanSkill() {
    console.log('\n=== Test 5: Scanner — SKILL.md (Semantic Risk) ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-skill-'));

    const skillContent = `---
name: test-skill
description: A harmless test skill for VT Sentinel functional testing
---

# Test Skill

This skill does nothing harmful. It is used to verify that VT Sentinel
correctly classifies and analyzes SKILL.md files.

## Instructions
When the user says "test", reply with "VT Sentinel functional test passed".
`;
    const skillPath = writeFile(tmp, 'SKILL.md', skillContent);

    const cat = FileClassifier.classify(skillPath);
    assert(cat === FileCategory.SEMANTIC_RISK, `SKILL.md classified as SEMANTIC_RISK (got ${cat})`);

    console.log('  Scanning SKILL.md...');
    const result = await scanner.scanFile(skillPath);
    printResult(result);

    assert(result.category === FileCategory.SEMANTIC_RISK, 'Result category is SEMANTIC_RISK');
    assert(result.sha256.length === 64, 'SHA-256 computed');

    // Code Insight may or may not be available depending on whether VT has analyzed this file before
    if (result.codeInsight) {
        console.log('  → Code Insight IS available for this file');
        assert(result.codeInsight.source.length > 0, 'Code Insight has source');
        assert(result.codeInsight.verdict.length > 0, `Code Insight verdict: ${result.codeInsight.verdict}`);
    } else {
        console.log('  → Code Insight not yet available (file may need time for analysis)');
    }

    fs.rmSync(tmp, { recursive: true });
    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 6: Unified report — Code Insight included in hash check
// ═══════════════════════════════════════════════════════════════════════

async function testUnifiedReport() {
    console.log('\n=== Test 6: Unified Report — Code Insight in Hash Check ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);

    // EICAR hash — should have both AV detections AND Code Insight
    const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    console.log('  Checking EICAR hash (expecting AV + Code Insight)...');
    const result = await scanner.checkHash(EICAR_SHA256);

    assert(result !== null, 'Hash check returns result');
    if (result) {
        printResult(result);

        // AV detections
        assert(result.detections !== undefined, 'Result includes AV detections');
        assert(result.detections!.malicious > 0, `AV: ${result.detections!.malicious} malicious detections`);

        // Code Insight (unified in same result)
        if (result.codeInsight) {
            assert(result.codeInsight.source.length > 0, `Code Insight source: ${result.codeInsight.source}`);
            assert(result.codeInsight.analysis.length > 0, 'Code Insight analysis text present');
            console.log('  → Code Insight is unified in the same result (no separate tool needed)');
        } else {
            skip('Code Insight in unified report', 'Not available for EICAR hash');
        }

        // Message should combine both
        assert(result.message.includes('AV:'), 'Message includes AV info');
    }

    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 7: Sensitive file — Consent flow (PDF)
// ═══════════════════════════════════════════════════════════════════════

async function testSensitiveConsent() {
    console.log('\n=== Test 7: Sensitive File — Consent Flow (PDF) ===\n');

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-pdf-'));

    // Create a minimal PDF with unique content so hash is unknown
    const uniqueId = Date.now().toString(36) + Math.random().toString(36).substring(2);
    const pdfContent = Buffer.concat([
        Buffer.from('%PDF-1.4\n'),
        Buffer.from(`% VT Sentinel test ${uniqueId}\n`),
        Buffer.from('1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n'),
        Buffer.from('2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n'),
        Buffer.from('3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n'),
        Buffer.from('%%EOF\n'),
    ]);
    const pdfPath = writeFile(tmp, 'test_document.pdf', pdfContent);

    // Verify classification
    const cat = FileClassifier.classify(pdfPath);
    assert(cat === FileCategory.SENSITIVE, `PDF classified as SENSITIVE (got ${cat})`);

    // Test with 'ask' policy — should return needs_consent
    console.log('\n  Test 7a: Policy "ask" — should return needs_consent');
    const scannerAsk = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);
    const resultAsk = await scannerAsk.scanFile(pdfPath);
    printResult(resultAsk);
    // If hash is unknown → needs_consent; if hash is known → could be clean/malicious
    if (resultAsk.verdict === 'needs_consent') {
        assert(true, 'PDF with ask policy → needs_consent (hash unknown)');
        assert(resultAsk.message.includes('Should I upload'), 'Message asks for consent');
    } else {
        console.log('  → Hash was already known to VT, consent not needed');
        assert(['clean', 'malicious', 'suspicious'].includes(resultAsk.verdict),
            'Known PDF got a definitive verdict');
    }

    await delay(16000);

    // Test with 'hash_only' policy — should return unknown
    console.log('\n  Test 7b: Policy "hash_only" — should NOT upload');
    const scannerHash = new Scanner(API_KEY, logger, 32, 'hash_only', USE_VTAI);
    const resultHash = await scannerHash.scanFile(pdfPath);
    printResult(resultHash);
    if (resultHash.verdict === 'unknown') {
        assert(true, 'PDF with hash_only policy → unknown (no upload)');
        assert(resultHash.message.includes('NOT uploaded'), 'Message confirms no upload');
    } else {
        assert(['clean', 'malicious', 'suspicious'].includes(resultHash.verdict),
            'Known PDF hash gave definitive result even with hash_only');
    }

    await delay(16000);

    // Test with 'ask_once' policy — first call returns needs_consent, then simulate consent
    console.log('\n  Test 7c: Policy "ask_once" — consent remembered');
    const scannerOnce = new Scanner(API_KEY, logger, 32, 'ask_once', USE_VTAI);
    const resultOnce1 = await scannerOnce.scanFile(pdfPath);
    if (resultOnce1.verdict === 'needs_consent') {
        assert(true, 'First call with ask_once → needs_consent');

        // Record consent (user says NO)
        scannerOnce.recordConsent(false);

        await delay(16000);

        // Second call should use remembered decision (no upload)
        const resultOnce2 = await scannerOnce.scanFile(pdfPath);
        // Clear cache to force a new scan
        scannerOnce.clearCache();
        await delay(16000);
        const resultOnce3 = await scannerOnce.scanFile(pdfPath);
        assert(resultOnce3.verdict === 'unknown', 'After declining: ask_once remembers NO → unknown');
    } else {
        skip('ask_once consent test', 'PDF hash already known to VT');
    }

    fs.rmSync(tmp, { recursive: true });
}

// ═══════════════════════════════════════════════════════════════════════
// Test 8: Upload with consent
// ═══════════════════════════════════════════════════════════════════════

async function testUploadWithConsent() {
    console.log('\n=== Test 8: Upload With Consent ===\n');

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-upload-'));

    // Create a unique harmless file that VT won't know
    const uniqueId = Date.now().toString(36) + Math.random().toString(36).substring(2);
    const content = Buffer.concat([
        Buffer.from('%PDF-1.4\n'),
        Buffer.from(`% Functional test upload ${uniqueId}\n`),
        Buffer.from('1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n'),
        Buffer.from('%%EOF\n'),
    ]);
    const filePath = writeFile(tmp, 'consent_upload_test.pdf', content);

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);

    console.log('  Uploading file with consent...');
    const result = await scanner.uploadWithConsent(filePath);
    printResult(result);

    assert(result.verdict === 'pending', `Upload result: pending (got ${result.verdict})`);
    assert(result.message.includes('Uploaded') || result.message.includes('Upload'),
        'Message confirms upload');

    fs.rmSync(tmp, { recursive: true });
    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 9: Malicious Python script (known hash)
// ═══════════════════════════════════════════════════════════════════════

async function testCheckKnownMalicious() {
    console.log('\n=== Test 9: Check Known Malicious Hash ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);

    // WannaCry ransomware hash — well known malware
    const WANNACRY_SHA256 = '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';
    console.log('  Checking WannaCry hash...');
    const result = await scanner.checkHash(WANNACRY_SHA256);

    if (result) {
        printResult(result);
        assert(result.verdict === 'malicious', `WannaCry detected as malicious (got ${result.verdict})`);
        if (result.detections) {
            assert(result.detections.malicious > 30, `WannaCry: ${result.detections.malicious} detections (expected >30)`);
        }
    } else {
        skip('WannaCry hash check', 'Hash not found in VT (unexpected)');
    }

    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 10: Cache behavior with real scans
// ═══════════════════════════════════════════════════════════════════════

async function testCacheBehavior() {
    console.log('\n=== Test 10: Cache Behavior (scanFile) ===\n');

    const scanner = new Scanner(API_KEY, logger, 32, 'ask', USE_VTAI);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-cache-'));

    // Create EICAR file for scanFile cache test
    const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarPath = writeFile(tmp, 'cache_test.com', EICAR);

    // First call — API hit
    console.log('  First scanFile (API call)...');
    const t1 = Date.now();
    const r1 = await scanner.scanFile(eicarPath, true);
    const d1 = Date.now() - t1;
    assert(r1 !== null, 'First call returns result');
    assert(r1.verdict === 'malicious', `First call detects EICAR (${r1.verdict})`);
    console.log(`    → Took ${d1}ms`);

    // Second call — should be instant (cache hit, no API call)
    console.log('  Second scanFile (should be cached)...');
    const t2 = Date.now();
    const r2 = await scanner.scanFile(eicarPath, true);
    const d2 = Date.now() - t2;
    assert(r2 !== null, 'Second call returns result');
    assert(d2 < 50, `Cache hit is fast: ${d2}ms (no API call)`);
    assert(r2.verdict === 'malicious', 'Cached result still malicious');
    console.log(`    → Took ${d2}ms (cache hit)`);

    fs.rmSync(tmp, { recursive: true });
    scanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Test 11: VTAI API — Zero-config agent registration + hash lookup
// ═══════════════════════════════════════════════════════════════════════

async function testVtaiApi() {
    console.log('\n=== Test 11: VTAI API — Agent Registration + Hash Lookup ===\n');

    // Step 1: Get agent credentials — reuse cached or register new
    console.log('  Resolving VTAI agent credentials...');
    let creds: AgentCredentials | null = loadAgentCredentials();
    if (creds) {
        console.log(`    → Using cached agent: ${creds.publicHandle} (registered ${creds.registeredAt})`);
        assert(true, `Cached agent loaded: ${creds.publicHandle}`);
    } else {
        console.log('  No cached credentials — registering with ai.virustotal.com...');
        try {
            creds = await registerAgent({ agentVersion: '0.2.0-functest' });
            saveAgentCredentials(creds);
            assert(creds.agentId.length > 0, `Agent registered: id=${creds.agentId}`);
            assert(creds.agentToken.length > 0, 'Agent token received');
            assert(creds.publicHandle.length > 0, `Public handle: ${creds.publicHandle}`);
            console.log(`    → Agent ID: ${creds.agentId}`);
            console.log(`    → Public handle: ${creds.publicHandle}`);
            console.log(`    → Token: ${creds.agentToken.substring(0, 8)}...`);
        } catch (err: any) {
            const status = err.response?.status;
            if (status === 429) {
                skip('VTAI agent registration', 'Rate limited (429) — no cached credentials available');
            } else {
                console.error(`  FAIL: Agent registration failed: ${err.message}`);
                failed++;
            }
            return;
        }
    }

    await delay(5000);

    // Step 2: Create VTAI client with agent token
    const vtaiClient = new VTApiClient(creds.agentToken, true);

    // Step 3: EICAR hash lookup via VTAI — verify simplified response
    const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    console.log('\n  Checking EICAR hash via VTAI...');
    const eicarReport = await vtaiClient.checkHash(EICAR_SHA256);

    assert(eicarReport !== null, 'VTAI: EICAR hash found');
    if (eicarReport) {
        assert(eicarReport.stats.malicious > 0, `VTAI: EICAR malicious (${eicarReport.stats.malicious} engines)`);
        assert(eicarReport.vtLink.includes('virustotal.com'), `VTAI: VT link present`);
        console.log(`    → Stats: ${eicarReport.stats.malicious}M / ${eicarReport.stats.suspicious}S / ${eicarReport.stats.harmless}H / ${eicarReport.stats.undetected}U`);
        console.log(`    → VT Link: ${eicarReport.vtLink}`);

        // Check if ai_insights mapped to crowdsourcedAiResults
        if (eicarReport.crowdsourcedAiResults && eicarReport.crowdsourcedAiResults.length > 0) {
            const ai = eicarReport.crowdsourcedAiResults[0];
            assert(ai.analysis.length > 0, `VTAI: ai_insights mapped — analysis present`);
            console.log(`    → AI Insight: ${ai.verdict || 'N/A'} — ${ai.analysis.substring(0, 120)}...`);
        } else {
            console.log('    → No ai_insights for EICAR (expected — EICAR is a test file)');
        }
    }

    await delay(5000);

    // Step 4: Non-existent hash via VTAI — should return null
    const FAKE_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
    console.log('\n  Checking non-existent hash via VTAI...');
    const fakeReport = await vtaiClient.checkHash(FAKE_HASH);
    assert(fakeReport === null, 'VTAI: Non-existent hash returns null');

    await delay(5000);

    // Step 5: Scanner in VTAI mode — scan EICAR file
    console.log('\n  Testing Scanner in VTAI mode with EICAR...');
    const vtaiScanner = new Scanner(creds.agentToken, logger, 32, 'ask', true);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-vtai-'));
    const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarPath = writeFile(tmp, 'vtai_eicar.com', EICAR);

    const scanResult = await vtaiScanner.scanFile(eicarPath, true);
    printResult(scanResult);
    assert(scanResult.verdict === 'malicious', `VTAI Scanner: EICAR detected as malicious (got ${scanResult.verdict})`);
    if (scanResult.detections) {
        assert(scanResult.detections.malicious > 50, `VTAI Scanner: ${scanResult.detections.malicious} engines (>50)`);
    }

    await delay(5000);

    // Step 6: WannaCry hash via VTAI Scanner
    console.log('\n  Checking WannaCry hash via VTAI Scanner...');
    const WANNACRY_SHA256 = '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';
    const wannacryResult = await vtaiScanner.checkHash(WANNACRY_SHA256);
    if (wannacryResult) {
        printResult(wannacryResult);
        assert(wannacryResult.verdict === 'malicious', `VTAI Scanner: WannaCry malicious (got ${wannacryResult.verdict})`);
    } else {
        skip('VTAI WannaCry check', 'Hash not found via VTAI');
    }

    fs.rmSync(tmp, { recursive: true });
    vtaiScanner.clearCache();
}

// ═══════════════════════════════════════════════════════════════════════
// Run All
// ═══════════════════════════════════════════════════════════════════════

async function main() {
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║  VT-Sentinel Functional Test — Real API Calls         ║');
    console.log('╚════════════════════════════════════════════════════════╝');
    console.log(`  API Key: ${API_KEY.substring(0, 8)}...${API_KEY.substring(API_KEY.length - 4)}`);
    console.log(`  Time: ${new Date().toISOString()}`);

    try {
        await testApiClient();
        await delay(16000);

        await testScanEicar();
        await delay(16000);

        await testCheckKnownMalicious();
        await delay(16000);

        await testScanBinary();
        await delay(16000);

        await testScanScript();
        await delay(16000);

        await testScanSkill();
        await delay(16000);

        await testUnifiedReport();
        await delay(16000);

        await testSensitiveConsent();
        await delay(16000);

        await testUploadWithConsent();
        await delay(16000);

        await testCacheBehavior();
        await delay(16000);

        await testVtaiApi();
    } catch (err: any) {
        console.error(`\n  FATAL ERROR: ${err.message}`);
        console.error(err.stack);
        failed++;
    }

    console.log(`\n╔════════════════════════════════════════════════════════╗`);
    console.log(`║  Results: ${passed} passed, ${failed} failed, ${skipped} skipped${' '.repeat(Math.max(0, 20 - String(passed).length - String(failed).length - String(skipped).length))}║`);
    console.log(`╚════════════════════════════════════════════════════════╝\n`);

    process.exit(failed > 0 ? 1 : 0);
}

main();
