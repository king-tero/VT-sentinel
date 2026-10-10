import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { EventEmitter } from 'events';
import axios from 'axios';
import plugin from './index';
import { Scanner, ScanResult } from './scanner';
import { FileCategory } from './classifier';
import { loadAgentCredentials, saveAgentCredentials, getAgentCredentialsPath } from './vt-api';

type Check = (condition: boolean, name: string) => void;
function deferred<T>() {
    let resolve!: (value: T) => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}
async function until(check: () => boolean): Promise<void> {
    for (let i = 0; i < 100; i++) {
        if (check()) return;
        await new Promise<void>(resolve => setImmediate(resolve));
    }
    throw new Error('Controlled operation did not reach its expected barrier');
}
const credential = (id: string) => ({
    agentId: id, agentToken: `test-token-${id}`, publicHandle: `test-${id}`,
    registeredAt: '2026-01-01T00:00:00.000Z',
});
const response = (filePath = ''): ScanResult => ({
    filePath, fileName: path.basename(filePath), sha256: 'a'.repeat(64),
    category: FileCategory.HIGH_RISK, verdict: 'clean', message: 'Offline scan',
});

function fixture(config: Record<string, any> = {}, cached?: string) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-lifecycle-'));
    const state = path.join(root, 'state');
    const files = path.join(root, 'files');
    fs.mkdirSync(state);
    fs.mkdirSync(files);
    if (cached) saveAgentCredentials(credential(cached), state);
    const tools: Record<string, any> = {};
    const hooks: Record<string, any> = {};
    const requests: Array<ReturnType<typeof deferred<any>>> = [];
    const scanners = new Set<Scanner>();
    const observations: Array<{ token: string; sensitive: string; semantic: string; max: number; file?: string }> = [];
    let service: any;
    let saves = 0;
    let failNextSave = false;
    let scanBarrier: ReturnType<typeof deferred<ScanResult>> | undefined;
    const savedAdapter = axios.defaults.adapter;
    const savedCheck = Scanner.prototype.checkHash;
    const savedScan = Scanner.prototype.scanFile;
    const fsRuntime: typeof import('fs') = require('fs');
    const savedWrite = fsRuntime.writeFileSync;
    fsRuntime.writeFileSync = ((file: any, ...args: any[]) => {
        if (file === getAgentCredentialsPath(state)) {
            saves++;
            if (failNextSave) {
                failNextSave = false;
                savedWrite(file, '{');
                throw new Error('Controlled partial credential write');
            }
        }
        return (savedWrite as any)(file, ...args);
    }) as typeof fs.writeFileSync;
    axios.defaults.adapter = async (request: any) => {
        if (!request.url?.endsWith('/agents/register')) throw new Error('Unexpected offline request');
        const pending = deferred<any>();
        requests.push(pending);
        const data = await pending.promise;
        return { data, status: 200, statusText: 'OK', headers: {}, config: request };
    };
    function observe(scanner: Scanner, file?: string) {
        scanners.add(scanner);
        const value = scanner as any;
        observations.push({ token: value.api.apiKey, sensitive: value.sensitivePolicy,
            semantic: value.semanticPolicy, max: value.maxFileSizeMb, file });
    }
    Scanner.prototype.checkHash = async function () { observe(this); return response(); };
    Scanner.prototype.scanFile = async function (file) {
        observe(this, file);
        return scanBarrier ? scanBarrier.promise : response(file);
    };
    plugin.register({
        logger: { info() {}, warn() {}, error() {} },
        runtime: { state: { resolveStateDir: () => state } },
        config: { plugins: { entries: { 'openclaw-plugin-vt-sentinel': {
            config: { autoScan: false, watchDirs: [files], ...config },
        } } } },
        registerTool: (tool: any) => { tools[tool.name] = tool; },
        registerService: (value: any) => { service = value; },
        registerHook: (event: string, handler: any) => { hooks[event] = handler; },
    } as any);
    const watcherHandler = (plugin.register as any)._handleWatcherFile;
    const blocklist: Map<string, ScanResult> = (plugin.register as any)._blocklist;
    return {
        state, files, requests, scanners, observations, service, blocklist,
        get saves() { return saves; },
        failSave: () => { failNextSave = true; },
        call: (name = 'vt_check_hash', params: any = { hash: 'a'.repeat(64) }) => tools[name].execute({}, params),
        wave: () => Array.from({ length: 50 }, () => tools.vt_check_hash.execute({}, { hash: 'a'.repeat(64) })),
        register: () => tools.vt_sentinel_re_register.execute({}, { confirm: true }),
        configure: (params: any) => tools.vt_sentinel_configure.execute({}, { ...params, persist: 'session' }),
        hook: (file: string) => hooks.tool_result_persist({ toolName: 'write', toolParams: { path: file }, toolResult: '' }),
        watcher: (file: string) => watcherHandler(file),
        holdScan: () => { scanBarrier = deferred<ScanResult>(); return scanBarrier; },
        resolve: (index: number, id: string) => requests[index].resolve({ agent_id: id, agent_token: `test-token-${id}`, public_handle: `test-${id}` }),
        close: () => {
            service.stop();
            axios.defaults.adapter = savedAdapter;
            Scanner.prototype.checkHash = savedCheck;
            Scanner.prototype.scanFile = savedScan;
            fsRuntime.writeFileSync = savedWrite;
            fs.rmSync(root, { recursive: true, force: true });
        },
    };
}

export async function testScannerLifecycle(assert: Check): Promise<void> {
    console.log('\n=== Concurrent scanner initialization and lifecycle ===\n');
    {
        const f = fixture();
        try {
            const first = f.wave();
            await until(() => f.requests.length > 0);
            assert(f.requests.length === 1, 'initialization: 50 concurrent calls share one registration');
            f.requests[0].reject(new Error('Controlled registration failure'));
            const failed = await Promise.all(first);
            assert(failed.every(result => result.content[0].text.startsWith('Error:')), 'initialization: all 50 callers observe the shared failure');
            assert(f.saves === 0 && f.scanners.size === 0, 'initialization: failed wave publishes no credential or scanner');
            const second = f.wave();
            await until(() => f.requests.length > 1);
            assert(f.requests.length === 2, 'initialization: second wave of 50 starts only one retry');
            f.resolve(1, 'retry');
            await Promise.all(second);
            assert(f.saves === 1 && f.scanners.size === 1 && f.observations.length === 50,
                'initialization: retry shares one persisted identity and one scanner');
            await Promise.all(f.wave());
            assert(f.requests.length === 2 && f.scanners.size === 1, 'initialization: subsequent calls reuse initialized scanner');
        } finally { f.close(); }
    }
    for (const mode of ['cached', 'user-key']) {
        const f = fixture(mode === 'user-key' ? { apiKey: 'offline-user-key' } : {}, mode === 'cached' ? 'cached' : undefined);
        try {
            await Promise.all(f.wave());
            assert(f.requests.length === 0 && f.scanners.size === 1 && f.saves === 0,
                `initialization: ${mode} creates no registration and reuses scanner`);
        } finally { f.close(); }
    }
    for (const reset of [false, true]) {
        const f = fixture({ sensitiveFilePolicy: 'hash_only', semanticFilePolicy: 'hash_only', maxFileSizeMb: 2 });
        try {
            await f.configure({ sensitiveFilePolicy: 'always_upload', semanticFilePolicy: 'always_upload', maxFileSizeMb: 100 });
            const pending = f.call();
            await until(() => f.requests.length === 1);
            if (reset) await f.call('vt_sentinel_reset_policy', {});
            else await f.configure({ sensitiveFilePolicy: 'hash_only', semanticFilePolicy: 'hash_only', maxFileSizeMb: 2 });
            f.resolve(0, 'policy');
            await pending;
            const actual = f.observations[0];
            assert(actual.sensitive === 'hash_only' && actual.semantic === 'hash_only' && actual.max === 2,
                `initialization: ${reset ? 'reset' : 'configure'} while awaiting registration applies current restrictions`);
        } finally { f.close(); }
    }
    {
        const f = fixture();
        try {
            const automatic = f.call();
            await until(() => f.requests.length === 1);
            const explicit = f.register();
            await new Promise<void>(resolve => setImmediate(resolve));
            assert(f.requests.length === 1, 're-register: explicit identity waits for automatic registration');
            f.resolve(0, 'automatic');
            await until(() => f.requests.length === 2);
            assert(loadAgentCredentials(f.state)?.agentId === 'automatic', 're-register: pending replacement retains completed automatic identity');
            await f.configure({ sensitiveFilePolicy: 'hash_only', semanticFilePolicy: 'hash_only' });
            f.resolve(1, 'explicit');
            const result = await explicit;
            await automatic;
            await f.call();
            assert(result.content[0].text.includes('successfully') && loadAgentCredentials(f.state)?.agentId === 'explicit',
                're-register: explicit success is the persisted identity');
            assert(JSON.parse(fs.readFileSync(getAgentCredentialsPath(f.state) + '.bak', 'utf8')).agentId === 'automatic',
                're-register: backup captures identity at execution time');
            const last = f.observations[f.observations.length - 1];
            assert(last.token === 'test-token-explicit' && last.sensitive === 'hash_only' && last.semantic === 'hash_only',
                're-register: replacement scanner uses new token and current policies');
        } finally { f.close(); }
    }
    {
        const f = fixture({}, 'original');
        try {
            await f.call();
            const failed = f.register();
            const success = f.register();
            const consumer = f.call();
            await until(() => f.requests.length === 1);
            assert(f.requests.length === 1, 're-register: two explicit requests are ordered, not coalesced');
            f.requests[0].reject(new Error('Controlled replacement failure'));
            const result = await failed;
            await until(() => f.requests.length === 2);
            assert(result.content[0].text.includes('failed') && loadAgentCredentials(f.state)?.agentId === 'original',
                're-register: failed operation preserves previous credentials');
            f.resolve(1, 'replacement');
            await success;
            await consumer;
            assert(loadAgentCredentials(f.state)?.agentId === 'replacement' && f.observations[f.observations.length - 1]?.token === 'test-token-replacement',
                're-register: failure does not poison queue; waiting consumer uses successful replacement');
        } finally { f.close(); }
    }
    {
        const f = fixture();
        try {
            const explicit = f.register();
            await until(() => f.requests.length === 1);
            const consumers = f.wave();
            f.resolve(0, 'explicit-first');
            await explicit;
            await Promise.all(consumers);
            assert(f.requests.length === 1 && f.scanners.size === 1 && f.observations.every(value => value.token === 'test-token-explicit-first'),
                're-register: cold explicit registration supplies later initialization without an extra identity');
        } finally { f.close(); }
    }
    {
        const f = fixture({ autoScan: true });
        try {
            const file = path.join(f.files, 'pending.sh');
            fs.writeFileSync(file, '#!/bin/sh\necho offline');
            const old = f.watcher(file);
            await until(() => f.requests.length === 1);
            f.service.stop();
            f.service.start();
            const current = f.call();
            f.resolve(0, 'restart');
            await old;
            await current;
            assert(f.requests.length === 1 && f.saves === 1, 'stop/start: pending issued credential is saved once and reused');
            assert(f.observations.length === 1 && !f.observations[0].file,
                'stop/start: stale automatic scan is discarded, new manual lookup succeeds');
        } finally { f.close(); }
    }
    {
        const f = fixture({ autoScan: true });
        try {
            const file = path.join(f.files, 'disable.sh');
            fs.writeFileSync(file, '#!/bin/sh\necho offline');
            const old = f.hook(file);
            await until(() => f.requests.length === 1);
            await f.configure({ autoScan: false });
            f.resolve(0, 'disabled');
            await old;
            assert(f.observations.length === 0, 'autoScan=false: pending tool-result continuation performs no scan');
            await f.call();
            assert(f.observations.length === 1 && f.requests.length === 1, 'autoScan=false: manual tools still reuse scanner');
        } finally { f.close(); }
    }
    {
        const f = fixture({ autoScan: true }, 'cached');
        try {
            const file = path.join(f.files, 'in-flight.sh');
            fs.writeFileSync(file, '#!/bin/sh\necho offline');
            const barrier = f.holdScan();
            const old = f.watcher(file);
            await until(() => f.observations.length === 1);
            f.service.stop();
            barrier.resolve({ ...response(file), verdict: 'malicious' });
            await old;
            assert(fs.existsSync(file) && f.blocklist.size === 0, 'stop: result already in flight cannot quarantine or block after stop');
            const stopped = await f.call();
            assert(stopped.content[0].text.includes('stopped') && f.observations.length === 1, 'stop: manual call reports stopped lifecycle without scanning');
        } finally { f.close(); }
    }
    {
        const f = fixture();
        try {
            const file = getAgentCredentialsPath(f.state);
            fs.writeFileSync(file, 'pre-existing unreadable credential data');
            const savesBefore = f.saves;
            const pending = f.register();
            await until(() => f.requests.length === 1);
            f.requests[0].reject(new Error('Registration failed before saving'));
            await pending;
            assert(fs.readFileSync(file, 'utf8') === 'pre-existing unreadable credential data' && f.saves === savesBefore,
                're-register: failure before saving leaves pre-existing unparseable file untouched');
        } finally { f.close(); }
    }
    for (const cached of [undefined, 'previous']) {
        const f = fixture({}, cached);
        try {
            if (cached) await f.call();
            const pending = f.register();
            await until(() => f.requests.length === 1);
            f.failSave();
            f.resolve(0, 'write-failed');
            const result = await pending;
            assert(result.content[0].text.includes('failed'), 're-register: partial credential write is reported as failure');
            assert(cached ? loadAgentCredentials(f.state)?.agentId === cached : !fs.existsSync(getAgentCredentialsPath(f.state)),
                `re-register: partial write restores ${cached ? 'previous identity' : 'absence of credentials'}`);
            if (cached) {
                await f.call();
                assert(f.observations[f.observations.length - 1].token === 'test-token-previous',
                    're-register: failed credential write retains previous scanner');
            }
        } finally { f.close(); }
    }
    // Control the debounce clock and watcher events, avoiding timing-sensitive sleeps.
    {
        const chokidarRuntime: typeof import('chokidar') = require('chokidar');
        const savedWatch = chokidarRuntime.watch;
        const savedTimeout = global.setTimeout;
        const savedClear = global.clearTimeout;
        const timers = new Map<any, () => void>();
        const watchers: EventEmitter[] = [];
        chokidarRuntime.watch = (() => {
            const watcher = Object.assign(new EventEmitter(), { close: async () => {}, add() {}, unwatch() {} });
            watchers.push(watcher);
            return watcher;
        }) as any;
        global.setTimeout = ((callback: () => void, delay: number, ...args: any[]) => {
            if (delay !== 1500) return (savedTimeout as any)(callback, delay, ...args);
            const timer = {};
            timers.set(timer, callback);
            return timer;
        }) as any;
        global.clearTimeout = ((timer: any) => {
            if (timers.has(timer)) timers.delete(timer);
            else savedClear(timer);
        }) as any;
        const f = fixture({ autoScan: true });
        try {
            f.service.start();
            watchers[0].emit('add', path.join(f.files, 'old.sh'));
            assert(timers.size === 1, 'debounce: file event schedules delayed work');
            const lateCallback = [...timers.values()][0];
            f.service.stop();
            f.service.start();
            lateCallback();
            watchers[0].emit('add', path.join(f.files, 'late.sh'));
            await new Promise<void>(resolve => setImmediate(resolve));
            assert(timers.size === 0 && f.requests.length === 0, 'debounce: stop cancels timers and stale watcher callbacks cannot register');
            for (let i = 0; i < 50; i++) watchers[1].emit('add', path.join(f.files, `new-${i}.sh`));
            const callbacks = [...timers.values()];
            timers.clear();
            callbacks.forEach(callback => callback());
            await until(() => f.requests.length === 1);
            f.resolve(0, 'watcher-wave');
            await until(() => f.observations.length === 50);
            assert(f.requests.length === 1 && f.scanners.size === 1 && f.saves === 1,
                'debounce: 50 new-file callbacks share one registration and scanner');
            watchers[1].emit('change', path.join(f.files, 'disabled.sh'));
            await f.configure({ autoScan: false });
            assert(timers.size === 0, 'debounce: disabling auto-scan cancels pending timers');
        } finally {
            f.close();
            chokidarRuntime.watch = savedWatch;
            global.setTimeout = savedTimeout;
            global.clearTimeout = savedClear;
        }
    }
}
