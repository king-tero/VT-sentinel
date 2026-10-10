/** Test-only home/state paths and socket guard; the caller's HOME is untouched. */
import * as fs from 'fs';
import * as path from 'path';

const osRuntime: typeof import('os') = require('os');
const netRuntime: typeof import('net') = require('net');
const testRoot = fs.mkdtempSync(path.join(osRuntime.tmpdir(), 'vt-sentinel-suite-'));
const testHome = path.join(testRoot, 'home');
const testTmp = path.join(testRoot, 'tmp');
fs.mkdirSync(testHome);
fs.mkdirSync(testTmp);
osRuntime.homedir = () => testHome;
osRuntime.tmpdir = () => testTmp;
process.env.OPENCLAW_STATE_DIR = path.join(testHome, '.openclaw');
netRuntime.Socket.prototype.connect = function (): never {
    throw new Error('Outbound sockets disabled in tests');
};
process.on('exit', () => { fs.rmSync(testRoot, { recursive: true, force: true }); });
