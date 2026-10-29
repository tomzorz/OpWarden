// Renders index.html to video. Headless Edge draws each frame at an exact time through the
// DevTools protocol, at 1.5 times the page's 1280 by 720 layout, so the frames are 1080p.
// ffmpeg encodes them into the 1080p MP4 that the README shows, once it is uploaded to GitHub
// as an attachment. Needs Node 22 or later (for its built-in WebSocket), Edge and ffmpeg;
// nothing from npm.
//
//   node render.mjs
//
// EDGE_PATH overrides where Edge is installed.

import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const frames = path.join(here, 'out', 'frames');
const mp4 = path.join(here, 'out', 'opwarden-demo-1080p.mp4');
const edge = process.env.EDGE_PATH ?? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const port = 9332;
const fps = 30;

// The page lays itself out at 1280 by 720; the device pixel ratio scales the frames to 1920 by 1080.
const width = 1280;
const height = 720;
const pixelRatio = 1.5;

await rm(frames, { recursive: true, force: true });
await mkdir(frames, { recursive: true });
await renderFrames();

await run('ffmpeg', ['-y', '-loglevel', 'error', '-framerate', String(fps), '-i', path.join(frames, '%05d.png'),
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '18', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', mp4]);

console.log(`wrote ${mp4}`);

async function renderFrames() {
  const profile = await mkdtemp(path.join(tmpdir(), 'opwarden-demo-'));
  const browser = spawn(edge, [
    '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
    '--hide-scrollbars', '--mute-audio', '--no-first-run', `--window-size=${width},${height}`, 'about:blank',
  ], { stdio: 'ignore' });
  const exited = new Promise(resolve => browser.once('exit', resolve));

  try {
    const page = await connect('page');
    await page.send('Page.enable');
    await page.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: pixelRatio, mobile: false });
    const loaded = page.once('Page.loadEventFired');
    await page.send('Page.navigate', { url: `${pathToFileURL(path.join(here, 'index.html')).href}?render` });
    await loaded;
    await page.evaluate('document.fonts.ready');

    const count = Math.round((await page.evaluate('DURATION')) * fps);
    for (let i = 0; i < count; i++) {
      await page.evaluate(`renderAt(${i / fps})`);
      const { data } = await page.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(path.join(frames, `${String(i).padStart(5, '0')}.png`), Buffer.from(data, 'base64'));
      if (i % fps === 0) process.stdout.write(`\rframe ${i} of ${count}`);
    }

    process.stdout.write(`\rframe ${count} of ${count}\n`);
    page.close();
    await (await connect('browser')).send('Browser.close');
  } finally {
    // Edge holds its profile folder open until it has exited.
    const timeout = setTimeout(() => browser.kill(), 5000);
    await exited;
    clearTimeout(timeout);
    await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
}

// Opens a DevTools session on the page or on the browser itself, once Edge has opened its port.
async function connect(kind) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const url = kind === 'browser'
        ? (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).webSocketDebuggerUrl
        : (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find(t => t.type === 'page')?.webSocketDebuggerUrl;
      if (url) return await session(url);
    } catch {
      // Edge is still starting.
    }

    await new Promise(resolve => setTimeout(resolve, 200));
  }

  throw new Error(`Edge at ${edge} did not open DevTools port ${port} within 10 seconds`);
}

function session(url) {
  const socket = new WebSocket(url);
  const pending = new Map();
  const waiting = new Map();
  let id = 0;

  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    if (message.id === undefined) {
      waiting.get(message.method)?.(message.params);
      waiting.delete(message.method);
      return;
    }

    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(`${message.error.message} (DevTools error ${message.error.code})`));
    else resolve(message.result);
  });

  const api = {
    send: (method, params = {}) => new Promise((resolve, reject) => {
      pending.set(++id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    }),
    once: method => new Promise(resolve => waiting.set(method, resolve)),
    evaluate: async expression => {
      const { result, exceptionDetails } = await api.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
      if (exceptionDetails) throw new Error(`${expression}: ${exceptionDetails.exception?.description ?? exceptionDetails.text}`);
      return result.value;
    },
    close: () => socket.close(),
  };

  return new Promise((resolve, reject) => {
    socket.addEventListener('open', () => resolve(api), { once: true });
    socket.addEventListener('error', () => reject(new Error(`could not open the DevTools socket at ${url}`)), { once: true });
  });
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit' });
    child.on('error', reject);
    child.on('exit', code => (code === 0 ? resolve() : reject(new Error(`${command} exited with ${code}`))));
  });
}
