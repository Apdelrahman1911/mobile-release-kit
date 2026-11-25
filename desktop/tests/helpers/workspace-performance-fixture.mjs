// Isolated source renderer only. Effects do not run, so no native port connects.
import { performance } from 'node:perf_hooks';
const started = performance.now();
const React = await import('react');
const { renderToStaticMarkup } = await import('react-dom/server');
const { App } = await import('../../src/App.tsx');
const imported = performance.now();
const html = renderToStaticMarkup(React.createElement(App));
const rendered = performance.now();
global.gc?.();
const memory = process.memoryUsage();
const cpu = process.cpuUsage();
const idle = performance.now();
await new Promise((resolve) => setTimeout(resolve, 2000));
const idleCpu = process.cpuUsage(cpu);
process.stdout.write(JSON.stringify({ scope: 'source-SSR-no-effects',
  importMs: imported - started, renderMs: rendered - imported, htmlBytes: Buffer.byteLength(html),
  memory, idleMs: performance.now() - idle, idleCpuMs: (idleCpu.user + idleCpu.system) / 1000 }) + '\n');
