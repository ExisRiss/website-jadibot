#!/usr/bin/env node
/**
 * Bounded, non-destructive production availability check.
 * Limits: one public health endpoint, <=5 requests/sec, <=3 in flight, <=30 sec.
 */
import { writeFile } from 'node:fs/promises';

const target = 'https://website-jadibot-by-alzriss.vercel.app/api/health';
const durationMs = 30_000;
const intervalMs = 200; // hard ceiling of 5 request starts / sec
const maxConcurrency = 3;
const requestTimeoutMs = 3_000;
const slowThresholdMs = 2_000;
const maxServerErrorsBeforeStop = 3;
const maxConsecutiveSlowBeforeStop = 3;

const startedAt = Date.now();
let active = 0;
let attempted = 0;
let stopReason = null;
let consecutiveSlow = 0;
const results = [];

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

async function check() {
  active += 1;
  attempted += 1;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
  const began = performance.now();
  const item = { at: new Date().toISOString() };

  try {
    const response = await fetch(target, {
      method: 'GET',
      headers: { accept: 'application/json', 'user-agent': 'Umi-Safe-Load-Check/1.0' },
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    });
    item.status = response.status;
    item.ok = response.ok;
    // Consume a bounded portion of the public health response before releasing the connection.
    item.bodyBytes = (await response.text()).slice(0, 4096).length;
  } catch (error) {
    item.status = null;
    item.ok = false;
    item.error = error.name === 'AbortError' ? 'request timeout' : String(error.message).slice(0, 160);
  } finally {
    clearTimeout(timer);
    item.latencyMs = Math.round(performance.now() - began);
    results.push(item);
    active -= 1;

    if (item.latencyMs > slowThresholdMs) consecutiveSlow += 1;
    else consecutiveSlow = 0;

    const serverErrors = results.filter((r) => r.status >= 500).length;
    if (!stopReason && serverErrors >= maxServerErrorsBeforeStop) {
      stopReason = `safety stop: ${serverErrors} server errors observed`;
    }
    if (!stopReason && consecutiveSlow >= maxConsecutiveSlowBeforeStop) {
      stopReason = `safety stop: ${consecutiveSlow} consecutive responses slower than ${slowThresholdMs} ms`;
    }
  }
}

const scheduler = setInterval(() => {
  if (stopReason || Date.now() - startedAt >= durationMs) return;
  if (active < maxConcurrency) void check();
}, intervalMs);

while (!stopReason && Date.now() - startedAt < durationMs) {
  await new Promise((resolve) => setTimeout(resolve, 100));
}
clearInterval(scheduler);
while (active > 0) await new Promise((resolve) => setTimeout(resolve, 25));

const latencies = results.map((r) => r.latencyMs).sort((a, b) => a - b);
const statusCounts = Object.fromEntries(
  [...new Set(results.map((r) => String(r.status ?? 'network_error')))]
    .sort()
    .map((code) => [code, results.filter((r) => String(r.status ?? 'network_error') === code).length]),
);
const report = {
  test: 'bounded non-destructive production health check',
  target,
  guardrails: {
    durationLimitMs: durationMs,
    requestStartLimitPerSecond: 1000 / intervalMs,
    concurrencyLimit: maxConcurrency,
    endpointType: 'public read-only health endpoint',
    automaticStop: `>=${maxServerErrorsBeforeStop} HTTP 5xx responses or ${maxConsecutiveSlowBeforeStop} consecutive responses >${slowThresholdMs}ms`,
  },
  startedAt: new Date(startedAt).toISOString(),
  finishedAt: new Date().toISOString(),
  elapsedMs: Date.now() - startedAt,
  stopReason: stopReason ?? 'completed duration normally',
  requests: {
    attempted,
    completed: results.length,
    successful2xx: results.filter((r) => r.status >= 200 && r.status < 300).length,
    clientErrors4xx: results.filter((r) => r.status >= 400 && r.status < 500).length,
    serverErrors5xx: results.filter((r) => r.status >= 500).length,
    transportOrTimeoutErrors: results.filter((r) => r.status === null).length,
    statusCounts,
  },
  latencyMs: {
    min: latencies[0] ?? null,
    p50: percentile(latencies, 50),
    p95: percentile(latencies, 95),
    p99: percentile(latencies, 99),
    max: latencies.at(-1) ?? null,
    average: latencies.length ? Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length) : null,
  },
  samples: results,
};

await writeFile('security-load-test-results.json', `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));

if (report.requests.serverErrors5xx || report.requests.transportOrTimeoutErrors) process.exitCode = 1;
