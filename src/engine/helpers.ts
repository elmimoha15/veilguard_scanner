import type { Helpers } from '../types.js';

/** Global debug flag, flipped on by the CLI's --debug. */
let DEBUG = false;
export function setDebug(on: boolean): void {
  DEBUG = on;
}

export function debug(...args: unknown[]): void {
  if (DEBUG) console.error('[debug]', ...args);
}

/**
 * Fetch a URL with a bounded timeout, returning normalized headers + body, or
 * null on any network error / timeout. Never throws.
 */
export async function httpGet(
  url: string,
  opts: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number } = {},
): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10000);
  try {
    const res = await fetch(url, {
      method: opts.method ?? 'GET',
      headers: { 'user-agent': 'veilguard-scanner/0.1', ...opts.headers },
      body: opts.body,
      redirect: 'follow',
      signal: controller.signal,
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      // Preserve multiple set-cookie values by joining with newline.
      headers[k.toLowerCase()] = headers[k.toLowerCase()]
        ? `${headers[k.toLowerCase()]}\n${v}`
        : v;
    });
    const body = await res.text();
    return { status: res.status, headers, body };
  } catch (err) {
    debug('httpGet failed', url, (err as Error).message);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Scan text for all matches of a (global) regex, returning the match plus a
 * 1-based line number. Clones the regex to avoid lastIndex surprises.
 */
export function safeRegexScan(
  text: string,
  re: RegExp,
): { match: string; line: number; index: number; groups: (string | undefined)[] }[] {
  const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
  const rx = new RegExp(re.source, flags);
  const out: { match: string; line: number; index: number; groups: (string | undefined)[] }[] = [];
  let m: RegExpExecArray | null;
  while ((m = rx.exec(text)) !== null) {
    const index = m.index;
    const line = text.slice(0, index).split('\n').length;
    out.push({ match: m[0], line, index, groups: m.slice(1) });
    if (m.index === rx.lastIndex) rx.lastIndex++; // guard against zero-width
  }
  return out;
}

/** Redact a secret, keeping a short recognizable prefix and a masked tail. */
export function redact(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return '****';
  const prefix = v.slice(0, Math.min(10, Math.floor(v.length / 3)));
  return `${prefix}…${'*'.repeat(6)} (redacted)`;
}

/** Shannon entropy in bits/char. High entropy (>4) suggests a random secret. */
export function entropy(value: string): number {
  if (!value) return 0;
  const freq: Record<string, number> = {};
  for (const ch of value) freq[ch] = (freq[ch] ?? 0) + 1;
  let e = 0;
  const len = value.length;
  for (const ch in freq) {
    const p = freq[ch]! / len;
    e -= p * Math.log2(p);
  }
  return e;
}

export const helpers: Helpers = {
  httpGet: (url, opts) => httpGet(url, opts),
  safeRegexScan,
  redact,
  entropy,
  debug,
};
