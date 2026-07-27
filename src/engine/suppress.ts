import type { Finding } from '../types.js';
import { classifySecret } from './secret-matrix.js';
import { debug } from './helpers.js';

/**
 * Findings may carry a non-schema side channel with the raw matched value and
 * context, used only here. zod strips these before the report is emitted.
 */
export interface SuppressibleFinding extends Finding {
  _raw?: string;
  _name?: string;
  _line?: string;
}

/**
 * Static-asset paths that should never carry a "missing rate limit" finding —
 * they are cached/CDN-served and rate-limiting them is neither expected nor
 * useful. Matches both path prefixes and asset file extensions.
 */
const STATIC_ASSET =
  /(^|\/)(_next\/static|favicon\.ico|assets|images|img|fonts|static)(\/|$)|\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot)($|\?)/i;

/**
 * Paths that look like a DOCUMENTED public API — a wildcard CORS policy on
 * these is often intentional, so we lower confidence rather than dropping.
 */
const DOCUMENTED_PUBLIC_API = /(^|\/)(public|\.well-known|openapi|swagger|docs)(\/|$)|\/v\d+\/public/i;

/** The location string(s) a finding can be keyed on for path matching. */
function locationText(f: Finding): string {
  return `${f.location?.file ?? ''} ${f.location?.url ?? ''} ${f.evidence ?? ''}`;
}

/**
 * Final false-positive pass:
 *  - secrets-category findings whose raw value is public-by-design are dropped;
 *  - "missing rate limit" findings on static-asset paths are dropped (scaffolding
 *    for a future rate-limit rule — inert until one emits RATE_LIMIT_* findings);
 *  - wildcard-CORS findings on documented public-API paths are down-ranked to
 *    low confidence rather than dropped.
 * This double-guards the inline checks the individual rules already do.
 */
export function suppress(findings: SuppressibleFinding[]): Finding[] {
  const kept: Finding[] = [];
  for (const f of findings) {
    if (f.category === 'secrets' && f._raw) {
      const c = classifySecret(f._raw, { name: f._name, line: f._line });
      if (c.verdict === 'public') {
        debug(`suppressed ${f.ruleId} @ ${f.location?.file ?? f.location?.url ?? '?'}: ${c.reason}`);
        continue;
      }
    }

    // Drop missing-rate-limit findings on static assets (no rate-limit rule
    // ships today; this stays correct if/when one lands).
    if (/RATE_LIMIT/i.test(f.ruleId) && STATIC_ASSET.test(locationText(f))) {
      debug(`suppressed ${f.ruleId} @ ${f.location?.url ?? f.location?.file ?? '?'}: static asset path`);
      continue;
    }

    // Strip the side-channel fields so the emitted finding stays schema-clean.
    const { _raw, _name, _line, ...clean } = f;
    void _raw;
    void _name;
    void _line;

    // Lower confidence on wildcard-CORS findings that look like a documented
    // public API (intentional openness), instead of dropping them.
    if (clean.ruleId === 'WEB_CONFIG_CORS_WILDCARD_CREDENTIALS' && DOCUMENTED_PUBLIC_API.test(locationText(clean))) {
      debug(`down-ranked ${clean.ruleId} @ ${clean.location?.file ?? clean.location?.url ?? '?'}: documented public API`);
      clean.confidence = 'low';
    }

    kept.push(clean);
  }
  return kept;
}
