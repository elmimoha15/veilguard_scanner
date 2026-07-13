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
 * Final false-positive pass. Any secrets-category finding whose raw value
 * classifies as public-by-design is dropped. Everything else passes through.
 * This double-guards the inline checks the secret rules already do.
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
    // Strip the side-channel fields so the emitted finding stays schema-clean.
    const { _raw, _name, _line, ...clean } = f;
    void _raw;
    void _name;
    void _line;
    kept.push(clean);
  }
  return kept;
}
