import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

// Privileged fields written straight from the request body.
const TAMPER = /\b(isPro|isAdmin|is_admin|role|tier|plan|credits|balance|isPremium|subscription_status)\b\s*[:=]\s*(req|request)\.body/gi;
// Spreading the whole body into an update/insert (`...req.body`).
const SPREAD_BODY = /\.\.\.(req|request)\.body\b/g;

/**
 * White-box mass-assignment / payment-flag tampering: privileged fields set
 * directly from the client-controlled request body.
 */
export const massAssignment: Rule = {
  id: 'API_MASS_ASSIGNMENT',
  category: 'api_webhooks',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;

      // Collect all privileged fields set from the body, report once per file.
      const tamperHits = safeRegexScan(content, TAMPER);
      if (tamperHits.length > 0) {
        const fields = [...new Set(tamperHits.map((h) => h.groups[0]).filter(Boolean))];
        out.push(mk(path, tamperHits[0]!.line, `Privileged fields set from the request body: ${fields.join(', ')}`, 'high'));
      }

      // Spread into a db write is the more dangerous shape.
      for (const m of safeRegexScan(content, SPREAD_BODY)) {
        const around = content.slice(Math.max(0, m.index - 60), m.index + 40);
        if (/update|insert|create|set|save/i.test(around)) {
          out.push(mk(path, m.line, 'The entire request body is written to the database (…req.body)', 'high'));
          break;
        }
      }
    }
    return out;
  },
};

function mk(file: string, line: number, why: string, severity: Finding['severity']): Finding {
  return {
    ruleId: 'API_MASS_ASSIGNMENT',
    category: 'api_webhooks',
    severity,
    cwe: 'CWE-915',
    owasp: 'A08:2021',
    title: 'Users can grant themselves privileges by tampering with the request',
    whyItMatters: 'Writing client-controlled fields like isAdmin/tier/credits lets a user upgrade their own account or role for free.',
    evidence: why,
    location: { file, line },
    fix: 'Never trust client input for privileged fields. Pick an explicit allowlist of updatable fields and set role/tier/credits server-side only.',
    fixPrompt:
      'Change this handler so it only writes an explicit allowlist of user-editable fields, and never sets privileged fields (isAdmin, role, tier, credits) from req.body. Determine those server-side.',
    confidence: 'medium',
    mode: 'whitebox',
    source: 'native',
  };
}
