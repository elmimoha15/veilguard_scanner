import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';

const OPEN_RULE = /allow\s+(read|write|read\s*,\s*write|get|list|create|update|delete)\s*:\s*if\s+true/gi;

/**
 * White-box scan of Firebase security rules files (firestore.rules,
 * storage.rules) for wide-open `allow …: if true` grants.
 */
export const firebaseRules: Rule = {
  id: 'DATABASE_FIREBASE_RULES_OPEN',
  category: 'database',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];

    const ruleFiles = repo.files.filter((f) => /\.rules$/.test(f) || /(firestore|storage)\.rules/.test(f));
    const out: Finding[] = [];

    for (const file of ruleFiles) {
      const content = repo.readFile(file);
      if (!content) continue;
      for (const m of safeRegexScan(content, OPEN_RULE)) {
        out.push({
          ruleId: 'DATABASE_FIREBASE_RULES_OPEN',
          category: 'database',
          severity: 'critical',
          cwe: 'CWE-1220',
          owasp: 'A01:2021',
          title: 'Your Firebase security rules are wide open',
          whyItMatters:
            '`allow read, write: if true` lets anyone on the internet read and overwrite your entire database or storage bucket.',
          evidence: m.match,
          location: { file, line: m.line },
          fix: 'Replace `if true` with ownership checks, e.g. `allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;`.',
          fixPrompt:
            'Rewrite these Firebase security rules so reads/writes require authentication AND ownership (request.auth.uid must match the document owner), instead of `if true`.',
          confidence: 'high',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }
    return out;
  },
};
