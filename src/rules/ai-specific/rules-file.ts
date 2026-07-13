import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';

const RULES_FILE = /(^|\/)(\.cursorrules|CLAUDE\.md|AGENTS\.md|\.windsurfrules|\.clinerules)$|(^|\/)\.cursor\/rules\//;

const RISKY: { re: RegExp; label: string }[] = [
  { re: /\b(skip|disable|bypass|ignore|turn off|no need for)\b[^.\n]{0,40}\b(auth|authentication|authorization|security|validation|verification)\b/gi, label: 'instruction to skip auth/validation/security' },
  { re: /\b(hardcode|hard-code|embed)\b[^.\n]{0,30}\b(secret|key|token|password|credential)\b/gi, label: 'instruction to hardcode secrets' },
  { re: /\b(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED)\b/gi, label: 'instruction to disable TLS verification' },
  { re: /(base[_-]?url|api[_-]?base|endpoint)\s*[:=]\s*["']https?:\/\/(?!localhost)[^"']+["']/gi, label: 'base-URL override pointing off-host' },
  { re: /\b(exfiltrat|send .* to|POST .* to)\b[^.\n]{0,30}(http|webhook|external)/gi, label: 'possible data-exfiltration instruction' },
];

/**
 * White-box: AI coding-assistant rules files that instruct the model to weaken
 * security (skip auth, hardcode secrets, disable TLS, override the base URL).
 */
export const rulesFile: Rule = {
  id: 'AI_RISKY_RULES_FILE',
  category: 'ai_specific',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!RULES_FILE.test(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;

      for (const r of RISKY) {
        for (const m of safeRegexScan(content, r.re)) {
          out.push({
            ruleId: 'AI_RISKY_RULES_FILE',
            category: 'ai_specific',
            severity: 'high',
            cwe: 'CWE-1104',
            title: `Your AI rules file weakens security (${path})`,
            whyItMatters: `This file tells your AI coding tool to ${r.label}, so every feature it generates inherits the weakness.`,
            evidence: m.match.slice(0, 80),
            location: { file: path, line: m.line },
            fix: `Remove the “${r.label}” instruction from ${path}. AI rules files should reinforce security, not disable it.`,
            fixPrompt: `Edit ${path} to remove any instruction that tells the assistant to skip authentication, hardcode secrets, disable TLS verification, or override the API base URL. Replace them with instructions to always enforce auth and validation.`,
            confidence: 'medium',
            mode: 'whitebox',
            source: 'native',
          });
        }
      }
    }
    return out;
  },
};
