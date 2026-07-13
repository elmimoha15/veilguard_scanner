import type { Rule, Finding, ScanContext } from '../../types.js';
import { forEachCall, calleeName, isTaintedTemplateOrConcat } from '../../engine/ast.js';
import { isSourceFile } from '../_shared.js';

const EXEC = /(^|\.)(exec|execSync|spawn|spawnSync|execFile)$/;

/** White-box OS-command-injection: exec/spawn with an interpolated argument. */
export const commandInjection: Rule = {
  id: 'INJECTION_COMMAND',
  category: 'injection',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const ast = repo.astFor(path);
      if (!ast) continue;

      forEachCall(ast, (node, line) => {
        const name = calleeName(node);
        if (!EXEC.test(name)) return;
        const arg = node.arguments?.[0];
        if (arg && isTaintedTemplateOrConcat(arg)) {
          out.push({
            ruleId: 'INJECTION_COMMAND',
            category: 'injection',
            severity: 'critical',
            cwe: 'CWE-78',
            owasp: 'A03:2021',
            title: 'A shell command is built from untrusted input',
            whyItMatters: 'Splicing input into a shell command lets an attacker run arbitrary commands on your server.',
            evidence: `${name}(…)`,
            location: { file: path, line },
            fix: 'Avoid the shell: pass arguments as an array to execFile/spawn, and validate/allowlist any user-provided values.',
            fixPrompt:
              'Rewrite this to avoid shell interpolation: use execFile or spawn with the command and an array of arguments, and validate any user-supplied values against an allowlist.',
            confidence: 'high',
            mode: 'whitebox',
            source: 'native',
          });
        }
      });
    }
    return out;
  },
};
