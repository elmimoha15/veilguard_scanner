import type { Rule, Finding, ScanContext } from '../../types.js';

/**
 * Flags a committed `.env*` file (other than `.env.example`) — especially when
 * `.gitignore` does not exclude it, meaning real secrets are in the repo.
 */
export const committedEnv: Rule = {
  id: 'SECRETS_COMMITTED_ENV',
  category: 'secrets',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];

    const gitignore = repo.readFile('.gitignore') ?? '';
    const ignoresEnv = /^\s*\.env(\*|\.local)?\s*$/m.test(gitignore) || /(^|\n)\.env/.test(gitignore);

    const out: Finding[] = [];
    for (const path of repo.envFiles) {
      if (/\.env\.(example|sample|template)$/.test(path)) continue;
      const content = repo.readFile(path) ?? '';
      const hasValues = /^[A-Z0-9_]+=\S+/m.test(content);
      if (!hasValues) continue;
      out.push({
        ruleId: 'SECRETS_COMMITTED_ENV',
        category: 'secrets',
        severity: 'high',
        cwe: 'CWE-538',
        owasp: 'A05:2021',
        title: `A .env file with real values is committed (${path})`,
        whyItMatters: ignoresEnv
          ? 'Environment files hold secrets; committing one puts them in your git history forever.'
          : 'Your .gitignore does not exclude .env, so secrets get committed and shared with anyone who has the repo.',
        location: { file: path },
        fix: 'Add `.env*` to .gitignore, remove the file from git (`git rm --cached`), and rotate every value it contained.',
        fixPrompt:
          'Add a .gitignore entry for .env and .env.local, remove the committed .env from git tracking with `git rm --cached .env`, and rotate all secrets that were in it.',
        confidence: 'high',
        mode: 'whitebox',
        source: 'native',
      });
    }
    return out;
  },
};
