import type { ScanContext, Finding } from '../types.js';

export const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
export const CODE_AND_CONFIG_EXT = /\.(ts|tsx|js|jsx|mjs|cjs|json|env|yml|yaml|toml)$/;

/** True for files we treat as application source (for AST rules). */
export function isSourceFile(path: string): boolean {
  return SOURCE_EXT.test(path);
}

/** Iterate repo source files, yielding [path, content]. No-op for URL targets. */
export function forEachFile(
  ctx: ScanContext,
  filter: (path: string) => boolean,
  cb: (path: string, content: string) => void,
): void {
  const repo = ctx.repo;
  if (!repo) return;
  for (const path of repo.files) {
    if (!filter(path)) continue;
    const content = repo.readFile(path);
    if (content !== null) cb(path, content);
  }
}

/** Convenience: a Finding with sensible defaults. */
export function finding(f: Omit<Finding, 'source'> & { source?: Finding['source'] }): Finding {
  return { source: 'native', ...f };
}
