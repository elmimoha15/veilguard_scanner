import { parse as babelParse } from '@babel/parser';
import type { ScanContext, RepoArtifacts, PackageManifest, BabelFile, HttpArtifacts } from '../src/types.js';
import { helpers } from '../src/engine/helpers.js';

/** Build an in-memory repo ScanContext from a { path: content } map — no disk. */
export function makeRepoContext(files: Record<string, string>): ScanContext {
  const paths = Object.keys(files);
  const readFile = (p: string): string | null => (p in files ? files[p]! : null);

  const astCache = new Map<string, BabelFile | null>();
  const astFor = (p: string): BabelFile | null => {
    if (astCache.has(p)) return astCache.get(p)!;
    const content = readFile(p);
    let file: BabelFile | null = null;
    if (content !== null) {
      try {
        const ast = babelParse(content, {
          sourceType: 'unambiguous',
          errorRecovery: true,
          plugins: ['typescript', 'jsx', 'decorators-legacy'],
        });
        file = { path: p, content, ast };
      } catch {
        file = null;
      }
    }
    astCache.set(p, file);
    return file;
  };

  let packageManifest: PackageManifest | null = null;
  const pkgPath = paths.find((p) => p.endsWith('package.json'));
  if (pkgPath) {
    try {
      const parsed = JSON.parse(files[pkgPath]!) as Record<string, unknown>;
      const dependencies = (parsed.dependencies as Record<string, string>) ?? {};
      const devDependencies = (parsed.devDependencies as Record<string, string>) ?? {};
      packageManifest = { path: pkgPath, raw: parsed, dependencies, devDependencies, allDeps: { ...dependencies, ...devDependencies } };
    } catch {
      /* ignore */
    }
  }

  const repo: RepoArtifacts = {
    root: '/virtual',
    files: paths,
    readFile,
    sqlFiles: paths.filter((p) => p.endsWith('.sql')),
    envFiles: paths.filter((p) => /(^|\/)\.env(\.|$)/.test(p)),
    packageManifest,
    lockfiles: paths.filter((p) => /package-lock\.json|pnpm-lock\.yaml|yarn\.lock/.test(p)),
    astFor,
  };

  return { target: { type: 'repo', value: '/virtual' }, repo, helpers };
}

/** Build a black-box ScanContext from explicit HTTP artifacts. */
export function makeHttpContext(http: Partial<HttpArtifacts>, discovered: ScanContext['discovered'] = {}): ScanContext {
  const full: HttpArtifacts = {
    baseUrl: 'https://example.test',
    reachable: true,
    status: 200,
    homepageHtml: '',
    headers: {},
    jsBundles: [],
    cookies: [],
    ...http,
  };
  return { target: { type: 'url', value: full.baseUrl }, http: full, discovered, helpers };
}
