import { readFileSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import fg from 'fast-glob';
import { parse as babelParse } from '@babel/parser';
import * as cheerio from 'cheerio';
import type {
  ScanContext,
  Target,
  HttpArtifacts,
  DiscoveredConfig,
  RepoArtifacts,
  PackageManifest,
  BabelFile,
  JsBundle,
} from '../types.js';
import { helpers, httpGet, debug } from './helpers.js';

/** Decide whether a target string is a URL or a local repo path. */
export function detectTargetType(value: string): Target {
  if (/^https?:\/\//i.test(value)) return { type: 'url', value };
  return { type: 'repo', value: resolve(value) };
}

/* -------------------------------------------------------------------------- */
/* Black-box recon (URL targets)                                               */
/* -------------------------------------------------------------------------- */

const CONFIG_PATTERNS = {
  supabaseUrl: /https:\/\/([a-z0-9]{20})\.supabase\.co/i,
  // Legacy Supabase public key: an anon JWT (role "anon").
  supabaseAnonJwt: /(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/,
  // Newer Supabase public key format (managed backends: Bolt/Lovable/v0 ship these).
  supabasePublishableKey: /(sb_publishable_[A-Za-z0-9_-]{10,})/,
  firebaseApiKey: /["']?apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{35})["']/,
};

/**
 * Pull the Supabase/Firebase public config out of a set of text blobs (the
 * homepage HTML + JS bundles). Pure + deterministic so the black-box probe's
 * detection step can be unit-tested without hitting the network.
 *
 * `supabaseAnonKey` holds whichever PUBLIC key the app ships to every visitor —
 * the newer `sb_publishable_…` key is preferred, falling back to a legacy anon
 * JWT. Both are valid `apikey` values for the PostgREST endpoint. We only look
 * for a key once a Supabase project URL is present (a bare JWT elsewhere is not
 * ours to probe with).
 */
export function extractDiscovered(haystacks: string[]): DiscoveredConfig {
  const discovered: DiscoveredConfig = {};

  for (const hay of haystacks) {
    if (!discovered.supabaseUrl) {
      const m = hay.match(CONFIG_PATTERNS.supabaseUrl);
      if (m) discovered.supabaseUrl = m[0];
    }
    if (!discovered.firebaseConfig) {
      const m = hay.match(CONFIG_PATTERNS.firebaseApiKey);
      if (m) discovered.firebaseConfig = { apiKey: m[1]! };
    }
  }

  if (discovered.supabaseUrl) {
    for (const hay of haystacks) {
      const pub = hay.match(CONFIG_PATTERNS.supabasePublishableKey);
      if (pub) {
        discovered.supabaseAnonKey = pub[1];
        break;
      }
    }
    if (!discovered.supabaseAnonKey) {
      for (const hay of haystacks) {
        const jwt = hay.match(CONFIG_PATTERNS.supabaseAnonJwt);
        if (jwt) {
          discovered.supabaseAnonKey = jwt[1];
          break;
        }
      }
    }
  }

  return discovered;
}

async function reconUrl(baseUrl: string): Promise<{ http: HttpArtifacts; discovered: DiscoveredConfig }> {
  const home = await httpGet(baseUrl);
  const http: HttpArtifacts = {
    baseUrl,
    reachable: home !== null,
    status: home?.status,
    homepageHtml: home?.body ?? '',
    headers: home?.headers ?? {},
    jsBundles: [],
    cookies: home?.headers['set-cookie'] ? home.headers['set-cookie'].split('\n') : [],
  };

  let discovered: DiscoveredConfig = {};

  if (home) {
    // Collect script srcs from the homepage HTML, fetch a bounded number.
    const $ = cheerio.load(home.body);
    const scriptUrls = new Set<string>();
    $('script[src]').each((_, el) => {
      const src = $(el).attr('src');
      if (!src) return;
      try {
        scriptUrls.add(new URL(src, baseUrl).toString());
      } catch {
        /* ignore malformed */
      }
    });

    const bundles: JsBundle[] = [];
    const list = [...scriptUrls].slice(0, 15);
    await Promise.all(
      list.map(async (u) => {
        const r = await httpGet(u);
        if (r && r.status === 200 && r.body) bundles.push({ url: u, content: r.body });
      }),
    );
    http.jsBundles = bundles;

    // Parse Supabase/Firebase public config out of the HTML + bundles.
    discovered = extractDiscovered([home.body, ...bundles.map((b) => b.content)]);
  }

  return { http, discovered };
}

/* -------------------------------------------------------------------------- */
/* White-box recon (repo targets)                                              */
/* -------------------------------------------------------------------------- */

const IGNORE = [
  '**/node_modules/**', '**/.next/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.git/**',
  // Third-party / generated dependency trees — scanning these yields false
  // positives from other people's code and bloats the workspace.
  '**/venv/**', '**/.venv/**', '**/__pycache__/**', '**/vendor/**', '**/.tox/**', '**/.mypy_cache/**', '**/.pytest_cache/**', '**/.gradle/**',
  // Test/fixture/example artifacts — deliberately-vulnerable fixtures and test
  // files aren't deployed, so flagging them as production risks is a false
  // positive. (Bare test/ and tests/ are intentionally NOT ignored — they can
  // hold real code.)
  '**/test-fixtures/**', '**/fixtures/**', '**/__tests__/**', '**/__mocks__/**',
  '**/.storybook/**', '**/cypress/**', '**/e2e/**', '**/*.test.*', '**/*.spec.*', '**/*.stories.*',
];

function buildRepo(root: string): RepoArtifacts {
  const files = fg.sync(['**/*'], {
    cwd: root,
    dot: true,
    ignore: IGNORE,
    onlyFiles: true,
    followSymbolicLinks: false,
    suppressErrors: true,
  });

  const fileCache = new Map<string, string | null>();
  const readFile = (path: string): string | null => {
    if (fileCache.has(path)) return fileCache.get(path)!;
    let content: string | null = null;
    try {
      const abs = join(root, path);
      // Skip absurdly large files (bundles, images).
      if (statSync(abs).size < 2_000_000) content = readFileSync(abs, 'utf8');
    } catch {
      content = null;
    }
    fileCache.set(path, content);
    return content;
  };

  const astCache = new Map<string, BabelFile | null>();
  const astFor = (path: string): BabelFile | null => {
    if (astCache.has(path)) return astCache.get(path)!;
    const content = readFile(path);
    let file: BabelFile | null = null;
    if (content !== null) {
      try {
        const ast = babelParse(content, {
          sourceType: 'unambiguous',
          errorRecovery: true,
          plugins: ['typescript', 'jsx', 'decorators-legacy', 'importAttributes'],
        });
        file = { path, content, ast };
      } catch (err) {
        debug('AST parse failed', path, (err as Error).message);
        file = null;
      }
    }
    astCache.set(path, file);
    return file;
  };

  const sqlFiles = files.filter((f) => f.endsWith('.sql'));
  const envFiles = files.filter((f) => /(^|\/)\.env(\.|$)/.test(f) || /(^|\/)\.env$/.test(f));

  // Locate and parse the nearest package.json (prefer root).
  let packageManifest: PackageManifest | null = null;
  const pkgPath = files.find((f) => f === 'package.json') ?? files.find((f) => f.endsWith('package.json'));
  if (pkgPath) {
    const raw = readFile(pkgPath);
    if (raw) {
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        const dependencies = (parsed.dependencies as Record<string, string>) ?? {};
        const devDependencies = (parsed.devDependencies as Record<string, string>) ?? {};
        packageManifest = {
          path: pkgPath,
          raw: parsed,
          dependencies,
          devDependencies,
          allDeps: { ...dependencies, ...devDependencies },
        };
      } catch {
        debug('package.json parse failed', pkgPath);
      }
    }
  }

  const lockfiles = files.filter((f) =>
    ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb'].some((l) => f.endsWith(l)),
  );

  return { root, files, readFile, sqlFiles, envFiles, packageManifest, lockfiles, astFor };
}

/* -------------------------------------------------------------------------- */
/* Entry                                                                       */
/* -------------------------------------------------------------------------- */

export async function buildContext(target: Target): Promise<ScanContext> {
  if (target.type === 'url') {
    const { http, discovered } = await reconUrl(target.value);
    return { target, http, discovered, helpers };
  }
  const repo = buildRepo(target.value);
  return { target, repo, helpers };
}
