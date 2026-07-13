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
  supabaseAnonKey: /(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/,
  firebaseApiKey: /["']?apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{35})["']/,
};

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

  const discovered: DiscoveredConfig = {};

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

    // Parse Supabase/Firebase config out of the HTML + bundles.
    const haystacks = [home.body, ...bundles.map((b) => b.content)];
    for (const hay of haystacks) {
      const sUrl = hay.match(CONFIG_PATTERNS.supabaseUrl);
      if (sUrl && !discovered.supabaseUrl) discovered.supabaseUrl = sUrl[0];
      const fKey = hay.match(CONFIG_PATTERNS.firebaseApiKey);
      if (fKey && !discovered.firebaseConfig) discovered.firebaseConfig = { apiKey: fKey[1]! };
      // Grab an anon-looking JWT only when a supabase url is nearby.
      if (discovered.supabaseUrl && !discovered.supabaseAnonKey) {
        const jwt = hay.match(CONFIG_PATTERNS.supabaseAnonKey);
        if (jwt) discovered.supabaseAnonKey = jwt[1];
      }
    }
  }

  return { http, discovered };
}

/* -------------------------------------------------------------------------- */
/* White-box recon (repo targets)                                              */
/* -------------------------------------------------------------------------- */

const IGNORE = ['**/node_modules/**', '**/.next/**', '**/dist/**', '**/build/**', '**/coverage/**', '**/.git/**'];

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
