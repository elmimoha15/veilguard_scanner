/**
 * Tiny semver helpers — just enough for version-range CVE checks. No ranges
 * beyond simple comparisons; we intentionally avoid a dependency here.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

/** Parse a version string, stripping range operators like ^ ~ >= and build/pre tags. */
export function parseVersion(raw: string | undefined): SemVer | null {
  if (!raw) return null;
  const cleaned = raw.trim().replace(/^[\^~>=<v\s]+/, '');
  const m = cleaned.match(/(\d+)\.(\d+)\.(\d+)/) ?? cleaned.match(/(\d+)\.(\d+)/) ?? cleaned.match(/(\d+)/);
  if (!m) return null;
  return {
    major: Number(m[1] ?? 0),
    minor: Number(m[2] ?? 0),
    patch: Number(m[3] ?? 0),
  };
}

/** Returns negative if a<b, 0 if equal, positive if a>b. */
export function compare(a: SemVer, b: SemVer): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

export function lt(a: SemVer, b: SemVer): boolean {
  return compare(a, b) < 0;
}

export function gte(a: SemVer, b: SemVer): boolean {
  return compare(a, b) >= 0;
}

/** True if `v` falls in [min, maxExclusive). */
export function inRange(v: SemVer, min: SemVer, maxExclusive: SemVer): boolean {
  return gte(v, min) && lt(v, maxExclusive);
}

export function v(major: number, minor: number, patch: number): SemVer {
  return { major, minor, patch };
}

export function format(sv: SemVer): string {
  return `${sv.major}.${sv.minor}.${sv.patch}`;
}

/** True when a declared version is a range (^ ~ > < * x || -), not an exact pin. */
export function isRange(raw: string | undefined): boolean {
  return !!raw && /[\^~><*|x]|\s-\s|latest|next|canary/i.test(raw.trim());
}

export interface InstalledVersion {
  /** The version string to evaluate. */
  version: string;
  /** Where it came from: an exact lockfile entry, an exact pin, or only a range. */
  source: 'lockfile' | 'pinned' | 'range';
}

/**
 * The version of `pkg` actually installed, read from the lockfile when one is
 * present and readable (package-lock.json, pnpm-lock.yaml, yarn.lock). Falls
 * back to the declared version from package.json, marked as a pin or a range so
 * callers can lower confidence when they only know the range (`^14.1.0` may
 * already resolve to a patched release). bun.lockb is binary and not read.
 */
export function installedVersion(
  repo: { lockfiles: string[]; readFile: (p: string) => string | null; packageManifest: { allDeps: Record<string, string> } | null },
  pkg: string,
): InstalledVersion | null {
  const esc = pkg.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  for (const lf of [...repo.lockfiles].sort((a, b) => a.split('/').length - b.split('/').length)) {
    const text = repo.readFile(lf);
    if (!text) continue;
    let found: string | undefined;
    if (lf.endsWith('package-lock.json')) {
      try {
        const j = JSON.parse(text);
        found = j.packages?.[`node_modules/${pkg}`]?.version ?? j.dependencies?.[pkg]?.version;
      } catch { /* unreadable lockfile */ }
    } else if (lf.endsWith('pnpm-lock.yaml')) {
      found =
        text.match(new RegExp(`\\n\\s+${esc}:\\s*\\n\\s+specifier:[^\\n]*\\n\\s+version:\\s*['"]?(\\d+\\.\\d+\\.\\d+)`))?.[1] ??
        text.match(new RegExp(`\\n\\s+['"]?/?${esc}@(\\d+\\.\\d+\\.\\d+)`))?.[1];
    } else if (lf.endsWith('yarn.lock')) {
      found = text.match(new RegExp(`(?:^|\\n)"?${esc}@[^\\n]*:\\s*\\n\\s+version:?\\s+"?(\\d+\\.\\d+\\.\\d+)`))?.[1];
    }
    if (found) return { version: found, source: 'lockfile' };
  }
  const declared = repo.packageManifest?.allDeps[pkg];
  if (!declared) return null;
  return { version: declared, source: isRange(declared) ? 'range' : 'pinned' };
}
