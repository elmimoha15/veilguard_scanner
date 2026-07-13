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
