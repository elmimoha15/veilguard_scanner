import type { Finding, Counts, Grade, Confidence } from '../types.js';

const WEIGHTS: Record<Finding['severity'], number> = {
  critical: 35,
  high: 15,
  medium: 6,
  low: 2,
  info: 0,
};

/**
 * Confidence scales a finding's weight. A low-confidence finding (e.g. a pattern
 * in a docs/content file, or a "possible — verify" match) barely moves the score,
 * so a false positive cannot tank the grade; a high-confidence finding counts in
 * full. This is what keeps one documentation example from forcing an F.
 */
const CONF_MULT: Record<Confidence, number> = {
  high: 1,
  medium: 0.5,
  low: 0.15,
};

/** A "confirmed" finding is one we're reasonably sure is real (not low-confidence). */
function isConfirmed(f: Finding): boolean {
  return f.confidence !== 'low';
}

export function countBySeverity(findings: Finding[]): Counts {
  const counts: Counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, passed: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Weighted score, floored at 0. Weight = severity × confidence multiplier. */
export function computeScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) score -= WEIGHTS[f.severity] * CONF_MULT[f.confidence];
  return Math.max(0, Math.round(score));
}

/**
 * Map score → A–F. Any CONFIRMED (non-low-confidence) CRITICAL caps the grade at
 * D, no matter the numeric score (a single confirmed critical means the app is
 * not safe to charge on). A low-confidence "critical" does NOT cap — otherwise a
 * documentation false positive could force a D/F on an otherwise-clean app.
 */
export function scoreToGrade(score: number, confirmedCriticalCount: number): Grade {
  let grade: Grade;
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  if (confirmedCriticalCount > 0 && (grade === 'A' || grade === 'B' || grade === 'C')) {
    grade = 'D';
  }
  return grade;
}

export function grade(findings: Finding[]): { grade: Grade; score: number; counts: Counts } {
  const counts = countBySeverity(findings);
  const score = computeScore(findings);
  const confirmedCritical = findings.filter((f) => f.severity === 'critical' && isConfirmed(f)).length;
  return { grade: scoreToGrade(score, confirmedCritical), score, counts };
}
