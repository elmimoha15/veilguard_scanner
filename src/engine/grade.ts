import type { Finding, Counts, Grade } from '../types.js';

const WEIGHTS: Record<Finding['severity'], number> = {
  critical: 35,
  high: 15,
  medium: 6,
  low: 2,
  info: 0,
};

export function countBySeverity(findings: Finding[]): Counts {
  const counts: Counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, passed: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** Weighted score, floored at 0. */
export function computeScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) score -= WEIGHTS[f.severity];
  return Math.max(0, score);
}

/**
 * Map score → A–F. Any unresolved CRITICAL caps the grade at D, no matter the
 * numeric score (a single critical hole means the app is not safe to charge on).
 */
export function scoreToGrade(score: number, criticalCount: number): Grade {
  let grade: Grade;
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  if (criticalCount > 0 && (grade === 'A' || grade === 'B' || grade === 'C')) {
    grade = 'D';
  }
  return grade;
}

export function grade(findings: Finding[]): { grade: Grade; score: number; counts: Counts } {
  const counts = countBySeverity(findings);
  const score = computeScore(findings);
  return { grade: scoreToGrade(score, counts.critical), score, counts };
}
