import { describe, it, expect } from 'vitest';
import { loadCases, scanCase, precisionViolations, recallMisses } from './corpus.js';

const cases = loadCases();

// PRECISION GATE: real-world safe patterns must never produce a medium+ finding.
describe('precision corpus (safe patterns)', () => {
  for (const [name, meta] of cases.filter(([, m]) => m.kind === 'safe')) {
    it(`${name}: no medium+ findings (${meta.why ?? ''})`, async () => {
      const bad = precisionViolations(await scanCase(name, meta));
      expect(bad.map((f) => `${f.severity}/${f.confidence} ${f.ruleId} ${f.title} @ ${f.location?.file ?? f.location?.url ?? ''}`)).toEqual([]);
    });
  }
});

// RECALL GATE: every real vulnerability still fires at the right severity.
describe('recall corpus (real vulnerabilities)', () => {
  for (const [name, meta] of cases.filter(([, m]) => m.kind === 'vulnerable')) {
    it(`${name}: fires ${meta.expect!.map((e) => `${e.ruleId}>=${e.minSeverity}`).join(', ')}`, async () => {
      const findings = await scanCase(name, meta);
      const missed = recallMisses(findings, meta.expect!);
      expect(
        missed.map((m) => `${m.ruleId} (wanted >=${m.minSeverity}/${m.minConfidence}); got: ${findings.map((f) => `${f.ruleId}=${f.severity}/${f.confidence}`).join(', ') || 'nothing'}`),
      ).toEqual([]);
    });
  }
});
