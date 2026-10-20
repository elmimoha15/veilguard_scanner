# New rule checklist

Every rule (and every change to a rule) must pass all of these before merge.
The goal: a security engineer would agree with every medium+ finding.

1. **Evidence, not keywords.** The finding is backed by proof: a real secret
   VALUE, a real sink fed by request data, a real config line, an observed
   response. A variable name, a word in prose, or a comment is never enough for
   medium/high/critical. Use `src/engine/evidence.ts` (`looksLikeSecretValue`,
   `isPlaceholder`, `hasPemBody`) and `regionAt()` to ignore comments/strings.
2. **Confidence is set and justified.**
   - `high`: the evidence proves the issue.
   - `medium`: strong signal, one assumption.
   - `low`: heuristic. Calibration (`src/engine/calibrate.ts`) shows low as
     "Possible: verify" and never above low; critical requires high.
   - Low-confidence findings set a `verifyHint` (a concrete step to check).
3. **Severity matches real-world impact.** Critical = direct compromise (leaked
   live secret, open database, forgeable payments, injection from requests).
   Missing headers are low/medium. Don't inflate.
4. **Placeholders, public keys and context are handled.** Example values,
   public-by-design keys (Stripe pk_, Supabase anon/publishable, Firebase AIza,
   PostHog, Sentry DSN) and non-shipping files (docs, content, examples, demo
   components, tests, build output) don't produce medium+ findings. Real API
   routes and pages are always source (`classifyFile`).
5. **URL scans need observed evidence.** Bundles are full of copy: only flag
   what's really there (a secret value, an actual header, an actual response).
6. **Tested against both corpora.** Add at least one case to
   `test-fixtures/corpus/safe/` (must produce no medium+) and one to
   `test-fixtures/corpus/vulnerable/` with its expected severity in
   `test-fixtures/corpus/cases.json`. `npm test` and `npm run gate` must pass.
7. **One issue, one finding.** Emit a stable location (file + line) and make
   sure the same issue found by another rule or engine dedupes
   (`canonicalIdentity` in `runner.ts`).
8. **Evidence is redacted.** Secrets appear only as `redactSecret()` output
   (e.g. `sk_live_51Ab****`), never in full.

When a user marks a finding as a false positive, review the report and turn it
into a new safe-corpus case before fixing the rule, so it can never come back.
