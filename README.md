# veilguard-scanner

A standalone security scanner for AI-built web/SaaS apps (Next.js + Supabase/Firebase + Stripe). Point it at a **live URL** (black-box) or a **local repo** (white-box) and it prints a JSON report of findings plus an **A–F grade**.

This is **Slice 1** of the Veilguard backend: the core engine, as a CLI. No Firebase, no web frontend, no auth, no database — just detection.

## Highlights

- **Two modes.** URL targets get black-box recon (headers, CORS, exposed dotfiles, live Supabase RLS probing, secrets in JS bundles). Repo targets get white-box analysis (AST + SQL migration parsing + dependency CVEs + config review).
- **False-positive suppression is first-class.** Public-by-design values (Stripe `pk_`, Supabase anon keys, Firebase web config, PostHog/Sentry) are never reported as leaks, while real secrets (`sk_live_`, `sb_secret_`, service-account private keys, service-role JWTs) always are. See `src/engine/secret-matrix.ts`.
- **Native-first, engines optional.** All detection runs in-process with zero external dependencies. If `semgrep`, `gitleaks`, or `osv-scanner` are on your `PATH`, the scanner detects them automatically and merges their findings in. Nothing breaks if they're missing.

## Install

```bash
npm install
```

### Optional external engines (enrichment only)

The scanner works fully without these. Install any of them to get deeper coverage; they are auto-detected at scan time.

- **Semgrep** (SAST) — `pipx install semgrep` or `python3 -m pip install semgrep` (or `brew install semgrep`).
- **gitleaks** (secret + git-history scanning) — `brew install gitleaks`, or download a release binary from https://github.com/gitleaks/gitleaks/releases and put it on your `PATH`.
- **osv-scanner** (dependency CVEs, Google OSV) — `brew install osv-scanner`, `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`, or a release binary from https://github.com/google/osv-scanner/releases.

Verify what's detected with `veilguard scan <target> --debug` (prints engine availability).

## Usage

```bash
# Scan a local repo (white-box)
npm run scan -- ./path/to/app
# or, in dev, directly:
npx tsx src/cli.ts scan ./path/to/app

# Scan a live URL (black-box)
npx tsx src/cli.ts scan https://myapp.example.com

# Full JSON report
npx tsx src/cli.ts scan ./path/to/app --json
npx tsx src/cli.ts scan ./path/to/app --out report.json

# Skip external engines even if installed; verbose logging
npx tsx src/cli.ts scan ./path/to/app --no-engines --debug
```

After `npm run build`, the `veilguard` binary is available (`dist/cli.js`).

The CLI exits `2` when the target is grade **F** or has any **critical** finding, so it can gate CI.

## What it detects (Slice 1)

Secrets & credentials · Supabase/Firebase database rules (RLS) · auth & authorization (incl. Next.js middleware bypass CVE-2025-29927) · injection (SQL / command / XSS) · webhook signature verification & mass-assignment · web/transport config (headers, CORS, exposed files, cookies) · dependency CVEs · AI-coding-specific risks (`.cursorrules`/`CLAUDE.md`/`AGENTS.md`, insecure TLS defaults) · platform gotchas · business-logic (insecure uploads).

Adding a rule is a small, isolated change: drop a module in `src/rules/<category>/` and append it to the registry in `src/rules/index.ts`.

## Grading

Start at 100. Subtract critical −35, high −15, medium −6, low −2 (floored at 0). `A ≥ 90`, `B 75–89`, `C 60–74`, `D 40–59`, `F < 40`. **Any unresolved critical caps the grade at D.**

## Tests

```bash
npm test          # run the full vitest suite (unit + suppression + e2e)
npm run gate      # run the Slice-1 testing gate and print GATE RESULTS (A–E)
npm run typecheck # tsc --noEmit
npm run lint      # eslint
```

Fixtures live under `test-fixtures/`:
- `vulnerable/quickcart/` — an intentionally insecure Next.js app (the E2E target).
- `safe/public-secrets/` — public-by-design values that must produce **zero** secret findings.
- `safe/dangerous-secrets/` — real secrets that must each be reported **critical**.
- `safe/clean-app/` — a secure app that must grade **A/B** with zero criticals.

## Project layout

```
src/
  cli.ts              CLI entry (commander)
  index.ts            library surface (scan(), types)
  types.ts            zod schemas + types (Finding, ScanContext, ScanReport, Rule)
  engine/             recon, runner, normalize, suppress, grade, engines, ast, helpers
  rules/<category>/   one module per rule; index.ts is the registry
semgrep-rules/        custom Semgrep rules (used only when semgrep is installed)
test-fixtures/        vulnerable + safe sample apps
test/                 vitest suite + gate.ts
```
