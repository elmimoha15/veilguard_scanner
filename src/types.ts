import { z } from 'zod';

/* -------------------------------------------------------------------------- */
/* Enums                                                                       */
/* -------------------------------------------------------------------------- */

export const CategorySchema = z.enum([
  'secrets',
  'database',
  'auth',
  'injection',
  'api_webhooks',
  'web_config',
  'dependencies',
  'ai_specific',
  'platform',
  'business_logic',
]);
export type Category = z.infer<typeof CategorySchema>;

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const ConfidenceSchema = z.enum(['high', 'medium', 'low']);
export type Confidence = z.infer<typeof ConfidenceSchema>;

export const ModeSchema = z.enum(['blackbox', 'whitebox']);
export type Mode = z.infer<typeof ModeSchema>;

/* -------------------------------------------------------------------------- */
/* Finding                                                                     */
/* -------------------------------------------------------------------------- */

export const LocationSchema = z.object({
  file: z.string().optional(),
  line: z.number().int().optional(),
  url: z.string().optional(),
});
export type Location = z.infer<typeof LocationSchema>;

export const FindingSchema = z.object({
  /** Stable id, e.g. "SECRETS_STRIPE_SECRET_KEY". */
  ruleId: z.string(),
  category: CategorySchema,
  severity: SeveritySchema,
  cwe: z.string().optional(),
  owasp: z.string().optional(),
  /** Plain-English, founder-friendly title. */
  title: z.string(),
  /** One plain sentence of real-world impact. */
  whyItMatters: z.string(),
  /** REDACTED snippet or matched indicator — never a full secret. */
  evidence: z.string().optional(),
  location: LocationSchema.optional(),
  /** Concrete fix (code / SQL / steps). */
  fix: z.string().optional(),
  /** Copy-paste prompt the user can hand to their AI tool. */
  fixPrompt: z.string().optional(),
  confidence: ConfidenceSchema,
  mode: ModeSchema,
  /** Where this finding came from: our own engine, or an external tool. */
  source: z.enum(['native', 'semgrep', 'gitleaks', 'osv-scanner']).default('native'),
});
export type Finding = z.infer<typeof FindingSchema>;

/* -------------------------------------------------------------------------- */
/* Report                                                                      */
/* -------------------------------------------------------------------------- */

export const GradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);
export type Grade = z.infer<typeof GradeSchema>;

export const CountsSchema = z.object({
  critical: z.number().int(),
  high: z.number().int(),
  medium: z.number().int(),
  low: z.number().int(),
  info: z.number().int(),
  passed: z.number().int(),
});
export type Counts = z.infer<typeof CountsSchema>;

export const TargetSchema = z.object({
  type: z.enum(['url', 'repo']),
  value: z.string(),
});
export type Target = z.infer<typeof TargetSchema>;

export const ScanReportSchema = z.object({
  target: TargetSchema,
  startedAt: z.string(),
  finishedAt: z.string(),
  grade: GradeSchema,
  score: z.number().int(),
  counts: CountsSchema,
  findings: z.array(FindingSchema),
  engines: z.object({
    semgrep: z.boolean(),
    gitleaks: z.boolean(),
    osvScanner: z.boolean(),
  }),
});
export type ScanReport = z.infer<typeof ScanReportSchema>;

/* -------------------------------------------------------------------------- */
/* Scan context (input to rules) — not zod-validated (contains functions).     */
/* -------------------------------------------------------------------------- */

export interface JsBundle {
  url: string;
  content: string;
}

export interface HttpArtifacts {
  baseUrl: string;
  reachable: boolean;
  status?: number;
  homepageHtml: string;
  headers: Record<string, string>;
  jsBundles: JsBundle[];
  cookies: string[];
}

export interface DiscoveredConfig {
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  firebaseConfig?: Record<string, string>;
}

export interface RepoArtifacts {
  root: string;
  files: string[];
  readFile: (path: string) => string | null;
  sqlFiles: string[];
  envFiles: string[];
  packageManifest: PackageManifest | null;
  lockfiles: string[];
  /** Parse a JS/TS/JSX file into a Babel AST (cached). Null on parse failure. */
  astFor: (path: string) => BabelFile | null;
}

export interface PackageManifest {
  path: string;
  raw: Record<string, unknown>;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  allDeps: Record<string, string>;
}

/** Minimal shape we consume from @babel/parser output — kept loose on purpose. */
export interface BabelFile {
  path: string;
  content: string;
  ast: any;
}

export interface Helpers {
  httpGet: (
    url: string,
    // Read-only by design: rules can set headers and a short timeout, but not
    // the method or a body — so a rule physically cannot issue a write.
    opts?: { headers?: Record<string, string>; timeoutMs?: number },
  ) => Promise<{ status: number; headers: Record<string, string>; body: string } | null>;
  /** Scan text for a regex, returning matches with 1-based line numbers. */
  safeRegexScan: (
    text: string,
    re: RegExp,
  ) => { match: string; line: number; index: number; groups: (string | undefined)[] }[];
  /** Redact a secret so only a short prefix/suffix remains. */
  redact: (value: string) => string;
  /** Shannon entropy (bits per char) of a string. */
  entropy: (value: string) => number;
  /** debug logger, gated on --debug */
  debug: (...args: unknown[]) => void;
}

export interface ScanContext {
  target: Target;
  http?: HttpArtifacts;
  discovered?: DiscoveredConfig;
  repo?: RepoArtifacts;
  helpers: Helpers;
}

/* -------------------------------------------------------------------------- */
/* Rule                                                                        */
/* -------------------------------------------------------------------------- */

export interface Rule {
  id: string;
  category: Category;
  mode: 'blackbox' | 'whitebox' | 'both';
  run(ctx: ScanContext): Promise<Finding[]>;
}
