import type { Rule } from '../types.js';

import { hardcodedSecrets } from './secrets/hardcoded-secrets.js';
import { committedEnv } from './secrets/committed-env.js';
import { supabaseRls } from './database/supabase-rls.js';
import { firebaseRules } from './database/firebase-rules.js';
import { rlsOpenProbe } from './database/rls-open-probe.js';
import { nextjsMiddlewareCve } from './auth/nextjs-middleware-cve.js';
import { missingAuth } from './auth/missing-auth.js';
import { sqlInjection } from './injection/sql-injection.js';
import { commandInjection } from './injection/command-injection.js';
import { xss } from './injection/xss.js';
import { webhookVerification } from './api-webhooks/webhook-verification.js';
import { massAssignment } from './api-webhooks/mass-assignment.js';
import { nextConfig } from './web-config/nextconfig.js';
import { httpHeaders } from './web-config/http-headers.js';
import { exposedFiles } from './web-config/exposed-files.js';
import { knownCve } from './dependencies/known-cve.js';
import { rulesFile } from './ai-specific/rules-file.js';
import { insecureDefaults } from './ai-specific/insecure-defaults.js';
import { publicSecretVar } from './platform/public-secret-var.js';
import { insecureUpload } from './business-logic/insecure-upload.js';

/**
 * THE RULE REGISTRY. Adding a rule = import it and append it here. The runner
 * runs every rule whose `mode` matches the target type.
 */
export const rules: Rule[] = [
  // secrets
  hardcodedSecrets,
  committedEnv,
  // database
  supabaseRls,
  firebaseRules,
  rlsOpenProbe,
  // auth
  nextjsMiddlewareCve,
  missingAuth,
  // injection
  sqlInjection,
  commandInjection,
  xss,
  // api & webhooks
  webhookVerification,
  massAssignment,
  // web / transport / config
  nextConfig,
  httpHeaders,
  exposedFiles,
  // dependencies
  knownCve,
  // ai-specific
  rulesFile,
  insecureDefaults,
  // platform
  publicSecretVar,
  // business logic
  insecureUpload,
];
