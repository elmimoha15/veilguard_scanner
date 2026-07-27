/**
 * Shared route-detection helpers for webhook rules. Extracted so the
 * signature-verification and idempotency rules apply an identical definition of
 * "is this file actually a server route handler?" — a React page/component that
 * merely mentions webhooks in rendered text must never be treated as a handler.
 */

/** True if the file exports/handles a POST (the shape a webhook handler takes). */
export function isHandler(content: string): boolean {
  return /req\.body|request\.body|await\s+req\.(text|json)\(\)|export\s+(async\s+)?function\s+POST|export\s+const\s+POST/.test(
    content,
  );
}

/** A React page/component renders markup — it is UI, never a webhook handler. */
export function isReactView(content: string): boolean {
  return (
    /^\s*['"]use client['"]/m.test(content) || // client component directive
    /\bfrom\s+['"]react['"]/.test(content) || // imports React
    /<\/[A-Za-z][\w.]*>/.test(content) // contains a JSX/HTML closing tag → renders markup
  );
}

/**
 * True only for files that actually run server-side as a route handler:
 * framework route locations (App Router `route.ts`, Pages/App `api/`), or a
 * plain server module that exports a POST/handler — and never a React view.
 */
export function isServerRoute(path: string, content: string): boolean {
  if (/(^|\/)(pages|app)\/api\//.test(path)) return true; // Next.js API routes
  if (/(^|\/)route\.(ts|js|mjs|cjs)$/.test(path)) return true; // App Router route handler
  if (isReactView(content)) return false;
  return /export\s+(async\s+)?function\s+(POST|handler)\b|export\s+const\s+(POST|handler)\b|module\.exports\s*=|app\.(post|use)\s*\(|router\.post\s*\(/.test(
    content,
  );
}
