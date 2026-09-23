import type { Rule, Finding, ScanContext } from '../../types.js';

// A JSON source map has version 3 and a sources array. Require both so an SPA
// HTML fallback (200 for everything) can't be mistaken for a real map.
const LOOKS_LIKE_SOURCEMAP = (body: string): boolean =>
  /"version"\s*:\s*3\b/.test(body) && /"sources"\s*:\s*\[/.test(body);

// Only probe a bounded number of bundles to stay lightweight.
const MAX_PROBES = 10;

/**
 * Black-box: JavaScript source maps served in production. A reachable `.map`
 * exposes your original, un-minified source — comments, internal endpoints,
 * variable names, and sometimes secrets — to anyone who opens dev tools.
 */
export const sourceMaps: Rule = {
  id: 'WEB_CONFIG_EXPOSED_SOURCEMAP',
  category: 'web_config',
  mode: 'blackbox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const http = ctx.http;
    if (!http || !http.reachable) return [];

    const candidates = http.jsBundles
      .map((b) => b.url)
      .filter((u) => /\.m?js($|\?)/i.test(u) && !/\.map($|\?)/i.test(u))
      .slice(0, MAX_PROBES);

    const out: Finding[] = [];
    await Promise.all(
      candidates.map(async (jsUrl) => {
        const mapUrl = jsUrl.replace(/(\?.*)?$/, '') + '.map';
        const res = await ctx.helpers.httpGet(mapUrl);
        if (!res || res.status !== 200 || !LOOKS_LIKE_SOURCEMAP(res.body)) return;
        out.push({
          ruleId: 'WEB_CONFIG_EXPOSED_SOURCEMAP',
          category: 'web_config',
          severity: 'medium',
          cwe: 'CWE-540',
          owasp: 'A05:2021',
          title: 'Your original source code is downloadable (source maps exposed)',
          whyItMatters:
            'A publicly served .map file reconstructs your un-minified source — internal API routes, comments, and occasionally secrets — handing attackers a blueprint of your app.',
          evidence: mapUrl,
          location: { url: mapUrl },
          fix: 'Disable source maps in production (Next.js: leave `productionBrowserSourceMaps` off / default), or block *.map at the CDN.',
          fixPrompt:
            'Stop serving JavaScript source maps in production: ensure productionBrowserSourceMaps is not enabled in next.config, and/or block public access to *.map files at the CDN/web-server level.',
          confidence: 'high',
          mode: 'blackbox',
          source: 'native',
        });
      }),
    );

    // We actually probed bundles and none leaked a source map → a real pass.
    if (out.length === 0 && candidates.length > 0) {
      ctx.reportPass?.({
        id: 'PASS_WEB_CONFIG_NO_SOURCEMAPS',
        category: 'web_config',
        title: 'Source maps are not exposed',
        detail: 'Your production JavaScript does not serve .map files, so your original source stays private.',
        mode: 'blackbox',
      });
    }

    // One finding is enough — the fix is global. Keep the first if several leak.
    return out.slice(0, 1);
  },
};
