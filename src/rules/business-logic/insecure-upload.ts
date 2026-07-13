import type { Rule, Finding, ScanContext } from '../../types.js';
import { isSourceFile } from '../_shared.js';

/**
 * White-box (heuristic): a file-upload handler with no type or size validation.
 * Fires when a handler touches multipart/formData/file uploads but shows no
 * mimetype/extension allowlist and no size limit.
 */
export const insecureUpload: Rule = {
  id: 'BUSINESS_INSECURE_UPLOAD',
  category: 'business_logic',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;

      const isUpload = /(multer|formData\(\)|multipart\/form-data|\.upload\(|busboy|createReadStream.*upload|req\.file\b|\.files\[)/i.test(content);
      if (!isUpload) continue;

      const hasTypeCheck = /(mimetype|mime-type|contentType|allowedTypes|accept:|fileFilter|extname|\.type\s*===|image\/(png|jpe?g|webp))/i.test(content);
      const hasSizeLimit = /(limits\s*:|fileSize|maxSize|max_size|MAX_FILE|\.size\s*[<>])/i.test(content);
      if (hasTypeCheck && hasSizeLimit) continue;

      out.push({
        ruleId: 'BUSINESS_INSECURE_UPLOAD',
        category: 'business_logic',
        severity: 'medium',
        cwe: 'CWE-434',
        owasp: 'A04:2021',
        title: 'File uploads aren’t validated',
        whyItMatters: `This upload handler doesn’t restrict ${!hasTypeCheck ? 'file type' : ''}${!hasTypeCheck && !hasSizeLimit ? ' or ' : ''}${!hasSizeLimit ? 'file size' : ''}, so attackers can upload malicious or oversized files.`,
        location: { file: path },
        fix: 'Allowlist accepted MIME types/extensions and enforce a maximum file size before storing the upload.',
        fixPrompt: 'Add validation to this file-upload handler: allowlist specific MIME types/extensions and reject anything else, and enforce a maximum file size limit before saving the file.',
        confidence: 'low',
        mode: 'whitebox',
        source: 'native',
      });
    }
    return out;
  },
};
