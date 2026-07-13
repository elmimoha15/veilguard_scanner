import { describe, it, expect } from 'vitest';
import { insecureUpload } from '../src/rules/business-logic/insecure-upload.js';
import { makeRepoContext } from './helpers.js';

describe('BUSINESS_INSECURE_UPLOAD', () => {
  it('fires on an upload handler with no type/size validation', async () => {
    const ctx = makeRepoContext({ 'api/upload.ts': `const upload = multer({ dest: 'uploads/' }); app.post('/u', upload.single('file'), (req,res)=>{ save(req.file); });` });
    expect((await insecureUpload.run(ctx)).length).toBe(1);
  });
  it('does not fire when type + size are validated', async () => {
    const ctx = makeRepoContext({
      'api/upload.ts': `const upload = multer({ limits: { fileSize: 1000000 }, fileFilter: (r,f,cb)=>cb(null, f.mimetype==='image/png') });`,
    });
    expect((await insecureUpload.run(ctx)).length).toBe(0);
  });
});
