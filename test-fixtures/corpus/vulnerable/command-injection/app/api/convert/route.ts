import { exec } from 'child_process';
export async function POST(req: any) { exec(`convert ${req.body.file} out.png`); return new Response('ok'); }
