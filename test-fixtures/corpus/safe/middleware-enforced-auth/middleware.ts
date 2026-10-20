import { getToken } from 'next-auth/jwt';
export async function middleware(req: any) { const t = await getToken({ req }); if (!t) return Response.redirect('/login'); }
