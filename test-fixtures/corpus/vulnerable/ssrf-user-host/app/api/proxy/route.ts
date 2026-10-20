export async function GET(req: any) {
  return fetch(req.query.url);
}
