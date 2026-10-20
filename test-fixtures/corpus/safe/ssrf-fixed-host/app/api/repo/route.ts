export async function GET(req: Request, { params }: { params: { owner: string } }) {
  const res = await fetch(`https://api.github.com/repos/${params.owner}/readme`);
  return new Response(await res.text());
}
