// A CONTENT/learn article that TEACHES how a webhook handler looks. The handler
// code below is an example inside an article, not a live server route — it must
// not be flagged as a confirmed critical "unverified webhook".

export const article = {
  slug: 'how-webhooks-work',
  title: 'How webhooks work (with an example handler)',
  codeSample: `export async function POST(req: Request) {
  const body = await req.json();
  // In a real handler you would verify the signature here first.
  await handleEvent(body);
  return Response.json({ received: true });
}`,
};
