export async function DELETE(req: Request) {
  await prisma.item.delete({ where: { id: '1' } });
  return new Response(null, { status: 204 });
}
