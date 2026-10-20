const ID_RE = /^order_(\w+)$/;
export function parse(input: string) {
  const m = ID_RE.exec(`${input}`);
  return m?.[1];
}
