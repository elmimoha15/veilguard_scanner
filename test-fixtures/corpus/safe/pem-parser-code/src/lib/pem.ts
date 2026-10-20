export function toPem(b64: string) {
  return '-----BEGIN PRIVATE KEY-----\n' + b64 + '\n-----END PRIVATE KEY-----\n';
}
