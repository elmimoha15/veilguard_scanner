const BLOCKED = ['http://169.254.169.254', 'http://metadata.google.internal'];
export function isBlocked(u: string) { return BLOCKED.some((b) => u.startsWith(b)); }
