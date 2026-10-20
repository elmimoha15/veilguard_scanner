import { z } from 'zod';
export const clientSchema = z.object({
  NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN: z.string(),
  NEXT_PUBLIC_SITE_URL: z.string().url(),
  NEXT_PUBLIC_RECAPTCHA_SITE_KEY: z.string(),
});
export const errors = { missing: 'Missing NEXT_PUBLIC_STRIPE_SECRET_KEY, set it on the server instead.' };
