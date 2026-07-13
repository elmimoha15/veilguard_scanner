// Every value in this file is PUBLIC BY DESIGN. The scanner must report ZERO
// secret findings here — flagging any of these is a false positive.

import { createClient } from '@supabase/supabase-js';

// Stripe publishable key — meant to ship to the browser.
export const STRIPE_PUBLISHABLE_KEY = 'pk_live_51QabcdEFGH1234567890publishableKEY';

// Supabase publishable key + anon JWT (role claim = "anon").
export const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNjAwMDAwMDAwfQ.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEFG';
export const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_aBcDeFgHiJkLmNoPqRsTuV';

// Firebase web config — all public.
export const firebaseConfig = {
  apiKey: 'AIzaSyD-1234567890abcdefghijklmnopqrstuv',
  authDomain: 'quickcart.firebaseapp.com',
  projectId: 'quickcart',
  storageBucket: 'quickcart.appspot.com',
  messagingSenderId: '123456789012',
  appId: '1:123456789012:web:abcdef1234567890',
};

// PostHog project key — public.
export const POSTHOG_KEY = 'phc_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDE';

export const supabase = createClient('https://abcdefghijklmnopqrst.supabase.co', SUPABASE_ANON_KEY);
