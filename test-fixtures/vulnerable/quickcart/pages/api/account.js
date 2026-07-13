import { supabase } from '../../lib/supabase';

// No auth check, and mass-assignment of privileged fields from the body.
export default async function handler(req, res) {
  const { userId } = req.query;
  await supabase.from('profiles').update({
    isAdmin: req.body.isAdmin,
    tier: req.body.tier,
    credits: req.body.credits,
  }).eq('id', userId);

  res.status(200).json({ ok: true });
}
