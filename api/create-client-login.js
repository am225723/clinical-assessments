import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = process.env.VITE_SUPABASE_PUBLISHABLE_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ error: 'Server environment variables are missing.' });
    }

    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    const userClient = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const { data: userData, error: userError } = await userClient.auth.getUser(token);
    if (userError || !userData?.user) return res.status(401).json({ error: 'Not authenticated' });

    const { data: profile, error: profileError } = await userClient
      .from('assessment_user_profiles')
      .select('role')
      .eq('user_id', userData.user.id)
      .single();

    if (profileError || !profile || !['provider', 'admin'].includes(profile.role)) {
      return res.status(403).json({ error: 'Provider access required' });
    }

    const { email, password, fullName } = req.body || {};
    const cleanEmail = String(email || '').trim().toLowerCase();
    const cleanPassword = String(password || '');
    const cleanFullName = String(fullName || '').trim();

    if (!cleanEmail || !cleanPassword || !cleanFullName) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }

    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email: cleanEmail,
      password: cleanPassword,
      email_confirm: true,
      user_metadata: { full_name: cleanFullName },
    });

    if (createError) return res.status(400).json({ error: createError.message });

    const { error: profileInsertError } = await adminClient.from('assessment_user_profiles').upsert({
      user_id: created.user.id,
      role: 'client',
      full_name: cleanFullName,
      email: cleanEmail,
    });

    if (profileInsertError) return res.status(500).json({ error: profileInsertError.message });

    return res.status(200).json({ success: true, userId: created.user.id, email: cleanEmail, fullName: cleanFullName });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'Unexpected error' });
  }
}
