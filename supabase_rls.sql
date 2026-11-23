-- ====================================================================
-- SentinelGrid Defense // Supabase PostgreSQL & Row Level Security (RLS)
-- Cloud Audit Database Table for: login_audit_logs
-- Authorized SuperAdmin: bmwm25320@gmail.com
-- ====================================================================

-- 1. Create centralized audit table
CREATE TABLE IF NOT EXISTS public.login_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    uid TEXT NOT NULL,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    photo_url TEXT,
    event_type TEXT NOT NULL CHECK (event_type IN ('NEW_ACCOUNT_SIGNUP', 'USER_LOGIN')),
    login_date TEXT NOT NULL,
    login_time TEXT NOT NULL,
    iso_timestamp TIMESTAMPTZ DEFAULT NOW(),
    platform TEXT NOT NULL CHECK (platform IN ('Windows Desktop', 'Android Mobile', 'Web Portal')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Create index for performance
CREATE INDEX IF NOT EXISTS idx_audit_iso_timestamp ON public.login_audit_logs(iso_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_email ON public.login_audit_logs(email);

-- 3. Enable Row Level Security (RLS)
ALTER TABLE public.login_audit_logs ENABLE ROW LEVEL SECURITY;

-- Policy 1: Any authenticated user can insert their own login/signup event
CREATE POLICY "Users can insert their own login events"
ON public.login_audit_logs
FOR INSERT
TO authenticated
WITH CHECK (auth.uid()::text = uid);

-- Policy 2: STRICT ADMIN READ ACCESS - Only bmwm25320@gmail.com can select and read all rows
CREATE POLICY "Strict Admin can view all login audit logs"
ON public.login_audit_logs
FOR SELECT
TO authenticated
USING (
    lower(auth.jwt() ->> 'email') = 'bmwm25320@gmail.com'
);

-- Policy 3: Strict Admin can delete/prune audit records
CREATE POLICY "Strict Admin can delete audit records"
ON public.login_audit_logs
FOR DELETE
TO authenticated
USING (
    lower(auth.jwt() ->> 'email') = 'bmwm25320@gmail.com'
);
