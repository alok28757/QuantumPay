-- ═══════════════════════════════════════════════════════════════════
-- QuantumPay: Supabase Auth + RLS Migration
-- Run this in Supabase Dashboard → SQL Editor
-- ═══════════════════════════════════════════════════════════════════

-- 1. Add user_id column to profiles (links to Supabase Auth)
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id);
CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles(user_id);

-- 2. Enable RLS on profiles
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if re-running
DROP POLICY IF EXISTS "Anyone can read profiles" ON profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON profiles;
DROP POLICY IF EXISTS "Authenticated users can insert profile" ON profiles;

-- Allow reading all profiles (needed for UPI lookup when sending money)
CREATE POLICY "Anyone can read profiles" ON profiles
  FOR SELECT USING (true);

-- Only the owner can update their profile
CREATE POLICY "Users can update own profile" ON profiles
  FOR UPDATE USING (user_id = auth.uid());

-- Authenticated users can insert their own profile during registration
CREATE POLICY "Authenticated users can insert profile" ON profiles
  FOR INSERT WITH CHECK (user_id = auth.uid());

-- 3. Enable RLS on transactions
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if re-running
DROP POLICY IF EXISTS "Users can read own transactions" ON transactions;
DROP POLICY IF EXISTS "Authenticated users can insert transactions" ON transactions;

-- Users can only read transactions they are involved in
CREATE POLICY "Users can read own transactions" ON transactions
  FOR SELECT USING (
    sender_phone IN (SELECT phone FROM profiles WHERE user_id = auth.uid())
    OR receiver_phone IN (SELECT phone FROM profiles WHERE user_id = auth.uid())
  );

-- Authenticated users can insert transactions where they are the sender
CREATE POLICY "Authenticated users can insert transactions" ON transactions
  FOR INSERT WITH CHECK (
    sender_phone IN (SELECT phone FROM profiles WHERE user_id = auth.uid())
  );

-- 4. Make increment_balance work across users (SECURITY DEFINER)
CREATE OR REPLACE FUNCTION increment_balance(p_phone TEXT, p_amount NUMERIC)
RETURNS VOID AS $$
BEGIN
  UPDATE profiles SET balance = balance + p_amount WHERE phone = p_phone;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
