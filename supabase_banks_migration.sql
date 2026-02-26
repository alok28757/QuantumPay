-- Add linked_banks JSONB column to profiles
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS linked_banks JSONB DEFAULT '[]'::jsonb;
