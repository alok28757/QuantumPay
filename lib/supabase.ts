import { createClient } from '@supabase/supabase-js'

const SUPABASE_URL = 'https://ygplozkbpnjszatpyeeq.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlncGxvemticG5qc3phdHB5ZWVxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE5ODYzNjQsImV4cCI6MjA4NzU2MjM2NH0.pTYGZok6fjvl_iwQuOBB8y8phIf5irL49mub0fy_gv8'

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)