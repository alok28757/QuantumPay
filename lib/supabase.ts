import { createClient } from '@supabase/supabase-js'

const SUPABASE_URL = process.env.EXPO_PUBLIC_SUPABASE_URL || ''
const SUPABASE_ANON_KEY = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY || ''

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)

// ─── AUTH HELPERS (phone+MPIN → Supabase Auth) ─────────────────────────────

/** Convert phone to pseudo-email for Supabase Auth */
const toEmail = (phone: string) => `${phone}@qpay.app`

/** Sign up a new user with Supabase Auth */
export async function signUpUser(phone: string, hashedMpin: string) {
    const { data, error } = await supabase.auth.signUp({
        email: toEmail(phone),
        password: hashedMpin,
        options: { data: { phone } },
    })
    return { data, error }
}

/** Sign in an existing user */
export async function signInUser(phone: string, hashedMpin: string) {
    const { data, error } = await supabase.auth.signInWithPassword({
        email: toEmail(phone),
        password: hashedMpin,
    })
    return { data, error }
}

/** Sign out the current user */
export async function signOutUser() {
    return supabase.auth.signOut()
}

/** Get the current auth session */
export async function getSession() {
    const { data: { session } } = await supabase.auth.getSession()
    return session
}

/** Get the current auth user's ID */
export async function getAuthUserId() {
    const session = await getSession()
    return session?.user?.id || null
}