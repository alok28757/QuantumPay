import { initializeApp } from 'firebase/app';
import {
    createUserWithEmailAndPassword,
    getAuth,
    signInWithEmailAndPassword,
    signOut,
    RecaptchaVerifier,
    signInWithPhoneNumber
} from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: process.env.EXPO_PUBLIC_FIREBASE_API_KEY || "",
    authDomain: process.env.EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN || "",
    projectId: process.env.EXPO_PUBLIC_FIREBASE_PROJECT_ID || "",
    storageBucket: process.env.EXPO_PUBLIC_FIREBASE_STORAGE_BUCKET || "",
    messagingSenderId: process.env.EXPO_PUBLIC_FIREBASE_MESSAGING_SENDER_ID || "",
    appId: process.env.EXPO_PUBLIC_FIREBASE_APP_ID || ""
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

// ─── AUTH HELPERS (phone+MPIN → Firebase Auth) ─────────────────────────────

declare global {
    interface Window {
        recaptchaVerifier: any;
    }
}

export const setupRecaptcha = (containerId: string) => {
    if (!window.recaptchaVerifier) {
        window.recaptchaVerifier = new RecaptchaVerifier(auth, containerId, {
            size: 'invisible'
        });
    }
    return window.recaptchaVerifier;
};

export async function sendSignInOTP(phone: string, appVerifier: any) {
    try {
        const formattedPhone = phone.startsWith('+') ? phone : `+91${phone}`;
        const confirmationResult = await signInWithPhoneNumber(auth, formattedPhone, appVerifier);
        return { data: confirmationResult, error: null };
    } catch (error) {
        return { data: null, error };
    }
}


// ─── AUTH HELPERS (phone+MPIN → Firebase Auth) ─────────────────────────────

/** Convert phone to pseudo-email for Firebase Auth */
const toEmail = (phone: string) => `${phone}@qpay.app`

/** Sign up a new user with Firebase Auth */
export async function signUpUser(phone: string, hashedMpin: string) {
    try {
        const userCredential = await createUserWithEmailAndPassword(auth, toEmail(phone), hashedMpin);
        return { data: { user: userCredential.user }, error: null };
    } catch (error) {
        return { data: null, error };
    }
}

/** Sign in an existing user */
export async function signInUser(phone: string, hashedMpin: string) {
    try {
        const userCredential = await signInWithEmailAndPassword(auth, toEmail(phone), hashedMpin);
        return { data: { user: userCredential.user }, error: null };
    } catch (error) {
        return { data: null, error };
    }
}

/** Sign out the current user */
export async function signOutUser() {
    try {
        await signOut(auth);
        return { error: null };
    } catch (error) {
        return { error };
    }
}

/** Get the current auth session/user */
export async function getSession() {
    return auth.currentUser;
}

/** Get the current auth user's ID */
export async function getAuthUserId() {
    const user = auth.currentUser;
    return user?.uid || null;
}
