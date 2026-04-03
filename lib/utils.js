// QuantumPay — Utility functions

const FIREBASE_API_KEY = process.env.EXPO_PUBLIC_FIREBASE_API_KEY || '';
const FIREBASE_PROJECT_ID = process.env.EXPO_PUBLIC_FIREBASE_PROJECT_ID || '';

// Quick connectivity check (3s timeout)
export const checkFirebase = async () => {
  if (!FIREBASE_API_KEY || !FIREBASE_PROJECT_ID) return false;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    // Simple ping to Firestore REST API to check connectivity
    const res = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/profiles?pageSize=1`,
      { signal: controller.signal }
    );
    clearTimeout(timeout);
    return res.ok;
  } catch { return false; }
};

export const playSuccessSound = () => {
  try {
    const audio = new Audio("https://cdn.pixabay.com/download/audio/2021/08/04/audio_0625c1539c.mp3");
    audio.volume = 0.5;
    audio.play().catch(() => { });
  } catch (e) { }
};
