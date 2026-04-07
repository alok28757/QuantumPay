import { Platform } from 'react-native';

// In production, set EXPO_PUBLIC_API_URL to your deployed backend URL (e.g. https://quantumpay-api.vercel.app)
// In local development it falls back to localhost:4000
const PROD_URL = process.env.EXPO_PUBLIC_API_URL;
const DEV_URL = Platform.OS === 'android' ? 'http://10.0.2.2:4000' : 'http://localhost:4000';

export const API_URL = PROD_URL || DEV_URL;

export async function fetchPaymentIntent(amount, description = "Wallet Top-up") {
  try {
    const response = await fetch(`${API_URL}/api/payment/create-intent`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ amount, description }),
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Failed to create payment intent");
    }

    return { clientSecret: data.clientSecret, error: null };
  } catch (error) {
    console.error("API Fetch Error:", error);
    return { clientSecret: null, error: error.message };
  }
}
