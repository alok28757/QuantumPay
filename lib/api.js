import { Platform } from 'react-native';

// For local development
// Android emulators need 10.0.2.2 to reach localhost
// Web and iOS simulator can use localhost directly
export const API_URL = Platform.OS === 'android' ? 'http://10.0.2.2:4000' : 'http://localhost:4000';

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
