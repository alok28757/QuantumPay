import { Platform } from 'react-native';

// For local development
// Android emulators need 10.0.2.2 to reach localhost
// Web and iOS simulator can use localhost directly
export const API_URL = Platform.OS === 'android' ? 'http://10.0.2.2:4000' : 'http://localhost:4000';

export async function createRazorpayOrder(amount, phone) {
  try {
    const response = await fetch(`${API_URL}/api/payment/create-order`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ amount, phone }),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Failed to create order");

    return { data, error: null };
  } catch (error) {
    console.error("API Order Error:", error);
    return { data: null, error: error.message };
  }
}

export async function verifyRazorpayPayment(payload) {
  try {
    const response = await fetch(`${API_URL}/api/payment/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Verification failed");
    return { success: true, error: null };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function sendMoneyApi(payload) {
  try {
    const response = await fetch(`${API_URL}/api/wallet/send`, {
       method: "POST",
       headers: { "Content-Type": "application/json" },
       body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Failed to send money");
    return { success: true, error: null };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function withdrawBankApi(phone, amount) {
  try {
    const response = await fetch(`${API_URL}/api/payout/withdraw`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, amount }),
    });
    return await response.json();
  } catch (error) {
    return { error: error.message };
  }
}
