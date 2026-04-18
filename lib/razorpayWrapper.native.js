// Razorpay Native (iOS/Android) Checkout Wrapper
import RazorpayCheckout from 'react-native-razorpay';

export function useRazorpay() {
  const openCheckout = (options) => {
    return RazorpayCheckout.open(options);
  };

  return { openCheckout };
}
