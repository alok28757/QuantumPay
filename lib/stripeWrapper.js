// Web Fallback for Stripe
import React from 'react';

export function useStripe() {
  return {
    initPaymentSheet: async () => {
      // Mock initialization on web
      return { error: null };
    },
    presentPaymentSheet: async () => {
      // Mock presenting payment sheet on web
      if (window.confirm("Simulate Stripe Payment success? (Native sheets only appear on iOS/Android)")) {
          return { error: null };
      } else {
          return { error: { code: 'Canceled', message: "User canceled web mock payment" } };
      }
    },
  };
}

export function StripeProvider({ children }) {
  // Just render children directly on web
  return <>{children}</>;
}
