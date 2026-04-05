// Native (iOS/Android) Implementation for Stripe
import React from 'react';
import { useStripe as useNativeStripe, StripeProvider as NativeStripeProvider } from '@stripe/stripe-react-native';

export function useStripe() {
  return useNativeStripe();
}

export function StripeProvider({ children, publishableKey }) {
  return (
    <NativeStripeProvider publishableKey={publishableKey}>
      {children}
    </NativeStripeProvider>
  );
}
