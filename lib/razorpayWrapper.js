// Razorpay Web Checkout Wrapper
// On web, Razorpay uses a script-injected checkout popup

export function useRazorpay() {
  const openCheckout = (options) => {
    return new Promise((resolve, reject) => {
      // Load Razorpay script if not already loaded
      if (!window.Razorpay) {
        const script = document.createElement("script");
        script.src = "https://checkout.razorpay.com/v1/checkout.js";
        script.onload = () => startCheckout(options, resolve, reject);
        script.onerror = () => reject(new Error("Failed to load Razorpay SDK"));
        document.body.appendChild(script);
      } else {
        startCheckout(options, resolve, reject);
      }
    });
  };

  const startCheckout = (options, resolve, reject) => {
    const rzp = new window.Razorpay({
      ...options,
      handler: (response) => resolve(response),
      modal: {
        ondismiss: () => reject(new Error("Payment cancelled by user")),
      },
    });
    rzp.on("payment.failed", (response) => {
      reject(new Error(response.error.description || "Payment failed"));
    });
    rzp.open();
  };

  return { openCheckout };
}
