require("dotenv").config();
const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Stripe with the secret key from .env
const stripeConfig = process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY.startsWith('sk_') 
  ? process.env.STRIPE_SECRET_KEY 
  : "sk_test_mock"; // Prevents crash if user forgets to set key initially
const stripe = Stripe(stripeConfig);

// Basic health check route
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "QuantumPay Backend is running!" });
});

// Route to create a Payment Intent for adding money
app.post("/api/payment/create-intent", async (req, res) => {
  try {
    const { amount, currency = "inr", description } = req.body;
    
    // Amount must be in the smallest currency unit (paise for INR)
    // So ₹500 * 100 = 50000 paise
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100,
      currency,
      description: description || "Wallet Top-up",
      automatic_payment_methods: {
        enabled: true,
      },
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error("Stripe Error:", error.message);
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 QuantumPay Backend running on http://localhost:${PORT}`);
});
