<div align="center">
  <img src="https://i.ibb.co/L5k6h6c/quantumpay-logo.png" alt="QuantumPay" width="120" />
  <h1>QuantumPay</h1>
  <p><strong>A Next-Gen Hybrid Wallet & UPI Mock Experience</strong></p>
  <p>
    Built with React Native Web, Supabase, and a sprinkle of <b>Audio-Visual Polish</b>. 
    Experience Post-Quantum Cryptography realism in a browser!
  </p>
</div>

<br />

## 🌟 Overview

**QuantumPay** is a high-fidelity, portfolio-ready mock payment application designed to feel exactly like a production wallet (GPay, PhonePe). Running entirely in the browser using React Native Web, it features dual-mode storage (Local Device + Cloud Supabase), gorgeous dark-mode aesthetics, and simulated next-gen cryptographic security verifications.

Whether you're sending mock money to friends, "linking" fake bank accounts, or marveling at the post-quantum payload verification overlay—QuantumPay delivers an incredibly satisfying payment UI experience.

---

## 🚀 Key Features

### 1. Dual-Mode Infrastructure
- **Cloud Mode:** Authenticate via Mobile + OTP (or password) and sync your wallet balance, transactions, and linked banks across devices in real-time using **Supabase** (Postgres + Row-Level Security).
- **Local Mode:** Don't want to log in? No problem. The app defaults to an isolated LocalDB (`localStorage`) allowing instant offline testing.

### 2. High-Fidelity Money Transfers 💸
- **Send & Receive:** Smooth multi-step flow for selecting contacts, typing amount, entering a mock UPI PIN, and viewing a beautiful success screen.
- **Wallet Top-ups:** Add money to your local or cloud wallet instantly.
- **Audio & Haptic Polish:** Satisfying CSS keyframe pulse animations and HTML5 Audio success chimes trigger exactly when payments complete! 🎵

### 3. "Quantum Secured" Receipts 🔒
We care about mock security! Click on any past transaction to open its **Receipt**. At the bottom, tap **"QUANTUM VALIDATED"** to slide up a gorgeous mock cryptographic verification overlay showing:
- **Dilithium ML-DSA-65** Signature Algorithms
- **Kyber-1024** Key Encapsulation
- Beautiful animated Hex matrix outputs 🟢

### 4. Interactive Bank Linking 🏦
- Open the Profile and click **Linked Cards & Banks**.
- Select a bank, see a mocked "Fetching Accounts" processing state, and confirm linking via a mock OTP.
- newly linked bank then appears as a funding source when sending money!

### 5. Utilities & UI Polish
- **QR Scanner:** Working `html5-qrcode` integration that can scan live UPI QRs and parse `upi://pay?pa=...` links directly into the Send flow.
- Glassmorphic navigation, sleek SVG gradients, and seamless transitions between tabs.

---

## 🛠️ Tech Stack

- **Frontend:** React, React Native Web, Expo
- **Backend:** Supabase (PostgreSQL, Auth, RLS Policies)
- **Styling:** Inline Vanilla CSS Objects + CSS Keyframes
- **Scanner:** `html5-qrcode`

---

## 🚦 Getting Started

To run QuantumPay locally on your machine:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/alok28757/quantumpay.git
   cd quantumpay
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Set Up Env Variables:**
   Create a `.env` in the root and add your Supabase details (or leave empty to run entirely in Local Mode):
   ```env
   EXPO_PUBLIC_SUPABASE_URL=your-url
   EXPO_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
   ```

4. **Start the Development Server:**
   ```bash
   npm run web
   ```
   *The app is heavily optimized for mobile-web layouts. View it on your desktop browser and open Chrome DevTools (F12) -> Device Toolbar (Cmd+Shift+M) to run it in a simulated iPhone/Pixel frame for the best experience.*

---

## 📸 Screenshots & Feel

*(Add screenshots of your application here before sharing! Great places to screenshot: The Home Screen, The Success Pulse Checkmark, The PQC Overlay, and the Bank Linking Flow.)*

---

<div align="center">
  <b>Designed and Built by Alok.</b>
</div>
