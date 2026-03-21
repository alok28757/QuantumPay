<div align="center">
  <img src="https://i.ibb.co/L5k6h6c/quantumpay-logo.png" alt="QuantumPay" width="120" />
  <h1>QuantumPay</h1>
  <p><strong>A Quantum-Resistant Hybrid Wallet & UPI Experience for Mobile Platforms</strong></p>
  <p>
    Built with React Native, Expo, and Firebase. 
    Implements Post-Quantum Cryptography directly on the mobile edge device.
  </p>
</div>

<br />

## Overview

QuantumPay is a high-fidelity payment application designed to simulate a production-grade digital wallet with integrated next-generation cryptographic security. Operating as a native Android application via Expo, it features a dual-mode storage architecture (Local Edge Storage and Firebase Cloud Sync) to ensure offline functionality and seamless transaction routing. 

The application serves as a proof-of-concept for deploying NIST-standardized Post-Quantum algorithms in consumer financial interfaces.

---

## Key Features

### 1. Dual-Mode Infrastructure
- **Cloud Mode:** Authenticate via mobile number and synchronize wallet balances, transaction histories, and user profiles across devices in real-time utilizing Firebase Authentication and Firestore.
- **Local Mode:** Provides an isolated local database fallback leveraging asynchronous storage for offline testing and development without network dependencies.

### 2. Money Transfer Protocol
- **Send & Receive:** A complete transactional flow for selecting contacts, specifying transfer amounts, securely hashing MPINs (SHA-256), and processing peer-to-peer transfers.
- **Atomic Operations:** Ensures data integrity by executing double-entry accounting updates (deducting sender, attributing receiver) via Firestore atomic transactions to prevent race conditions.
- **Audio & Haptic Feedback:** Integrated success cues and native haptic responses for a refined user experience.

### 3. Cryptographic Security & Validation
QuantumPay utilizes standard Web Crypto APIs and specialized polyfills to shift the cryptographic burden to the client device. Accessing any past transaction provides a validation interface containing:
- **ML-DSA-65 (Dilithium) Signatures:** Every outgoing transaction is digitally signed using Post-Quantum keys generated locally on the device.
- **AES-256-GCM Encryption:** Transaction payloads are encrypted end-to-end to ensure zero-knowledge routing by the central cloud infrastructure.
- **PBKDF2 Key Derivation:** 256-bit symmetric keys are derived sequentially from user credentials utilizing 100,000 algorithmic hash iterations.

### 4. Interactive Bank Linking
- Bank linking simulation interface to connect secondary funding sources.
- Mock OTP verification workflows to emulate standard Know Your Customer (KYC) onboarding processes.

### 5. Utility Integrations
- **QR Scanner:** Integrated optical parsing for live UPI QR codes and deep links.
- Cross-platform navigation utilizing modern frontend architectural patterns.

---

## Technology Stack

- **Frontend:** React Native, Expo (Android/Web targets), JavaScript
- **Backend & Database:** Google Firebase (Firestore NoSQL, Authentication)
- **Cryptography:** `@noble/post-quantum`, React Native Quick Crypto, Web Crypto API
- **Optical Scanner:** `html5-qrcode`

---

## Getting Started

To configure and run QuantumPay locally on an Android device or Web emulator:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/alok28757/quantumpay.git
   cd quantumpay
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory and append the following Firebase credentials (or leave empty to run entirely in Local fallback mode):
   ```env
   EXPO_PUBLIC_FIREBASE_API_KEY=your_api_key
   EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
   EXPO_PUBLIC_FIREBASE_PROJECT_ID=your_project_id
   EXPO_PUBLIC_FIREBASE_STORAGE_BUCKET=your_project.firebasestorage.app
   EXPO_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
   EXPO_PUBLIC_FIREBASE_APP_ID=your_app_id
   EXPO_PUBLIC_FIREBASE_MEASUREMENT_ID=your_measurement_id
   ```

4. **Start the Development Server:**
   ```bash
   npx expo start --android
   ```
   Alternatively, run `npm run web` to initiate the local web instance.

---

## Screenshots & Interface

[Insert application screenshots here]

---

<div align="center">
  <b>Designed and Engineered by Alok.</b>
</div>
