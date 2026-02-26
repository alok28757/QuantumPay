// QuantumPay Crypto Library
// SHA-256 (MPIN hashing) + AES-256-GCM (transaction encryption) + Dilithium (PQC signatures)

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

// ═══════════════════════════════════════════════════════════════════════════════
// 1. SHA-256 — MPIN HASHING
// ═══════════════════════════════════════════════════════════════════════════════

export async function hashMpin(pin) {
    const encoder = new TextEncoder();
    const data = encoder.encode(pin + "_qpay_salt_v1");
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. AES-256-GCM — TRANSACTION ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════════

// Derive a stable AES key from phone number using PBKDF2
async function deriveKey(phone) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(phone), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: encoder.encode("qpay_aes_salt_v1"), iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function encryptField(phone, plaintext) {
    if (!plaintext && plaintext !== 0) return "";
    const key = await deriveKey(phone);
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(String(plaintext)));
    // Combine IV + ciphertext, encode as base64
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined));
}

export async function decryptField(phone, ciphertext) {
    if (!ciphertext) return "";
    try {
        const key = await deriveKey(phone);
        const combined = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
        return new TextDecoder().decode(decrypted);
    } catch {
        return ciphertext; // Return as-is if decryption fails (unencrypted legacy data)
    }
}

// Encrypt multiple transaction fields at once
export async function encryptTransaction(phone, tx) {
    const [amount, note, senderName, receiverName] = await Promise.all([
        encryptField(phone, String(tx.amount)),
        encryptField(phone, tx.note || ""),
        encryptField(phone, tx.sender_name || ""),
        encryptField(phone, tx.receiver_name || ""),
    ]);
    return { ...tx, amount, note, sender_name: senderName, receiver_name: receiverName, encrypted: true };
}

// Decrypt multiple transaction fields at once
export async function decryptTransaction(phone, tx) {
    if (!tx.encrypted) return tx;
    const [amount, note, senderName, receiverName] = await Promise.all([
        decryptField(phone, tx.amount),
        decryptField(phone, tx.note),
        decryptField(phone, tx.sender_name),
        decryptField(phone, tx.receiver_name),
    ]);
    return { ...tx, amount: Number(amount) || tx.amount, note, sender_name: senderName, receiver_name: receiverName };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. DILITHIUM (ML-DSA-65) — POST-QUANTUM SIGNATURES
// ═══════════════════════════════════════════════════════════════════════════════

// Convert Uint8Array to base64 string for storage
function toBase64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function fromBase64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }

export function generatePQCKeys() {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const { publicKey, secretKey } = ml_dsa65.keygen(seed);
    return {
        publicKey: toBase64(publicKey),
        privateKey: toBase64(secretKey),
    };
}

export function signTransaction(privateKeyBase64, txData) {
    const privateKey = fromBase64(privateKeyBase64);
    const encoder = new TextEncoder();
    const message = encoder.encode(JSON.stringify(txData));
    const signature = ml_dsa65.sign(privateKey, message);
    return toBase64(signature);
}

export function verifyTransaction(publicKeyBase64, txData, signatureBase64) {
    try {
        const publicKey = fromBase64(publicKeyBase64);
        const encoder = new TextEncoder();
        const message = encoder.encode(JSON.stringify(txData));
        const signature = fromBase64(signatureBase64);
        return ml_dsa65.verify(publicKey, message, signature);
    } catch {
        return false;
    }
}

// Store PQC private key locally (never sent to server)
export function storePQCPrivateKey(phone, privateKey) {
    const keys = JSON.parse(localStorage.getItem("qp_pqc_keys") || "{}");
    keys[phone] = privateKey;
    localStorage.setItem("qp_pqc_keys", JSON.stringify(keys));
}

export function getPQCPrivateKey(phone) {
    const keys = JSON.parse(localStorage.getItem("qp_pqc_keys") || "{}");
    return keys[phone] || null;
}
