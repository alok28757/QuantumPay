from pqcrypto.kem import ml_kem_512
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# 1. Generate Keypair
pk_obj, sk_obj = ml_kem_512.generate_keypair()

# 2. Encrypt (Encapsulate)
ct, ss_enc = ml_kem_512.encrypt(pk_obj)

# 3. Decrypt (Decapsulate)
# Remember: Secret Key first, Ciphertext second!
ss_dec = ml_kem_512.decrypt(sk_obj, ct)

# 4. Verify & Derive
if ss_dec == ss_enc:
    print("Success! Shared secret matches.")
    # We only show the first few bytes for safety
    print(f"Raw Shared Secret: {ss_dec.hex()[:16]}...")

    # ===== Step 1: Derive symmetric key =====
    # We do this INSIDE the 'if' block because we only want 
    # a key if the exchange was successful.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,       # Derive a 256-bit AES key
        salt=None,       # Optional: random salt is better in prod
        info=b'quantumpay', # Context info
    )
    symmetric_key = hkdf.derive(ss_dec)
    print(f"AES Key Derived: {symmetric_key.hex()}")

# ===== Step 2: Encrypt transaction =====
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os

    transaction_data = b"Send 10 QuantumCoins to Bob"
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, transaction_data, associated_data=None)

    print("Ciphertext:", ciphertext.hex())
    print("Nonce:", nonce.hex())

    # ===== Step 3: Decrypt transaction on recipient side =====
# Recipient uses their secret key to derive the same AES key

# Decrypt the KEM ciphertext to get the shared secret
ss_rec = ml_kem_512.decrypt(sk_obj, ct)

# Derive the same symmetric AES key
hkdf_rec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'quantumpay',
)
symmetric_key_rec = hkdf_rec.derive(ss_rec)

# Decrypt the transaction using AES-GCM
aesgcm_rec = AESGCM(symmetric_key_rec)
transaction_decrypted = aesgcm_rec.decrypt(nonce, ciphertext, associated_data=None)

print("Decrypted Transaction:", transaction_decrypted.decode())
