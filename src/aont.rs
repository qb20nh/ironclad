use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use anyhow::{Result, anyhow};
use blake3;

/// Size of the key and canary block (32 bytes for AES-256 and BLAKE3)
pub const BLOCK_SIZE: usize = 32;
/// Size of the Nonce for AES-GCM (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Encrypts data using the Ironclad AONT scheme.
///
/// 1. Generates a random ephemeral key $K_{rand}$.
/// 2. Encrypts `data` using AES-256-GCM with $K_{rand}$.
/// 3. Computes hash of ciphertext: $H = \text{BLAKE3}(C)$.
/// 4. Computes canary block: $X = K_{rand} \oplus H$.
///
/// Returns a concatenated vector: `[Nonce (12) | Ciphertext (N) | Tag (16) | Canary (32)]`
/// Note: AES-GCM produces Ciphertext + Tag. We treat (Ciphertext + Tag) as "C" for hashing.
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>> {
    // 1. Generate random ephemeral key K_rand
    let mut key_bytes = [0u8; BLOCK_SIZE];
    OsRng.fill_bytes(&mut key_bytes);
    let k_rand = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // 2. Encrypt data
    let cipher = Aes256Gcm::new(k_rand);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // 3. Hash ciphertext (including the nonce to be safe, though prompt says Hash(C).
    // Usually we bind the nonce too. But prompt says Hash(C).
    // Robustness: Hash(Nonce + Ciphertext + Tag) ensures we can't flip bits in nonce either.
    // The prompt's "C" likely implies the full encrypted payload.
    // Let's include Nonce in the hash for maximum integrity or just the ciphertext.
    // Prompt: "Encrypt M... to get Ciphertext C. Hash... H = SHA-256(C)."
    // We will treat (Nonce + Ciphertext + Tag) as the "C" equivalent for storage.

    // Construct the payload so far: Nonce | Ciphertext | Tag
    let mut payload = Vec::with_capacity(NONCE_SIZE + ciphertext_with_tag.len() + BLOCK_SIZE);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext_with_tag);

    // Compute H = BLAKE3(Payload)
    let hash = blake3::hash(&payload);

    // 4. Entangle: X = K_rand ^ H
    let mut x = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        x[i] = key_bytes[i] ^ hash.as_bytes()[i];
    }

    // Append X to package
    payload.extend_from_slice(&x);

    Ok(payload)
}

/// Decrypts an Ironclad AONT package.
///
/// Input format: `[Nonce (12) | Ciphertext (N) | Tag (16) | Canary (32)]`
pub fn decrypt(package: &[u8]) -> Result<Vec<u8>> {
    if package.len() < NONCE_SIZE + 16 + BLOCK_SIZE {
        return Err(anyhow!("Package too short"));
    }

    // Extract parts
    let split_idx = package.len() - BLOCK_SIZE;
    let (c_part, x_part) = package.split_at(split_idx);

    // c_part contains: Nonce | Ciphertext | Tag
    // x_part contains: Canary X

    // 1. Recompute H = BLAKE3(C)
    let hash = blake3::hash(c_part);

    // 2. Recover Key: K_rand = X ^ H
    let mut key_bytes = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        key_bytes[i] = x_part[i] ^ hash.as_bytes()[i];
    }
    let k_rand = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // 3. Decrypt
    let nonce = Nonce::from_slice(&c_part[0..NONCE_SIZE]);
    let ciphertext_with_tag = &c_part[NONCE_SIZE..];

    let cipher = Aes256Gcm::new(k_rand);
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|e| anyhow!("Decryption failed (integrity check or key mismatch): {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let data = b"The quick brown fox jumps over the lazy dog. 1234567890";
        let package = encrypt(data).expect("Encryption failed");

        assert_ne!(data.as_slice(), package.as_slice());

        let decrypted = decrypt(&package).expect("Decryption failed");
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tamper_ciphertext() {
        let data = b"SECRET";
        let mut package = encrypt(data).unwrap();

        // Flip a bit in the ciphertext (somewhere in the middle)
        let idx = NONCE_SIZE + 2;
        package[idx] ^= 0x01;

        // Attempt decrypt
        // This should fail because:
        // 1. Hash(C) will change -> Derived Key will change -> Decryption with wrong key fails (likely GCM tag failure)
        // OR
        // 2. If we used the correct key, GCM tag would fail.
        // With AONT, the key itself becomes garbage, so GCM decrypt essentially tries to decrypt with a random key.
        // The GCM tag check will almost certainly fail.
        let res = decrypt(&package);
        assert!(res.is_err());
    }

    #[test]
    fn test_tamper_canary() {
        let data = b"SECRET";
        let mut package = encrypt(data).unwrap();

        // Flip a bit in the canary (last byte)
        let len = package.len();
        package[len - 1] ^= 0x01;

        // Key recovery will yield wrong key -> GCM tag failure
        let res = decrypt(&package);
        assert!(res.is_err());
    }
}
