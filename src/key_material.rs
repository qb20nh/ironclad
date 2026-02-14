use anyhow::{Result, anyhow};

const ROOT_KEY_BYTES: usize = 32;
const ROOT_KEY_HEX_LEN: usize = ROOT_KEY_BYTES * 2;
const AONT_MASK_CONTEXT: &str = "ironclad/v2/aont-mask";
const META_MAC_CONTEXT: &str = "ironclad/v2/meta-mac";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootKey(pub [u8; ROOT_KEY_BYTES]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedKeys {
    pub aont_mask_key: [u8; ROOT_KEY_BYTES],
    pub meta_mac_key: [u8; ROOT_KEY_BYTES],
}

impl RootKey {
    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != ROOT_KEY_HEX_LEN {
            return Err(anyhow!(
                "Root key must be {} hex characters (32 bytes)",
                ROOT_KEY_HEX_LEN
            ));
        }

        let mut bytes = [0u8; ROOT_KEY_BYTES];
        for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let hi = decode_nibble(chunk[0]).ok_or_else(|| anyhow!("Invalid root key hex"))?;
            let lo = decode_nibble(chunk[1]).ok_or_else(|| anyhow!("Invalid root key hex"))?;
            bytes[i] = (hi << 4) | lo;
        }

        Ok(Self(bytes))
    }

    pub fn derive(self) -> DerivedKeys {
        DerivedKeys {
            aont_mask_key: blake3::derive_key(AONT_MASK_CONTEXT, &self.0),
            meta_mac_key: blake3::derive_key(META_MAC_CONTEXT, &self.0),
        }
    }
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_key_from_hex_round_trip() {
        let key =
            RootKey::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("valid hex");
        assert_eq!(key.0[0], 0x00);
        assert_eq!(key.0[1], 0x01);
        assert_eq!(key.0[31], 0x1f);
    }

    #[test]
    fn test_root_key_from_hex_rejects_bad_length() {
        let err = RootKey::from_hex("abcd").expect_err("length should fail");
        assert!(err.to_string().contains("64 hex characters"));
    }

    #[test]
    fn test_root_key_from_hex_rejects_bad_chars() {
        let bad = "g00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let err = RootKey::from_hex(bad).expect_err("chars should fail");
        assert!(err.to_string().contains("Invalid root key hex"));
    }

    #[test]
    fn test_derive_separates_subkeys() {
        let key = RootKey([7u8; 32]).derive();
        assert_ne!(key.aont_mask_key, key.meta_mac_key);
    }
}
