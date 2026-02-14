use reed_solomon_erasure::galois_8::ReedSolomon;
use anyhow::{Result, anyhow};

/// Encodes data into data_shards + parity_shards.
/// 
/// Returns a vector of shards.
/// The original data length is prepended (u64 little endian).
pub fn encode(data: &[u8], data_shards: usize, parity_shards: usize) -> Result<Vec<Vec<u8>>> {
    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| anyhow!("Failed to initialize ReedSolomon: {}", e))?;

    // 1. Prepend length (8 bytes)
    let len = data.len() as u64;
    let mut buffer = Vec::with_capacity(8 + data.len());
    buffer.extend_from_slice(&len.to_le_bytes());
    buffer.extend_from_slice(data);

    // 2. Pad to multiple of data_shards
    let total_len = buffer.len();
    let shard_size = (total_len + data_shards - 1) / data_shards;
    let padded_len = shard_size * data_shards;
    
    buffer.resize(padded_len, 0);

    // 3. Split into shards
    let mut shards: Vec<Vec<u8>> = buffer.chunks(shard_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    assert_eq!(shards.len(), data_shards);

    // 4. Create parity shards
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    // 5. Encode
    r.encode(&mut shards)
        .map_err(|e| anyhow!("Encoding failed: {}", e))?;

    Ok(shards)
}

/// Reconstructs original data from a subset of shards.
/// 
/// `shards` must be a vector of `data_shards + parity_shards` options. 
pub fn reconstruct(shards: Vec<Option<Vec<u8>>>, data_shards: usize, parity_shards: usize) -> Result<Vec<u8>> {
    let total_shards = data_shards + parity_shards;
    if shards.len() != total_shards {
        return Err(anyhow!("Must provide exactly {} shard containers (Some or None)", total_shards));
    }

    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| anyhow!("Failed to initialize RS: {}", e))?;

    // Check shard lengths
    let _shard_len = shards.iter().find_map(|s| s.as_ref().map(|v| v.len()))
        .ok_or(anyhow!("No shards provided"))?;

    let mut recon_shards = shards.clone();

    r.reconstruct(&mut recon_shards)
        .map_err(|e| anyhow!("Reconstruction failed: {}", e))?;

    // Extract data
    let mut result = Vec::new();
    for i in 0..data_shards {
        if let Some(shard) = &recon_shards[i] {
            result.extend_from_slice(shard);
        } else {
             return Err(anyhow!("Failed to reconstruct data shard {}", i));
        }
    }

    // Strip padding and length prefix
    if result.len() < 8 {
        return Err(anyhow!("Reconstructed data too short"));
    }

    let len_bytes: [u8; 8] = result[0..8].try_into()?;
    let original_len = u64::from_le_bytes(len_bytes) as usize;

    if result.len() < 8 + original_len {
         return Err(anyhow!("Reconstructed data length mismatch"));
    }

    Ok(result[8..8+original_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_erasure_round_trip() {
        let data = b"Ironclad Stack Resilience Test Data";
        let shards = encode(data, 4, 8).expect("Encode failed");
        
        assert_eq!(shards.len(), 12);

        // Simulate loss: Keep only 4 shards (e.g., 0, 5, 8, 11)
        let mut partial_shards: Vec<Option<Vec<u8>>> = vec![None; 12];
        partial_shards[0] = Some(shards[0].clone());
        partial_shards[5] = Some(shards[5].clone());
        partial_shards[8] = Some(shards[8].clone());
        partial_shards[11] = Some(shards[11].clone());

        let recovered = reconstruct(partial_shards, 4, 8).expect("Reconstruct failed");
        assert_eq!(data.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_insufficient_shards() {
        let data = b"Fail me";
        let shards = encode(data, 4, 8).unwrap();

        // Only 3 shards
        let mut partial_shards: Vec<Option<Vec<u8>>> = vec![None; 12];
        partial_shards[0] = Some(shards[0].clone());
        partial_shards[1] = Some(shards[1].clone());
        partial_shards[2] = Some(shards[2].clone());

        let res = reconstruct(partial_shards, 4, 8);
        assert!(res.is_err());
    }

    #[test]
    fn test_custom_config() {
        let data = b"Custom Config Data";
        // 10 data, 2 parity
        let shards = encode(data, 10, 2).unwrap();
        assert_eq!(shards.len(), 12);

        // Lose 1 shard (should recover)
        let mut partial = vec![None; 12];
        for i in 0..11 {
            partial[i] = Some(shards[i].clone());
        }
        
        let recovered = reconstruct(partial, 10, 2).unwrap();
        assert_eq!(data.as_slice(), recovered.as_slice());
    }
}
