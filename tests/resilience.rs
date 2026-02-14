use ironclad::{aont, erasure, integrity::Manifest};
use rand::prelude::*; 

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::rng().fill_bytes(&mut data);
    data
}

fn corrupt_shard(shard: &mut [u8], num_bitflips: usize) {
    let mut rng = rand::rng();
    for _ in 0..num_bitflips {
        let idx = rng.random_range(0..shard.len());
        let bit = rng.random_range(0..8);
        shard[idx] ^= 1 << bit;
    }
}

#[test]
fn test_resilience_random_bitflips() {
    // 1. Setup
    let original_data = generate_random_data(1024 * 1024); // 1MB
    let package = aont::encrypt(&original_data).expect("Encryption failed");
    let shards = erasure::encode(&package, 4, 8).expect("Encoding failed");
    let manifest = Manifest::new("test_data", original_data.len() as u64, &shards, 4, 8);

    // 2. Corrupt EVERY shard slightly (simulate high radiation)
    // We expect the Integrity Layer to reject them.
    // If we corrupt > 8 shards, recovery should fail.
    // If we corrupt <= 8 shards, recovery should succeed (because we need 4 valid).
    
    // Scenario A: Corrupt 5 shards. 7 remain valid. Recovery -> Success.
    let mut corrupted_shards = shards.clone();
    for i in 0..5 {
        corrupt_shard(&mut corrupted_shards[i], 10);
    }

    // 3. Simulated Recovery
    let mut valid_shards = vec![None; 12];
    let mut valid_count = 0;

    for i in 0..12 {
        if manifest.verify_shard(i, &corrupted_shards[i]) {
            valid_shards[i] = Some(corrupted_shards[i].clone());
            valid_count += 1;
        }
    }

    assert_eq!(valid_count, 7, "Should have exactly 7 valid shards");

    let recovered_pkg = erasure::reconstruct(valid_shards, 4, 8).expect("Reconstruction failed");
    let decrypted = aont::decrypt(&recovered_pkg).expect("Decryption failed");

    assert_eq!(original_data, decrypted);
}

#[test]
fn test_resilience_mixed_failures() {
    // Scenario: "Missing bits" (Loss) AND "Random bitflips" (Corruption)
    // We need 4 valid shards. 
    // Let's Drop 4 shards (8 left).
    // Let's Corrupt 4 shards (4 left).
    // This is the absolute limit.
    
    let original_data = generate_random_data(500 * 1024); // 500KB
    let package = aont::encrypt(&original_data).expect("Encryption failed");
    let shards = erasure::encode(&package, 4, 8).expect("Encoding failed");
    let manifest = Manifest::new("mixed_test", original_data.len() as u64, &shards, 4, 8);

    let mut test_shards = shards.clone();

    // 1. Delete shards 0, 1, 2, 3 (Simulate by mangling them or treating as missing later)
    // We will just NOT load them into the valid_shards vector.

    // 2. Corrupt shards 4, 5, 6, 7
    for i in 4..8 {
        corrupt_shard(&mut test_shards[i], 5);
    }

    // 3. Shards 8, 9, 10, 11 are pristine.

    // Recovery Attempt
    let mut valid_shards = vec![None; 12];
    let mut valid_count = 0;

    // Simulate reading all 12 (0-3 are missing/io_error, 4-7 are corrupt, 8-11 are good)
    for i in 0..12 {
        // Simulating 0-3 missing
        if i < 4 { continue; }

        let shard_data = &test_shards[i];
        
        // Verify
        if manifest.verify_shard(i, shard_data) {
            valid_shards[i] = Some(shard_data.clone());
            valid_count += 1;
        }
    }

    assert_eq!(valid_count, 4, "Should have exactly 4 valid shards remaining");

    let recovered = erasure::reconstruct(valid_shards, 4, 8).expect("Reconstruction failed");
    let decrypted = aont::decrypt(&recovered).expect("Decryption failed");

    assert_eq!(original_data, decrypted);
}
