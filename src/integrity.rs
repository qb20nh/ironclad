use serde::{Serialize, Deserialize};

use anyhow::{Result, anyhow};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Manifest {
    pub file_name: String,
    pub original_size: u64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_hashes: Vec<String>, // Store as hex strings for easier JSON reading/debugging
}

impl Manifest {
    pub fn new(file_name: &str, original_size: u64, shards: &[Vec<u8>], data_shards: usize, parity_shards: usize) -> Self {
        let shard_hashes = shards.iter()
            .map(|s| blake3::hash(s).to_hex().to_string())
            .collect();
        
        Manifest {
            file_name: file_name.to_string(),
            original_size,
            data_shards,
            parity_shards,
            shard_hashes,
        }
    }

    pub fn verify_shard(&self, index: usize, shard_data: &[u8]) -> bool {
        if index >= self.shard_hashes.len() {
            return false;
        }
        let calculated_hash = blake3::hash(shard_data).to_hex().to_string();
        self.shard_hashes[index] == calculated_hash
    }

    /// Saves the manifest to 3 locations for TMR (Triple Modular Redundancy).
    pub fn save_tmr(&self, base_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        
        for i in 0..3 {
            let path = base_path.join(format!("manifest_{}.json", i));
            fs::write(path, &json)?;
        }
        Ok(())
    }

    /// Loads the manifest using 2-out-of-3 majority voting.
    pub fn load_tmr(base_path: &Path) -> Result<Self> {
        let mut manifests = Vec::new();
        
        for i in 0..3 {
            let path = base_path.join(format!("manifest_{}.json", i));
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(m) = serde_json::from_str::<Manifest>(&content) {
                    manifests.push(m);
                }
            }
        }

        if manifests.is_empty() {
             return Err(anyhow!("Critical Failure: No manifest files found or parseable"));
        }

        // Vote
        // We need 2 matches.
        // If we have 2 or 3 items, check if any 2 are equal.
        for i in 0..manifests.len() {
             let mut count = 0;
             for j in 0..manifests.len() {
                 if manifests[i] == manifests[j] {
                     count += 1;
                 }
             }
             if count >= 2 {
                 return Ok(manifests[i].clone());
             }
        }

        // Fallback: If 3 valid manifests but all different (extremely unlikely for random errors, imply malicious rewrite or massive corruption),
        // or 1 valid manifest (others lost).
        // If only 1 exists, we might trust it if we have no choice, 
        // OR we enforce strict 2-out-of-3.
        // The prompt says "Vote on the correct hashes (2-out-of-3 majority). Now you have the 'Trusted Hashes'."
        // This implies strict majority.
        
        Err(anyhow!("Integrity Failure: Consensus not reached on Manifest (Need 2/3 agreement)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_creation_verification() {
        let shards = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let manifest = Manifest::new("test.txt", 100, &shards, 4, 8);

        assert!(manifest.verify_shard(0, &vec![1, 2, 3]));
        assert!(!manifest.verify_shard(0, &vec![1, 2, 4])); // Wrong data
        assert!(manifest.verify_shard(1, &vec![4, 5, 6]));
    }
}
