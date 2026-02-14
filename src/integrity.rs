use crate::io_guard;
use crate::io_guard::IoOptions;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlockMetadata {
    pub id: usize,
    pub original_size: u64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_hashes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Manifest {
    pub epoch: u64,
    pub file_name: String,
    pub total_size: u64,
    pub blocks: Vec<BlockMetadata>,
}

impl Manifest {
    pub fn new(file_name: &str) -> Self {
        Manifest {
            epoch: 0,
            file_name: file_name.to_string(),
            total_size: 0,
            blocks: Vec::new(),
        }
    }

    pub fn add_block(&mut self, block: BlockMetadata) {
        self.total_size += block.original_size;
        self.blocks.push(block);
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen_ids = HashSet::new();
        let mut recomputed_total: u64 = 0;

        for block in &self.blocks {
            let total_shards = block
                .data_shards
                .checked_add(block.parity_shards)
                .ok_or_else(|| anyhow!("Block {} has shard count overflow", block.id))?;

            if block.data_shards == 0 {
                return Err(anyhow!("Block {} has zero data shards", block.id));
            }
            if total_shards == 0 {
                return Err(anyhow!("Block {} has zero total shards", block.id));
            }
            if block.shard_hashes.len() != total_shards {
                return Err(anyhow!(
                    "Block {} has {} shard hashes, expected {}",
                    block.id,
                    block.shard_hashes.len(),
                    total_shards
                ));
            }
            if !seen_ids.insert(block.id) {
                return Err(anyhow!("Duplicate block id {}", block.id));
            }

            recomputed_total = recomputed_total
                .checked_add(block.original_size)
                .ok_or_else(|| anyhow!("Manifest total_size overflow"))?;
        }

        if recomputed_total != self.total_size {
            return Err(anyhow!(
                "Manifest total_size mismatch: declared {}, actual {}",
                self.total_size,
                recomputed_total
            ));
        }

        Ok(())
    }

    /// Saves the manifest to 3 locations for TMR (Triple Modular Redundancy).
    pub fn save_tmr(&self, base_path: &Path, io_options: IoOptions) -> Result<()> {
        self.validate()?;
        let json = serde_json::to_vec_pretty(self)?;
        io_guard::write_manifest_triplet_verified(base_path, &json, io_options)
    }

    /// Loads the manifest metadata using strict 2-out-of-3 voting.
    pub fn load_tmr_consensus(base_path: &Path) -> Result<Manifest> {
        let mut manifests = Vec::new();

        for i in 0..3 {
            let path = io_guard::manifest_path(base_path, i);
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(m) = serde_json::from_str::<Manifest>(&content) {
                    if m.validate().is_ok() {
                        manifests.push(m);
                    }
                }
            }
        }

        if manifests.is_empty() {
            return Err(anyhow!(
                "Critical Failure: No manifest files found or parseable"
            ));
        }

        if let Some(consensus) = choose_consensus_manifest(&manifests) {
            return Ok(consensus);
        }

        Err(anyhow!(
            "Integrity Failure: Consensus not reached on manifest (need 2/3 agreement)"
        ))
    }
}

fn choose_consensus_manifest(manifests: &[Manifest]) -> Option<Manifest> {
    let mut selected: Option<Manifest> = None;

    for candidate in manifests {
        let count = manifests.iter().filter(|m| *m == candidate).count();
        if count >= 2 {
            match &selected {
                None => selected = Some(candidate.clone()),
                Some(current) if candidate.epoch > current.epoch => {
                    selected = Some(candidate.clone())
                }
                _ => {}
            }
        }
    }

    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_manifest(epoch: u64) -> Manifest {
        Manifest {
            epoch,
            file_name: "consensus.txt".to_string(),
            total_size: 0,
            blocks: Vec::new(),
        }
    }

    #[test]
    fn test_manifest_validation() {
        let shards = [vec![1, 2, 3], vec![4, 5, 6]];
        let shard_hashes: Vec<String> = shards
            .iter()
            .map(|s| blake3::hash(s).to_hex().to_string())
            .collect();

        let block = BlockMetadata {
            id: 1,
            original_size: 100,
            data_shards: 1,
            parity_shards: 1,
            shard_hashes,
        };

        let mut manifest = Manifest::new("test.txt");
        manifest.add_block(block);
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_manifest_consensus_current_schema() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let manifest = test_manifest(7);
        manifest
            .save_tmr(root, IoOptions::strict())
            .expect("save_tmr");

        let loaded = Manifest::load_tmr_consensus(root).expect("load consensus");
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn test_manifest_consensus_requires_quorum() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let m0 = test_manifest(1);
        let mut m1 = test_manifest(2);
        m1.file_name = "other.txt".to_string();

        fs::write(
            io_guard::manifest_path(root, 0),
            serde_json::to_vec_pretty(&m0).expect("json"),
        )
        .expect("write m0");
        fs::write(
            io_guard::manifest_path(root, 1),
            serde_json::to_vec_pretty(&m1).expect("json"),
        )
        .expect("write m1");
        fs::write(io_guard::manifest_path(root, 2), b"not-json").expect("write broken");

        let err = Manifest::load_tmr_consensus(root).expect_err("consensus should fail");
        assert!(err.to_string().contains("Consensus not reached"));
    }

    #[test]
    fn test_manifest_consensus_ignores_corrupt_copy() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let manifest = test_manifest(9);
        let bytes = serde_json::to_vec_pretty(&manifest).expect("json");

        fs::write(io_guard::manifest_path(root, 0), &bytes).expect("write 0");
        fs::write(io_guard::manifest_path(root, 1), &bytes).expect("write 1");
        fs::write(io_guard::manifest_path(root, 2), b"{bad json").expect("write 2");

        let loaded = Manifest::load_tmr_consensus(root).expect("load");
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn test_manifest_consensus_selects_highest_epoch_quorum() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let old = test_manifest(10);
        let new = test_manifest(11);

        let old_bytes = serde_json::to_vec_pretty(&old).expect("json old");
        let new_bytes = serde_json::to_vec_pretty(&new).expect("json new");

        fs::write(io_guard::manifest_path(root, 0), &new_bytes).expect("write 0");
        fs::write(io_guard::manifest_path(root, 1), &new_bytes).expect("write 1");
        fs::write(io_guard::manifest_path(root, 2), &old_bytes).expect("write 2");

        let loaded = Manifest::load_tmr_consensus(root).expect("load");
        assert_eq!(loaded.epoch, 11);
        assert_eq!(loaded, new);
    }

    #[test]
    fn test_manifest_rejects_invalid_payload() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();

        let invalid_json = r#"{
            "file_name": "invalid.txt",
            "original_size": 12,
            "data_shards": 4,
            "parity_shards": 2,
            "shard_hashes": ["a", "b", "c", "d", "e", "f"]
        }"#;

        for i in 0..3 {
            fs::write(io_guard::manifest_path(root, i), invalid_json).expect("write invalid");
        }

        let err = Manifest::load_tmr_consensus(root).expect_err("invalid payload must fail");
        assert!(err.to_string().contains("No manifest files found"));
    }
}
