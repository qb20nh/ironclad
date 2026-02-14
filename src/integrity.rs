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
    pub file_name: String,
    pub total_size: u64,
    pub blocks: Vec<BlockMetadata>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LegacyManifest {
    pub file_name: String,
    pub original_size: u64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusManifest {
    Current(Manifest),
    Legacy(LegacyManifest),
}

impl LegacyManifest {
    pub fn to_manifest(&self) -> Manifest {
        Manifest {
            file_name: self.file_name.clone(),
            total_size: self.original_size,
            blocks: vec![BlockMetadata {
                id: 0,
                original_size: self.original_size,
                data_shards: self.data_shards,
                parity_shards: self.parity_shards,
                shard_hashes: self.shard_hashes.clone(),
            }],
        }
    }
}

impl Manifest {
    pub fn new(file_name: &str) -> Self {
        Manifest {
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
    pub fn save_tmr(&self, base_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;

        for i in 0..3 {
            let path = base_path.join(format!("manifest_{}.json", i));
            fs::write(path, &json)?;
        }
        Ok(())
    }

    /// Loads the manifest metadata using strict 2-out-of-3 majority voting.
    /// Supports both the current and legacy manifest schema.
    pub fn load_tmr_consensus(base_path: &Path) -> Result<ConsensusManifest> {
        let mut manifests = Vec::new();

        for i in 0..3 {
            let path = base_path.join(format!("manifest_{}.json", i));
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(m) = serde_json::from_str::<Manifest>(&content) {
                    manifests.push(ConsensusManifest::Current(m));
                    continue;
                }
                if let Ok(m) = serde_json::from_str::<LegacyManifest>(&content) {
                    manifests.push(ConsensusManifest::Legacy(m));
                }
            }
        }

        if manifests.is_empty() {
            return Err(anyhow!(
                "Critical Failure: No manifest files found or parseable"
            ));
        }

        if let Some(consensus) = vote_consensus(&manifests) {
            return Ok(consensus);
        }

        Err(anyhow!(
            "Integrity Failure: Consensus not reached on Manifest (Need 2/3 agreement)"
        ))
    }
}

fn vote_consensus<T: Clone + PartialEq>(items: &[T]) -> Option<T> {
    for (i, item) in items.iter().enumerate() {
        let count = items.iter().filter(|candidate| *candidate == item).count();
        if count >= 2 {
            return Some(items[i].clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

        let manifest = Manifest {
            file_name: "consensus.txt".to_string(),
            total_size: 0,
            blocks: Vec::new(),
        };
        manifest.save_tmr(root).expect("save_tmr");

        let loaded = Manifest::load_tmr_consensus(root).expect("load consensus");
        match loaded {
            ConsensusManifest::Current(m) => assert_eq!(m, manifest),
            ConsensusManifest::Legacy(_) => panic!("unexpected legacy manifest"),
        }
    }

    #[test]
    fn test_legacy_conversion() {
        let legacy = LegacyManifest {
            file_name: "legacy.txt".to_string(),
            original_size: 12,
            data_shards: 4,
            parity_shards: 2,
            shard_hashes: vec!["a".to_string(); 6],
        };
        let manifest = legacy.to_manifest();
        assert_eq!(manifest.file_name, "legacy.txt");
        assert_eq!(manifest.total_size, 12);
        assert_eq!(manifest.blocks.len(), 1);
        assert_eq!(manifest.blocks[0].id, 0);
        assert_eq!(manifest.blocks[0].shard_hashes.len(), 6);
    }
}
