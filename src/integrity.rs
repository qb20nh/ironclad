use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

    pub fn with_epoch(&self, epoch: u64) -> Self {
        let mut copy = self.clone();
        copy.epoch = epoch;
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_manifest_with_epoch_preserves_content() {
        let mut manifest = Manifest::new("demo.txt");
        manifest.total_size = 42;
        let bumped = manifest.with_epoch(7);
        assert_eq!(bumped.epoch, 7);
        assert_eq!(bumped.file_name, "demo.txt");
        assert_eq!(bumped.total_size, 42);
    }
}
