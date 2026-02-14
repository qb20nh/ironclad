use crate::aont;
use crate::erasure;
use crate::integrity::{BlockMetadata, ConsensusManifest, LegacyManifest, Manifest};
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BlockStore {
    root_path: PathBuf,
    pub manifest: Manifest,
}

impl BlockStore {
    /// Creates a fresh dataset store.
    /// Existing managed files for this dataset are removed, while unrelated files are preserved.
    pub fn create(root_path: PathBuf, file_name: &str) -> Result<Self> {
        fs::create_dir_all(&root_path)?;
        Self::cleanup_managed_files(&root_path)?;
        Ok(BlockStore {
            root_path,
            manifest: Manifest::new(file_name),
        })
    }

    /// Opens an existing dataset store.
    /// Supports auto-migration from the legacy single-block manifest format.
    pub fn open(root_path: PathBuf) -> Result<Self> {
        if !root_path.exists() {
            return Err(anyhow!(
                "Dataset path does not exist: {}",
                root_path.display()
            ));
        }

        let manifest = match Manifest::load_tmr_consensus(&root_path) {
            Ok(ConsensusManifest::Current(m)) => {
                m.validate()?;
                m
            }
            Ok(ConsensusManifest::Legacy(m)) => Self::migrate_legacy_manifest(&root_path, &m)?,
            Err(e) => {
                if Self::manifest_files_exist(&root_path) {
                    return Err(anyhow!(
                        "Manifest exists but could not be loaded (corruption or tampering): {}",
                        e
                    ));
                }
                return Err(anyhow!(
                    "Dataset is not initialized: {}",
                    root_path.display()
                ));
            }
        };

        Ok(BlockStore {
            root_path,
            manifest,
        })
    }

    pub fn save_manifest(&self) -> Result<()> {
        self.manifest.save_tmr(&self.root_path)
    }

    fn cleanup_managed_files(root_path: &Path) -> Result<()> {
        if !root_path.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(root_path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            let name = entry.file_name();
            let name = name.to_string_lossy();
            if Self::is_managed_file(&name) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn is_managed_file(name: &str) -> bool {
        (name.starts_with("manifest_") && name.ends_with(".json"))
            || (name.starts_with("block_") && name.ends_with(".bin"))
            || (name.starts_with("shard_") && name.ends_with(".dat"))
    }

    fn manifest_files_exist(root_path: &Path) -> bool {
        (0..3).any(|i| root_path.join(format!("manifest_{}.json", i)).exists())
    }

    fn migrate_legacy_manifest(root_path: &Path, legacy: &LegacyManifest) -> Result<Manifest> {
        let manifest = legacy.to_manifest();
        manifest.validate()?;

        let block = &manifest.blocks[0];
        let total_shards = block
            .data_shards
            .checked_add(block.parity_shards)
            .ok_or_else(|| anyhow!("Legacy block shard count overflow"))?;

        for i in 0..total_shards {
            let legacy_path = root_path.join(format!("shard_{}.dat", i));
            let block_path = root_path.join(format!("block_{}_{}.bin", block.id, i));

            if !legacy_path.exists() {
                continue;
            }

            if block_path.exists() {
                fs::remove_file(legacy_path)?;
                continue;
            }

            if fs::rename(&legacy_path, &block_path).is_err() {
                fs::copy(&legacy_path, &block_path)?;
                fs::remove_file(legacy_path)?;
            }
        }

        manifest.save_tmr(root_path)?;
        Ok(manifest)
    }

    fn delete_block_files(&self, block: &BlockMetadata) -> Result<()> {
        let total_shards = block
            .data_shards
            .checked_add(block.parity_shards)
            .ok_or_else(|| anyhow!("Block {} shard count overflow", block.id))?;

        for i in 0..total_shards {
            let path = self.root_path.join(format!("block_{}_{}.bin", block.id, i));
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    /// Encodes data into a new block and saves shards to disk.
    /// Returns the BlockMetadata.
    fn create_block(
        &self,
        data: &[u8],
        id: usize,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<BlockMetadata> {
        Self::validate_shard_config(data_shards, parity_shards)?;

        // 1. AONT Encrypt
        let package = aont::encrypt(data)?;

        // 2. Erasure Encode
        let shards = erasure::encode(&package, data_shards, parity_shards)?;

        // 3. Calculate Hashes
        let mut shard_hashes = Vec::new();
        for shard in &shards {
            let hash = blake3::hash(shard).to_hex().to_string();
            shard_hashes.push(hash);
        }

        // 4. Save Shards
        // Naming convention: block_{id}_{shard_index}.bin
        for (i, shard) in shards.iter().enumerate() {
            let path = self.root_path.join(format!("block_{}_{}.bin", id, i));
            fs::write(path, shard)?;
        }

        Ok(BlockMetadata {
            id,
            original_size: data.len() as u64,
            data_shards,
            parity_shards,
            shard_hashes,
        })
    }

    /// Reads and reconstructs a block.
    fn read_block(&self, block: &BlockMetadata) -> Result<Vec<u8>> {
        let total_shards = block
            .data_shards
            .checked_add(block.parity_shards)
            .ok_or_else(|| anyhow!("Block {} shard count overflow", block.id))?;

        if block.shard_hashes.len() != total_shards {
            return Err(anyhow!(
                "Block {} metadata invalid: {} hashes for {} shards",
                block.id,
                block.shard_hashes.len(),
                total_shards
            ));
        }

        let mut loaded_shards = Vec::with_capacity(total_shards);

        for i in 0..total_shards {
            let path = self.root_path.join(format!("block_{}_{}.bin", block.id, i));
            // Try check if file exists
            if path.exists() {
                let data = fs::read(&path)?;
                // Verify hash
                let hash = blake3::hash(&data).to_hex().to_string();
                if hash == block.shard_hashes[i] {
                    loaded_shards.push(Some(data));
                } else {
                    // Tampered/Corrupted
                    loaded_shards.push(None);
                }
            } else {
                // Missing
                loaded_shards.push(None);
            }
        }

        // Reconstruct
        let package = erasure::reconstruct(loaded_shards, block.data_shards, block.parity_shards)?;

        // Decrypt
        let data = aont::decrypt(&package)?;
        let expected_size = usize::try_from(block.original_size)
            .map_err(|_| anyhow!("Block {} size too large for this platform", block.id))?;
        if data.len() != expected_size {
            return Err(anyhow!(
                "Block {} size mismatch: expected {}, reconstructed {}",
                block.id,
                expected_size,
                data.len()
            ));
        }

        Ok(data)
    }

    /// High-level Read
    pub fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let read_end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow!("Read range overflow"))?;
        if read_end > self.manifest.total_size {
            return Err(anyhow!("Read out of bounds"));
        }
        if length == 0 {
            return Ok(Vec::new());
        }

        let expected_length = usize::try_from(length)
            .map_err(|_| anyhow!("Requested read size too large for this platform"))?;

        let mut current_offset: u64 = 0;
        let mut collected_data = Vec::new();

        for block in &self.manifest.blocks {
            let block_end = current_offset
                .checked_add(block.original_size)
                .ok_or_else(|| anyhow!("Block range overflow"))?;

            // Check overlap
            if current_offset < read_end && block_end > offset {
                // Determine intersection
                let start_in_block = offset.saturating_sub(current_offset);
                let end_in_block = if read_end < block_end {
                    read_end - current_offset
                } else {
                    block.original_size
                };

                // Optimisation: If we need just a part, we still have to decode the whole block (limitation of Erasure/AONT)
                // In a production system we might cache this.
                let block_data = self.read_block(block)?;
                let start_idx = usize::try_from(start_in_block)
                    .map_err(|_| anyhow!("Block offset too large for this platform"))?;
                let end_idx = usize::try_from(end_in_block)
                    .map_err(|_| anyhow!("Block offset too large for this platform"))?;

                if start_idx > end_idx || end_idx > block_data.len() {
                    return Err(anyhow!("Block {} range is inconsistent", block.id));
                }

                let chunk = &block_data[start_idx..end_idx];
                collected_data.extend_from_slice(chunk);
            }

            current_offset = block_end;
        }

        if collected_data.len() != expected_length {
            return Err(anyhow!(
                "Read size mismatch: expected {}, got {}",
                expected_length,
                collected_data.len()
            ));
        }

        Ok(collected_data)
    }

    /// Insert data at offset.
    /// This splits the block at `offset` into [Left, Inserted, Right]
    pub fn insert_at(
        &mut self,
        offset: u64,
        data: &[u8],
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<()> {
        Self::validate_shard_config(data_shards, parity_shards)?;

        if offset > self.manifest.total_size {
            return Err(anyhow!("Insert out of bounds (can append at exact end)"));
        }

        let mut next_id = self.next_available_id()?;

        // Find the block to split
        let mut current_offset: u64 = 0;
        let mut split_index = None;
        let mut split_pos_in_block = 0;

        // If inserting at absolute end, we just append
        if offset == self.manifest.total_size {
            let new_id = Self::take_next_id(&mut next_id)?;
            let new_block = self.create_block(data, new_id, data_shards, parity_shards)?;
            self.manifest.add_block(new_block);
            return Ok(());
        }

        for (i, block) in self.manifest.blocks.iter().enumerate() {
            let block_end = current_offset
                .checked_add(block.original_size)
                .ok_or_else(|| anyhow!("Block range overflow"))?;
            if offset >= current_offset && offset < block_end {
                split_index = Some(i);
                split_pos_in_block = offset - current_offset;
                break;
            }
            current_offset = block_end;
        }

        let idx =
            split_index.ok_or_else(|| anyhow!("Insert offset not found in manifest blocks"))?;
        let block_to_split = self.manifest.blocks[idx].clone();
        let full_data = self.read_block(&block_to_split)?;
        let split_idx = usize::try_from(split_pos_in_block)
            .map_err(|_| anyhow!("Split offset too large for this platform"))?;
        if split_idx > full_data.len() {
            return Err(anyhow!("Split offset is inconsistent with block data"));
        }
        let (left_data, right_data) = full_data.split_at(split_idx);

        // Create new blocks
        let mut new_blocks = Vec::new();

        // 1. Left part (if not empty)
        if !left_data.is_empty() {
            let id = Self::take_next_id(&mut next_id)?;
            new_blocks.push(self.create_block(
                left_data,
                id,
                block_to_split.data_shards,
                block_to_split.parity_shards,
            )?);
        }

        // 2. Inserted part
        let id = Self::take_next_id(&mut next_id)?;
        new_blocks.push(self.create_block(data, id, data_shards, parity_shards)?);

        // 3. Right part (if not empty)
        if !right_data.is_empty() {
            let id = Self::take_next_id(&mut next_id)?;
            new_blocks.push(self.create_block(
                right_data,
                id,
                block_to_split.data_shards,
                block_to_split.parity_shards,
            )?);
        }

        // Replace old block with new set
        self.delete_block_files(&block_to_split)?;
        self.manifest.blocks.splice(idx..idx + 1, new_blocks);

        // Re-calculate total size
        self.recalc_total_size();

        Ok(())
    }

    /// Deletes data in range [offset, offset + length).
    /// This may involve:
    /// 1. Identifying blocks to remove completely.
    /// 2. Trimming blocks (read -> cut -> new block).
    pub fn delete_range(&mut self, offset: u64, length: u64) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        let delete_end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow!("Delete range overflow"))?;
        if delete_end > self.manifest.total_size {
            return Err(anyhow!("Delete out of bounds"));
        }

        let mut next_id = self.next_available_id()?;
        let mut current_offset: u64 = 0;
        let mut new_blocks = Vec::new();

        for block in &self.manifest.blocks {
            let block_start = current_offset;
            let block_end = current_offset
                .checked_add(block.original_size)
                .ok_or_else(|| anyhow!("Block range overflow"))?;

            // Check intersection
            let overlap_start = u64::max(offset, block_start);
            let overlap_end = u64::min(delete_end, block_end);

            if overlap_start < overlap_end {
                // This block is affected
                let data = self.read_block(block)?;
                let start_in_block = usize::try_from(overlap_start - block_start)
                    .map_err(|_| anyhow!("Delete offset too large for this platform"))?;
                let end_in_block = usize::try_from(overlap_end - block_start)
                    .map_err(|_| anyhow!("Delete offset too large for this platform"))?;
                if start_in_block > end_in_block || end_in_block > data.len() {
                    return Err(anyhow!("Delete range is inconsistent with block data"));
                }

                // Keep Left Part
                if start_in_block > 0 {
                    let left_data = &data[0..start_in_block];
                    let id = Self::take_next_id(&mut next_id)?;
                    new_blocks.push(self.create_block(
                        left_data,
                        id,
                        block.data_shards,
                        block.parity_shards,
                    )?);
                }

                // Skip Middle (Deleted)

                // Keep Right Part
                if end_in_block < data.len() {
                    let right_data = &data[end_in_block..];
                    let id = Self::take_next_id(&mut next_id)?;
                    new_blocks.push(self.create_block(
                        right_data,
                        id,
                        block.data_shards,
                        block.parity_shards,
                    )?);
                }

                // Delete old block files
                self.delete_block_files(block)?;
            } else {
                // Not affected, keep as is
                new_blocks.push(block.clone());
            }

            current_offset = block_end;
        }

        self.manifest.blocks = new_blocks;
        self.recalc_total_size();
        Ok(())
    }

    fn validate_shard_config(data_shards: usize, parity_shards: usize) -> Result<()> {
        if data_shards == 0 {
            return Err(anyhow!("data_shards must be greater than zero"));
        }
        if parity_shards == 0 {
            return Err(anyhow!("parity_shards must be greater than zero"));
        }
        let total_shards = data_shards
            .checked_add(parity_shards)
            .ok_or_else(|| anyhow!("Shard count overflow"))?;
        if total_shards > 256 {
            return Err(anyhow!(
                "Shard count too large: data_shards + parity_shards must be <= 256"
            ));
        }
        Ok(())
    }

    fn next_available_id(&self) -> Result<usize> {
        self.manifest
            .blocks
            .iter()
            .map(|b| b.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow!("Block id overflow"))
    }

    fn take_next_id(next_id: &mut usize) -> Result<usize> {
        let id = *next_id;
        *next_id = next_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("Block id overflow"))?;
        Ok(id)
    }

    fn recalc_total_size(&mut self) {
        self.manifest.total_size = self.manifest.blocks.iter().map(|b| b.original_size).sum();
    }
}
