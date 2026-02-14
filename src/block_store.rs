use crate::aont;
use crate::chunk_format::{self, ChunkEnvelope, ChunkKind};
use crate::erasure;
use crate::integrity::{BlockMetadata, Manifest};
use crate::io_guard::{self, IoOptions};
use crate::key_material::{DerivedKeys, RootKey};
use crate::manifest_recovery;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

const METADATA_COPY_TARGET: usize = 3;
const TEST_MANIFEST_FAIL_MARKER: &str = ".ironclad_fail_manifest_commit";

#[derive(Debug, Clone)]
struct PendingBlock {
    metadata: BlockMetadata,
    shards: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct BlockStore {
    root_path: PathBuf,
    pub manifest: Manifest,
    io_options: IoOptions,
    derived_keys: DerivedKeys,
}

impl BlockStore {
    /// Creates a fresh dataset store.
    /// Existing managed files for this dataset are removed, while unrelated files are preserved.
    pub fn create(root_path: PathBuf, file_name: &str, root_key: [u8; 32]) -> Result<Self> {
        Self::create_with_options(root_path, file_name, root_key, IoOptions::strict())
    }

    /// Creates a fresh dataset store with explicit I/O options.
    pub fn create_with_options(
        root_path: PathBuf,
        file_name: &str,
        root_key: [u8; 32],
        io_options: IoOptions,
    ) -> Result<Self> {
        fs::create_dir_all(&root_path)?;
        Self::cleanup_managed_files(&root_path)?;
        Ok(BlockStore {
            root_path,
            manifest: Manifest::new(file_name),
            io_options,
            derived_keys: RootKey(root_key).derive(),
        })
    }

    /// Opens an existing dataset store.
    pub fn open(root_path: PathBuf, root_key: [u8; 32]) -> Result<Self> {
        Self::open_with_options(root_path, root_key, IoOptions::strict())
    }

    /// Opens an existing dataset store with explicit I/O options.
    pub fn open_with_options(
        root_path: PathBuf,
        root_key: [u8; 32],
        io_options: IoOptions,
    ) -> Result<Self> {
        if !root_path.exists() {
            return Err(anyhow!(
                "Dataset path does not exist: {}",
                root_path.display()
            ));
        }

        let derived_keys = RootKey(root_key).derive();
        let manifest =
            manifest_recovery::load_manifest_from_chunks(&root_path, &derived_keys.meta_mac_key)
                .map_err(|err| {
                    anyhow!(
                        "Dataset is not initialized: {} ({})",
                        root_path.display(),
                        err
                    )
                })?;

        Ok(BlockStore {
            root_path,
            manifest,
            io_options,
            derived_keys,
        })
    }

    pub fn save_manifest(&self) -> Result<()> {
        self.persist_manifest_artifacts(&self.manifest, &[])
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
            || (name.starts_with("meta_") && name.ends_with(".bin"))
            || (name.starts_with("shard_") && name.ends_with(".dat"))
    }

    fn delete_block_files(&self, block: &BlockMetadata) -> Result<()> {
        let total_shards = block
            .data_shards
            .checked_add(block.parity_shards)
            .ok_or_else(|| anyhow!("Block {} shard count overflow", block.id))?;
        self.delete_block_files_by_id(block.id, total_shards)
    }

    fn delete_block_files_by_id(&self, block_id: usize, total_shards: usize) -> Result<()> {
        for i in 0..total_shards {
            let path = self.root_path.join(format!("block_{}_{}.bin", block_id, i));
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    fn delete_block_files_best_effort(&self, block: &BlockMetadata) {
        let _ = self.delete_block_files(block);
    }

    fn cleanup_old_meta_files_best_effort(&self, current_epoch: u64) {
        let entries = match fs::read_dir(&self.root_path) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if !file_type.is_file() {
                continue;
            }

            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(epoch) = Self::parse_meta_epoch(&name) else {
                continue;
            };
            if epoch < current_epoch {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn parse_meta_epoch(name: &str) -> Option<u64> {
        if !name.starts_with("meta_") || !name.ends_with(".bin") {
            return None;
        }

        let stem = name.strip_suffix(".bin")?;
        let mut parts = stem.split('_');
        if parts.next() != Some("meta") {
            return None;
        }
        let epoch = parts.next()?.parse::<u64>().ok()?;
        parts.next()?;
        Some(epoch)
    }

    /// Encodes data into a new block but keeps output in memory until commit.
    fn create_block(
        &self,
        data: &[u8],
        id: usize,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<PendingBlock> {
        Self::validate_shard_config(data_shards, parity_shards)?;

        // 1. AONT Encrypt
        let package = aont::encrypt(data, &self.derived_keys.aont_mask_key)?;

        // 2. Erasure Encode
        let shards = erasure::encode(&package, data_shards, parity_shards)?;

        // 3. Calculate Hashes for shard payloads
        let shard_hashes = shards
            .iter()
            .map(|shard| blake3::hash(shard).to_hex().to_string())
            .collect();

        Ok(PendingBlock {
            metadata: BlockMetadata {
                id,
                original_size: data.len() as u64,
                data_shards,
                parity_shards,
                shard_hashes,
            },
            shards,
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
            let envelope_bytes = match fs::read(path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    loaded_shards.push(None);
                    continue;
                }
                Err(_) => {
                    loaded_shards.push(None);
                    continue;
                }
            };

            let envelope = match chunk_format::decode_envelope(
                &envelope_bytes,
                &self.derived_keys.meta_mac_key,
            ) {
                Ok(envelope) => envelope,
                Err(_) => {
                    loaded_shards.push(None);
                    continue;
                }
            };

            if envelope.kind != ChunkKind::DataShard
                || envelope.block_id != Some(block.id)
                || envelope.shard_index != Some(i)
                || envelope.data_shards != Some(block.data_shards)
                || envelope.parity_shards != Some(block.parity_shards)
            {
                loaded_shards.push(None);
                continue;
            }

            let payload_hash = blake3::hash(&envelope.payload).to_hex().to_string();
            if payload_hash != block.shard_hashes[i] {
                loaded_shards.push(None);
                continue;
            }

            loaded_shards.push(Some(envelope.payload));
        }

        // Reconstruct
        let package = erasure::reconstruct(loaded_shards, block.data_shards, block.parity_shards)?;

        // Decrypt
        let data = aont::decrypt(&package, &self.derived_keys.aont_mask_key)?;
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

            if current_offset < read_end && block_end > offset {
                let start_in_block = offset.saturating_sub(current_offset);
                let end_in_block = if read_end < block_end {
                    read_end - current_offset
                } else {
                    block.original_size
                };

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
    /// This splits the block at `offset` into [Left, Inserted, Right].
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
        let mut next_manifest = self.manifest.clone();
        let mut obsolete_blocks = Vec::new();
        let mut pending_blocks = Vec::new();

        if offset == self.manifest.total_size {
            let new_id = Self::take_next_id(&mut next_id)?;
            let new_block = self.create_block(data, new_id, data_shards, parity_shards)?;
            next_manifest.add_block(new_block.metadata.clone());
            pending_blocks.push(new_block);
            return self.commit_manifest(next_manifest, obsolete_blocks, pending_blocks);
        }

        let mut current_offset: u64 = 0;
        let mut split_index = None;
        let mut split_pos_in_block = 0;

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

        let mut new_blocks = Vec::new();

        if !left_data.is_empty() {
            let id = Self::take_next_id(&mut next_id)?;
            let pending = self.create_block(
                left_data,
                id,
                block_to_split.data_shards,
                block_to_split.parity_shards,
            )?;
            new_blocks.push(pending.metadata.clone());
            pending_blocks.push(pending);
        }

        let id = Self::take_next_id(&mut next_id)?;
        let inserted = self.create_block(data, id, data_shards, parity_shards)?;
        new_blocks.push(inserted.metadata.clone());
        pending_blocks.push(inserted);

        if !right_data.is_empty() {
            let id = Self::take_next_id(&mut next_id)?;
            let pending = self.create_block(
                right_data,
                id,
                block_to_split.data_shards,
                block_to_split.parity_shards,
            )?;
            new_blocks.push(pending.metadata.clone());
            pending_blocks.push(pending);
        }

        next_manifest.blocks.splice(idx..idx + 1, new_blocks);
        Self::recalc_total_size(&mut next_manifest)?;

        obsolete_blocks.push(block_to_split);
        self.commit_manifest(next_manifest, obsolete_blocks, pending_blocks)
    }

    /// Deletes data in range [offset, offset + length).
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
        let mut obsolete_blocks = Vec::new();
        let mut pending_blocks = Vec::new();

        for block in &self.manifest.blocks {
            let block_start = current_offset;
            let block_end = current_offset
                .checked_add(block.original_size)
                .ok_or_else(|| anyhow!("Block range overflow"))?;

            let overlap_start = u64::max(offset, block_start);
            let overlap_end = u64::min(delete_end, block_end);

            if overlap_start < overlap_end {
                let data = self.read_block(block)?;
                let start_in_block = usize::try_from(overlap_start - block_start)
                    .map_err(|_| anyhow!("Delete offset too large for this platform"))?;
                let end_in_block = usize::try_from(overlap_end - block_start)
                    .map_err(|_| anyhow!("Delete offset too large for this platform"))?;
                if start_in_block > end_in_block || end_in_block > data.len() {
                    return Err(anyhow!("Delete range is inconsistent with block data"));
                }

                if start_in_block > 0 {
                    let left_data = &data[0..start_in_block];
                    let id = Self::take_next_id(&mut next_id)?;
                    let pending =
                        self.create_block(left_data, id, block.data_shards, block.parity_shards)?;
                    new_blocks.push(pending.metadata.clone());
                    pending_blocks.push(pending);
                }

                if end_in_block < data.len() {
                    let right_data = &data[end_in_block..];
                    let id = Self::take_next_id(&mut next_id)?;
                    let pending =
                        self.create_block(right_data, id, block.data_shards, block.parity_shards)?;
                    new_blocks.push(pending.metadata.clone());
                    pending_blocks.push(pending);
                }

                obsolete_blocks.push(block.clone());
            } else {
                new_blocks.push(block.clone());
            }

            current_offset = block_end;
        }

        let mut next_manifest = self.manifest.clone();
        next_manifest.blocks = new_blocks;
        Self::recalc_total_size(&mut next_manifest)?;

        self.commit_manifest(next_manifest, obsolete_blocks, pending_blocks)
    }

    fn write_envelope_file(&self, path: &Path, envelope: &ChunkEnvelope) -> Result<()> {
        let bytes = chunk_format::encode_envelope(envelope, &self.derived_keys.meta_mac_key)?;
        let expected_hash = blake3::hash(&bytes).to_hex().to_string();
        io_guard::write_atomic_verified(path, &bytes, &expected_hash, self.io_options)?;
        Ok(())
    }

    fn persist_manifest_artifacts(
        &self,
        manifest: &Manifest,
        pending_blocks: &[PendingBlock],
    ) -> Result<()> {
        let fail_marker = self.root_path.join(TEST_MANIFEST_FAIL_MARKER);
        if fail_marker.exists() {
            return Err(anyhow!(
                "Manifest commit aborted due to failure marker: {}",
                fail_marker.display()
            ));
        }

        let (manifest_blob_zstd, manifest_hash) =
            manifest_recovery::encode_manifest_snapshot(manifest)?;
        let mut written_paths = Vec::new();

        let write_result = (|| -> Result<()> {
            let mut metadata_copies = 0usize;

            for pending in pending_blocks {
                let total_shards = pending
                    .metadata
                    .data_shards
                    .checked_add(pending.metadata.parity_shards)
                    .ok_or_else(|| anyhow!("Block {} shard count overflow", pending.metadata.id))?;
                if pending.shards.len() != total_shards {
                    return Err(anyhow!(
                        "Pending block {} shard count mismatch ({} != {})",
                        pending.metadata.id,
                        pending.shards.len(),
                        total_shards
                    ));
                }

                for (i, shard_payload) in pending.shards.iter().enumerate() {
                    let envelope = ChunkEnvelope::data_shard(
                        pending.metadata.id,
                        i,
                        pending.metadata.data_shards,
                        pending.metadata.parity_shards,
                        shard_payload.clone(),
                        manifest.epoch,
                        manifest_hash,
                        manifest_blob_zstd.clone(),
                    );
                    let path = self
                        .root_path
                        .join(format!("block_{}_{}.bin", pending.metadata.id, i));
                    self.write_envelope_file(&path, &envelope)?;
                    written_paths.push(path);
                    metadata_copies += 1;
                }
            }

            let mut fallback_idx = 0usize;
            while metadata_copies < METADATA_COPY_TARGET {
                let path = self
                    .root_path
                    .join(format!("meta_{}_{}.bin", manifest.epoch, fallback_idx));
                fallback_idx = fallback_idx
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("Meta fallback index overflow"))?;

                if path.exists() {
                    continue;
                }

                let envelope = ChunkEnvelope::meta_only(
                    manifest.epoch,
                    manifest_hash,
                    manifest_blob_zstd.clone(),
                );
                self.write_envelope_file(&path, &envelope)?;
                written_paths.push(path);
                metadata_copies += 1;
            }

            Ok(())
        })();

        if let Err(err) = write_result {
            for path in written_paths {
                let _ = fs::remove_file(path);
            }
            return Err(err);
        }

        Ok(())
    }

    fn commit_manifest(
        &mut self,
        mut next_manifest: Manifest,
        obsolete_blocks: Vec<BlockMetadata>,
        pending_blocks: Vec<PendingBlock>,
    ) -> Result<()> {
        next_manifest.epoch = self
            .manifest
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow!("Manifest epoch overflow"))?;
        next_manifest.validate()?;
        self.persist_manifest_artifacts(&next_manifest, &pending_blocks)?;

        self.manifest = next_manifest;

        for block in &obsolete_blocks {
            self.delete_block_files_best_effort(block);
        }
        self.cleanup_old_meta_files_best_effort(self.manifest.epoch);

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

    fn recalc_total_size(manifest: &mut Manifest) -> Result<()> {
        manifest.total_size = manifest
            .blocks
            .iter()
            .try_fold(0u64, |acc, block| acc.checked_add(block.original_size))
            .ok_or_else(|| anyhow!("Manifest total_size overflow"))?;
        Ok(())
    }
}
