use crate::chunk_format::{ChunkEnvelope, decode_envelope};
use crate::integrity::Manifest;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;

const REQUIRED_METADATA_QUORUM: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CandidateKey {
    epoch: u64,
    manifest_hash: [u8; 32],
}

pub fn load_manifest_from_chunks(root_path: &Path, meta_mac_key: &[u8; 32]) -> Result<Manifest> {
    let mut counts: HashMap<CandidateKey, usize> = HashMap::new();
    let mut manifests: HashMap<CandidateKey, Manifest> = HashMap::new();

    for entry in fs::read_dir(root_path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        if entry.path().extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }

        let bytes = match fs::read(entry.path()) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let envelope = match decode_envelope(&bytes, meta_mac_key) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        let manifest = match decode_embedded_manifest(&envelope) {
            Ok(manifest) => manifest,
            Err(_) => continue,
        };

        let key = CandidateKey {
            epoch: envelope.epoch,
            manifest_hash: envelope.manifest_hash,
        };
        *counts.entry(key).or_insert(0) += 1;
        manifests.entry(key).or_insert(manifest);
    }

    let mut qualified: Vec<(CandidateKey, usize)> = counts
        .into_iter()
        .filter(|(_, count)| *count >= REQUIRED_METADATA_QUORUM)
        .collect();
    if qualified.is_empty() {
        return Err(anyhow!(
            "Critical Failure: No committed manifest quorum found in chunk files"
        ));
    }

    qualified.sort_by_key(|(key, _)| key.epoch);
    let highest_epoch = qualified
        .last()
        .map(|(key, _)| key.epoch)
        .ok_or_else(|| anyhow!("No manifest candidates after quorum filtering"))?;

    let mut winners: Vec<CandidateKey> = qualified
        .into_iter()
        .filter_map(|(key, _)| (key.epoch == highest_epoch).then_some(key))
        .collect();

    winners.sort_by_key(|k| k.manifest_hash);
    winners.dedup();

    if winners.len() > 1 {
        return Err(anyhow!(
            "Integrity Failure: Multiple manifest quorums at epoch {}",
            highest_epoch
        ));
    }

    let winner = winners
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No winner for manifest consensus"))?;

    manifests
        .remove(&winner)
        .ok_or_else(|| anyhow!("Manifest winner missing payload"))
}

pub fn encode_manifest_snapshot(manifest: &Manifest) -> Result<(Vec<u8>, [u8; 32])> {
    let config = bincode::config::standard();
    let manifest_bytes = bincode::serde::encode_to_vec(manifest, config)?;
    let manifest_hash = *blake3::hash(&manifest_bytes).as_bytes();
    let compressed = zstd::stream::encode_all(Cursor::new(manifest_bytes), 3)?;
    Ok((compressed, manifest_hash))
}

pub fn decode_embedded_manifest(envelope: &ChunkEnvelope) -> Result<Manifest> {
    let decompressed = zstd::stream::decode_all(Cursor::new(&envelope.manifest_blob_zstd))?;
    let computed_hash = *blake3::hash(&decompressed).as_bytes();
    if computed_hash != envelope.manifest_hash {
        return Err(anyhow!("Manifest hash mismatch in envelope"));
    }

    let config = bincode::config::standard();
    let (manifest, used) = bincode::serde::decode_from_slice::<Manifest, _>(&decompressed, config)?;
    if used != decompressed.len() {
        return Err(anyhow!("Trailing bytes in embedded manifest"));
    }
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_format::{ChunkEnvelope, encode_envelope};
    use tempfile::tempdir;

    fn manifest(epoch: u64, name: &str) -> Manifest {
        Manifest {
            epoch,
            file_name: name.to_string(),
            total_size: 0,
            blocks: Vec::new(),
        }
    }

    fn write_meta_copy(
        root: &Path,
        name: &str,
        m: &Manifest,
        key: &[u8; 32],
        epoch: u64,
    ) -> Result<()> {
        let (blob, hash) = encode_manifest_snapshot(m)?;
        let env = ChunkEnvelope::meta_only(epoch, hash, blob);
        let bytes = encode_envelope(&env, key)?;
        fs::write(root.join(name), bytes)?;
        Ok(())
    }

    #[test]
    fn test_recovery_selects_highest_epoch_quorum() {
        let dir = tempdir().expect("tempdir");
        let key = [5u8; 32];
        let old = manifest(2, "old");
        let new = manifest(3, "new");

        write_meta_copy(dir.path(), "meta_2_0.bin", &old, &key, 2).expect("old0");
        write_meta_copy(dir.path(), "meta_2_1.bin", &old, &key, 2).expect("old1");
        write_meta_copy(dir.path(), "meta_3_0.bin", &new, &key, 3).expect("new0");
        write_meta_copy(dir.path(), "meta_3_1.bin", &new, &key, 3).expect("new1");

        let recovered = load_manifest_from_chunks(dir.path(), &key).expect("recover");
        assert_eq!(recovered, new);
    }

    #[test]
    fn test_recovery_conflict_same_epoch_fails() {
        let dir = tempdir().expect("tempdir");
        let key = [6u8; 32];
        let a = manifest(4, "a");
        let b = manifest(4, "b");

        write_meta_copy(dir.path(), "meta_4_a0.bin", &a, &key, 4).expect("a0");
        write_meta_copy(dir.path(), "meta_4_a1.bin", &a, &key, 4).expect("a1");
        write_meta_copy(dir.path(), "meta_4_b0.bin", &b, &key, 4).expect("b0");
        write_meta_copy(dir.path(), "meta_4_b1.bin", &b, &key, 4).expect("b1");

        let err = load_manifest_from_chunks(dir.path(), &key).expect_err("must fail");
        assert!(err.to_string().contains("Multiple manifest quorums"));
    }

    #[test]
    fn test_recovery_ignores_bad_mac_copy() {
        let dir = tempdir().expect("tempdir");
        let key = [7u8; 32];
        let m = manifest(1, "ok");

        write_meta_copy(dir.path(), "meta_1_0.bin", &m, &key, 1).expect("copy0");
        write_meta_copy(dir.path(), "meta_1_1.bin", &m, &key, 1).expect("copy1");
        write_meta_copy(dir.path(), "meta_1_bad.bin", &m, &key, 1).expect("bad");

        let bad_path = dir.path().join("meta_1_bad.bin");
        let mut bytes = fs::read(&bad_path).expect("read");
        let idx = bytes.len() / 2;
        bytes[idx] ^= 0x01;
        fs::write(&bad_path, bytes).expect("write");

        let recovered = load_manifest_from_chunks(dir.path(), &key).expect("recover");
        assert_eq!(recovered, m);
    }
}
