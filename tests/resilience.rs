use ironclad::block_store::BlockStore;
use rand::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

const ROOT_KEY: [u8; 32] = [0x5a; 32];

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::rng().fill_bytes(&mut data);
    data
}

fn corrupt_file(path: &Path, num_bitflips: usize) {
    if let Ok(mut data) = fs::read(path) {
        let mut rng = rand::rng();
        for _ in 0..num_bitflips {
            if data.is_empty() {
                break;
            }
            let idx = rng.random_range(0..data.len());
            let bit = rng.random_range(0..8);
            data[idx] ^= 1 << bit;
        }
        fs::write(path, &data).expect("Failed to write corrupted data");
    }
}

#[test]
fn test_resilience_random_bitflips_blockstore() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let original_data = generate_random_data(1024 * 1024);
    let mut store = BlockStore::create(root.clone(), "test.txt", ROOT_KEY).unwrap();

    store
        .insert_at(0, &original_data, 4, 8)
        .expect("Insert failed");
    let block_id = store.manifest.blocks[0].id;

    for i in 0..5 {
        let path = root.join(format!("block_{}_{}.bin", block_id, i));
        corrupt_file(&path, 10);
    }

    let recovered = store
        .read_at(0, original_data.len() as u64)
        .expect("Recover failed");
    assert_eq!(original_data, recovered);
}

#[test]
fn test_resilience_erasure_loss_blockstore() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let original_data = generate_random_data(500 * 1024);
    let mut store = BlockStore::create(root.clone(), "loss.txt", ROOT_KEY).unwrap();
    store
        .insert_at(0, &original_data, 4, 8)
        .expect("Insert failed");
    let block_id = store.manifest.blocks[0].id;

    for i in 0..4 {
        let path = root.join(format!("block_{}_{}.bin", block_id, i));
        fs::remove_file(path).expect("Failed to delete shard");
    }

    let recovered = store
        .read_at(0, original_data.len() as u64)
        .expect("Recover failed");
    assert_eq!(original_data, recovered);
}

#[test]
fn test_resilience_mixed_loss_and_corruption_blockstore() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let original_data = generate_random_data(400 * 1024);
    let mut store = BlockStore::create(root.clone(), "mixed.txt", ROOT_KEY).unwrap();
    store
        .insert_at(0, &original_data, 4, 8)
        .expect("Insert failed");
    let block_id = store.manifest.blocks[0].id;

    for i in 0..3 {
        let path = root.join(format!("block_{}_{}.bin", block_id, i));
        fs::remove_file(path).expect("Failed to delete shard");
    }

    for i in 3..5 {
        let path = root.join(format!("block_{}_{}.bin", block_id, i));
        corrupt_file(&path, 16);
    }

    let recovered = store
        .read_at(0, original_data.len() as u64)
        .expect("Recover failed");
    assert_eq!(original_data, recovered);
}

#[test]
fn test_open_survives_single_corrupted_metadata_copy() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "meta-single-corrupt.txt", ROOT_KEY).unwrap();
    store.insert_at(0, b"abc123", 1, 1).expect("insert");
    let epoch = store.manifest.epoch;
    drop(store);

    let mut copies = metadata_files_for_epoch(&root, epoch);
    copies.sort();
    assert!(
        copies.len() >= 3,
        "expected at least 3 metadata-bearing files"
    );

    corrupt_file(&copies[0], 8);

    let reopened =
        BlockStore::open(root, ROOT_KEY).expect("open should succeed with 2 good copies");
    let data = reopened.read_at(0, 6).expect("read");
    assert_eq!(data, b"abc123");
}

#[test]
fn test_open_fails_when_two_metadata_copies_corrupted() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "meta-double-corrupt.txt", ROOT_KEY).unwrap();
    store.insert_at(0, b"abcdef", 1, 1).expect("insert");
    let epoch = store.manifest.epoch;
    drop(store);

    let mut copies = metadata_files_for_epoch(&root, epoch);
    copies.sort();
    assert!(
        copies.len() >= 3,
        "expected at least 3 metadata-bearing files"
    );

    corrupt_file(&copies[0], 8);
    corrupt_file(&copies[1], 8);

    let err = BlockStore::open(root, ROOT_KEY).expect_err("open should fail with <2 good copies");
    assert!(err.to_string().contains("not initialized"));
}

fn metadata_files_for_epoch(root: &Path, epoch: u64) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("meta_{}_", epoch))
            || (name.starts_with("block_") && name.ends_with(".bin"))
        {
            result.push(path);
        }
    }
    result
}
