use ironclad::block_store::BlockStore;
use rand::prelude::*;
use std::fs;
use tempfile::tempdir;

fn generate_random_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::rng().fill_bytes(&mut data);
    data
}

fn corrupt_file(path: &std::path::Path, num_bitflips: usize) {
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

    // 1. Setup with BlockStore
    let original_data = generate_random_data(1024 * 1024); // 1MB
    let mut store = BlockStore::create(root.clone(), "test.txt").unwrap();

    store
        .insert_at(0, &original_data, 4, 8)
        .expect("Insert failed");
    let block_id = store.manifest.blocks[0].id;

    // 2. Corrupt 5 shards (files)
    // Filename pattern: block_{id}_{shard_index}.bin
    for i in 0..5 {
        let path = root.join(format!("block_{}_{}.bin", block_id, i));
        corrupt_file(&path, 10);
    }

    // 3. Read back
    let recovered = store
        .read_at(0, original_data.len() as u64)
        .expect("Recover failed");
    assert_eq!(original_data, recovered);
}

#[test]
fn test_resilience_erasure_loss_blockstore() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let original_data = generate_random_data(500 * 1024); // 500KB
    let mut store = BlockStore::create(root.clone(), "loss.txt").unwrap();
    store
        .insert_at(0, &original_data, 4, 8)
        .expect("Insert failed");
    let block_id = store.manifest.blocks[0].id;

    // 2. Delete 4 shards completely
    for i in 0..4 {
        let path = root.join(format!("block_{}_{}.bin", block_id, i));
        fs::remove_file(path).expect("Failed to delete shard");
    }

    // 3. Read back
    let recovered = store
        .read_at(0, original_data.len() as u64)
        .expect("Recover failed");
    assert_eq!(original_data, recovered);
}
