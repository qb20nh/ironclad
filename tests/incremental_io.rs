use ironclad::block_store::BlockStore;
use ironclad::{aont, erasure};
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_block_store_basic_flow() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "test.txt").unwrap();

    // 1. Insert Initial Data
    // "Hello World"
    store
        .insert_at(0, b"Hello World", 4, 2)
        .expect("Insert failed");

    let data = store.read_at(0, 11).expect("Read failed");
    assert_eq!(data, b"Hello World");

    // 2. Insert in middle
    // "Hello " + "Beautiful " + "World"
    store
        .insert_at(6, b"Beautiful ", 4, 2)
        .expect("Insert middle failed");

    let data = store.read_at(0, 21).expect("Read full failed");
    assert_eq!(data, b"Hello Beautiful World"); // 6 + 10 + 5 = 21

    assert_eq!(store.manifest.total_size, 21);

    // 3. Delete "Beautiful "
    // Offset 6, length 10
    store.delete_range(6, 10).expect("Delete failed");

    let data = store.read_at(0, 11).expect("Read after delete failed");
    assert_eq!(data, b"Hello World");
    assert_eq!(store.manifest.total_size, 11);
}

#[test]
fn test_block_store_persistence() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    {
        let mut store = BlockStore::create(root.clone(), "persist.txt").unwrap();
        store.insert_at(0, b"Persist Me", 4, 2).unwrap();
        store.save_manifest().unwrap();
    }

    {
        let store = BlockStore::open(root.clone()).unwrap();
        assert_eq!(store.manifest.total_size, 10);
        let data = store.read_at(0, 10).unwrap();
        assert_eq!(data, b"Persist Me");
    }
}

#[test]
fn test_block_store_gc() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root.clone(), "gc.txt").unwrap();

    // 1. Insert data -> creates block 1
    store.insert_at(0, b"12345678", 4, 2).unwrap();
    let block_id_1 = store.manifest.blocks[0].id;
    let file_1 = root.join(format!("block_{}_0.bin", block_id_1));
    assert!(file_1.exists(), "Block 1 file should exist");

    // 2. Overwrite/Delete -> should delete block 1
    // Deleting everything
    store.delete_range(0, 8).unwrap();

    // Check if block 1 files are gone
    assert!(!file_1.exists(), "Block 1 file should be deleted by GC");

    // 3. Insert new data -> creates block 2
    store.insert_at(0, b"NewData", 4, 2).unwrap();
    let block_id_2 = store.manifest.blocks[0].id;
    let file_2 = root.join(format!("block_{}_0.bin", block_id_2));
    assert!(file_2.exists(), "Block 2 file should exist");
}

#[test]
fn test_insert_reaches_later_blocks() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root, "later.txt").unwrap();

    store.insert_at(0, b"A", 4, 2).unwrap();
    store.insert_at(1, b"B", 4, 2).unwrap();
    store.insert_at(2, b"C", 4, 2).unwrap();
    assert_eq!(store.read_at(0, 3).unwrap(), b"ABC");

    // Offset 2 is in a later block and regressed previously.
    store.insert_at(2, b"X", 4, 2).unwrap();
    assert_eq!(store.read_at(0, 4).unwrap(), b"ABXC");
    assert_eq!(store.manifest.total_size, 4);
}

#[test]
fn test_malformed_manifest_rejected_without_panic() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let malformed = json!({
        "file_name": "bad.bin",
        "total_size": 1,
        "blocks": [{
            "id": 1,
            "original_size": 1,
            "data_shards": 1,
            "parity_shards": 1,
            "shard_hashes": []
        }]
    });

    let manifest_text = serde_json::to_vec_pretty(&malformed).unwrap();
    for i in 0..3 {
        fs::write(root.join(format!("manifest_{}.json", i)), &manifest_text).unwrap();
    }

    let err = match BlockStore::open(root.to_path_buf()) {
        Ok(_) => panic!("malformed manifest should fail to open"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("shard hashes"));
}

#[test]
fn test_overflow_bounds_checks() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root, "overflow.txt").unwrap();
    store.insert_at(0, b"123456", 4, 2).unwrap();

    assert!(store.read_at(u64::MAX, 1).is_err());
    assert!(store.read_at(1, u64::MAX).is_err());
    assert!(store.delete_range(u64::MAX, 1).is_err());
    assert!(store.delete_range(1, u64::MAX).is_err());
}

#[test]
fn test_legacy_manifest_migration() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let original = b"legacy migration payload".to_vec();
    let package = aont::encrypt(&original).unwrap();
    let data_shards = 4;
    let parity_shards = 2;
    let shards = erasure::encode(&package, data_shards, parity_shards).unwrap();

    for (i, shard) in shards.iter().enumerate() {
        fs::write(root.join(format!("shard_{}.dat", i)), shard).unwrap();
    }

    let shard_hashes: Vec<String> = shards
        .iter()
        .map(|shard| blake3::hash(shard).to_hex().to_string())
        .collect();
    let legacy_manifest = json!({
        "file_name": "legacy.txt",
        "original_size": original.len() as u64,
        "data_shards": data_shards,
        "parity_shards": parity_shards,
        "shard_hashes": shard_hashes
    });
    let legacy_manifest_text = serde_json::to_vec_pretty(&legacy_manifest).unwrap();
    for i in 0..3 {
        fs::write(
            root.join(format!("manifest_{}.json", i)),
            &legacy_manifest_text,
        )
        .unwrap();
    }

    let store = BlockStore::open(root.clone()).unwrap();
    let data = store.read_at(0, original.len() as u64).unwrap();
    assert_eq!(data, original);
    assert!(root.join("block_0_0.bin").exists());
    assert!(!root.join("shard_0.dat").exists());
}

#[test]
fn test_block_id_uniqueness_under_churn() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root, "id-churn.txt").unwrap();

    store.insert_at(0, b"abcdef", 4, 2).unwrap();
    assert_unique_ids(&store);

    for _ in 0..20 {
        store.insert_at(3, b"Z", 4, 2).unwrap();
        assert_unique_ids(&store);
        store.delete_range(3, 1).unwrap();
        assert_unique_ids(&store);
    }
}

fn assert_unique_ids(store: &BlockStore) {
    let mut ids = HashSet::new();
    for block in &store.manifest.blocks {
        assert!(ids.insert(block.id), "duplicate block id {}", block.id);
    }
}
