use ironclad::block_store::BlockStore;
use ironclad::io_guard;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use tempfile::tempdir;

const MANIFEST_FAIL_MARKER: &str = ".ironclad_fail_manifest_commit";

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
        assert!(root.join("manifest_0.json").exists());
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
        "epoch": 1,
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
        fs::write(io_guard::manifest_path(root, i), &manifest_text).unwrap();
    }

    let err = match BlockStore::open(root.to_path_buf()) {
        Ok(_) => panic!("malformed manifest should fail to open"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("No manifest files") || err.to_string().contains("Consensus"));
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
fn test_copy_on_write_failed_manifest_commit_preserves_previous_data() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "cow.txt").unwrap();
    store.insert_at(0, b"abcdef", 4, 2).unwrap();

    fs::write(root.join(MANIFEST_FAIL_MARKER), b"1").unwrap();

    let err = store
        .insert_at(3, b"Z", 4, 2)
        .expect_err("insert should fail due to forced manifest commit failure");
    assert!(err.to_string().contains("Manifest commit aborted"));

    fs::remove_file(root.join(MANIFEST_FAIL_MARKER)).unwrap();

    let reopened = BlockStore::open(root).unwrap();
    let data = reopened.read_at(0, 6).unwrap();
    assert_eq!(data, b"abcdef");
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
