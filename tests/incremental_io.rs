use ironclad::block_store::BlockStore;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

const MANIFEST_FAIL_MARKER: &str = ".ironclad_fail_manifest_commit";
const ROOT_KEY: [u8; 32] = [0x5a; 32];
const WRONG_ROOT_KEY: [u8; 32] = [0x4b; 32];

#[test]
fn test_block_store_basic_flow() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "test.txt", ROOT_KEY).unwrap();

    store
        .insert_at(0, b"Hello World", 4, 2)
        .expect("Insert failed");

    let data = store.read_at(0, 11).expect("Read failed");
    assert_eq!(data, b"Hello World");

    store
        .insert_at(6, b"Beautiful ", 4, 2)
        .expect("Insert middle failed");

    let data = store.read_at(0, 21).expect("Read full failed");
    assert_eq!(data, b"Hello Beautiful World");
    assert_eq!(store.manifest.total_size, 21);

    store.delete_range(6, 10).expect("Delete failed");

    let data = store.read_at(0, 11).expect("Read after delete failed");
    assert_eq!(data, b"Hello World");
    assert_eq!(store.manifest.total_size, 11);
}

#[test]
fn test_block_store_persistence_without_manifest_files() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    {
        let mut store = BlockStore::create(root.clone(), "persist.txt", ROOT_KEY).unwrap();
        store.insert_at(0, b"Persist Me", 4, 2).unwrap();
        store.save_manifest().unwrap();
    }

    {
        let store = BlockStore::open(root.clone(), ROOT_KEY).unwrap();
        assert_eq!(store.manifest.total_size, 10);
        let data = store.read_at(0, 10).unwrap();
        assert_eq!(data, b"Persist Me");
        assert!(!root.join("manifest_0.json").exists());
    }
}

#[test]
fn test_block_store_gc() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root.clone(), "gc.txt", ROOT_KEY).unwrap();

    store.insert_at(0, b"12345678", 4, 2).unwrap();
    let block_id_1 = store.manifest.blocks[0].id;
    let file_1 = root.join(format!("block_{}_0.bin", block_id_1));
    assert!(file_1.exists(), "Block 1 file should exist");

    store.delete_range(0, 8).unwrap();
    assert!(!file_1.exists(), "Block 1 file should be deleted by GC");

    store.insert_at(0, b"NewData", 4, 2).unwrap();
    let block_id_2 = store.manifest.blocks[0].id;
    let file_2 = root.join(format!("block_{}_0.bin", block_id_2));
    assert!(file_2.exists(), "Block 2 file should exist");
}

#[test]
fn test_insert_reaches_later_blocks() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root, "later.txt", ROOT_KEY).unwrap();

    store.insert_at(0, b"A", 4, 2).unwrap();
    store.insert_at(1, b"B", 4, 2).unwrap();
    store.insert_at(2, b"C", 4, 2).unwrap();
    assert_eq!(store.read_at(0, 3).unwrap(), b"ABC");

    store.insert_at(2, b"X", 4, 2).unwrap();
    assert_eq!(store.read_at(0, 4).unwrap(), b"ABXC");
    assert_eq!(store.manifest.total_size, 4);
}

#[test]
fn test_open_rejects_missing_metadata_quorum_without_panic() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    fs::write(root.join("garbage.bin"), b"not-a-valid-envelope").unwrap();

    let err = BlockStore::open(root, ROOT_KEY).expect_err("open must fail");
    assert!(err.to_string().contains("not initialized"));
}

#[test]
fn test_overflow_bounds_checks() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root, "overflow.txt", ROOT_KEY).unwrap();
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

    let mut store = BlockStore::create(root.clone(), "cow.txt", ROOT_KEY).unwrap();
    store.insert_at(0, b"abcdef", 4, 2).unwrap();

    fs::write(root.join(MANIFEST_FAIL_MARKER), b"1").unwrap();

    let err = store
        .insert_at(3, b"Z", 4, 2)
        .expect_err("insert should fail due to forced manifest commit failure");
    assert!(err.to_string().contains("Manifest commit aborted"));

    fs::remove_file(root.join(MANIFEST_FAIL_MARKER)).unwrap();

    let reopened = BlockStore::open(root, ROOT_KEY).unwrap();
    let data = reopened.read_at(0, 6).unwrap();
    assert_eq!(data, b"abcdef");
}

#[test]
fn test_full_delete_persists_empty_state_via_meta_fallback() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "empty-after-delete.txt", ROOT_KEY).unwrap();
    store.insert_at(0, b"abcdef", 4, 2).unwrap();
    store.delete_range(0, 6).unwrap();

    assert_eq!(store.manifest.total_size, 0);
    assert!(store.manifest.blocks.is_empty());

    let meta_files = list_meta_files(&root);
    assert!(
        meta_files
            .iter()
            .any(|name| name.starts_with(&format!("meta_{}_", store.manifest.epoch))),
        "expected metadata fallback for latest epoch"
    );

    let reopened = BlockStore::open(root, ROOT_KEY).unwrap();
    assert_eq!(reopened.manifest.total_size, 0);
    assert!(reopened.manifest.blocks.is_empty());
}

#[test]
fn test_block_id_uniqueness_under_churn() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut store = BlockStore::create(root, "id-churn.txt", ROOT_KEY).unwrap();

    store.insert_at(0, b"abcdef", 4, 2).unwrap();
    assert_unique_ids(&store);

    for _ in 0..20 {
        store.insert_at(3, b"Z", 4, 2).unwrap();
        assert_unique_ids(&store);
        store.delete_range(3, 1).unwrap();
        assert_unique_ids(&store);
    }
}

#[test]
fn test_open_with_wrong_root_key_fails() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let mut store = BlockStore::create(root.clone(), "wrong-key.txt", ROOT_KEY).unwrap();
    store.insert_at(0, b"abcdef", 4, 2).unwrap();
    drop(store);

    let err = BlockStore::open(root, WRONG_ROOT_KEY).expect_err("wrong key must fail");
    assert!(err.to_string().contains("not initialized"));
}

fn assert_unique_ids(store: &BlockStore) {
    let mut ids = HashSet::new();
    for block in &store.manifest.blocks {
        assert!(ids.insert(block.id), "duplicate block id {}", block.id);
    }
}

fn list_meta_files(root: &Path) -> Vec<String> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("meta_") && name.ends_with(".bin") {
            result.push(name);
        }
    }
    result
}
