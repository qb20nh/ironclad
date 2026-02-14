use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

const ROOT_KEY_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn run_cli(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ironclad"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to run ironclad binary")
}

fn run_cli_with_env(cwd: &Path, args: &[&str], env_key_hex: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ironclad"))
        .current_dir(cwd)
        .env("IRONCLAD_ROOT_KEY_HEX", env_key_hex)
        .args(args)
        .output()
        .expect("failed to run ironclad binary")
}

#[test]
fn test_namespace_write_preserves_unrelated_files() {
    let dir = tempdir().unwrap();
    let storage_root = dir.path().join("storage");
    fs::create_dir_all(&storage_root).unwrap();
    fs::write(storage_root.join("keep.txt"), b"keep").unwrap();

    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let input_arg = input.to_string_lossy().to_string();

    let output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            ROOT_KEY_HEX,
            "write",
            input_arg.as_str(),
            "--dataset",
            "alpha",
        ],
    );
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(storage_root.join("keep.txt").exists());
    assert!(storage_root.join("alpha").join("block_1_0.bin").exists());
    assert!(!storage_root.join("alpha").join("manifest_0.json").exists());
}

#[test]
fn test_read_fails_for_uninitialized_dataset() {
    let dir = tempdir().unwrap();

    let output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            ROOT_KEY_HEX,
            "read",
            "out.txt",
            "--dataset",
            "missing_dataset",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Dataset path does not exist")
            || stderr.contains("Dataset is not initialized")
    );
}

#[test]
fn test_cli_rejects_missing_value_for_data_flag() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let input_arg = input.to_string_lossy().to_string();

    let output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            ROOT_KEY_HEX,
            "write",
            input_arg.as_str(),
            "--data",
        ],
    );
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--data"));
    assert!(stderr.to_lowercase().contains("value"));
}

#[test]
fn test_read_fails_when_dataset_has_no_blocks() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let input_arg = input.to_string_lossy().to_string();

    let write_output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            ROOT_KEY_HEX,
            "write",
            input_arg.as_str(),
            "--dataset",
            "ephemeral",
        ],
    );
    assert!(write_output.status.success());

    let delete_output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            ROOT_KEY_HEX,
            "delete",
            "0",
            "5",
            "--dataset",
            "ephemeral",
        ],
    );
    assert!(delete_output.status.success());

    let read_output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            ROOT_KEY_HEX,
            "read",
            "out.txt",
            "--dataset",
            "ephemeral",
        ],
    );
    assert!(!read_output.status.success());

    let stderr = String::from_utf8_lossy(&read_output.stderr);
    assert!(stderr.contains("has no blocks"));
}

#[test]
fn test_cli_accepts_env_root_key() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let input_arg = input.to_string_lossy().to_string();

    let output = run_cli_with_env(
        dir.path(),
        &["write", input_arg.as_str(), "--dataset", "envkey"],
        ROOT_KEY_HEX,
    );
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_fails_when_root_key_missing() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let input_arg = input.to_string_lossy().to_string();

    let output = run_cli(
        dir.path(),
        &["write", input_arg.as_str(), "--dataset", "nokey"],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Root key required"));
}

#[test]
fn test_cli_fails_on_malformed_root_key() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    fs::write(&input, b"hello").unwrap();
    let input_arg = input.to_string_lossy().to_string();

    let output = run_cli(
        dir.path(),
        &[
            "--root-key-hex",
            "abcd",
            "write",
            input_arg.as_str(),
            "--dataset",
            "badkey",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Root key must be"));
}
