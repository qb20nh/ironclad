use anyhow::{Context, Result, anyhow};
use ironclad::{aont, erasure, integrity::Manifest};
use std::env;
use std::fs;
use std::path::Path;

const STORAGE_DIR: &str = "storage";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = &args[1];

    match command.as_str() {
        "write" => {
            // Primitive arg parsing
            if args.len() < 3 {
                println!("Usage: cargo run -- write <file> [--data <N> --parity <M>]");
                return Ok(());
            }
            let input_path = &args[2];

            // Defaults
            let mut data_shards = 4;
            let mut parity_shards = 4;

            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--data" | "-d" => {
                        if i + 1 < args.len() {
                            data_shards = args[i + 1].parse()?;
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    "--parity" | "-p" => {
                        if i + 1 < args.len() {
                            parity_shards = args[i + 1].parse()?;
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    _ => i += 1,
                }
            }

            write_file(input_path, data_shards, parity_shards)?;
        }
        "read" => {
            if args.len() < 3 {
                println!("Usage: cargo run -- read <file>");
                return Ok(());
            }
            let output_path = &args[2];
            read_file(output_path)?;
        }
        "tamper" => {
            if args.len() < 3 {
                println!("Usage: cargo run -- tamper <shard_index> [byte_index]");
                return Ok(());
            }
            let index: usize = args[2].parse()?;
            let byte_index: usize = if args.len() > 3 { args[3].parse()? } else { 0 };
            tamper_shard(index, byte_index)?;
        }
        "delete" => {
            if args.len() < 3 {
                println!("Usage: cargo run -- delete <shard_index>");
                return Ok(());
            }
            let index: usize = args[2].parse()?;
            delete_shard(index)?;
        }
        _ => {
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Ironclad Stack CLI");
    println!("Commands:");
    println!(
        "  write <file> [-d N] [-p M]  - Encrypt, Encode, and Store file with N data and M parity shards"
    );
    println!("  read <output_file>          - Read, Verify, Reconstruct, and Decrypt");
    println!("  tamper <shard_index>        - Corrupt a shard to test integrity");
    println!("  delete <shard_index>        - Delete a shard to test erasure coding");
}

fn write_file(path: &str, data_shards: usize, parity_shards: usize) -> Result<()> {
    println!("Reading file: {}", path);
    println!(
        "Configuration: Data={}, Parity={} (Total={})",
        data_shards,
        parity_shards,
        data_shards + parity_shards
    );

    let data = fs::read(path).context("Failed to read input file")?;
    let file_name = Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let original_size = data.len() as u64;

    println!("Phase 1: AONT Transform (Encrypt + Entangle)...");
    let package = aont::encrypt(&data)?;
    println!("  - Package size: {} bytes", package.len());

    println!(
        "Phase 2: Dispersal (Reed-Solomon {}, {})...",
        data_shards, parity_shards
    );
    let shards = erasure::encode(&package, data_shards, parity_shards)?;
    println!("  - Generated {} shards", shards.len());

    println!("Phase 3: Integrity (Hashing & Manifest)...");
    // Pass config to Manifest
    let manifest = Manifest::new(
        &file_name,
        original_size,
        &shards,
        data_shards,
        parity_shards,
    );

    // Storage
    let storage_path = Path::new(STORAGE_DIR);
    if !storage_path.exists() {
        fs::create_dir(storage_path)?;
    }

    // Clear old shards to avoid confusion if we shrink total shards
    // In a real app we might handle this better, but here we just overwrite/add.
    // If we went from 12 down to 6, shards 6-11 would remain from old run.

    for (i, shard) in shards.iter().enumerate() {
        let path = storage_path.join(format!("shard_{}.dat", i));
        fs::write(&path, shard)?;
        println!("  - Store shard {}: {} bytes", i, shard.len());
    }

    manifest.save_tmr(storage_path)?;
    println!("Manifest saved (TMR). Write complete.");
    Ok(())
}

fn read_file(output_path_str: &str) -> Result<()> {
    let storage_path = Path::new(STORAGE_DIR);

    println!("Phase 1: Fetching Manifest...");
    let manifest = Manifest::load_tmr(storage_path).context("Failed to load verified manifest")?;
    println!(
        "  - Validated Manifest for '{}' (Size: {})",
        manifest.file_name, manifest.original_size
    );
    println!(
        "  - Configuration: Data={}, Parity={}",
        manifest.data_shards, manifest.parity_shards
    );

    println!("Phase 2: Scavenging Shards...");
    let total_shards = manifest.data_shards + manifest.parity_shards;
    let mut collected_shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    let mut valid_count = 0;

    for i in 0..total_shards {
        let path = storage_path.join(format!("shard_{}.dat", i));
        if !path.exists() {
            println!("  [Checking Shard {}] MISSING", i);
            continue;
        }

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                println!("  [Checking Shard {}] READ ERROR", i);
                continue;
            }
        };

        if manifest.verify_shard(i, &data) {
            println!("  [Checking Shard {}] VALID", i);
            collected_shards[i] = Some(data);
            valid_count += 1;
        } else {
            println!(
                "  [Checking Shard {}] CORRUPT (Hash mismatch) -> DISCARDING",
                i
            );
        }

        if valid_count >= manifest.data_shards {
            println!(
                "  -> Found {} valid shards. Stopping search.",
                manifest.data_shards
            );
            break;
        }
    }

    if valid_count < manifest.data_shards {
        return Err(anyhow!(
            "Critical Failure: Found {} valid shards, need {}. Data is irretrievable.",
            valid_count,
            manifest.data_shards
        ));
    }

    println!("Phase 3: Reconstructing...");
    let recovered_package = erasure::reconstruct(
        collected_shards,
        manifest.data_shards,
        manifest.parity_shards,
    )?;
    println!(
        "  - Reconstructed package size: {} bytes",
        recovered_package.len()
    );

    println!("Phase 4: Decrypting (AONT Reverse)...");
    let decrypted = aont::decrypt(&recovered_package)?;

    println!("Writing output to: {}", output_path_str);
    fs::write(output_path_str, &decrypted)?;

    println!("Success! Data recovered.");
    Ok(())
}

fn tamper_shard(index: usize, byte_index: usize) -> Result<()> {
    let path = Path::new(STORAGE_DIR).join(format!("shard_{}.dat", index));
    if !path.exists() {
        return Err(anyhow!("Shard {} does not exist", index));
    }

    let mut data = fs::read(&path)?;
    if byte_index >= data.len() {
        return Err(anyhow!("Byte index out of bounds"));
    }

    let original = data[byte_index];
    data[byte_index] ^= 0xFF; // Flip all bits
    println!(
        "Tampering shard {}: Changed byte {} from {:02x} to {:02x}",
        index, byte_index, original, data[byte_index]
    );

    fs::write(&path, &data)?;
    Ok(())
}

fn delete_shard(index: usize) -> Result<()> {
    let path = Path::new(STORAGE_DIR).join(format!("shard_{}.dat", index));
    if path.exists() {
        fs::remove_file(&path)?;
        println!("Deleted shard {}", index);
    } else {
        println!("Shard {} not found", index);
    }
    Ok(())
}
