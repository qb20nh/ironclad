use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use ironclad::block_store::BlockStore;
use std::fs;
use std::path::PathBuf;

const STORAGE_DIR: &str = "storage";
const DEFAULT_DATA_SHARDS: usize = 4;
const DEFAULT_PARITY_SHARDS: usize = 4;

#[derive(Parser, Debug)]
#[command(name = "ironclad", about = "Ironclad Stack CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt and disperse a file into a dataset
    Write {
        input_file: PathBuf,
        #[arg(
            short = 'd',
            long = "data",
            default_value_t = DEFAULT_DATA_SHARDS
        )]
        data: usize,
        #[arg(
            short = 'p',
            long = "parity",
            default_value_t = DEFAULT_PARITY_SHARDS
        )]
        parity: usize,
        #[arg(long, default_value = "default")]
        dataset: String,
    },
    /// Recover and decrypt a dataset into an output file
    Read {
        output_file: PathBuf,
        #[arg(long, default_value = "default")]
        dataset: String,
    },
    /// Insert text at byte offset
    Insert {
        offset: u64,
        text: String,
        #[arg(
            short = 'd',
            long = "data",
            default_value_t = DEFAULT_DATA_SHARDS
        )]
        data: usize,
        #[arg(
            short = 'p',
            long = "parity",
            default_value_t = DEFAULT_PARITY_SHARDS
        )]
        parity: usize,
        #[arg(long, default_value = "default")]
        dataset: String,
    },
    /// Delete a byte range
    Delete {
        offset: u64,
        length: u64,
        #[arg(long, default_value = "default")]
        dataset: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Write {
            input_file,
            data,
            parity,
            dataset,
        } => {
            validate_shard_config(data, parity)?;
            let dataset_path = dataset_path(&dataset)?;
            fs::create_dir_all(&dataset_path)?;

            let data_bytes = fs::read(&input_file)?;
            let file_name = input_file
                .file_name()
                .ok_or_else(|| anyhow!("Input path has no file name: {}", input_file.display()))?
                .to_string_lossy()
                .into_owned();

            let mut store = BlockStore::create(dataset_path, &file_name)?;
            store.insert_at(0, &data_bytes, data, parity)?;
            store.save_manifest()?;
            println!(
                "Write complete. Dataset: {}, total size: {}",
                dataset, store.manifest.total_size
            );
        }
        Commands::Read {
            output_file,
            dataset,
        } => {
            let store = BlockStore::open(dataset_path(&dataset)?)?;
            if store.manifest.blocks.is_empty() {
                return Err(anyhow!("Dataset '{}' has no blocks to read", dataset));
            }
            println!(
                "Reading dataset '{}' (file '{}', size {})",
                dataset, store.manifest.file_name, store.manifest.total_size
            );
            let data = store.read_at(0, store.manifest.total_size)?;
            fs::write(output_file, &data)?;
            println!("Read complete.");
        }
        Commands::Insert {
            offset,
            text,
            data,
            parity,
            dataset,
        } => {
            validate_shard_config(data, parity)?;
            let mut store = BlockStore::open(dataset_path(&dataset)?)?;
            store.insert_at(offset, text.as_bytes(), data, parity)?;
            store.save_manifest()?;
            println!(
                "Insert complete. Dataset: {}, new size: {}",
                dataset, store.manifest.total_size
            );
        }
        Commands::Delete {
            offset,
            length,
            dataset,
        } => {
            let mut store = BlockStore::open(dataset_path(&dataset)?)?;
            store.delete_range(offset, length)?;
            store.save_manifest()?;
            println!(
                "Delete complete. Dataset: {}, new size: {}",
                dataset, store.manifest.total_size
            );
        }
    }

    Ok(())
}

fn dataset_path(dataset: &str) -> Result<PathBuf> {
    if dataset.is_empty() {
        return Err(anyhow!("Dataset name cannot be empty"));
    }
    if dataset == "." || dataset == ".." {
        return Err(anyhow!("Dataset name cannot be '.' or '..'"));
    }
    if dataset.contains('/') || dataset.contains('\\') {
        return Err(anyhow!("Dataset name cannot contain path separators"));
    }
    if !dataset
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "Dataset name must be ASCII alphanumeric, '-' or '_'"
        ));
    }
    Ok(PathBuf::from(STORAGE_DIR).join(dataset))
}

fn validate_shard_config(data_shards: usize, parity_shards: usize) -> Result<()> {
    if data_shards == 0 {
        return Err(anyhow!("data_shards must be greater than zero"));
    }
    if parity_shards == 0 {
        return Err(anyhow!("parity_shards must be greater than zero"));
    }
    let total = data_shards
        .checked_add(parity_shards)
        .ok_or_else(|| anyhow!("Shard count overflow"))?;
    if total > 256 {
        return Err(anyhow!(
            "Shard count too large: data + parity must be <= 256"
        ));
    }
    Ok(())
}
