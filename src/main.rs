use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use ironclad::block_store::BlockStore;
use ironclad::io_guard::IoOptions;
use ironclad::key_material::RootKey;
use std::fs;
use std::path::PathBuf;

const STORAGE_DIR: &str = "storage";
const DEFAULT_DATA_SHARDS: usize = 4;
const DEFAULT_PARITY_SHARDS: usize = 4;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum IoModeArg {
    Strict,
    Fast,
}

impl Default for IoModeArg {
    fn default() -> Self {
        Self::Strict
    }
}

impl IoModeArg {
    fn to_io_options(self) -> IoOptions {
        match self {
            IoModeArg::Strict => IoOptions::strict(),
            IoModeArg::Fast => IoOptions::fast(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "ironclad", about = "Ironclad Stack CLI")]
struct Cli {
    #[arg(long = "root-key-hex", global = true)]
    root_key_hex: Option<String>,
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
        #[arg(long = "io-mode", value_enum, default_value_t = IoModeArg::Strict)]
        io_mode: IoModeArg,
    },
    /// Recover and decrypt a dataset into an output file
    Read {
        output_file: PathBuf,
        #[arg(long, default_value = "default")]
        dataset: String,
        #[arg(long = "io-mode", value_enum, default_value_t = IoModeArg::Strict)]
        io_mode: IoModeArg,
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
        #[arg(long = "io-mode", value_enum, default_value_t = IoModeArg::Strict)]
        io_mode: IoModeArg,
    },
    /// Delete a byte range
    Delete {
        offset: u64,
        length: u64,
        #[arg(long, default_value = "default")]
        dataset: String,
        #[arg(long = "io-mode", value_enum, default_value_t = IoModeArg::Strict)]
        io_mode: IoModeArg,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root_key = resolve_root_key(&cli)?;

    match cli.command {
        Commands::Write {
            input_file,
            data,
            parity,
            dataset,
            io_mode,
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

            let mut store = BlockStore::create_with_options(
                dataset_path,
                &file_name,
                root_key,
                io_mode.to_io_options(),
            )?;
            store.insert_at(0, &data_bytes, data, parity)?;
            println!(
                "Write complete. Dataset: {}, total size: {}",
                dataset, store.manifest.total_size
            );
        }
        Commands::Read {
            output_file,
            dataset,
            io_mode,
        } => {
            let store = BlockStore::open_with_options(
                dataset_path(&dataset)?,
                root_key,
                io_mode.to_io_options(),
            )?;
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
            io_mode,
        } => {
            validate_shard_config(data, parity)?;
            let mut store = BlockStore::open_with_options(
                dataset_path(&dataset)?,
                root_key,
                io_mode.to_io_options(),
            )?;
            store.insert_at(offset, text.as_bytes(), data, parity)?;
            println!(
                "Insert complete. Dataset: {}, new size: {}",
                dataset, store.manifest.total_size
            );
        }
        Commands::Delete {
            offset,
            length,
            dataset,
            io_mode,
        } => {
            let mut store = BlockStore::open_with_options(
                dataset_path(&dataset)?,
                root_key,
                io_mode.to_io_options(),
            )?;
            store.delete_range(offset, length)?;
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

fn resolve_root_key(cli: &Cli) -> Result<[u8; 32]> {
    let raw = cli
        .root_key_hex
        .clone()
        .or_else(|| std::env::var("IRONCLAD_ROOT_KEY_HEX").ok())
        .ok_or_else(|| {
            anyhow!(
                "Root key required: provide --root-key-hex or set IRONCLAD_ROOT_KEY_HEX (64 hex chars)"
            )
        })?;

    Ok(RootKey::from_hex(&raw)?.0)
}
