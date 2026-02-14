# Ironclad

The **Ironclad** is a "Nuclear-Grade" Verifiable Information Dispersal Scheme (VIDS) designed for maximum mathematical efficiency, resilience to radiation-induced "lying" data (Byzantine faults), and simultaneous security.

## Architecture

The system relies on three distinct mathematical layers:

1. **Integrity Layer**: Cryptographic Hashing (BLAKE3). Converts "errors" (bitflips) to "erasures" (missing data).
2. **Security Layer**: All-Or-Nothing Transform (AONT) using AES-256-GCM and key entanglement.
3. **Resilience Layer**: Systematic Cauchy Reed-Solomon Erasure Coding configured by default as $n=8, k=4$ (4 data, 4 parity).

### Capabilities

- **Configurable Redundancy**: Users can define the number of data ($N$) and parity ($M$) shards.
- **Storage Overhead**: Determined by $(N + M) / N$. (Default: 200%).
- **Resilience**: Can survive the loss or corruption of any $M$ shards. (Default: 4).
  - *Example: With N=4, M=4 (Default), the system tolerates 4 failures.*

*Note: These parameters are fully configurable via the `--data` and `--parity` flags.*

## Usage

### Prerequisites

- Rust (stable)

### Build

```bash
cargo build --release
```

### CLI Commands

#### 1. Write (Encrypt & Disperse)

```bash
cargo run --release -- write <input_file> [--data <N> --parity <M> --dataset <name>]
```

*Splits the file into `N` data shards and `M` parity shards (Default: N=4, M=4).*
*Example: `cargo run --release -- write secret.txt --data 10 --parity 2 --dataset archive`*

#### 2. Read (Recover & Decrypt)

```bash
cargo run --release -- read <output_file> [--dataset <name>]
```

*Reconstructs the original file from `storage/<dataset>/` (default dataset: `default`).*

#### 3. Insert Bytes

```bash
cargo run --release -- insert <offset> <text> [--data <N> --parity <M> --dataset <name>]
```

*Inserts text at byte offset and re-encodes affected blocks.*

#### 4. Delete Range

```bash
cargo run --release -- delete <offset> <length> [--dataset <name>]
```

*Deletes a byte range and re-encodes affected blocks.*

## Security Guarantees

- **Zero Leakage**: If even 1 bit of the ciphertext is missing, the encryption key cannot be recovered (AONT property).
- **Self-Healing**: The system automatically discards corrupt shards and regenerates data from the remaining valid shards.
