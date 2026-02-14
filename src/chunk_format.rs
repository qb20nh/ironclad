use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

const CHUNK_MAGIC: [u8; 8] = *b"IRCLADV2";
const CHUNK_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkKind {
    DataShard,
    MetaOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEnvelope {
    pub kind: ChunkKind,
    pub block_id: Option<usize>,
    pub shard_index: Option<usize>,
    pub data_shards: Option<usize>,
    pub parity_shards: Option<usize>,
    pub payload: Vec<u8>,
    pub epoch: u64,
    pub manifest_hash: [u8; 32],
    pub manifest_blob_zstd: Vec<u8>,
}

impl ChunkEnvelope {
    pub fn data_shard(
        block_id: usize,
        shard_index: usize,
        data_shards: usize,
        parity_shards: usize,
        payload: Vec<u8>,
        epoch: u64,
        manifest_hash: [u8; 32],
        manifest_blob_zstd: Vec<u8>,
    ) -> Self {
        Self {
            kind: ChunkKind::DataShard,
            block_id: Some(block_id),
            shard_index: Some(shard_index),
            data_shards: Some(data_shards),
            parity_shards: Some(parity_shards),
            payload,
            epoch,
            manifest_hash,
            manifest_blob_zstd,
        }
    }

    pub fn meta_only(epoch: u64, manifest_hash: [u8; 32], manifest_blob_zstd: Vec<u8>) -> Self {
        Self {
            kind: ChunkKind::MetaOnly,
            block_id: None,
            shard_index: None,
            data_shards: None,
            parity_shards: None,
            payload: Vec::new(),
            epoch,
            manifest_hash,
            manifest_blob_zstd,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChunkBody {
    magic: [u8; 8],
    version: u16,
    kind: ChunkKind,
    block_id: Option<usize>,
    shard_index: Option<usize>,
    data_shards: Option<usize>,
    parity_shards: Option<usize>,
    payload: Vec<u8>,
    epoch: u64,
    manifest_hash: [u8; 32],
    manifest_blob_zstd: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChunkPacket {
    body: Vec<u8>,
    mac: [u8; 32],
}

pub fn encode_envelope(envelope: &ChunkEnvelope, meta_mac_key: &[u8; 32]) -> Result<Vec<u8>> {
    let body = ChunkBody {
        magic: CHUNK_MAGIC,
        version: CHUNK_VERSION,
        kind: envelope.kind,
        block_id: envelope.block_id,
        shard_index: envelope.shard_index,
        data_shards: envelope.data_shards,
        parity_shards: envelope.parity_shards,
        payload: envelope.payload.clone(),
        epoch: envelope.epoch,
        manifest_hash: envelope.manifest_hash,
        manifest_blob_zstd: envelope.manifest_blob_zstd.clone(),
    };
    validate_body(&body)?;

    let config = bincode::config::standard();
    let body_bytes = bincode::serde::encode_to_vec(&body, config)?;
    let mac = *blake3::keyed_hash(meta_mac_key, &body_bytes).as_bytes();
    let packet = ChunkPacket {
        body: body_bytes,
        mac,
    };
    Ok(bincode::serde::encode_to_vec(packet, config)?)
}

pub fn decode_envelope(bytes: &[u8], meta_mac_key: &[u8; 32]) -> Result<ChunkEnvelope> {
    let config = bincode::config::standard();
    let (packet, used) = bincode::serde::decode_from_slice::<ChunkPacket, _>(bytes, config)?;
    if used != bytes.len() {
        return Err(anyhow!("Unexpected trailing bytes in envelope"));
    }

    let expected_mac = *blake3::keyed_hash(meta_mac_key, &packet.body).as_bytes();
    if packet.mac != expected_mac {
        return Err(anyhow!("Envelope MAC verification failed"));
    }

    let (body, body_used) =
        bincode::serde::decode_from_slice::<ChunkBody, _>(&packet.body, config)?;
    if body_used != packet.body.len() {
        return Err(anyhow!("Unexpected trailing bytes in chunk body"));
    }
    validate_body(&body)?;

    Ok(ChunkEnvelope {
        kind: body.kind,
        block_id: body.block_id,
        shard_index: body.shard_index,
        data_shards: body.data_shards,
        parity_shards: body.parity_shards,
        payload: body.payload,
        epoch: body.epoch,
        manifest_hash: body.manifest_hash,
        manifest_blob_zstd: body.manifest_blob_zstd,
    })
}

fn validate_body(body: &ChunkBody) -> Result<()> {
    if body.magic != CHUNK_MAGIC {
        return Err(anyhow!("Invalid chunk magic"));
    }
    if body.version != CHUNK_VERSION {
        return Err(anyhow!("Unsupported chunk version {}", body.version));
    }
    if body.manifest_blob_zstd.is_empty() {
        return Err(anyhow!("Manifest snapshot blob cannot be empty"));
    }

    match body.kind {
        ChunkKind::DataShard => {
            if body.block_id.is_none()
                || body.shard_index.is_none()
                || body.data_shards.is_none()
                || body.parity_shards.is_none()
            {
                return Err(anyhow!("Data shard envelope missing shard metadata"));
            }
        }
        ChunkKind::MetaOnly => {
            if body.block_id.is_some()
                || body.shard_index.is_some()
                || body.data_shards.is_some()
                || body.parity_shards.is_some()
            {
                return Err(anyhow!("Meta-only envelope cannot include shard metadata"));
            }
            if !body.payload.is_empty() {
                return Err(anyhow!("Meta-only envelope payload must be empty"));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_round_trip_data_shard() {
        let key = [3u8; 32];
        let envelope = ChunkEnvelope::data_shard(
            11,
            2,
            4,
            2,
            b"payload".to_vec(),
            7,
            [5u8; 32],
            b"compressed".to_vec(),
        );

        let encoded = encode_envelope(&envelope, &key).expect("encode");
        let decoded = decode_envelope(&encoded, &key).expect("decode");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn test_chunk_round_trip_meta_only() {
        let key = [7u8; 32];
        let envelope = ChunkEnvelope::meta_only(3, [9u8; 32], b"blob".to_vec());

        let encoded = encode_envelope(&envelope, &key).expect("encode");
        let decoded = decode_envelope(&encoded, &key).expect("decode");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn test_chunk_tamper_fails_mac() {
        let key = [1u8; 32];
        let envelope = ChunkEnvelope::meta_only(1, [2u8; 32], b"blob".to_vec());
        let mut encoded = encode_envelope(&envelope, &key).expect("encode");
        let idx = encoded.len() / 2;
        encoded[idx] ^= 0x01;

        let err = decode_envelope(&encoded, &key).expect_err("tamper must fail");
        assert!(err.to_string().contains("MAC"));
    }
}
