//! Codec for record packfiles: `encrypt(zstd(msgpack(records)))`.

use atuin_domain::record::{
    AdditionalData, DecryptedData, Encryption, Host, HostId, Record, RecordId, RecordIdx,
};
use eyre::Result;
use serde::{Deserialize, Serialize};

use super::record::PACKFILE_TAG;
use crate::record::encryption::PASETO_V4;

/// Version bound into a packfile body's encryption AD, distinct from the manifest record's own
/// version so the two ciphertexts cannot be substituted for each other.
pub const PACKFILE_BODY_VERSION: &str = "packfile-body-v1";

/// Identity a packfile's encryption is bound to: its manifest record.
#[derive(Debug)]
pub struct PackManifestRef {
    pub id: RecordId,
    pub idx: RecordIdx,
    pub host: HostId,
}

impl<'a> From<&'a PackManifestRef> for AdditionalData<'a> {
    fn from(manifest_ref: &'a PackManifestRef) -> Self {
        Self {
            id: &manifest_ref.id,
            idx: &manifest_ref.idx,
            version: PACKFILE_BODY_VERSION,
            tag: PACKFILE_TAG,
            host: &manifest_ref.host,
        }
    }
}

/// A packfile is anchored to the manifest record that describes it; `PackManifestRef` is that
/// record's identity, so it converts straight from the record (any data type -- only id/idx/host
/// are read).
impl<T> From<&Record<T>> for PackManifestRef {
    fn from(record: &Record<T>) -> Self {
        Self {
            id: record.id,
            idx: record.idx,
            host: record.host.id,
        }
    }
}

/// A record as it appears inside a packfile.
///
/// `DecryptedData` is deliberately not `Serialize`, and this is a persisted cross-client
/// format, so the packfile owns its own wire shape rather than deriving one on a shared type.
#[derive(Serialize, Deserialize)]
struct PackedRecord {
    id: RecordId,
    idx: RecordIdx,
    host: Host,
    timestamp: u64,
    version: String,
    tag: String,
    data: Vec<u8>,
}

impl From<&Record<DecryptedData>> for PackedRecord {
    fn from(r: &Record<DecryptedData>) -> Self {
        Self {
            id: r.id,
            idx: r.idx,
            host: r.host.clone(),
            timestamp: r.timestamp,
            version: r.version.clone(),
            tag: r.tag.clone(),
            data: r.data.0.clone(),
        }
    }
}

impl From<PackedRecord> for Record<DecryptedData> {
    fn from(p: PackedRecord) -> Self {
        Record {
            id: p.id,
            idx: p.idx,
            host: p.host,
            timestamp: p.timestamp,
            version: p.version,
            tag: p.tag,
            data: DecryptedData(p.data),
        }
    }
}

/// Compress and encrypt `records` into an S3-uploadable packfile body.
pub fn pack(
    records: &[Record<DecryptedData>],
    manifest_ref: &PackManifestRef,
    key: &[u8; 32],
) -> Result<Vec<u8>> {
    let packed: Vec<PackedRecord> = records.iter().map(PackedRecord::from).collect();
    let encoded = rmp_serde::to_vec(&packed)?;
    let compressed = zstd::stream::encode_all(encoded.as_slice(), 3)?;
    let encrypted = PASETO_V4::encrypt(DecryptedData(compressed), manifest_ref.into(), key);
    Ok(rmp_serde::to_vec(&encrypted)?)
}

/// Reverse of [`pack`].
pub fn unpack(
    bytes: &[u8],
    manifest_ref: &PackManifestRef,
    key: &[u8; 32],
) -> Result<Vec<Record<DecryptedData>>> {
    let encrypted = rmp_serde::from_slice(bytes)?;
    let decrypted = PASETO_V4::decrypt(encrypted, manifest_ref.into(), key)?;
    let decompressed = zstd::stream::decode_all(decrypted.0.as_slice())?;
    let packed: Vec<PackedRecord> = rmp_serde::from_slice(&decompressed)?;
    Ok(packed.into_iter().map(Record::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atuin_domain::record::Host;
    use proptest::prelude::*;
    use uuid::Uuid;

    use super::super::record::PACKFILE_VERSION;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    fn manifest_ref() -> PackManifestRef {
        PackManifestRef {
            id: RecordId(atuin_common::utils::uuid_v7()),
            idx: 42,
            host: HostId(atuin_common::utils::uuid_v7()),
        }
    }

    fn records(n: usize) -> Vec<Record<DecryptedData>> {
        let host = Host::new(HostId(atuin_common::utils::uuid_v7()));
        (0..n)
            .map(|i| {
                Record::builder()
                    .host(host.clone())
                    .version("v1".into())
                    .tag("history".into())
                    .idx(i as u64)
                    .data(DecryptedData(b"ls -la /very/repetitive/path".to_vec()))
                    .build()
            })
            .collect()
    }

    /// A fully-randomised record, so a round-trip has to preserve every field.
    fn arb_record() -> impl Strategy<Value = Record<DecryptedData>> {
        (
            any::<u128>(),
            any::<u64>(),
            any::<u128>(),
            any::<u64>(),
            "[a-z0-9]{1,8}",
            "[a-z0-9]{1,8}",
            prop::collection::vec(any::<u8>(), 0..48),
        )
            .prop_map(|(id, idx, host, timestamp, version, tag, data)| Record {
                id: RecordId(Uuid::from_u128(id)),
                idx,
                host: Host::new(HostId(Uuid::from_u128(host))),
                timestamp,
                version,
                tag,
                data: DecryptedData(data),
            })
    }

    fn arb_manifest_ref() -> impl Strategy<Value = PackManifestRef> {
        (any::<u128>(), any::<u64>(), any::<u128>()).prop_map(|(id, idx, host)| PackManifestRef {
            id: RecordId(Uuid::from_u128(id)),
            idx,
            host: HostId(Uuid::from_u128(host)),
        })
    }

    proptest! {
        /// `unpack(pack(records)) == records` for any records, manifest, and key.
        #[test]
        fn round_trips(
            records in prop::collection::vec(arb_record(), 0..16),
            manifest_ref in arb_manifest_ref(),
            key in proptest::array::uniform32(any::<u8>()),
        ) {
            let bytes = pack(&records, &manifest_ref, &key).unwrap();
            let out = unpack(&bytes, &manifest_ref, &key).unwrap();
            prop_assert_eq!(records, out);
        }

        /// A body packed for one manifest cannot be opened with a different one -- the AEAD binds
        /// the ciphertext to the manifest's `(id, idx, host)`.
        #[test]
        fn wrong_manifest_ref_fails(
            records in prop::collection::vec(arb_record(), 0..16),
            a in arb_manifest_ref(),
            b in arb_manifest_ref(),
            key in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!((a.id.0, a.idx, a.host.0) != (b.id.0, b.idx, b.host.0));
            let bytes = pack(&records, &a, &key).unwrap();
            prop_assert!(unpack(&bytes, &b, &key).is_err());
        }

        /// A body packed with one key cannot be opened with a different key.
        #[test]
        fn wrong_key_fails(
            records in prop::collection::vec(arb_record(), 0..16),
            manifest_ref in arb_manifest_ref(),
            key_a in proptest::array::uniform32(any::<u8>()),
            key_b in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(key_a != key_b);
            let bytes = pack(&records, &manifest_ref, &key_a).unwrap();
            prop_assert!(unpack(&bytes, &manifest_ref, &key_b).is_err());
        }
    }

    /// Concrete example: repetitive records compress well (the whole point of packing).
    #[test]
    fn compresses_repetitive_records() {
        let (a, k) = (manifest_ref(), key());
        let input = records(200);
        let packed_records: Vec<PackedRecord> = input.iter().map(PackedRecord::from).collect();
        let raw = rmp_serde::to_vec(&packed_records).unwrap().len();
        let packed = pack(&input, &a, &k).unwrap().len();
        assert!(packed * 4 < raw, "packed {packed} should be << raw {raw}");
    }

    /// A manifest-record ciphertext must not decrypt as a body, even with identical
    /// id/idx/host/tag -- the distinct `PACKFILE_BODY_VERSION` in the AEAD prevents substitution.
    #[test]
    fn manifest_ciphertext_is_not_a_valid_body() {
        let (a, k) = (manifest_ref(), key());
        let ad = AdditionalData {
            id: &a.id,
            idx: &a.idx,
            version: PACKFILE_VERSION,
            tag: PACKFILE_TAG,
            host: &a.host,
        };
        let manifest = PASETO_V4::encrypt(DecryptedData(b"manifest".to_vec()), ad, &k);
        let bytes = rmp_serde::to_vec(&manifest).unwrap();
        assert!(unpack(&bytes, &a, &k).is_err());
    }
}
