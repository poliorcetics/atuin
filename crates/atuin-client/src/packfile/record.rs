//! The record schema for the packfile-tagged object.

use atuin_domain::record::{EncryptedData, Record, RecordIdx};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Tag under which the packfile manifest records are stored.
pub const PACKFILE_TAG: &str = "packfile";
/// Version string of a packfile manifest record.
pub const PACKFILE_VERSION: &str = "packfile-v1";

/// Structure encoded within the `data` column of the packfile-encoded records.
#[derive(Debug, Clone)]
pub enum PackManifest {
    /// Version 1 of the manifest.
    V1(PackManifestDataV1),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifestDataV1 {
    /// The first record which is encoded within the packfile, ie. **inclusive** lower bound.
    pub start_idx: RecordIdx,
    /// The last record which is encoded within the packfile, ie. **inclusive** upper bound.
    pub end_idx: RecordIdx,
}

#[derive(Debug, Error)]
pub enum LoadingError {
    #[error("\"{_0}\" is not a packfile tag")]
    WrongTag(String),
    #[error("failed to find version bytes.")]
    UnknownVersion,
    #[error("invalid body: {_0}")]
    MalformedBody(Box<dyn std::error::Error + Send + Sync>),
}

impl TryFrom<&Record<EncryptedData>> for PackManifest {
    type Error = LoadingError;

    fn try_from(value: &Record<EncryptedData>) -> Result<Self, Self::Error> {
        if value.tag != PACKFILE_TAG {
            return Err(LoadingError::WrongTag(value.tag.clone()));
        }

        let data: &String = &value.data.data;

        // When deserializing, the first three bytes are always reserved to identify the version of
        // the manifest.
        if data.starts_with("001") {
            let body = data.get(3..).ok_or(LoadingError::UnknownVersion)?;
            let body =
                serde_json::from_str(body).map_err(|e| LoadingError::MalformedBody(Box::new(e)))?;
            Ok(PackManifest::V1(body))
        } else {
            Err(LoadingError::UnknownVersion)
        }
    }
}

#[derive(Debug, Error)]
pub enum StoringError {
    #[error("invalid body: {_0}")]
    InvalidBody(Box<dyn std::error::Error + Send + Sync>),
}

impl TryFrom<&PackManifestDataV1> for EncryptedData {
    type Error = StoringError;

    fn try_from(value: &PackManifestDataV1) -> Result<Self, Self::Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"001");
        serde_json::to_writer(&mut buf, value)
            .map_err(|e| StoringError::InvalidBody(Box::new(e)))?;
        let data = String::from_utf8(buf).unwrap();

        Ok(Self {
            data,
            content_encryption_key: String::new(),
        })
    }
}

impl TryFrom<&PackManifest> for EncryptedData {
    type Error = StoringError;

    fn try_from(value: &PackManifest) -> Result<Self, Self::Error> {
        match value {
            PackManifest::V1(v1) => v1.try_into(),
        }
    }
}
