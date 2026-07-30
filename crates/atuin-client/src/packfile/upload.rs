//! Uploads a packed history range: rebuild the blob from a manifest and ship it.
//!
//! [`upload_packed`] takes a `packfile` manifest record, reads the history run it covers,
//! compresses + encrypts it with the pack codec (bound to the manifest via [`PackManifestRef`]), and PUTs
//! the blob to the presigned URL the server hands back. The manifest record itself is authored by
//! the packer and synced separately; this only ships the bytes.

use atuin_domain::record::{EncryptedData, Record, RecordId};
use futures::future::try_join_all;
use thiserror::Error;

use crate::{
    api_client::Client,
    history::HISTORY_TAG,
    record::{encryption::PASETO_V4, sqlite_store::SqliteStore},
};

use super::codec::{PackManifestRef, pack};
use super::record::{LoadingError, PackManifest};

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("failed to load the packfile manifest: {0}")]
    PackManifest(#[from] LoadingError),

    #[error("failed to read the history range from the store: {0}")]
    Store(eyre::Report),

    #[error("failed to decrypt a history record: {0}")]
    Decrypt(eyre::Report),

    #[error("failed to pack the bundle: {0}")]
    Pack(eyre::Report),

    #[error("bundle upload failed: {0}")]
    Api(eyre::Report),
}

/// Build and upload the bundle blob for a single `packfile` manifest record.
///
/// The manifest gives both the source range (`start_idx..=end_idx`) and the [`PackManifestRef`] identity
/// (its own `id`/`idx`/`host`) that the blob's encryption is bound to. The referenced records must
/// already be on the server -- `create_bundle` bundles ids the server already knows -- so this
/// runs after the loose records for the range have synced.
///
/// Returns the server's bundle id.
pub async fn upload_packed(
    manifest: &Record<EncryptedData>,
    store: &SqliteStore,
    key: &[u8; 32],
    client: &Client<'_>,
) -> Result<RecordId, UploadError> {
    let PackManifest::V1(range) = PackManifest::try_from(manifest)?;

    let host = manifest.host.id;
    let manifest_ref = PackManifestRef::from(manifest);

    let count = range.end_idx - range.start_idx + 1;
    let run = store
        .next(host, HISTORY_TAG, range.start_idx, count)
        .await
        .map_err(UploadError::Store)?;

    let ids: Vec<RecordId> = run.iter().map(|record| record.id).collect();

    let decrypted = run
        .into_iter()
        .map(|record| record.decrypt::<PASETO_V4>(key))
        .collect::<Result<Vec<_>, _>>()
        .map_err(UploadError::Decrypt)?;

    let blob = pack(&decrypted, &manifest_ref, key).map_err(UploadError::Pack)?;

    let (url, bundle_id) = client
        .create_bundle(&ids, blob.len())
        .await
        .map_err(UploadError::Api)?;
    client
        .put_packfile(&url, blob)
        .await
        .map_err(UploadError::Api)?;

    Ok(bundle_id)
}

/// Maximum bundle uploads to run concurrently within one batch.
const UPLOAD_CONCURRENCY: usize = 8;

/// Build and upload the bundle blobs for many `packfile` manifest records.
///
/// The manifests are shipped in bounded concurrent batches of [`UPLOAD_CONCURRENCY`]: each bundle
/// is independent (it carries its own history range and manifest identity), so they need no
/// ordering between them. Returns the server bundle ids in input order. The first failure aborts
/// and propagates -- any bundles already shipped are harmless, since a re-run re-ships the range.
pub async fn upload_packed_many(
    manifests: &[Record<EncryptedData>],
    store: &SqliteStore,
    key: &[u8; 32],
    client: &Client<'_>,
) -> Result<Vec<RecordId>, UploadError> {
    let mut bundle_ids = Vec::with_capacity(manifests.len());
    for batch in manifests.chunks(UPLOAD_CONCURRENCY) {
        let ids = try_join_all(
            batch
                .iter()
                .map(|manifest| upload_packed(manifest, store, key, client)),
        )
        .await?;
        bundle_ids.extend(ids);
    }
    Ok(bundle_ids)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use atuin_common::utils::uuid_v7;
    use atuin_domain::record::{DecryptedData, Host, HostId};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::{
        api_client::AuthToken,
        packfile::{PACKFILE_TAG, try_pack},
        settings::test_local_timeout,
    };

    async fn seed_encrypted_history(store: &SqliteStore, host: HostId, key: &[u8; 32], count: u64) {
        for idx in 0..count {
            let record = Record::builder()
                .host(Host::new(host))
                .version("v1".into())
                .tag(HISTORY_TAG.to_owned())
                .idx(idx)
                .data(DecryptedData(format!("command number {idx}").into_bytes()))
                .build()
                .encrypt::<PASETO_V4>(key);
            store.push(&record).await.unwrap();
        }
    }

    #[tokio::test]
    async fn uploads_the_packed_range() {
        let key = [3u8; 32];
        let host = HostId(uuid_v7());
        let store = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();

        // Seed history, then let the packer author a manifest over it.
        seed_encrypted_history(&store, host, &key, 5).await;
        try_pack(&store, host, 1..=5, HISTORY_TAG).await.unwrap();
        let manifest = store
            .last(host, PACKFILE_TAG)
            .await
            .unwrap()
            .expect("packer should have written a manifest");

        // Mock the two-step upload: create_bundle -> presigned URL, then the PUT.
        let server = MockServer::start().await;
        let bundle_id = RecordId(uuid_v7());
        Mock::given(method("POST"))
            .and(path("/api/v0/bundles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "upload_url": format!("{}/upload/abc", server.uri()),
                "bundle_id": bundle_id.0.to_string(),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/upload/abc"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let sync_addr: url::Url = server.uri().parse().unwrap();
        let client = Client::new(
            &sync_addr,
            AuthToken::Token("t".into()),
            30,
            30,
            &HashMap::new(),
        )
        .unwrap();

        let got = upload_packed(&manifest, &store, &key, &client)
            .await
            .unwrap();

        // `.expect(1)` on both mocks verifies create_bundle + put_packfile each fired once.
        assert_eq!(got, bundle_id);
    }
}
