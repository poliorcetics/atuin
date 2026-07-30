//! Downloads a packed history range: fetch the blob for a manifest and expand it into the store.
//!
//! [`download_packed`] is the dual of [`super::upload::upload_packed`]: it resolves a `packfile`
//! manifest to its bundle (`GET /api/v0/bundles/{manifest_id}`), [`unpack`](super::codec::unpack)s
//! it back into the history records for the manifest's range, re-encrypts them, and pushes them
//! into the local store. [`download_packed_many`] batches this with bounded concurrency.

use atuin_domain::record::{EncryptedData, Record, RecordId};
use futures::future::try_join_all;
use thiserror::Error;

use crate::{
    api_client::Client,
    history::HISTORY_TAG,
    record::{encryption::PASETO_V4, sqlite_store::SqliteStore},
};

use super::codec::{PackManifestRef, unpack};
use super::record::{LoadingError, PackManifest};

/// Maximum bundle downloads to run concurrently within one batch.
const DOWNLOAD_CONCURRENCY: usize = 8;

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("failed to load the packfile manifest: {0}")]
    PackManifest(#[from] LoadingError),

    #[error("bundle download failed: {0}")]
    Api(eyre::Report),

    #[error("failed to unpack the bundle: {0}")]
    Unpack(eyre::Report),

    #[error("failed to store the unpacked history: {0}")]
    Store(eyre::Report),
}

/// Fetch, unpack, and locally store the history covered by a single `packfile` manifest.
///
/// Returns the ids of the history records the manifest's range covers, whether they were just
/// inserted or were already present locally (idempotent re-runs / a retry after a prior run
/// persisted the history but failed before indexing). Callers rely on this id list to drive
/// re-indexing, so it is always populated for a successfully resolved manifest. Any failure leaves
/// the manifest un-persisted by the caller, so it retries cleanly next sync.
pub async fn download_packed(
    manifest: &Record<EncryptedData>,
    store: &SqliteStore,
    key: &[u8; 32],
    client: &Client<'_>,
) -> Result<Vec<RecordId>, DownloadError> {
    let PackManifest::V1(range) = PackManifest::try_from(manifest)?;
    let host = manifest.host.id;

    // Skip if we already have the whole range (history is contiguous, bundles are prefixes).
    // History is the only tag packed today, so hard-coding `HISTORY_TAG` here (and in the
    // loose-download dedup this mirrors) is correct for now.
    if let Some(head) = store
        .last(host, HISTORY_TAG)
        .await
        .map_err(DownloadError::Store)?
        && head.idx >= range.end_idx
    {
        // Range already local (idempotent re-run, or a retry after a prior run persisted this
        // history but failed before indexing). Return the covered records' ids anyway, so the
        // id-driven history.db rebuild re-indexes them; skipping the network fetch is the point,
        // not skipping indexing.
        let count = range.end_idx - range.start_idx + 1;
        let existing = store
            .next(host, HISTORY_TAG, range.start_idx, count)
            .await
            .map_err(DownloadError::Store)?;
        return Ok(existing.iter().map(|r| r.id).collect());
    }

    let manifest_ref = PackManifestRef::from(manifest);

    let url = client
        .download_bundle(manifest.id)
        .await
        .map_err(DownloadError::Api)?;
    let blob = client
        .get_packfile(&url)
        .await
        .map_err(DownloadError::Api)?;

    let decrypted = unpack(&blob, &manifest_ref, key).map_err(DownloadError::Unpack)?;

    let encrypted: Vec<Record<EncryptedData>> = decrypted
        .into_iter()
        .map(|record| record.encrypt::<PASETO_V4>(key))
        .collect();
    let ids: Vec<RecordId> = encrypted.iter().map(|record| record.id).collect();

    store
        .push_batch(encrypted.iter())
        .await
        .map_err(DownloadError::Store)?;

    Ok(ids)
}

/// Expand many `packfile` manifests, in bounded concurrent batches.
pub async fn download_packed_many(
    manifests: &[Record<EncryptedData>],
    store: &SqliteStore,
    key: &[u8; 32],
    client: &Client<'_>,
) -> Result<Vec<RecordId>, DownloadError> {
    let mut ids = Vec::new();
    for batch in manifests.chunks(DOWNLOAD_CONCURRENCY) {
        let batch_ids = try_join_all(
            batch
                .iter()
                .map(|manifest| download_packed(manifest, store, key, client)),
        )
        .await?;
        for record_ids in batch_ids {
            ids.extend(record_ids);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use atuin_common::utils::uuid_v7;
    use atuin_domain::record::{DecryptedData, Host, HostId, Record};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::api_client::{AuthToken, Client};
    use crate::history::HISTORY_TAG;
    use crate::packfile::{PACKFILE_TAG, try_pack};
    use crate::packfile::{PackManifestRef, pack};
    use crate::record::encryption::PASETO_V4;
    use crate::record::sqlite_store::SqliteStore;
    use crate::settings::test_local_timeout;

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
    async fn download_packed_populates_history_from_the_bundle() {
        let key = [3u8; 32];
        let host = HostId(uuid_v7());

        // The UPLOADER's store: seed history, author a manifest, build the blob it would ship.
        let up = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        seed_encrypted_history(&up, host, &key, 5).await;
        try_pack(&up, host, 1..=5, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();
        let run = up.next(host, HISTORY_TAG, 0, 5).await.unwrap();
        let decrypted: Vec<Record<DecryptedData>> = run
            .into_iter()
            .map(|r| r.decrypt::<PASETO_V4>(&key).unwrap())
            .collect();
        let blob = pack(&decrypted, &PackManifestRef::from(&manifest), &key).unwrap();

        // Mock the download: manifest id -> download_url -> blob bytes.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v0/bundles/{}", manifest.id.0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": format!("{}/download/abc", server.uri()),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        // The DOWNLOADER's fresh store.
        let down = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        let sync_addr: url::Url = server.uri().parse().unwrap();
        let client = Client::new(
            &sync_addr,
            AuthToken::Token("t".into()),
            30,
            30,
            &HashMap::new(),
        )
        .unwrap();

        let ids = download_packed(&manifest, &down, &key, &client)
            .await
            .unwrap();
        assert_eq!(ids.len(), 5, "all five history records populated");

        // History is present locally and decrypts to the same commands.
        let got = down.next(host, HISTORY_TAG, 0, 5).await.unwrap();
        assert_eq!(got.len(), 5);
        let first = got[0].clone().decrypt::<PASETO_V4>(&key).unwrap();
        assert_eq!(first.data.0, b"command number 0");
    }

    #[tokio::test]
    async fn download_packed_returns_range_ids_when_already_local() {
        let key = [3u8; 32];
        let host = HostId(uuid_v7());
        let up = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        seed_encrypted_history(&up, host, &key, 5).await;
        try_pack(&up, host, 1..=5, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();

        // Downloader that already HAS the history the manifest covers.
        let down = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        seed_encrypted_history(&down, host, &key, 5).await;
        let expected_ids: Vec<RecordId> = down
            .next(host, HISTORY_TAG, 0, 5)
            .await
            .unwrap()
            .iter()
            .map(|record| record.id)
            .collect();
        assert_eq!(expected_ids.len(), 5, "sanity: seeded ids captured");

        // No server needed: the skip must happen before any network call.
        let sync_addr: url::Url = "http://127.0.0.1:1/".parse().unwrap();
        let client = Client::new(
            &sync_addr,
            AuthToken::Token("t".into()),
            1,
            1,
            &HashMap::new(),
        )
        .unwrap();

        let ids = download_packed(&manifest, &down, &key, &client)
            .await
            .unwrap();

        // Range already present -> no fetch, but the covered ids are still returned so the
        // id-driven history.db rebuild can re-index them (see download_packed's doc comment).
        assert_eq!(
            ids, expected_ids,
            "range already local -> covered ids returned anyway, for re-indexing"
        );
    }
}
