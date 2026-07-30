// do a sync :O
use std::{cmp::Ordering, fmt::Write};

use eyre::Result;
use thiserror::Error;

use super::{encryption::PASETO_V4, sqlite_store::SqliteStore};
use crate::{
    api_client::Client,
    packfile::{PACKFILE_TAG, download_packed_many, upload_packed_many},
    settings::Settings,
};

use atuin_domain::record::{Diff, HostId, RecordId, RecordIdx, RecordStatus};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("the local store is ahead of the remote, but for another host. has remote lost data?")]
    LocalAheadOtherHost,

    #[error("an issue with the local database occurred: {msg:?}")]
    LocalStoreError { msg: String },

    #[error("something has gone wrong with the sync logic: {msg:?}")]
    SyncLogicError { msg: String },

    #[error("operational error: {msg:?}")]
    OperationalError { msg: String },

    #[error("a request to the sync server failed: {msg:?}")]
    RemoteRequestError { msg: String },

    #[error(
        "the encryption key on this machine does not match the data on the server. \
         this usually means a new machine was set up without copying the existing key. \
         to fix: run `atuin key` on a machine that already syncs correctly, then run \
         `atuin store rekey <key>` on this machine with the value from the other machine"
    )]
    WrongKey,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Operation {
    // Either upload or download until the states matches the below
    Upload {
        local: RecordIdx,
        remote: Option<RecordIdx>,
        host: HostId,
        tag: String,
    },
    Download {
        local: Option<RecordIdx>,
        remote: RecordIdx,
        host: HostId,
        tag: String,
    },
    Noop {
        host: HostId,
        tag: String,
    },
}

pub async fn build_client(settings: &Settings) -> Result<Client<'_>, SyncError> {
    Client::new(
        &settings.sync_address,
        settings
            .sync_auth_token()
            .await
            .map_err(|e| SyncError::RemoteRequestError { msg: e.to_string() })?,
        settings.network_connect_timeout,
        settings.network_timeout,
        &settings.extra_headers,
    )
    .map_err(|e| SyncError::OperationalError { msg: e.to_string() })
}

pub async fn diff(
    client: &Client<'_>,
    store: &SqliteStore,
) -> Result<(Vec<Diff>, RecordStatus), SyncError> {
    let local_index = store
        .status()
        .await
        .map_err(|e| SyncError::LocalStoreError { msg: e.to_string() })?;

    let remote_index = client
        .record_status()
        .await
        .map_err(|e| SyncError::RemoteRequestError { msg: e.to_string() })?;

    let diff = local_index.diff(&remote_index);

    Ok((diff, remote_index))
}

// Take a diff, along with a local store, and resolve it into a set of operations.
// With the store as context, we can determine if a tail exists locally or not and therefore if it needs uploading or download.
// In theory this could be done as a part of the diffing stage, but it's easier to reason
// about and test this way
pub async fn operations(
    diffs: Vec<Diff>,
    _store: &SqliteStore,
) -> Result<Vec<Operation>, SyncError> {
    let mut operations = Vec::with_capacity(diffs.len());

    for diff in diffs {
        let op = match (diff.local, diff.remote) {
            // We both have it! Could be either. Compare.
            (Some(local), Some(remote)) => match local.cmp(&remote) {
                Ordering::Equal => Operation::Noop {
                    host: diff.host,
                    tag: diff.tag,
                },
                Ordering::Greater => Operation::Upload {
                    local,
                    remote: Some(remote),
                    host: diff.host,
                    tag: diff.tag,
                },
                Ordering::Less => Operation::Download {
                    local: Some(local),
                    remote,
                    host: diff.host,
                    tag: diff.tag,
                },
            },

            // Remote has it, we don't. Gotta be download
            (None, Some(remote)) => Operation::Download {
                local: None,
                remote,
                host: diff.host,
                tag: diff.tag,
            },

            // We have it, remote doesn't. Gotta be upload.
            (Some(local), None) => Operation::Upload {
                local,
                remote: None,
                host: diff.host,
                tag: diff.tag,
            },

            // something is pretty fucked.
            (None, None) => {
                return Err(SyncError::SyncLogicError {
                    msg: String::from(
                        "diff has nothing for local or remote - (host, tag) does not exist",
                    ),
                });
            }
        };

        operations.push(op);
    }

    // sort them - purely so we have a stable testing order, and can rely on
    // same input = same output
    // We can sort by ID so long as we continue to use UUIDv7 or something
    // with the same properties

    operations.sort_by_key(|op| match op {
        Operation::Noop { host, tag } => (0u8, *host, 0u8, tag.clone()),
        Operation::Upload { host, tag, .. } => (1u8, *host, 0u8, tag.clone()),
        Operation::Download { host, tag, .. } => {
            // Packfile manifests must expand before the history download runs, so the history
            // records they populate are skipped by the live-head dedup in sync_download.
            let tag_priority = if tag == PACKFILE_TAG { 0u8 } else { 1u8 };
            (2u8, *host, tag_priority, tag.clone())
        }
    });

    Ok(operations)
}

#[allow(
    clippy::too_many_arguments,
    reason = "threading the key for bundle uploads pushes this one param over the limit"
)]
async fn sync_upload(
    store: &SqliteStore,
    client: &Client<'_>,
    host: HostId,
    tag: String,
    local: RecordIdx,
    remote: Option<RecordIdx>,
    page_size: u64,
    key: &[u8; 32],
) -> Result<i64, SyncError> {
    let remote = remote.unwrap_or(0);
    let expected = local - remote;
    let mut progress = 0;

    let pb = ProgressBar::new(expected);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {human_pos}/{human_len} ({eta})")
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
        .progress_chars("#>-"));

    println!(
        "Uploading {} records to {}/{}",
        expected,
        host.0.as_simple(),
        tag
    );

    loop {
        let page = store
            .next(host, tag.as_str(), remote + progress, page_size)
            .await
            .map_err(|e| {
                error!("failed to read upload page: {e:?}");

                SyncError::LocalStoreError { msg: e.to_string() }
            })?;

        if page.is_empty() {
            break;
        }

        // Ship the page's bundle blobs *before* posting the manifest records, so a manifest
        // that reaches the server always has its bundle. Each blob references history records
        // already uploaded (the `history` tag sorts before `packfile`) plus its own manifest's
        // identity, so the bundles are independent -- `upload_packed_many` ships them in bounded
        // concurrent batches. A bundle failure fails this page, which retries cleanly next sync
        // (the manifest records here were not posted).
        if tag == PACKFILE_TAG {
            upload_packed_many(&page, store, key, client)
                .await
                .map_err(|e| {
                    error!("failed to upload packfile bundles: {e:?}");
                    SyncError::RemoteRequestError { msg: e.to_string() }
                })?;
        }

        client.post_records(&page).await.map_err(|e| {
            error!("failed to post records: {e:?}");

            SyncError::RemoteRequestError { msg: e.to_string() }
        })?;

        progress += page.len() as u64;
        pb.set_position(progress);

        if progress >= expected {
            break;
        }
    }

    pb.finish_with_message("Uploaded records");

    Ok(progress as i64)
}

#[allow(
    clippy::too_many_arguments,
    reason = "threading the key for bundle downloads pushes this one param over the limit"
)]
async fn sync_download(
    store: &SqliteStore,
    client: &Client<'_>,
    host: HostId,
    tag: String,
    local: Option<RecordIdx>,
    remote: RecordIdx,
    page_size: u64,
    key: &[u8; 32],
) -> Result<Vec<RecordId>, SyncError> {
    // Re-derive the local head from the store at execution time. An earlier packfile expansion in
    // this same sync may have populated records for this (host, tag); starting from the frozen
    // diff value would re-download the range those bundles already covered.
    // Note: as with the pre-existing incremental-download boundary behavior below, the record at
    // idx == this re-derived `local` gets re-requested by the first loose page (start = local +
    // 0); that's harmless since `push_batch` is an insert-or-ignore upsert on id.
    let local = match store.last(host, &tag).await {
        Ok(Some(record)) => record.idx.max(local.unwrap_or(0)),
        Ok(None) => local.unwrap_or(0),
        Err(e) => return Err(SyncError::LocalStoreError { msg: e.to_string() }),
    };
    // Saturating: the live-derived `local` head (above) can exceed the `remote` snapshot taken at
    // the start of `sync()` if a concurrent upload from another device landed in between -- a
    // plain subtraction would underflow (panic in debug, wrap in release).
    let expected = remote.saturating_sub(local);
    let mut progress = 0;
    let mut ret = Vec::new();

    println!(
        "Downloading {} records from {}/{}",
        expected,
        host.0.as_simple(),
        tag
    );

    let pb = ProgressBar::new(expected);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {human_pos}/{human_len} ({eta})")
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
        .progress_chars("#>-"));

    loop {
        let page = client
            .next_records(host, tag.clone(), local + progress, page_size)
            .await
            .map_err(|e| SyncError::RemoteRequestError { msg: e.to_string() })?;

        if page.is_empty() {
            break;
        }

        // For packfile manifests, ship the bundle's history into the local store BEFORE we
        // persist the manifests -- so a manifest we record locally always has its history, and a
        // failed expansion leaves the manifests un-persisted to retry next sync (dual of upload).
        if tag == PACKFILE_TAG {
            let expanded = download_packed_many(&page, store, key, client)
                .await
                .map_err(|e| {
                    error!("failed to download packfile bundles: {e:?}");
                    SyncError::RemoteRequestError { msg: e.to_string() }
                })?;
            // The expanded HISTORY ids must flow to `downloaded` so history.db's id-driven
            // incremental_build indexes them (the manifests are non-HISTORY_TAG, skipped there).
            ret.extend(expanded);
        }

        store
            .push_batch(page.iter())
            .await
            .map_err(|e| SyncError::LocalStoreError { msg: e.to_string() })?;

        ret.extend(page.iter().map(|f| f.id));

        progress += page.len() as u64;
        pb.set_position(progress);

        if progress >= expected {
            break;
        }
    }

    pb.finish_with_message("Downloaded records");

    Ok(ret)
}

pub async fn sync_remote(
    client: &Client<'_>,
    operations: Vec<Operation>,
    local_store: &SqliteStore,
    page_size: u64,
    key: &[u8; 32],
) -> Result<(i64, Vec<RecordId>), SyncError> {
    let mut uploaded = 0;
    let mut downloaded = Vec::new();

    // this can totally run in parallel, but lets get it working first
    for i in operations {
        match i {
            Operation::Upload {
                host,
                tag,
                local,
                remote,
            } => {
                uploaded += sync_upload(
                    local_store,
                    client,
                    host,
                    tag,
                    local,
                    remote,
                    page_size,
                    key,
                )
                .await?
            }

            Operation::Download {
                host,
                tag,
                local,
                remote,
            } => {
                let mut d = sync_download(
                    local_store,
                    client,
                    host,
                    tag,
                    local,
                    remote,
                    page_size,
                    key,
                )
                .await?;
                downloaded.append(&mut d)
            }

            Operation::Noop { .. } => continue,
        }
    }

    Ok((uploaded, downloaded))
}

pub async fn check_encryption_key(
    client: &Client<'_>,
    remote_index: &RecordStatus,
    encryption_key: &[u8; 32],
) -> Result<(), SyncError> {
    let sample = remote_index
        .hosts
        .iter()
        .flat_map(|(host, tags)| tags.keys().map(move |tag| (*host, tag.clone())))
        .next();

    let Some((host, tag)) = sample else {
        return Ok(());
    };

    let records = client
        .next_records(host, tag, 0, 1)
        .await
        .map_err(|e| SyncError::RemoteRequestError { msg: e.to_string() })?;

    let Some(record) = records.into_iter().next() else {
        return Ok(());
    };

    record
        .decrypt::<PASETO_V4>(encryption_key)
        .map_err(|_| SyncError::WrongKey)?;

    Ok(())
}

pub async fn sync(
    settings: &Settings,
    store: &SqliteStore,
    encryption_key: &[u8; 32],
) -> Result<(i64, Vec<RecordId>), SyncError> {
    let client = build_client(settings).await?;
    let (diff, remote_index) = diff(&client, store).await?;

    // Bail before mutating either side if the local key can't read the remote.
    check_encryption_key(&client, &remote_index, encryption_key).await?;

    let operations = operations(diff, store).await?;
    let (uploaded, downloaded) =
        sync_remote(&client, operations, store, 100, encryption_key).await?;

    Ok((uploaded, downloaded))
}

#[cfg(test)]
mod tests {
    use atuin_domain::record::{Diff, EncryptedData, HostId, Record};
    use pretty_assertions::assert_eq;

    use crate::{
        record::{
            encryption::PASETO_V4,
            sqlite_store::SqliteStore,
            sync::{self, Operation},
        },
        settings::test_local_timeout,
    };

    fn test_record() -> Record<EncryptedData> {
        Record::builder()
            .host(atuin_domain::record::Host::new(HostId(
                atuin_common::utils::uuid_v7(),
            )))
            .version("v1".into())
            .tag(atuin_common::utils::uuid_v7().simple().to_string())
            .data(EncryptedData {
                data: String::new(),
                content_encryption_key: String::new(),
            })
            .idx(0)
            .build()
    }

    // Take a list of local records, and a list of remote records.
    // Return the local database, and a diff of local/remote, ready to build
    // ops
    async fn build_test_diff(
        local_records: Vec<Record<EncryptedData>>,
        remote_records: Vec<Record<EncryptedData>>,
    ) -> (SqliteStore, Vec<Diff>) {
        let local_store = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .expect("failed to open in memory sqlite");
        let remote_store = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .expect("failed to open in memory sqlite"); // "remote"

        for i in local_records {
            local_store.push(&i).await.unwrap();
        }

        for i in remote_records {
            remote_store.push(&i).await.unwrap();
        }

        let local_index = local_store.status().await.unwrap();
        let remote_index = remote_store.status().await.unwrap();

        let diff = local_index.diff(&remote_index);

        (local_store, diff)
    }

    #[tokio::test]
    async fn test_basic_diff() {
        // a diff where local is ahead of remote. nothing else.

        let record = test_record();
        let (store, diff) = build_test_diff(vec![record.clone()], vec![]).await;

        assert_eq!(diff.len(), 1);

        let operations = sync::operations(diff, &store).await.unwrap();

        assert_eq!(operations.len(), 1);

        assert_eq!(
            operations[0],
            Operation::Upload {
                host: record.host.id,
                tag: record.tag,
                local: record.idx,
                remote: None,
            }
        );
    }

    #[tokio::test]
    async fn build_two_way_diff() {
        // a diff where local is ahead of remote for one, and remote for
        // another. One upload, one download

        let shared_record = test_record();
        let remote_ahead = test_record();

        let local_ahead = shared_record
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);

        assert_eq!(local_ahead.idx, 1);

        let local = vec![shared_record.clone(), local_ahead.clone()]; // local knows about the already synced, and something newer in the same store
        let remote = vec![shared_record.clone(), remote_ahead.clone()]; // remote knows about the already-synced, and one new record in a new store

        let (store, diff) = build_test_diff(local, remote).await;
        let operations = sync::operations(diff, &store).await.unwrap();

        assert_eq!(operations.len(), 2);

        assert_eq!(
            operations,
            vec![
                // Or in otherwords, local is ahead by one
                Operation::Upload {
                    host: local_ahead.host.id,
                    tag: local_ahead.tag,
                    local: 1,
                    remote: Some(0),
                },
                // Or in other words, remote knows of a record in an entirely new store (tag)
                Operation::Download {
                    host: remote_ahead.host.id,
                    tag: remote_ahead.tag,
                    local: None,
                    remote: 0,
                },
            ]
        );
    }

    #[tokio::test]
    async fn build_complex_diff() {
        // One shared, ahead but known only by remote
        // One known only by local
        // One known only by remote

        let shared_record = test_record();
        let local_only = test_record();

        let local_only_20 = test_record();
        let local_only_21 = local_only_20
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let local_only_22 = local_only_21
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let local_only_23 = local_only_22
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);

        let remote_only = test_record();

        let remote_only_20 = test_record();
        let remote_only_21 = remote_only_20
            .append(vec![2, 3, 2])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let remote_only_22 = remote_only_21
            .append(vec![2, 3, 2])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let remote_only_23 = remote_only_22
            .append(vec![2, 3, 2])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let remote_only_24 = remote_only_23
            .append(vec![2, 3, 2])
            .encrypt::<PASETO_V4>(&[0; 32]);

        let second_shared = test_record();
        let second_shared_remote_ahead = second_shared
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let second_shared_remote_ahead2 = second_shared_remote_ahead
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);

        let third_shared = test_record();
        let third_shared_local_ahead = third_shared
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let third_shared_local_ahead2 = third_shared_local_ahead
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);

        let fourth_shared = test_record();
        let fourth_shared_remote_ahead = fourth_shared
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);
        let fourth_shared_remote_ahead2 = fourth_shared_remote_ahead
            .append(vec![1, 2, 3])
            .encrypt::<PASETO_V4>(&[0; 32]);

        let local = vec![
            shared_record.clone(),
            second_shared.clone(),
            third_shared.clone(),
            fourth_shared.clone(),
            fourth_shared_remote_ahead.clone(),
            // single store, only local has it
            local_only.clone(),
            // bigger store, also only known by local
            local_only_20.clone(),
            local_only_21.clone(),
            local_only_22.clone(),
            local_only_23.clone(),
            // another shared store, but local is ahead on this one
            third_shared_local_ahead.clone(),
            third_shared_local_ahead2.clone(),
        ];

        let remote = vec![
            remote_only.clone(),
            remote_only_20.clone(),
            remote_only_21.clone(),
            remote_only_22.clone(),
            remote_only_23.clone(),
            remote_only_24.clone(),
            shared_record.clone(),
            second_shared.clone(),
            third_shared.clone(),
            second_shared_remote_ahead.clone(),
            second_shared_remote_ahead2.clone(),
            fourth_shared.clone(),
            fourth_shared_remote_ahead.clone(),
            fourth_shared_remote_ahead2.clone(),
        ]; // remote knows about the already-synced, and one new record in a new store

        let (store, diff) = build_test_diff(local, remote).await;
        let operations = sync::operations(diff, &store).await.unwrap();

        assert_eq!(operations.len(), 7);

        let mut result_ops = vec![
            // We started with a shared record, but the remote knows of two newer records in the
            // same store
            Operation::Download {
                local: Some(0),
                remote: 2,
                host: second_shared_remote_ahead.host.id,
                tag: second_shared_remote_ahead.tag,
            },
            // We have a shared record, local knows of the first two but not the last
            Operation::Download {
                local: Some(1),
                remote: 2,
                host: fourth_shared_remote_ahead2.host.id,
                tag: fourth_shared_remote_ahead2.tag,
            },
            // Remote knows of a store with a single record that local does not have
            Operation::Download {
                local: None,
                remote: 0,
                host: remote_only.host.id,
                tag: remote_only.tag,
            },
            // Remote knows of a store with a bunch of records that local does not have
            Operation::Download {
                local: None,
                remote: 4,
                host: remote_only_20.host.id,
                tag: remote_only_20.tag,
            },
            // Local knows of a record in a store that remote does not have
            Operation::Upload {
                local: 0,
                remote: None,
                host: local_only.host.id,
                tag: local_only.tag,
            },
            // Local knows of 4 records in a store that remote does not have
            Operation::Upload {
                local: 3,
                remote: None,
                host: local_only_20.host.id,
                tag: local_only_20.tag,
            },
            // Local knows of 2 more records in a shared store that remote only has one of
            Operation::Upload {
                local: 2,
                remote: Some(0),
                host: third_shared.host.id,
                tag: third_shared.tag,
            },
        ];

        result_ops.sort_by_key(|op| match op {
            Operation::Noop { host, tag } => (0, *host, tag.clone()),

            Operation::Upload { host, tag, .. } => (1, *host, tag.clone()),

            Operation::Download { host, tag, .. } => (2, *host, tag.clone()),
        });

        assert_eq!(result_ops, operations);
    }
}

#[cfg(test)]
mod packfile_download_tests {
    use super::*;
    use std::collections::HashMap;

    use atuin_common::utils::uuid_v7;
    use atuin_domain::record::{DecryptedData, EncryptedData, Host, HostId, Record};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::api_client::{AuthToken, Client};
    use crate::history::HISTORY_TAG;
    use crate::packfile::{PACKFILE_TAG, try_pack};
    use crate::packfile::{PackManifestRef, pack};
    use crate::record::encryption::PASETO_V4;
    use crate::record::sqlite_store::SqliteStore;
    use crate::settings::test_local_timeout;

    #[tokio::test]
    async fn sync_download_expands_packfile_manifests_into_history() {
        let key = [4u8; 32];
        let host = HostId(uuid_v7());

        // Uploader-side artifacts: history + manifest + blob.
        let up = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        for idx in 0..3u64 {
            let r = Record::builder()
                .host(Host::new(host))
                .version("v1".into())
                .tag(HISTORY_TAG.to_owned())
                .idx(idx)
                .data(DecryptedData(format!("cmd {idx}").into_bytes()))
                .build()
                .encrypt::<PASETO_V4>(&key);
            up.push(&r).await.unwrap();
        }
        try_pack(&up, host, 1..=3, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();
        let run = up.next(host, HISTORY_TAG, 0, 3).await.unwrap();
        let decrypted: Vec<_> = run
            .into_iter()
            .map(|r| r.decrypt::<PASETO_V4>(&key).unwrap())
            .collect();
        let blob = pack(&decrypted, &PackManifestRef::from(&manifest), &key).unwrap();

        let server = MockServer::start().await;
        // First page: the manifest. Second page (start advanced): empty -> loop ends.
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .and(query_param("start", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![manifest.clone()]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Vec::<Record<EncryptedData>>::new()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v0/bundles/{}", manifest.id.0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": format!("{}/download/abc", server.uri()) })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

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

        sync_download(
            &down,
            &client,
            host,
            PACKFILE_TAG.to_owned(),
            None,
            1,
            100,
            &key,
        )
        .await
        .unwrap();

        // The manifest is stored AND the history it covers was populated.
        assert!(down.last(host, PACKFILE_TAG).await.unwrap().is_some());
        assert_eq!(down.next(host, HISTORY_TAG, 0, 3).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn sync_download_returns_expanded_history_ids_for_indexing() {
        let key = [6u8; 32];
        let host = HostId(uuid_v7());

        let up = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        for idx in 0..3u64 {
            let r = Record::builder()
                .host(Host::new(host))
                .version("v1".into())
                .tag(HISTORY_TAG.to_owned())
                .idx(idx)
                .data(DecryptedData(format!("cmd {idx}").into_bytes()))
                .build()
                .encrypt::<PASETO_V4>(&key);
            up.push(&r).await.unwrap();
        }
        try_pack(&up, host, 1..=3, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();
        let run = up.next(host, HISTORY_TAG, 0, 3).await.unwrap();
        let history_ids: Vec<_> = run.iter().map(|r| r.id).collect();
        let decrypted: Vec<_> = run
            .into_iter()
            .map(|r| r.decrypt::<PASETO_V4>(&key).unwrap())
            .collect();
        let blob = pack(&decrypted, &PackManifestRef::from(&manifest), &key).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .and(query_param("start", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![manifest.clone()]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Vec::<Record<EncryptedData>>::new()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v0/bundles/{}", manifest.id.0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": format!("{}/download/abc", server.uri()) })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

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

        let returned = sync_download(
            &down,
            &client,
            host,
            PACKFILE_TAG.to_owned(),
            None,
            1,
            100,
            &key,
        )
        .await
        .unwrap();

        for id in &history_ids {
            assert!(
                returned.contains(id),
                "expanded history id {id:?} must be returned for indexing"
            );
        }
    }

    #[tokio::test]
    async fn history_download_skips_the_range_a_bundle_covered() {
        let key = [5u8; 32];
        let host = HostId(uuid_v7());

        let up = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        for idx in 0..3u64 {
            let r = Record::builder()
                .host(Host::new(host))
                .version("v1".into())
                .tag(HISTORY_TAG.to_owned())
                .idx(idx)
                .data(DecryptedData(format!("cmd {idx}").into_bytes()))
                .build()
                .encrypt::<PASETO_V4>(&key);
            up.push(&r).await.unwrap();
        }
        try_pack(&up, host, 1..=3, HISTORY_TAG).await.unwrap();
        let manifest = up.last(host, PACKFILE_TAG).await.unwrap().unwrap();
        let run = up.next(host, HISTORY_TAG, 0, 3).await.unwrap();
        let decrypted: Vec<_> = run
            .into_iter()
            .map(|r| r.decrypt::<PASETO_V4>(&key).unwrap())
            .collect();
        let blob = pack(&decrypted, &PackManifestRef::from(&manifest), &key).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .and(query_param("tag", PACKFILE_TAG))
            .and(query_param("start", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(vec![manifest.clone()]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .and(query_param("tag", PACKFILE_TAG))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Vec::<Record<EncryptedData>>::new()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v0/bundles/{}", manifest.id.0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": format!("{}/download/abc", server.uri()) })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download/abc"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;
        // Loose history endpoint: record any hit so we can assert the covered range is skipped.
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .and(query_param("tag", HISTORY_TAG))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Vec::<Record<EncryptedData>>::new()),
            )
            .mount(&server)
            .await;

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

        // Packfile op first (populates history 0..=2), then the history op.
        sync_download(
            &down,
            &client,
            host,
            PACKFILE_TAG.to_owned(),
            None,
            1,
            100,
            &key,
        )
        .await
        .unwrap();
        sync_download(
            &down,
            &client,
            host,
            HISTORY_TAG.to_owned(),
            None,
            3,
            100,
            &key,
        )
        .await
        .unwrap();

        // The history download must have started AFTER the bundled prefix (idx 2), i.e. never
        // requested start=0 for HISTORY_TAG.
        let requests = server.received_requests().await.unwrap();
        let requested_history_start_0 = requests.iter().any(|r| {
            r.url.path() == "/api/v0/record/next"
                && r.url
                    .query_pairs()
                    .any(|(k, v)| k == "tag" && v == HISTORY_TAG)
                && r.url.query_pairs().any(|(k, v)| k == "start" && v == "0")
        });
        assert!(
            !requested_history_start_0,
            "bundled history range must not be re-requested loose"
        );
    }

    #[tokio::test]
    async fn sync_download_does_not_underflow_when_local_head_exceeds_remote() {
        let key = [7u8; 32];
        let host = HostId(uuid_v7());

        // Local store already has HISTORY [0..=4] (head idx 4).
        let down = SqliteStore::new(":memory:", test_local_timeout())
            .await
            .unwrap();
        for idx in 0..5u64 {
            let r = Record::builder()
                .host(Host::new(host))
                .version("v1".into())
                .tag(HISTORY_TAG.to_owned())
                .idx(idx)
                .data(DecryptedData(format!("cmd {idx}").into_bytes()))
                .build()
                .encrypt::<PASETO_V4>(&key);
            down.push(&r).await.unwrap();
        }

        // Server that returns empty for any record page (nothing new to fetch).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v0/record/next"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(Vec::<Record<EncryptedData>>::new()),
            )
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

        // remote (2) is BEHIND the live local head (4) -- must not underflow/panic.
        let got = sync_download(
            &down,
            &client,
            host,
            HISTORY_TAG.to_owned(),
            Some(0),
            2,
            100,
            &key,
        )
        .await
        .unwrap();
        assert!(
            got.is_empty(),
            "nothing to download when local head already exceeds remote"
        );
    }
}
