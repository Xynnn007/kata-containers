//! # Initdata Module
//!
//! This module will do the following things if [`INITDATA_DEV`] exists.
//! 1. Parse the initdata block device and extract the config files to [`INITDATA_PATH`].
//! 2. Store the initdata hash in [`INITDATA`].

// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    io::{BufReader, Read},
    os::unix::fs::FileTypeExt,
    path::Path,
};

use anyhow::{bail, Context, Result};
use backhand::{FilesystemReader, InnerNode};
use base64::Engine;
use const_format::concatcp;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use slog::Logger;
use tokio::{io::AsyncReadExt, sync::OnceCell};

/// This is the target directory to store the extracted initdata.
pub const INITDATA_PATH: &str = "/run/confidential-containers/initdata";

/// The path of AA's config file
pub const AA_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/aa.toml");

/// The path of CDH's config file
pub const CDH_CONFIG_PATH: &str = concatcp!(INITDATA_PATH, "/cdh.toml");

/// The path of policy file
pub const POLICY_PATH: &str = concatcp!(INITDATA_PATH, "/policy.rego");

/// Now only initdata `0.1.0` is defined.
const DEFAULT_INITDATA_VERSION: &str = "0.1.0";

/// If initdata is given and parsed successfully, this static
/// variable will be set with the base64 encoded digest of the
/// initdata.
pub static INITDATA: OnceCell<String> = OnceCell::const_new();

/// Initdata defined in
/// <https://github.com/confidential-containers/trustee/blob/47d7a2338e0be76308ac19be5c0c172c592780aa/kbs/docs/initdata.md>
#[derive(Deserialize)]
pub struct Initdata {
    version: String,
    algorithm: String,
    data: DefinedFields,
}

/// Well-defined keys for initdata of kata/CoCo
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DefinedFields {
    #[serde(rename = "aa.toml")]
    aa_config: Option<String>,
    #[serde(rename = "cdh.toml")]
    cdh_config: Option<String>,
    #[serde(rename = "policy.rego")]
    policy: Option<String>,
}

/// SquashFS magic number
const SQUASHFS_MAGIC: [u8; 4] = [0x68, 0x73, 0x71, 0x73];

async fn detective_initdata_device(logger: &Logger) -> Result<Option<String>> {
    let dev_dir = Path::new("/dev");
    let mut read_dir = tokio::fs::read_dir(dev_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        debug!(logger, "Initdata check device `{filename}`");
        if !filename.starts_with("vd") {
            continue;
        }
        let path = entry.path();

        debug!(logger, "Initdata find potential device: `{path:?}`");
        let metadata = std::fs::metadata(path.clone())?;
        if !metadata.file_type().is_block_device() {
            continue;
        }

        let mut file = tokio::fs::File::open(&path).await?;
        let mut magic = [0; 4];
        match file.read_exact(&mut magic).await {
            Ok(_) => {
                debug!(
                    logger,
                    "Initdata read device `{filename}` first 4 bytes: {magic:?}"
                );
                if magic == SQUASHFS_MAGIC {
                    let path = path.as_path().to_string_lossy().to_string();
                    debug!(logger, "Found SquashFS device: {path}");
                    return Ok(Some(path));
                }
            }
            Err(e) => debug!(logger, "Initdata read device `{filename}` failed: {e:?}"),
        }
    }

    Ok(None)
}

pub async fn initialize_initdata(logger: &Logger) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "initdata"));
    let Some(initdata_device) = detective_initdata_device(&logger).await? else {
        info!(
            logger,
            "Initdata device not found, skip initdata initialization"
        );
        return Ok(());
    };
    let initdata_devfile = std::fs::File::open(initdata_device)?;
    let buf_reader = BufReader::new(initdata_devfile);
    let read_filesystem = FilesystemReader::from_reader(buf_reader)?;

    let mut initdata_content = Vec::new();

    // initdata squash device only allow 1 file `initdata.toml` inside
    for node in read_filesystem.files() {
        // skip root
        if node.fullpath.as_path() == Path::new("/") {
            continue;
        }

        if node.fullpath.as_path() != Path::new("/initdata.toml") {
            bail!(
                "Illegal initdata device! get path {:?}",
                node.fullpath.as_path()
            );
        }

        let InnerNode::File(file) = &node.inner else {
            bail!("illegal initdata device! not a file!");
        };

        let mut reader = read_filesystem.file(&file).reader();
        let _ = reader.read_to_end(&mut initdata_content)?;
        break;
    }

    tokio::fs::create_dir_all(INITDATA_PATH)
        .await
        .inspect_err(|e| error!(logger, "Failed to create initdata dir: {e:?}"))?;

    let initdata_plaintext = String::from_utf8(initdata_content.clone())?;
    debug!(logger, "Initdata full content: {initdata_plaintext}");

    let initdata: Initdata =
        toml::from_slice(&initdata_content).context("parse initdata failed")?;
    info!(logger, "Initdata version: {}", initdata.version);

    if initdata.version != DEFAULT_INITDATA_VERSION {
        bail!("Unsupported initdata version");
    }

    let digest = match &initdata.algorithm[..] {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(&initdata_content);
            hasher.finalize().to_vec()
        }
        "sha384" => {
            let mut hasher = Sha384::new();
            hasher.update(&initdata_content);
            hasher.finalize().to_vec()
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(&initdata_content);
            hasher.finalize().to_vec()
        }
        others => bail!("Unsupported hash algorithm {others}"),
    };

    let initdata_digest = base64::engine::general_purpose::STANDARD.encode(digest);
    INITDATA
        .set(initdata_digest)
        .context("Failed to set INITDATA")?;

    if let Some(config) = initdata.data.aa_config {
        tokio::fs::write(AA_CONFIG_PATH, config)
            .await
            .context("write aa config failed")?;
        info!(logger, "write AA config from initdata");
    }

    if let Some(config) = initdata.data.cdh_config {
        tokio::fs::write(CDH_CONFIG_PATH, config)
            .await
            .context("write cdh config failed")?;
        info!(logger, "write CDH config from initdata");
    }

    if let Some(policy) = initdata.data.policy {
        tokio::fs::write(POLICY_PATH, policy)
            .await
            .context("write policy failed")?;
        info!(logger, "write policy from initdata");
    }

    Ok(())
}
