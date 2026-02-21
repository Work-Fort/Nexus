// SPDX-License-Identifier: GPL-2.0-only
//! Test fixtures for download integration tests.
//! Builds fake asset files and configures wiremock to serve them.

use sha2::{Digest, Sha256};
use std::path::Path;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// SHA256 hex digest of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// A fake kernel: identifiable bytes, xz-compressed, with a SHA256SUMS file.
pub struct FakeKernel {
    pub version: String,
    pub compressed_bytes: Vec<u8>,
    pub compressed_sha256: String,
    pub decompressed_sha256: String,
    pub sums_content: String,
}

impl FakeKernel {
    pub fn new(version: &str) -> Self {
        let decompressed_bytes = format!("fake-kernel-{version}-x86_64").into_bytes();
        let decompressed_sha256 = sha256_hex(&decompressed_bytes);

        let mut compressed_bytes = Vec::new();
        {
            let mut compressor = xz2::write::XzEncoder::new(&mut compressed_bytes, 1);
            std::io::Write::write_all(&mut compressor, &decompressed_bytes).unwrap();
            compressor.finish().unwrap();
        }
        let compressed_sha256 = sha256_hex(&compressed_bytes);

        let compressed_filename = format!("vmlinux-{version}-x86_64.xz");
        let decompressed_filename = format!("vmlinux-{version}-x86_64");
        let sums_content = format!(
            "{}  {}\n{}  {}\n",
            compressed_sha256, compressed_filename,
            decompressed_sha256, decompressed_filename,
        );

        FakeKernel {
            version: version.to_string(),
            compressed_bytes,
            compressed_sha256,
            decompressed_sha256,
            sums_content,
        }
    }
}

/// A fake rootfs: a real .tar.gz containing a single file.
pub struct FakeRootfs {
    pub version: String,
    pub tarball_bytes: Vec<u8>,
    pub tarball_sha256: String,
    pub sums_content: String,
}

impl FakeRootfs {
    pub fn new(distro: &str, version: &str) -> Self {
        let mut tar_bytes = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::fast());
            let mut ar = tar::Builder::new(gz);
            let content = format!("fake-rootfs-{distro}-{version}").into_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_cksum();
            ar.append_data(&mut header, "rootfs-marker.txt", &content[..]).unwrap();
            ar.into_inner().unwrap().finish().unwrap();
        }
        let tarball_sha256 = sha256_hex(&tar_bytes);

        let filename = format!("alpine-minirootfs-{version}-x86_64.tar.gz");
        let sums_content = format!("{}  {}\n", tarball_sha256, filename);

        FakeRootfs {
            version: version.to_string(),
            tarball_bytes: tar_bytes,
            tarball_sha256,
            sums_content,
        }
    }
}

/// A fake Firecracker release: a .tgz containing a shell script that
/// responds to --version (passes the daemon's binary validation check).
pub struct FakeFirecracker {
    pub version: String,
    pub tgz_bytes: Vec<u8>,
    pub tgz_sha256: String,
    pub sums_content: String,
}

impl FakeFirecracker {
    pub fn new(version: &str) -> Self {
        let binary_content = format!(
            "#!/bin/sh\necho \"Firecracker v{version}\"\n"
        ).into_bytes();

        let mut tgz_bytes = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tgz_bytes, flate2::Compression::fast());
            let mut ar = tar::Builder::new(gz);

            let mut header = tar::Header::new_gnu();
            header.set_size(binary_content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            let entry_path = format!(
                "release-v{version}-x86_64/firecracker-v{version}-x86_64",
            );
            ar.append_data(&mut header, &entry_path, &binary_content[..]).unwrap();
            ar.into_inner().unwrap().finish().unwrap();
        }
        let tgz_sha256 = sha256_hex(&tgz_bytes);
        let sums_content = format!("{}  firecracker-v{}-x86_64.tgz\n", tgz_sha256, version);

        FakeFirecracker {
            version: version.to_string(),
            tgz_bytes,
            tgz_sha256,
            sums_content,
        }
    }
}

/// Configure wiremock to serve a fake kernel download.
pub async fn serve_kernel_from_mock(server: &MockServer, kernel: &FakeKernel) {
    let version = &kernel.version;
    let download_path = format!(
        "/Work-Fort/Anvil/releases/download/v{version}/vmlinux-{version}-x86_64.xz"
    );
    let sums_path = format!(
        "/Work-Fort/Anvil/releases/download/v{version}/SHA256SUMS"
    );

    Mock::given(method("GET"))
        .and(path(&download_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(kernel.compressed_bytes.clone()),
        )
        .mount(server).await;

    Mock::given(method("GET"))
        .and(path(&sums_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(&kernel.sums_content),
        )
        .mount(server).await;
}

/// Configure wiremock to serve a fake rootfs download.
/// Uses the same version-parsing algorithm as AlpineProvider::download_url().
pub async fn serve_rootfs_from_mock(server: &MockServer, rootfs: &FakeRootfs) {
    let version = &rootfs.version;
    // Match AlpineProvider's algorithm: splitn(3, '.').take(2).join(".")
    let major_minor: String = version
        .splitn(3, '.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    let download_path = format!(
        "/alpine/v{major_minor}/releases/x86_64/alpine-minirootfs-{version}-x86_64.tar.gz"
    );
    let sums_path = format!(
        "/alpine/v{major_minor}/releases/x86_64/sha256.txt"
    );

    Mock::given(method("GET"))
        .and(path(&download_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(rootfs.tarball_bytes.clone()),
        )
        .mount(server).await;

    Mock::given(method("GET"))
        .and(path(&sums_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(&rootfs.sums_content),
        )
        .mount(server).await;
}

/// Configure wiremock to serve a fake Firecracker download.
pub async fn serve_firecracker_from_mock(server: &MockServer, fc: &FakeFirecracker) {
    let version = &fc.version;
    let download_path = format!(
        "/firecracker-microvm/firecracker/releases/download/v{version}/firecracker-v{version}-x86_64.tgz"
    );
    let sums_path = format!(
        "/firecracker-microvm/firecracker/releases/download/v{version}/firecracker-v{version}-x86_64.tgz.sha256.txt"
    );

    Mock::given(method("GET"))
        .and(path(&download_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(fc.tgz_bytes.clone()),
        )
        .mount(server).await;

    Mock::given(method("GET"))
        .and(path(&sums_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(&fc.sums_content),
        )
        .mount(server).await;
}

/// Configure a provider in the daemon's SQLite database to use the mock server.
/// Sets base_url, disables TLS requirement, and optionally overrides the pipeline.
pub fn configure_provider_for_mock(
    db_path: &Path,
    asset_type: &str,
    mock_base_url: &str,
    pipeline_json: &str,
) {
    let conn = rusqlite::Connection::open(db_path).expect("cannot open test DB");
    conn.execute(
        "UPDATE providers SET pipeline = ?1 WHERE asset_type = ?2",
        rusqlite::params![pipeline_json, asset_type],
    ).expect("cannot update provider pipeline");
    conn.execute(
        "UPDATE providers SET config = json_set(config, '$.base_url', ?1) WHERE asset_type = ?2",
        rusqlite::params![mock_base_url, asset_type],
    ).expect("cannot update provider base_url");
}
