// SPDX-License-Identifier: GPL-2.0-only
//! Workflow unit tests for download lifecycles using mocked HTTP responses.
//!
//! These tests validate the complete download → register → list → verify → remove
//! workflows by running a TestDaemon and mocking external HTTP providers with wiremock.
//! They are fast unit tests (not integration tests) because they don't touch real networks.
//!
//! Note: These tests require the `test-support` feature to access TestDaemon.
//! This is automatically enabled by Cargo during test runs.

#[cfg(test)]
mod tests {
    use crate::test_support::TestDaemon;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use sha2::{Digest, Sha256};
    use std::path::Path;

    /// SHA256 hex digest of a byte slice.
    pub(super) fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// A fake kernel: identifiable bytes, xz-compressed, with a SHA256SUMS file.
    pub(super) struct FakeKernel {
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
    pub(super) struct FakeRootfs {
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
    pub(super) struct FakeFirecracker {
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
    async fn serve_kernel_from_mock(server: &MockServer, kernel: &FakeKernel) {
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
    async fn serve_rootfs_from_mock(server: &MockServer, rootfs: &FakeRootfs) {
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
    async fn serve_firecracker_from_mock(server: &MockServer, fc: &FakeFirecracker) {
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
    fn configure_provider_for_mock(
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

    #[tokio::test]
    async fn workflow_kernel_download_full_lifecycle() {
        let daemon = TestDaemon::start().await;

        let client = reqwest::Client::new();
        let base = format!("http://{}", daemon.addr);

        // Pre-check: no kernels installed
        let resp = client.get(format!("{base}/v1/kernels")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let kernels: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(kernels.is_empty(), "expected no kernels initially");

        // Build fake kernel and start mock server
        let kernel = FakeKernel::new("6.99.0");
        let mock_server = MockServer::start().await;
        serve_kernel_from_mock(&mock_server, &kernel).await;

        // Configure provider: mock server base_url, HTTP without TLS, xz pipeline
        let pipeline = serde_json::to_string(&vec![
            serde_json::json!({"transport": "http", "credentials": {}, "host": "", "encrypted": false}),
            serde_json::json!({"checksum": "SHA256"}),
            serde_json::json!({"verify": "none"}),
            serde_json::json!({"decompress": "xz"}),
            serde_json::json!({"checksum": "SHA256"}),
        ]).unwrap();
        configure_provider_for_mock(
            &daemon.db_path, "kernel", &mock_server.uri(), &pipeline,
        );

        // 1. Download kernel via REST API
        let resp = client.post(format!("{base}/v1/kernels/download"))
            .json(&serde_json::json!({"version": "6.99.0"}))
            .send().await.unwrap();
        assert_eq!(resp.status(), 201, "kernel download should return 201 Created");
        let k: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(k["version"], "6.99.0");
        assert_eq!(k["architecture"], "x86_64");
        assert!(!k["sha256"].as_str().unwrap().is_empty());

        // Comprehensive verification: file exists, executable, correct version
        let path = k["path_on_host"].as_str().unwrap();
        assert!(path.contains("vmlinux"));
        let kernel_path = std::path::Path::new(path);
        assert!(kernel_path.exists(), "kernel file must exist at expected path");
        let metadata = std::fs::metadata(kernel_path).unwrap();
        assert!(metadata.len() > 0, "kernel file must not be empty");
        // Verify SHA256 matches expected value
        let actual_sha256 = k["sha256"].as_str().unwrap();
        assert_eq!(actual_sha256, kernel.decompressed_sha256, "kernel SHA256 must match expected value");

        // 2. Verify list endpoint includes the kernel
        let resp = client.get(format!("{base}/v1/kernels")).send().await.unwrap();
        let kernels: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(kernels.len(), 1);
        assert_eq!(kernels[0]["version"], "6.99.0");

        // 3. Verify file integrity via verify endpoint
        let resp = client.get(format!("{base}/v1/kernels/6.99.0/verify"))
            .send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let verified: bool = resp.json().await.unwrap();
        assert!(verified, "kernel SHA256 re-verification should pass");

        // 4. Verify duplicate download returns error
        let resp = client.post(format!("{base}/v1/kernels/download"))
            .json(&serde_json::json!({"version": "6.99.0"}))
            .send().await.unwrap();
        assert_ne!(resp.status(), 201, "duplicate download should fail");

        // 5. Remove and verify cleanup
        let resp = client.delete(format!("{base}/v1/kernels/6.99.0"))
            .send().await.unwrap();
        assert_eq!(resp.status(), 204);
        let resp = client.get(format!("{base}/v1/kernels")).send().await.unwrap();
        let kernels: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(kernels.is_empty(), "kernel list should be empty after removal");
    }

    #[tokio::test]
    async fn workflow_rootfs_download_full_lifecycle() {
        let daemon = TestDaemon::start().await;

        let client = reqwest::Client::new();
        let base = format!("http://{}", daemon.addr);

        // Pre-check: no rootfs images
        let resp = client.get(format!("{base}/v1/rootfs-images")).send().await.unwrap();
        let images: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(images.is_empty());

        // Build fake rootfs and start mock server
        let rootfs = FakeRootfs::new("alpine", "3.99.0");
        let mock_server = MockServer::start().await;
        serve_rootfs_from_mock(&mock_server, &rootfs).await;

        // Configure provider: mock server, HTTP without TLS, simple checksum pipeline
        let pipeline = serde_json::to_string(&vec![
            serde_json::json!({"transport": "http", "credentials": {}, "host": "", "encrypted": false}),
            serde_json::json!({"checksum": "SHA256"}),
        ]).unwrap();
        configure_provider_for_mock(
            &daemon.db_path, "rootfs", &mock_server.uri(), &pipeline,
        );

        // 1. Download rootfs via REST API
        let resp = client.post(format!("{base}/v1/rootfs-images/download"))
            .json(&serde_json::json!({"distro": "alpine", "version": "3.99.0"}))
            .send().await.unwrap();
        assert_eq!(resp.status(), 201, "rootfs download should return 201 Created");
        let image: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(image["distro"], "alpine");
        assert_eq!(image["version"], "3.99.0");
        assert_eq!(image["architecture"], "x86_64");

        // Comprehensive verification: file exists, correct SHA256
        let path = image["path_on_host"].as_str().unwrap();
        let rootfs_path = std::path::Path::new(path);
        assert!(rootfs_path.exists(), "rootfs tarball must exist at expected path");
        let metadata = std::fs::metadata(rootfs_path).unwrap();
        assert!(metadata.len() > 0, "rootfs tarball must not be empty");
        // Verify SHA256 matches expected value
        let actual_sha256 = image["sha256"].as_str().unwrap();
        assert_eq!(actual_sha256, rootfs.tarball_sha256, "rootfs SHA256 must match expected value");

        // 2. Verify list endpoint
        let resp = client.get(format!("{base}/v1/rootfs-images")).send().await.unwrap();
        let images: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0]["distro"], "alpine");
        assert_eq!(images[0]["version"], "3.99.0");

        // 3. Verify duplicate download rejected
        let resp = client.post(format!("{base}/v1/rootfs-images/download"))
            .json(&serde_json::json!({"distro": "alpine", "version": "3.99.0"}))
            .send().await.unwrap();
        assert_ne!(resp.status(), 201);

        // 4. Remove and verify
        let resp = client.delete(format!("{base}/v1/rootfs-images/alpine/3.99.0"))
            .send().await.unwrap();
        assert_eq!(resp.status(), 204);
        let resp = client.get(format!("{base}/v1/rootfs-images")).send().await.unwrap();
        let images: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(images.is_empty());
    }

    #[tokio::test]
    async fn workflow_firecracker_download_full_lifecycle() {
        let daemon = TestDaemon::start().await;

        let client = reqwest::Client::new();
        let base = format!("http://{}", daemon.addr);

        // Pre-check: no firecracker versions
        let resp = client.get(format!("{base}/v1/firecracker")).send().await.unwrap();
        let versions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(versions.is_empty());

        // Build fake firecracker tgz and start mock server
        let fc = FakeFirecracker::new("9.99.0");
        let mock_server = MockServer::start().await;
        serve_firecracker_from_mock(&mock_server, &fc).await;

        // Configure provider: mock server, HTTP without TLS
        let pipeline = serde_json::to_string(&vec![
            serde_json::json!({"transport": "http", "credentials": {}, "host": "", "encrypted": false}),
            serde_json::json!({"checksum": "SHA256"}),
        ]).unwrap();
        configure_provider_for_mock(
            &daemon.db_path, "firecracker", &mock_server.uri(), &pipeline,
        );

        // 1. Download firecracker via REST API
        let resp = client.post(format!("{base}/v1/firecracker/download"))
            .json(&serde_json::json!({"version": "9.99.0"}))
            .send().await.unwrap();
        assert_eq!(resp.status(), 201, "firecracker download should return 201 Created");
        let fc_resp: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(fc_resp["version"], "9.99.0");
        assert_eq!(fc_resp["architecture"], "x86_64");

        // Comprehensive verification: binary exists, executable, correct version
        let path = fc_resp["path_on_host"].as_str().unwrap();
        let fc_path = std::path::Path::new(path);
        assert!(fc_path.exists(), "firecracker binary must exist at expected path");
        let metadata = std::fs::metadata(fc_path).unwrap();
        assert!(metadata.len() > 0, "firecracker binary must not be empty");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(metadata.permissions().mode() & 0o111 != 0, "binary must be executable");
        }
        // Verify --version reports correct version
        let output = std::process::Command::new(path)
            .arg("--version")
            .output()
            .expect("failed to run firecracker --version");
        assert!(output.status.success(), "firecracker --version must succeed");
        let version_output = String::from_utf8_lossy(&output.stdout);
        assert!(version_output.contains("9.99.0"), "firecracker --version must report correct version");

        // 2. Verify list endpoint
        let resp = client.get(format!("{base}/v1/firecracker")).send().await.unwrap();
        let versions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "9.99.0");

        // 3. Verify duplicate download rejected
        let resp = client.post(format!("{base}/v1/firecracker/download"))
            .json(&serde_json::json!({"version": "9.99.0"}))
            .send().await.unwrap();
        assert_ne!(resp.status(), 201);

        // 4. Remove and verify
        let resp = client.delete(format!("{base}/v1/firecracker/9.99.0"))
            .send().await.unwrap();
        assert_eq!(resp.status(), 204);
        let resp = client.get(format!("{base}/v1/firecracker")).send().await.unwrap();
        let versions: Vec<serde_json::Value> = resp.json().await.unwrap();
        assert!(versions.is_empty());
    }
}
