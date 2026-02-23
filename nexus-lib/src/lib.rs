// SPDX-License-Identifier: GPL-2.0-only
pub mod asset;
pub mod backend;
pub mod build_service;
pub mod client;
pub mod config;
pub mod embedded;
pub mod firecracker_service;
pub mod github;
pub mod id;
pub mod kernel_service;
pub mod pgp;
pub mod pipeline;
pub mod rootfs_service;
pub mod store;
pub mod template;
pub mod vm;
pub mod vm_service;
pub mod vsock_manager;
pub mod drive;
pub mod drive_service;
pub mod mcp_client;
pub mod network_service;

#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(all(test, feature = "test-support"))]
mod download_workflow_tests;

#[cfg(all(test, feature = "test-support"))]
mod networking_integration_tests;
