/// Embedded guest-agent binary (statically linked musl)
/// Built from guest-agent crate with: cargo build -p guest-agent --target x86_64-unknown-linux-musl --release
pub const GUEST_AGENT_BINARY: &[u8] = include_bytes!(
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/x86_64-unknown-linux-musl/release/guest-agent"
    )
);

/// Systemd service unit for guest-agent
pub const GUEST_AGENT_SYSTEMD_UNIT: &str = r#"[Unit]
Description=Nexus Guest Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/guest-agent
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#;

/// Placeholder image metadata (will be overwritten during image builds)
pub const PLACEHOLDER_IMAGE_YAML: &str = r#"image_id: "aaaaaaaaaaaaa"
image_name: "placeholder"
build_id: "aaaaaaaaaaaaa"
built_at: 0
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_agent_binary_is_not_empty() {
        assert!(!GUEST_AGENT_BINARY.is_empty(), "guest-agent binary must be embedded");
        assert!(GUEST_AGENT_BINARY.len() > 1024, "guest-agent binary seems too small");
    }

    #[test]
    fn systemd_unit_contains_expected_fields() {
        assert!(GUEST_AGENT_SYSTEMD_UNIT.contains("ExecStart=/usr/local/bin/guest-agent"));
        assert!(GUEST_AGENT_SYSTEMD_UNIT.contains("WantedBy=multi-user.target"));
    }
}
