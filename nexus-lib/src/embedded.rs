/// Embedded guest-agent binary (statically linked musl)
/// Built from guest-agent crate with: cargo build -p guest-agent --target x86_64-unknown-linux-musl --release
pub const GUEST_AGENT_BINARY: &[u8] = include_bytes!(
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/x86_64-unknown-linux-musl/release/guest-agent"
    )
);

/// BusyBox system initialization for Alpine minirootfs
/// This provides basic system init when no inittab exists.
/// Alpine minirootfs does NOT include OpenRC, so this handles
/// mount /proc, /sys, /dev and basic system services.
/// Format: <id>:<runlevels>:<action>:<process>
pub const BUSYBOX_SYSTEM_INIT: &str = r#"::sysinit:/bin/mkdir -p /dev /proc /sys
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sys /sys
::sysinit:/bin/mount -t devtmpfs dev /dev
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
"#;

/// Guest-agent entry for BusyBox inittab (appended to existing inittab)
pub const GUEST_AGENT_INITTAB_ENTRY: &str = "::respawn:/usr/local/bin/guest-agent\n";

/// OpenRC service script for guest-agent
pub const GUEST_AGENT_OPENRC_SCRIPT: &str = r#"#!/sbin/openrc-run

name="nexus-guest-agent"
description="Nexus Guest Agent"
command="/usr/local/bin/guest-agent"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"

depend() {
    need net
    after firewall
}
"#;

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
