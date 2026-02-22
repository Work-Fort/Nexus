// SPDX-License-Identifier: GPL-2.0-only
//! Step 12 QA integration tests for VM networking functionality.
//!
//! These tests validate:
//! - ICMP connectivity (ping)
//! - HTTPS connectivity (wget)
//! - DNS configuration
//! - VM isolation
//! - CLI display of network information
//!
//! Note: These tests require the `test-support` feature to access TestDaemon.

#[cfg(test)]
mod tests {
    use crate::test_support::TestDaemon;
    use crate::mcp_client::McpClient;

    /// Step 12 QA: Test 2 - VM networking ICMP connectivity (ping)
    #[tokio::test]
    async fn step12_test_icmp_connectivity() {
        let daemon = TestDaemon::start().await;
        let vm = daemon.start_vm("test-vm").await.unwrap();

        // Wait for MCP to be ready
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Get MCP connection
        let mcp_stream = daemon.vsock_manager
            .get_mcp_connection(vm.id, &vm.uds_path)
            .await
            .expect("Failed to get MCP connection");
        let client = McpClient::new(mcp_stream);

        // Test ICMP: ping 8.8.8.8
        let result = client
            .run_command("ping", &["-c".to_string(), "3".to_string(), "8.8.8.8".to_string()])
            .await
            .expect("ping command failed");

        println!("Ping output:\n{}", result.stdout);
        println!("Ping stderr:\n{}", result.stderr);

        assert_eq!(result.exit_code, 0, "ping should succeed");
        assert!(result.stdout.contains("3 packets transmitted"), "should show packets transmitted");
        assert!(result.stdout.contains("3 received") || result.stdout.contains("3 packets received"), "should show 0% packet loss");
    }

    /// Step 12 QA: Test 2b - VM networking HTTPS connectivity (wget)
    #[tokio::test]
    async fn step12_test_https_connectivity() {
        let daemon = TestDaemon::start().await;
        let vm = daemon.start_vm("test-vm").await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let mcp_stream = daemon.vsock_manager
            .get_mcp_connection(vm.id, &vm.uds_path)
            .await
            .expect("Failed to get MCP connection");
        let client = McpClient::new(mcp_stream);

        // Test HTTPS: wget example.com
        let result = client
            .run_command("wget", &[
                "-O".to_string(),
                "/tmp/test.html".to_string(),
                "https://example.com".to_string(),
            ])
            .await
            .expect("wget command failed");

        println!("Wget output:\n{}", result.stdout);
        println!("Wget stderr:\n{}", result.stderr);

        assert_eq!(result.exit_code, 0, "wget should succeed");
        assert!(result.stderr.contains("200 OK") || result.stderr.contains("saved"), "should show successful download");
    }

    /// Step 12 QA: Test 3 - DNS configuration
    #[tokio::test]
    async fn step12_test_dns_configuration() {
        let daemon = TestDaemon::start().await;
        let vm = daemon.start_vm("test-vm").await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let mcp_stream = daemon.vsock_manager
            .get_mcp_connection(vm.id, &vm.uds_path)
            .await
            .expect("Failed to get MCP connection");
        let client = McpClient::new(mcp_stream);

        // Read /etc/resolv.conf
        let resolv_conf = client
            .file_read("/etc/resolv.conf")
            .await
            .expect("Failed to read /etc/resolv.conf");

        println!("resolv.conf contents:\n{}", resolv_conf);

        assert!(resolv_conf.contains("nameserver 8.8.8.8"), "should contain Google DNS");
        assert!(resolv_conf.contains("nameserver 1.1.1.1"), "should contain Cloudflare DNS");

        // Test DNS resolution
        let result = client
            .run_command("nslookup", &["example.com".to_string()])
            .await
            .expect("nslookup command failed");

        println!("nslookup output:\n{}", result.stdout);

        assert_eq!(result.exit_code, 0, "nslookup should succeed");
        assert!(result.stdout.contains("example.com") || result.stdout.contains("Address"), "should resolve example.com");
    }

    /// Step 12 QA: Test 4 - VM isolation
    #[tokio::test]
    async fn step12_test_vm_isolation() {
        let daemon = TestDaemon::start().await;

        // Start two VMs
        let vm1 = daemon.start_vm("vm1").await.unwrap();
        let vm2 = daemon.start_vm("vm2").await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Get VM2 IP
        let vm2_details = daemon.get_vm_details(&vm2.id).await.unwrap();
        let vm2_ip = vm2_details.network.as_ref()
            .expect("VM2 should have network")
            .ip_address.as_ref()
            .expect("VM2 should have IP");

        println!("VM1 ID: {}, VM2 ID: {}, VM2 IP: {}", vm1.id, vm2.id, vm2_ip);

        // Connect to VM1 via MCP
        let mcp_stream = daemon.vsock_manager
            .get_mcp_connection(vm1.id, &vm1.uds_path)
            .await
            .expect("Failed to get MCP connection to VM1");
        let client = McpClient::new(mcp_stream);

        // Try to ping VM2 from VM1 (should fail due to isolation)
        let result = client
            .run_command("ping", &["-c".to_string(), "1".to_string(), "-W".to_string(), "2".to_string(), vm2_ip.clone()])
            .await
            .expect("ping command should execute but fail");

        println!("Isolation test ping output:\n{}", result.stdout);
        println!("Isolation test ping stderr:\n{}", result.stderr);

        assert_ne!(result.exit_code, 0, "ping should fail due to firewall rules");
        assert!(
            result.stdout.contains("100% packet loss") || result.stdout.contains("0 received"),
            "should show 100% packet loss"
        );
    }

    /// Step 12 QA: Test 6 - CLI display
    #[tokio::test]
    async fn step12_test_cli_display() {
        let daemon = TestDaemon::start().await;
        let vm = daemon.start_vm("test-vm").await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Get VM details via API
        let vm_details = daemon.get_vm_details(&vm.id).await.unwrap();

        // Verify network information is present
        assert!(vm_details.network.is_some(), "VM should have network information");

        let network = vm_details.network.unwrap();
        assert!(network.ip_address.is_some(), "VM should have IP address");
        assert_eq!(network.bridge, Some("nexbr0".to_string()), "VM should be on nexbr0 bridge");

        let ip = network.ip_address.unwrap();
        assert!(ip.starts_with("172.16."), "IP should be in 172.16.0.0/12 range");

        println!("VM network info - IP: {}, Bridge: {:?}", ip, network.bridge);
    }
}
