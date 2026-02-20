// SPDX-License-Identifier: GPL-2.0-only
use crate::id::Id;
use serde::{Deserialize, Serialize};

/// VM role determines the VM's function in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmRole {
    Portal,
    Work,
    Service,
}

impl VmRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            VmRole::Portal => "portal",
            VmRole::Work => "work",
            VmRole::Service => "service",
        }
    }
}

impl std::fmt::Display for VmRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for VmRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "portal" => Ok(VmRole::Portal),
            "work" => Ok(VmRole::Work),
            "service" => Ok(VmRole::Service),
            _ => Err(format!("invalid VM role: '{s}' (expected: portal, work, service)")),
        }
    }
}

/// VM lifecycle state. Step 4 only uses `Created`.
/// Other states are defined for the data model but transitions
/// are not implemented until Firecracker integration (Step 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Created,
    Running,
    Ready,
    Stopped,
    Crashed,
    Failed,
    Unreachable,
}

impl VmState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VmState::Created => "created",
            VmState::Running => "running",
            VmState::Ready => "ready",
            VmState::Stopped => "stopped",
            VmState::Crashed => "crashed",
            VmState::Failed => "failed",
            VmState::Unreachable => "unreachable",
        }
    }
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for VmState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created" => Ok(VmState::Created),
            "running" => Ok(VmState::Running),
            "ready" => Ok(VmState::Ready),
            "stopped" => Ok(VmState::Stopped),
            "crashed" => Ok(VmState::Crashed),
            "failed" => Ok(VmState::Failed),
            "unreachable" => Ok(VmState::Unreachable),
            _ => Err(format!("invalid VM state: '{s}'")),
        }
    }
}

/// Parameters for creating a new VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVmParams {
    pub name: String,
    #[serde(default = "default_role")]
    pub role: VmRole,
    #[serde(default = "default_vcpu")]
    pub vcpu_count: u32,
    #[serde(default = "default_mem")]
    pub mem_size_mib: u32,
}

fn default_role() -> VmRole { VmRole::Work }
fn default_vcpu() -> u32 { 1 }
fn default_mem() -> u32 { 128 }

/// A VM record as stored in the database and returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vm {
    pub id: Id,
    pub name: String,
    pub role: VmRole,
    pub state: VmState,
    pub cid: u32,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uds_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_connected_at: Option<i64>,
}

/// A single state transition record from the vm_state_history table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateHistory {
    pub id: Id,
    pub vm_id: Id,
    pub from_state: String,
    pub to_state: String,
    pub reason: Option<String>,
    pub transitioned_at: i64,
}

impl CreateVmParams {
    pub fn validate(&self) -> Result<(), String> {
        if Id::is_valid_base32(&self.name) {
            return Err(format!(
                "VM name '{}' cannot be a valid base32 ID (reserved for resource IDs)",
                self.name
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_roundtrip() {
        assert_eq!("work".parse::<VmRole>().unwrap(), VmRole::Work);
        assert_eq!("portal".parse::<VmRole>().unwrap(), VmRole::Portal);
        assert_eq!("service".parse::<VmRole>().unwrap(), VmRole::Service);
        assert!("invalid".parse::<VmRole>().is_err());
    }

    #[test]
    fn state_roundtrip() {
        assert_eq!("created".parse::<VmState>().unwrap(), VmState::Created);
        assert_eq!("running".parse::<VmState>().unwrap(), VmState::Running);
        assert_eq!("ready".parse::<VmState>().unwrap(), VmState::Ready);
        assert_eq!("stopped".parse::<VmState>().unwrap(), VmState::Stopped);
        assert_eq!("crashed".parse::<VmState>().unwrap(), VmState::Crashed);
        assert_eq!("failed".parse::<VmState>().unwrap(), VmState::Failed);
        assert_eq!("unreachable".parse::<VmState>().unwrap(), VmState::Unreachable);
        assert!("bogus".parse::<VmState>().is_err());
    }

    #[test]
    fn role_display() {
        assert_eq!(VmRole::Work.to_string(), "work");
        assert_eq!(VmRole::Portal.to_string(), "portal");
        assert_eq!(VmRole::Service.to_string(), "service");
    }

    #[test]
    fn create_params_deserialize_with_defaults() {
        let json = r#"{"name": "my-vm"}"#;
        let params: CreateVmParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "my-vm");
        assert_eq!(params.role, VmRole::Work);
        assert_eq!(params.vcpu_count, 1);
        assert_eq!(params.mem_size_mib, 128);
    }

    #[test]
    fn create_params_deserialize_with_overrides() {
        let json = r#"{"name": "big-vm", "role": "portal", "vcpu_count": 4, "mem_size_mib": 1024}"#;
        let params: CreateVmParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "big-vm");
        assert_eq!(params.role, VmRole::Portal);
        assert_eq!(params.vcpu_count, 4);
        assert_eq!(params.mem_size_mib, 1024);
    }

    #[test]
    fn vm_serializes_without_none_fields() {
        let vm = Vm {
            id: Id::from_i64(1),
            name: "test".to_string(),
            role: VmRole::Work,
            state: VmState::Created,
            cid: 3,
            vcpu_count: 1,
            mem_size_mib: 128,
            created_at: 1000,
            updated_at: 1000,
            started_at: None,
            stopped_at: None,
            pid: None,
            socket_path: None,
            uds_path: None,
            console_log_path: None,
            config_json: None,
            agent_connected_at: None,
        };
        let json = serde_json::to_string(&vm).unwrap();
        assert!(!json.contains("started_at"));
        assert!(!json.contains("pid"));
        assert!(json.contains("\"cid\":3"));
    }

    #[test]
    fn create_vm_params_rejects_base32_name() {
        let params = CreateVmParams {
            name: "aaaaaaaaaaaaa".to_string(), // Valid base32, 13 chars
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn create_vm_params_accepts_normal_name() {
        let params = CreateVmParams {
            name: "my-dev-vm".to_string(),
            role: VmRole::Work,
            vcpu_count: 1,
            mem_size_mib: 128,
        };
        assert!(params.validate().is_ok());
    }
}
