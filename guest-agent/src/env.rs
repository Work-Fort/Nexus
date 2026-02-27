use std::collections::HashMap;
use tracing::{info, warn};

/// Parse the output of `/bin/sh -lc env` into key=value pairs.
///
/// Each line is expected to be `KEY=VALUE`. Lines without `=` are skipped
/// (e.g., exported functions in some shells). Values may contain `=` characters.
///
/// Note: Multiline values (e.g., bash exported functions) are not handled.
/// This is fine for Alpine where /bin/sh is busybox ash which does not export
/// functions. For non-Alpine VMs, consider `env -0` (null-delimited) parsing.
pub fn parse_env_output(output: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    for line in output.lines() {
        if let Some(pos) = line.find('=') {
            let key = &line[..pos];
            let value = &line[pos + 1..];
            if !key.is_empty() {
                env.insert(key.to_string(), value.to_string());
            }
        }
    }
    env
}

/// Capture the shell login environment by running `/bin/sh -lc env`.
///
/// Falls back to a minimal default environment if the shell command fails
/// (e.g., on systems without /bin/sh or during testing).
pub fn capture_login_env() -> HashMap<String, String> {
    match std::process::Command::new("/bin/sh")
        .args(["-lc", "env"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let env = parse_env_output(&stdout);
            info!("captured {} environment variables from login shell", env.len());
            env
        }
        Ok(output) => {
            warn!(
                "login shell exited with {}, using default environment",
                output.status
            );
            default_env()
        }
        Err(e) => {
            warn!("cannot run /bin/sh: {}, using default environment", e);
            default_env()
        }
    }
}

/// Returns a minimal fallback environment with essential PATH.
fn default_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env.insert("HOME".to_string(), "/root".to_string());
    env.insert("TERM".to_string(), "linux".to_string());
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_env_output_basic() {
        let output = "HOME=/root\nPATH=/usr/local/bin:/usr/bin:/bin\nTERM=linux\n";
        let env = parse_env_output(output);
        assert_eq!(env.get("HOME").unwrap(), "/root");
        assert_eq!(env.get("PATH").unwrap(), "/usr/local/bin:/usr/bin:/bin");
        assert_eq!(env.get("TERM").unwrap(), "linux");
        assert_eq!(env.len(), 3);
    }

    #[test]
    fn parse_env_output_value_with_equals() {
        let output = "LESSOPEN=| /usr/bin/lesspipe %s\nPATH=/bin\n";
        let env = parse_env_output(output);
        assert_eq!(env.get("LESSOPEN").unwrap(), "| /usr/bin/lesspipe %s");
    }

    #[test]
    fn parse_env_output_skips_blank_and_malformed_lines() {
        let output = "\nPATH=/bin\n\nNOEQUALS\n\nHOME=/root\n";
        let env = parse_env_output(output);
        assert_eq!(env.len(), 2);
        assert_eq!(env.get("PATH").unwrap(), "/bin");
        assert_eq!(env.get("HOME").unwrap(), "/root");
    }

    #[test]
    fn parse_env_output_empty_value() {
        let output = "EMPTY_VAR=\nPATH=/bin\n";
        let env = parse_env_output(output);
        assert_eq!(env.get("EMPTY_VAR").unwrap(), "");
    }

    #[test]
    fn default_env_has_path() {
        let env = default_env();
        let path = env.get("PATH").unwrap();
        assert!(path.contains("/usr/bin"));
        assert!(path.contains("/bin"));
    }
}
