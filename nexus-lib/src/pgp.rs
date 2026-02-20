// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/pgp.rs

use pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};

/// Errors from PGP verification.
#[derive(Debug)]
pub enum PgpError {
    /// Failed to parse the public key.
    InvalidKey(String),
    /// Failed to parse the signature.
    InvalidSignature(String),
    /// Signature verification failed.
    VerificationFailed(String),
}

impl std::fmt::Display for PgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgpError::InvalidKey(e) => write!(f, "invalid PGP key: {e}"),
            PgpError::InvalidSignature(e) => write!(f, "invalid PGP signature: {e}"),
            PgpError::VerificationFailed(e) => write!(f, "PGP verification failed: {e}"),
        }
    }
}

impl std::error::Error for PgpError {}

/// Verify a detached PGP signature (ASCII-armored) against signed data
/// using a public key (ASCII-armored).
///
/// Returns `Ok(())` if the signature is valid, or `Err(PgpError::VerificationFailed(...))`
/// if verification fails. Used for verifying SHA256SUMS.asc against SHA256SUMS
/// for anvil kernel releases and Firecracker releases.
pub fn verify_detached_signature(
    public_key_armored: &str,
    signature_armored: &str,
    signed_data: &[u8],
) -> Result<(), PgpError> {
    // Parse the public key
    let (public_key, _) = SignedPublicKey::from_string(public_key_armored)
        .map_err(|e| PgpError::InvalidKey(e.to_string()))?;

    // Parse the detached signature
    let (signature, _) = StandaloneSignature::from_string(signature_armored)
        .map_err(|e| PgpError::InvalidSignature(e.to_string()))?;

    // Verify the signature -- returns Ok(()) on success, Err on failure
    signature.verify(&public_key, signed_data)
        .map_err(|e| PgpError::VerificationFailed(e.to_string()))
}

/// Fetch a PGP public key from a URL (e.g., signing-key.asc from a GitHub release).
pub async fn fetch_public_key(client: &reqwest::Client, url: &str) -> Result<String, PgpError> {
    let resp = client.get(url).send().await
        .map_err(|e| PgpError::InvalidKey(format!("failed to fetch key: {e}")))?;
    if !resp.status().is_success() {
        return Err(PgpError::InvalidKey(
            format!("HTTP {} fetching key from {}", resp.status(), url)
        ));
    }
    resp.text().await
        .map_err(|e| PgpError::InvalidKey(format!("failed to read key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgp_error_display() {
        let err = PgpError::InvalidKey("bad key".to_string());
        assert!(err.to_string().contains("invalid PGP key"));

        let err = PgpError::VerificationFailed("bad sig".to_string());
        assert!(err.to_string().contains("PGP verification failed"));
    }

    #[test]
    fn verify_with_invalid_key_returns_error() {
        let result = verify_detached_signature(
            "not a real key",
            "not a real signature",
            b"data",
        );
        assert!(result.is_err());
    }
}
