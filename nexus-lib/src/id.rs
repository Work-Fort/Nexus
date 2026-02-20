// SPDX-License-Identifier: GPL-2.0-only

//! ID generation and encoding for Nexus resources.
//!
//! All resource IDs are 64-bit signed integers encoded as base32 strings.
//! - Internal storage: i64 (INTEGER in SQLite)
//! - API/CLI: base32-encoded string (13 chars)
//! - Generation: random positive i64 via rand::random::<u64>() >> 1

use data_encoding::BASE32_NOPAD;
use std::fmt;

/// A resource ID: a 64-bit signed integer (positive values only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(i64);

impl Id {
    /// Generate a new random ID (positive i64, range 0 to i64::MAX).
    pub fn generate() -> Self {
        // Shift right by 1 to ensure the value fits in i64 (63 bits of randomness)
        Id((rand::random::<u64>() >> 1) as i64)
    }

    /// Create an ID from a raw i64 (for tests or database reads).
    pub fn from_i64(value: i64) -> Self {
        Id(value)
    }

    /// Get the raw i64 value (for database writes).
    pub fn as_i64(&self) -> i64 {
        self.0
    }

    /// Encode the ID as a base32 string (lowercase, 13 chars).
    /// BASE32_NOPAD produces uppercase; we lowercase it manually.
    pub fn encode(&self) -> String {
        let bytes = self.0.to_be_bytes();
        BASE32_NOPAD.encode(&bytes).to_lowercase()
    }

    /// Decode an ID from a base32 string.
    pub fn decode(s: &str) -> Result<Self, IdError> {
        let upper = s.to_uppercase();
        let bytes = BASE32_NOPAD
            .decode(upper.as_bytes())
            .map_err(|_| IdError::InvalidEncoding)?;

        if bytes.len() != 8 {
            return Err(IdError::InvalidLength);
        }

        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(Id(i64::from_be_bytes(arr)))
    }

    /// Check if a string could be a valid base32 ID.
    /// Used for name validation to prevent collision with IDs.
    pub fn is_valid_base32(s: &str) -> bool {
        Self::decode(s).is_ok()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl serde::Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Id::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("invalid base32 encoding")]
    InvalidEncoding,
    #[error("invalid ID length (expected 8 bytes)")]
    InvalidLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_generates_random() {
        let id1 = Id::generate();
        let id2 = Id::generate();
        assert_ne!(id1, id2); // extremely unlikely to collide
    }

    #[test]
    fn id_encode_decode_roundtrip() {
        let id = Id::from_i64(0x0102030405060708);
        let encoded = id.encode();
        assert_eq!(encoded.len(), 13); // 64 bits / 5 bits per char = 12.8 → 13 chars
        let decoded = Id::decode(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn id_decode_case_insensitive() {
        let id = Id::from_i64(12345);
        let lower = id.encode();
        let upper = lower.to_uppercase();
        let decoded_lower = Id::decode(&lower).unwrap();
        let decoded_upper = Id::decode(&upper).unwrap();
        assert_eq!(decoded_lower, decoded_upper);
        assert_eq!(decoded_lower.as_i64(), 12345);
    }

    #[test]
    fn id_decode_invalid_encoding() {
        let result = Id::decode("invalid!@#");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdError::InvalidEncoding));
    }

    #[test]
    fn id_decode_wrong_length() {
        // Base32 of 4 bytes instead of 8
        let short = BASE32_NOPAD.encode(&[1, 2, 3, 4]).to_lowercase();
        let result = Id::decode(&short);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdError::InvalidLength));
    }

    #[test]
    fn id_serializes_as_base32_string() {
        let id = Id::from_i64(999999);
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        let encoded = id.encode();
        assert_eq!(json, format!("\"{}\"", encoded));
    }

    #[test]
    fn id_deserializes_from_base32_string() {
        let id = Id::from_i64(123456789);
        let encoded = id.encode();
        let json = format!("\"{}\"", encoded);
        let decoded: Id = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn id_display_shows_encoded() {
        let id = Id::from_i64(42);
        let display = format!("{}", id);
        assert_eq!(display, id.encode());
    }

    #[test]
    fn is_valid_base32_detects_valid_ids() {
        let id = Id::generate();
        let encoded = id.encode();
        assert!(Id::is_valid_base32(&encoded));
        assert!(Id::is_valid_base32(&encoded.to_uppercase()));
    }

    #[test]
    fn is_valid_base32_rejects_invalid_strings() {
        assert!(!Id::is_valid_base32("my-vm-name"));
        assert!(!Id::is_valid_base32("invalid!@#"));
        assert!(!Id::is_valid_base32("short"));
        assert!(!Id::is_valid_base32("toolongforbase32id"));
    }

    #[test]
    fn is_valid_base32_rejects_13char_non_base32() {
        // 13 chars but contains invalid base32 characters
        assert!(!Id::is_valid_base32("abcd-efgh-ijk"));
        assert!(!Id::is_valid_base32("1234567890123"));
    }
}
