//! Cryptographic SHA-256 validation for ephemeral IDs.
//! Uses assembly constant-time comparison to prevent side-channel timing attacks.

use sha2::{Digest, Sha256};
use crate::ffi::{constant_time_eq, fill_secure_random};

const ID_SALT: &[u8] = b"OUIJA_EPHEMERAL_SALT_V1_2026";

/// Generates a new ephemeral ID with embedded SHA-256 verification hash.
/// Format: OUIJA-<16-hex-token>-<16-hex-sha256-checksum>
pub fn generate_ephemeral_id() -> Result<String, String> {
    let mut random_bytes = [0u8; 16];
    fill_secure_random(&mut random_bytes)?;

    let token_hex = hex::encode(random_bytes);
    let checksum_hex = compute_token_checksum(&token_hex);

    Ok(format!("OUIJA-{}-{}", token_hex, checksum_hex))
}

/// Computes the SHA-256 checksum for a token string.
fn compute_token_checksum(token_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ID_SALT);
    hasher.update(token_hex.as_bytes());
    let hash = hasher.finalize();
    // Return first 16 hex characters (8 bytes) of the hash
    hex::encode(&hash[..8])
}

/// Validates whether an ephemeral ID is structurally and cryptographically valid.
/// Returns true only if the SHA-256 checksum matches via constant-time assembly verification.
pub fn validate_ephemeral_id_crypto(id: &str) -> bool {
    let trimmed = id.trim();
    if !trimmed.starts_with("OUIJA-") {
        return false;
    }

    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() != 3 {
        return false;
    }

    let prefix = parts[0];
    let token = parts[1];
    let provided_checksum = parts[2];

    if prefix != "OUIJA" || token.len() != 32 || provided_checksum.len() != 16 {
        return false;
    }

    // Verify token is valid hex
    if hex::decode(token).is_err() || hex::decode(provided_checksum).is_err() {
        return false;
    }

    let expected_checksum = compute_token_checksum(token);

    // Constant-time assembly comparison
    constant_time_eq(provided_checksum.as_bytes(), expected_checksum.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation_and_validation() {
        let id = generate_ephemeral_id().expect("Failed to generate ID");
        assert!(validate_ephemeral_id_crypto(&id), "Generated ID should be valid");

        // Test forged ID
        let forged = format!("{}1", &id[..id.len() - 1]);
        assert!(!validate_ephemeral_id_crypto(&forged), "Forged ID must fail validation");

        let bad_prefix = id.replace("OUIJA-", "WRONG-");
        assert!(!validate_ephemeral_id_crypto(&bad_prefix), "Bad prefix must fail");
    }
}
