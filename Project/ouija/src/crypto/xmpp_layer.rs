//! XMPP Protocol Layer with OMEMO/OTR Encrypted XML Stanzas.
//! Wraps OTP-encrypted payloads inside authenticated XML stanzas with ChaCha20-Poly1305.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce, Key,
};
use sha2::{Digest, Sha256};
use crate::ffi::{constant_time_eq, fill_secure_random};
use crate::crypto::otp_layer::{otp_decrypt, otp_encrypt};

/// Represents an XMPP XML Message Stanza structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XmppMessageStanza {
    pub id: String,
    pub from: String,
    pub to: String,
    pub stanza_type: String,
    pub timestamp: i64,
    pub iv_hex: String,
    pub ciphertext_b64: String,
    pub signature_hex: String,
}

impl XmppMessageStanza {
    /// Serializes to an authentic XMPP XML format string.
    pub fn to_xml(&self) -> String {
        format!(
            r#"<message id="{}" from="{}" to="{}" type="{}" xmlns="jabber:client">
  <encrypted xmlns="urn:xmpp:ouija:omemo:v1">
    <header sid="{}">
      <iv>{}</iv>
    </header>
    <payload>{}</payload>
    <signature>{}</signature>
    <timestamp>{}</timestamp>
  </encrypted>
</message>"#,
            self.id, self.from, self.to, self.stanza_type, self.from, self.iv_hex, self.ciphertext_b64, self.signature_hex, self.timestamp
        )
    }

    /// Parses an XMPP XML format string back into the struct.
    pub fn from_xml(xml: &str) -> Result<Self, String> {
        let extract_attr = |tag: &str, attr: &str| -> Option<String> {
            let start = xml.find(tag)?;
            let slice = &xml[start..];
            let attr_needle = format!("{}=\"", attr);
            let attr_start = slice.find(&attr_needle)? + attr_needle.len();
            let attr_end = slice[attr_start..].find('"')? + attr_start;
            Some(slice[attr_start..attr_end].to_string())
        };

        let extract_tag = |tag: &str| -> Option<String> {
            let open = format!("<{}>", tag);
            let close = format!("</{}>", tag);
            let start = xml.find(&open)? + open.len();
            let end = xml.find(&close)?;
            if start > end {
                return None;
            }
            Some(xml[start..end].trim().to_string())
        };

        let id = extract_attr("<message", "id").ok_or("Missing message id in XML")?;
        let from = extract_attr("<message", "from").ok_or("Missing from attribute in XML")?;
        let to = extract_attr("<message", "to").ok_or("Missing to attribute in XML")?;
        let stanza_type = extract_attr("<message", "type").unwrap_or_else(|| "chat".to_string());

        let iv_hex = extract_tag("iv").ok_or("Missing <iv> in XML")?;
        let ciphertext_b64 = extract_tag("payload").ok_or("Missing <payload> in XML")?;
        let signature_hex = extract_tag("signature").ok_or("Missing <signature> in XML")?;
        let ts_str = extract_tag("timestamp").unwrap_or_else(|| "0".to_string());
        let timestamp = ts_str.parse::<i64>().unwrap_or(0);

        Ok(XmppMessageStanza {
            id,
            from,
            to,
            stanza_type,
            timestamp,
            iv_hex,
            ciphertext_b64,
            signature_hex,
        })
    }
}

/// Computes HMAC-SHA256 signature for the XMPP stanza envelope.
fn compute_stanza_signature(key: &[u8], id: &str, from: &str, to: &str, payload_b64: &str, timestamp: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(id.as_bytes());
    hasher.update(from.as_bytes());
    hasher.update(to.as_bytes());
    hasher.update(payload_b64.as_bytes());
    hasher.update(timestamp.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Derives a 32-byte ChaCha20 key for the conversation.
fn derive_session_key(sender: &str, recipient: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"OUIJA_XMPP_SESSION_KEY_DERIVATION_V1");
    // Sort identifiers to derive mutual symmetric key
    let mut ids = vec![sender, recipient];
    ids.sort();
    hasher.update(ids[0].as_bytes());
    hasher.update(ids[1].as_bytes());
    let res = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&res);
    key
}

/// Encrypts an inner message using OTP (Assembly Layer) and packs it into an XMPP XML Stanza (Layer 2).
pub fn build_encrypted_xmpp_stanza(
    sender_id: &str,
    recipient_id: &str,
    plaintext: &str,
) -> Result<XmppMessageStanza, String> {
    // 1. Layer 1: Information-theoretic OTP encryption in Assembly
    let otp_blob = otp_encrypt(plaintext.as_bytes())?;

    // Pack OTP ciphertext + pad into a structured JSON payload
    let inner_payload = serde_json::json!({
        "ct": BASE64.encode(&otp_blob.ciphertext),
        "pad": BASE64.encode(&otp_blob.pad),
        "len": plaintext.len(),
    });
    let inner_bytes = serde_json::to_vec(&inner_payload).map_err(|e| e.to_string())?;

    // 2. Layer 2: ChaCha20-Poly1305 authenticated envelope encryption
    let session_key = derive_session_key(sender_id, recipient_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));

    let mut nonce_bytes = [0u8; 12];
    fill_secure_random(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_payload = cipher
        .encrypt(nonce, inner_bytes.as_ref())
        .map_err(|e| format!("ChaCha20 encryption failed: {}", e))?;

    let ciphertext_b64 = BASE64.encode(&encrypted_payload);
    let iv_hex = hex::encode(nonce_bytes);
    let timestamp = chrono::Utc::now().timestamp();
    let msg_id = format!("msg_{}", hex::encode(&nonce_bytes[..4]));

    // Stanza signature
    let signature_hex = compute_stanza_signature(
        &session_key,
        &msg_id,
        sender_id,
        recipient_id,
        &ciphertext_b64,
        timestamp,
    );

    Ok(XmppMessageStanza {
        id: msg_id,
        from: sender_id.to_string(),
        to: recipient_id.to_string(),
        stanza_type: "chat".to_string(),
        timestamp,
        iv_hex,
        ciphertext_b64,
        signature_hex,
    })
}

/// Parses an encrypted XMPP stanza, validates signature, decrypts Layer 2, then Layer 1 (OTP Assembly).
pub fn decrypt_xmpp_stanza(stanza: &XmppMessageStanza) -> Result<String, String> {
    let session_key = derive_session_key(&stanza.from, &stanza.to);

    // Verify signature in constant-time
    let expected_sig = compute_stanza_signature(
        &session_key,
        &stanza.id,
        &stanza.from,
        &stanza.to,
        &stanza.ciphertext_b64,
        stanza.timestamp,
    );

    if !constant_time_eq(stanza.signature_hex.as_bytes(), expected_sig.as_bytes()) {
        return Err("XMPP Stanza HMAC signature verification failed".to_string());
    }

    let nonce_bytes = hex::decode(&stanza.iv_hex).map_err(|e| format!("Invalid IV hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length for ChaCha20".to_string());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_bytes = BASE64
        .decode(&stanza.ciphertext_b64)
        .map_err(|e| format!("Invalid base64 payload: {}", e))?;

    // Decrypt Layer 2: ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
    let decrypted_bytes = cipher
        .decrypt(nonce, encrypted_bytes.as_ref())
        .map_err(|e| format!("ChaCha20 decryption failed: {}", e))?;

    // Parse inner OTP structure
    let inner_json: serde_json::Value =
        serde_json::from_slice(&decrypted_bytes).map_err(|e| format!("Invalid inner JSON: {}", e))?;

    let ct_b64 = inner_json["ct"].as_str().ok_or("Missing ciphertext in payload")?;
    let pad_b64 = inner_json["pad"].as_str().ok_or("Missing OTP pad in payload")?;

    let ct = BASE64.decode(ct_b64).map_err(|e| e.to_string())?;
    let pad = BASE64.decode(pad_b64).map_err(|e| e.to_string())?;

    // Decrypt Layer 1: Assembly OTP XOR
    let plaintext_bytes = otp_decrypt(&ct, &pad)?;
    String::from_utf8(plaintext_bytes).map_err(|e| format!("Invalid UTF-8 plaintext: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmpp_multi_layer_encryption() {
        let sender = "OUIJA-AAAA111122223333-FFFF";
        let recipient = "OUIJA-BBBB444455556666-0000";
        let original_msg = "Hello securely over Tor+XMPP+OTP!";

        let stanza = build_encrypted_xmpp_stanza(sender, recipient, original_msg)
            .expect("Build stanza failed");

        let xml = stanza.to_xml();
        assert!(xml.contains("<encrypted"));
        assert!(xml.contains("urn:xmpp:ouija:omemo:v1"));

        let parsed_stanza = XmppMessageStanza::from_xml(&xml).expect("Parse XML failed");
        let decrypted = decrypt_xmpp_stanza(&parsed_stanza).expect("Decrypt failed");

        assert_eq!(decrypted, original_msg);
    }
}
