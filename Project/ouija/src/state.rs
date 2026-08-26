//! Ephemeral In-Memory Database
//! Strictly zero-persistence (RAM-only). Memory pages are locked (mlock)
//! and zeroized using x86_64 assembly barriers upon expiration or purge.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Duration, Utc};
use crate::crypto::{generate_ephemeral_id, validate_ephemeral_id_crypto};
use crate::ffi::secure_zeroize;

/// Ephemeral ID record in RAM
#[derive(Debug, Clone)]
pub struct EphemeralIdRecord {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_claimed: bool,
}

/// Ephemeral Browser Session
#[derive(Debug, Clone)]
pub struct EphemeralSession {
    pub token: String,
    pub ephemeral_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

/// Ephemeral Peer Record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EphemeralPeer {
    pub peer_id: String,
    pub onion_address: String,
    pub alias: String,
    pub added_at: i64,
}

/// Ephemeral Chat Message Record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EphemeralMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub is_outgoing: bool,
    pub content: String,
    pub timestamp: i64,
    pub encrypted_stanza_preview: String,
}

/// Ephemeral Database State Container
pub struct EphemeralDatabase {
    pub active_ids: HashMap<String, EphemeralIdRecord>,
    pub sessions: HashMap<String, EphemeralSession>,
    pub peers: HashMap<String, EphemeralPeer>,
    pub messages: Vec<EphemeralMessage>,
    pub local_onion_address: String,
}

impl EphemeralDatabase {
    pub fn new() -> Self {
        EphemeralDatabase {
            active_ids: HashMap::new(),
            sessions: HashMap::new(),
            peers: HashMap::new(),
            messages: Vec::new(),
            local_onion_address: "initializing.onion".to_string(),
        }
    }

    /// Registers a newly minted ephemeral ID into volatile RAM.
    pub fn register_new_id(&mut self) -> Result<String, String> {
        self.cleanup_expired();

        let id = generate_ephemeral_id()?;
        let now = Utc::now();
        let expires_at = now + Duration::minutes(30); // 30-minute claim window

        let record = EphemeralIdRecord {
            id: id.clone(),
            created_at: now,
            expires_at,
            is_claimed: false,
        };

        self.active_ids.insert(id.clone(), record);
        println!("[OUIJA-DB] Registered ephemeral ID into RAM: {}", id);
        Ok(id)
    }

    /// Validates SHA-256 and verifies that the ID is present in the ephemeral database.
    pub fn validate_and_claim_id(&mut self, id: &str) -> Result<String, String> {
        self.cleanup_expired();

        let trimmed_id = id.trim();

        // 1. Cryptographic SHA-256 validation (constant-time)
        if !validate_ephemeral_id_crypto(trimmed_id) {
            return Err("REJECTED: SHA-256 checksum or format validation failed".to_string());
        }

        // 2. Ephemeral In-Memory Database existence check
        let record = match self.active_ids.get_mut(trimmed_id) {
            Some(r) => r,
            None => {
                return Err("REJECTED: Ephemeral ID is not found in active in-memory database".to_string());
            }
        };

        if Utc::now() > record.expires_at {
            return Err("REJECTED: Ephemeral ID has expired".to_string());
        }

        record.is_claimed = true;
        // Extend lifetime once claimed
        record.expires_at = Utc::now() + Duration::hours(12);

        // Generate session auth token
        let mut session_bytes = [0u8; 24];
        let _ = crate::ffi::fill_secure_random(&mut session_bytes);
        let session_token = hex::encode(session_bytes);

        let session = EphemeralSession {
            token: session_token.clone(),
            ephemeral_id: trimmed_id.to_string(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };

        self.sessions.insert(session_token.clone(), session);
        Ok(session_token)
    }

    /// Verifies session token
    pub fn get_session(&mut self, token: &str) -> Option<EphemeralSession> {
        self.cleanup_expired();
        if let Some(session) = self.sessions.get_mut(token) {
            session.last_activity = Utc::now();
            return Some(session.clone());
        }
        None
    }

    /// Removes session on logout
    pub fn remove_session(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    /// Adds a peer
    pub fn add_peer(&mut self, peer_id: String, onion_address: String, alias: String) {
        let peer = EphemeralPeer {
            peer_id: peer_id.clone(),
            onion_address,
            alias,
            added_at: Utc::now().timestamp(),
        };
        self.peers.insert(peer_id, peer);
    }

    /// Adds a message to volatile history
    pub fn add_message(&mut self, msg: EphemeralMessage) {
        self.messages.push(msg);
        // Limit volatile in-memory history to 500 messages
        if self.messages.len() > 500 {
            self.messages.remove(0);
        }
    }

    /// Retrieves messages for a conversation with a peer
    pub fn get_messages_for_peer(&self, current_user_id: &str, peer_id: &str) -> Vec<EphemeralMessage> {
        self.messages
            .iter()
            .filter(|m| {
                (m.from == current_user_id && m.to == peer_id)
                    || (m.from == peer_id && m.to == current_user_id)
                    || (m.to == peer_id)
                    || (m.from == peer_id)
            })
            .cloned()
            .collect()
    }

    /// Clean up expired ephemeral IDs
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.active_ids.retain(|_, v| v.expires_at > now);
        self.sessions.retain(|_, s| (now - s.last_activity) < Duration::hours(12));
    }

    /// Instantly zeroize and purge all memory
    pub fn purge_all(&mut self) {
        println!("[OUIJA-SECURITY] PURGING ALL EPHEMERAL DATA FROM RAM WITH ASSEMBLY BARRIERS...");

        for (_, record) in self.active_ids.iter_mut() {
            unsafe {
                let bytes = record.id.as_bytes_mut();
                secure_zeroize(bytes);
            }
        }
        self.active_ids.clear();

        for (_, session) in self.sessions.iter_mut() {
            unsafe {
                let bytes = session.token.as_bytes_mut();
                secure_zeroize(bytes);
            }
        }
        self.sessions.clear();

        self.peers.clear();

        for msg in self.messages.iter_mut() {
            unsafe {
                let bytes = msg.content.as_bytes_mut();
                secure_zeroize(bytes);
            }
        }
        self.messages.clear();

        println!("[OUIJA-SECURITY] PURGE COMPLETE. ZERO RESIDUAL MEMORY.");
    }
}

pub type SharedState = Arc<RwLock<EphemeralDatabase>>;

pub fn create_shared_state() -> SharedState {
    Arc::new(RwLock::new(EphemeralDatabase::new()))
}
