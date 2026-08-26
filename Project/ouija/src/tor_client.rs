//! Tor Network Client Bridge
//! Communicates with the Python Tor subsystem to route messages to .onion addresses.

use std::process::{Child, Command};
use std::time::Duration;
use serde::{Deserialize, Serialize};

pub const TOR_BRIDGE_URL: &str = "http://127.0.0.1:9058";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStatusResponse {
    pub status: String,
    pub onion_address: String,
    pub socks_port: u16,
    pub hidden_service_port: u16,
    pub target_port: u16,
}

#[derive(Debug, Serialize)]
struct SendOnionRequest<'a> {
    target_onion: &'a str,
    payload: &'a serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct SendOnionResponse {
    success: bool,
    message: Option<String>,
    error: Option<String>,
}

pub struct TorController {
    child_process: Option<Child>,
}

impl TorController {
    pub fn new() -> Self {
        TorController {
            child_process: None,
        }
    }

    /// Spawns the Python Tor manager background process.
    pub fn spawn_manager(&mut self) -> Result<(), String> {
        // First check if bridge is already running
        if self.fetch_status().is_ok() {
            println!("[OUIJA-TOR] Tor bridge is already active.");
            return Ok(());
        }

        println!("[OUIJA-TOR] Spawning Python Tor subsystem...");
        let script_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tor/ouija_tor_manager.py");

        let child = Command::new("python3")
            .arg(script_path)
            .spawn()
            .map_err(|e| format!("Failed to spawn Python Tor manager: {}", e))?;

        self.child_process = Some(child);

        // Wait up to 5 seconds for bridge to respond
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(500));
            if self.fetch_status().is_ok() {
                println!("[OUIJA-TOR] Connected to Tor bridge.");
                return Ok(());
            }
        }

        println!("[OUIJA-TOR] Notice: Tor bridge starting asynchronously.");
        Ok(())
    }

    /// Queries current Tor Hidden Service status and .onion address.
    pub fn fetch_status(&self) -> Result<TorStatusResponse, String> {
        let url = format!("{}/status", TOR_BRIDGE_URL);
        let resp = ureq::get(&url)
            .timeout(Duration::from_secs(3))
            .call()
            .map_err(|e| format!("Tor bridge unavailable: {}", e))?;

        let status: TorStatusResponse = resp
            .into_json()
            .map_err(|e| format!("Invalid JSON from Tor bridge: {}", e))?;

        Ok(status)
    }

    /// Sends an encrypted envelope payload to a remote .onion address through Tor.
    pub fn send_onion_message(
        &self,
        target_onion: &str,
        payload: &serde_json::Value,
    ) -> Result<String, String> {
        let url = format!("{}/send_onion", TOR_BRIDGE_URL);
        let req_body = SendOnionRequest {
            target_onion,
            payload,
        };

        let resp = ureq::post(&url)
            .timeout(Duration::from_secs(45)) // SOCKS Tor circuits may take time
            .send_json(&req_body)
            .map_err(|e| format!("Network delivery error over Tor: {}", e))?;

        let parsed: SendOnionResponse = resp
            .into_json()
            .map_err(|e| format!("Failed to parse Tor bridge response: {}", e))?;

        if parsed.success {
            Ok(parsed.message.unwrap_or_else(|| "Delivered successfully".to_string()))
        } else {
            Err(parsed.error.unwrap_or_else(|| "Unknown Tor routing failure".to_string()))
        }
    }
}

impl Drop for TorController {
    fn drop(&mut self) {
        if let Some(mut child) = self.child_process.take() {
            println!("[OUIJA-TOR] Stopping Python Tor manager...");
            let _ = child.kill();
        }
    }
}
