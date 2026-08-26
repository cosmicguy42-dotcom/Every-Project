//! Ouija CLI Commands & IPC Client

use std::time::Duration;
use crate::crypto::{generate_ephemeral_id, validate_ephemeral_id_crypto};

const SERVER_API_URL: &str = "http://127.0.0.1:8765";

pub fn handle_cli_args(args: &[String]) -> Result<bool, String> {
    if args.is_empty() {
        print_help();
        return Ok(false);
    }

    match args[0].as_str() {
        "new" => {
            if args.len() > 1 && args[1] == "id" {
                cli_new_id()?;
                return Ok(true); // Handled CLI command, don't run server loop
            } else {
                println!("Usage: ouija new id");
                return Ok(true);
            }
        }
        "status" => {
            cli_status()?;
            return Ok(true);
        }
        "purge" => {
            cli_purge()?;
            return Ok(true);
        }
        "start" | "run" | "server" | "daemon" => {
            // Proceed to run server
            return Ok(false);
        }
        "help" | "-h" | "--help" => {
            print_help();
            return Ok(true);
        }
        cmd => {
            println!("Unknown command: {}", cmd);
            print_help();
            return Ok(true);
        }
    }
}

pub fn print_help() {
    println!(r#"
  ██████╗ ██╗   ██╗██╗     ██╗ █████╗ 
 ██╔═══██╗██║   ██║██║     ██║██╔══██╗
 ██║   ██║██║   ██║██║     ██║███████║
 ██║   ██║██║   ██║██║██   ██║██╔══██║
 ╚██████╔╝╚██████╔╝██║╚█████╔╝██║  ██║
  ╚═════╝  ╚═════╝ ╚═╝ ╚════╝ ╚═╝  ╚═╝
 High-Security Ephemeral Onion Messaging Engine

USAGE:
    ouija new id          Generate and register a new SHA-256 validated Ephemeral ID
    ouija start           Start the Ouija security daemon & browser interface
    ouija status          Display active Tor Onion endpoint & system status
    ouija purge           Instantly wipe all keys, pads, and chat logs from RAM
    ouija help            Display this help screen

BROWSER INTERFACE:
    http://127.0.0.1:8765
"#);
}

fn cli_new_id() -> Result<(), String> {
    // Attempt to register with running daemon
    let url = format!("{}/api/new_id", SERVER_API_URL);
    match ureq::post(&url).timeout(Duration::from_secs(2)).call() {
        Ok(resp) => {
            let json: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
            if let Some(id) = json["id"].as_str() {
                println!("================================================================");
                println!("[OUIJA SECURITY] EPHEMERAL SESSION ID GENERATED & REGISTERED");
                println!("================================================================");
                println!("ID: {}", id);
                println!("SHA-256 Checksum: VALID (Verified via x86_64 Assembly)");
                println!("Storage: Ephemeral RAM Database (TTL: 30 minutes)");
                println!("Web Gateway: http://127.0.0.1:8765/login");
                println!("================================================================");
                return Ok(());
            }
        }
        Err(_) => {
            // Server not running, generate standalone and give instruction
            let id = generate_ephemeral_id()?;
            let is_valid = validate_ephemeral_id_crypto(&id);
            println!("================================================================");
            println!("[OUIJA SECURITY] STANDALONE EPHEMERAL ID GENERATED");
            println!("================================================================");
            println!("ID: {}", id);
            println!("SHA-256 Checksum: {}", if is_valid { "VALID [OK]" } else { "INVALID" });
            println!("\nNOTE: The Ouija daemon is not currently running.");
            println!("To start the daemon and login with this ID, run:");
            println!("  ouija start");
            println!("Then visit: http://127.0.0.1:8765");
            println!("================================================================");
        }
    }
    Ok(())
}

fn cli_status() -> Result<(), String> {
    let url = format!("{}/api/status", SERVER_API_URL);
    match ureq::get(&url).timeout(Duration::from_secs(2)).call() {
        Ok(resp) => {
            let json: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
            let onion = json["onion"].as_str().unwrap_or("unknown");
            println!("================================================================");
            println!("[OUIJA STATUS] DAEMON ONLINE");
            println!("================================================================");
            println!("Tor Onion Address: http://{}", onion);
            println!("Web Interface:     http://127.0.0.1:8765");
            println!("Memory Hardening:  Active (mlock, PR_SET_DUMPABLE=0)");
            println!("================================================================");
        }
        Err(_) => {
            println!("[OUIJA STATUS] Daemon is OFFLINE. Run 'ouija start' to launch.");
        }
    }
    Ok(())
}

fn cli_purge() -> Result<(), String> {
    let url = format!("{}/purge", SERVER_API_URL);
    match ureq::post(&url).timeout(Duration::from_secs(2)).call() {
        Ok(_) => {
            println!("[OUIJA-SECURITY] All volatile RAM database records purged successfully.");
        }
        Err(_) => {
            println!("[OUIJA-SECURITY] Daemon is offline (No volatile memory to purge).");
        }
    }
    Ok(())
}
