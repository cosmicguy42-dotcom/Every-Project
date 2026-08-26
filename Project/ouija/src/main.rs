//! OUIJA - High-Security Ephemeral Onion Messaging Engine
//! Core: Rust + C (mlock/POSIX) + x86_64 Assembly (OTP XOR / CT-memcmp / Memzero) + Python (Tor v3 Onion Controller)

mod ffi;
mod crypto;
mod state;
mod tor_client;
mod server;
mod cli;

use std::sync::Arc;
use crate::state::create_shared_state;
use crate::tor_client::TorController;
use crate::server::OuijaServer;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // 1. Check CLI sub-commands (e.g. "ouija new id", "ouija status", "ouija purge")
    if !args.is_empty() {
        match cli::handle_cli_args(&args) {
            Ok(handled) => {
                if handled {
                    return;
                }
            }
            Err(e) => {
                eprintln!("[ERROR] CLI execution failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // 2. Harden OS Process (Anti-dumping, anti-ptrace, zero core dumps)
    ffi::harden_process();

    println!(r#"
  ██████╗ ██╗   ██╗██╗     ██╗ █████╗ 
 ██╔═══██╗██║   ██║██║     ██║██╔══██╗
 ██║   ██║██║   ██║██║     ██║███████║
 ██║   ██║██║   ██║██║██   ██║██╔══██║
 ╚██████╔╝╚██████╔╝██║╚█████╔╝██║  ██║
  ╚═════╝  ╚═════╝ ╚═╝ ╚════╝ ╚═╝  ╚═╝
 High-Security Ephemeral Onion Messaging Engine
"#);
    println!("[OUIJA-CORE] Process hardened: Core dumps disabled (RLIMIT_CORE=0), ptrace restricted (PR_SET_DUMPABLE=0)");
    println!("[OUIJA-CORE] Native Assembly: x86_64 constant-time OTP XOR, CT-memcmp, and memzero enabled.");

    // 3. Initialize RAM-only Ephemeral Database
    let state = create_shared_state();

    // Mint a default initial session ID on startup for instant use
    {
        let mut db = state.write().unwrap();
        if let Ok(initial_id) = db.register_new_id() {
            println!("================================================================");
            println!("[INITIAL EPHEMERAL ID MINTED]");
            println!("ID: {}", initial_id);
            println!("Login at: http://127.0.0.1:8765/login");
            println!("To generate additional IDs later, run: ouija new id");
            println!("================================================================");
        }
    }

    // 4. Initialize Tor Controller and spawn Python subsystem
    let mut tor = TorController::new();
    if let Err(e) = tor.spawn_manager() {
        eprintln!("[OUIJA-TOR-WARN] Tor manager initialization: {}", e);
    }
    let tor_arc = Arc::new(tor);

    // 5. Start Lightweight HTTP Server with Raw Brutalist HTML UI
    let port = 8765;
    let server = OuijaServer::new(state, tor_arc, port);
    if let Err(e) = server.start() {
        eprintln!("[OUIJA-FATAL] Server terminated with error: {}", e);
        std::process::exit(1);
    }
}
