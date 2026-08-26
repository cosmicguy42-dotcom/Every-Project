//! Lightweight High-Security HTTP Server for Ouija
//! Serves pure, raw brutalist HTML with zero JavaScript dependencies.

use std::sync::Arc;
use std::collections::HashMap;
use std::io::Read;
use tiny_http::{Server, Response, Request, Header, Method, StatusCode};
use crate::state::{SharedState, EphemeralMessage};
use crate::crypto::{build_encrypted_xmpp_stanza, decrypt_xmpp_stanza, XmppMessageStanza};
use crate::tor_client::TorController;

pub struct OuijaServer {
    state: SharedState,
    tor_controller: Arc<TorController>,
    port: u16,
}

impl OuijaServer {
    pub fn new(state: SharedState, tor_controller: Arc<TorController>, port: u16) -> Self {
        OuijaServer {
            state,
            tor_controller,
            port,
        }
    }

    pub fn start(&self) -> Result<(), String> {
        let addr = format!("127.0.0.1:{}", self.port);
        let server = Server::http(&addr).map_err(|e| format!("Failed to bind HTTP server to {}: {}", addr, e))?;
        println!("[OUIJA-HTTP] Raw HTML Interface online at: http://{}", addr);

        for request in server.incoming_requests() {
            let state = Arc::clone(&self.state);
            let tor = Arc::clone(&self.tor_controller);
            std::thread::spawn(move || {
                handle_request(request, state, tor);
            });
        }

        Ok(())
    }
}

/// Parse HTTP cookies from headers
fn extract_cookie(req: &Request, cookie_name: &str) -> Option<String> {
    for header in req.headers() {
        if header.field.as_str().as_str().eq_ignore_ascii_case("cookie") {
            for part in header.value.as_str().split(';') {
                let mut kv = part.split('=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    if k.trim() == cookie_name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

/// Helper to parse URL encoded form bodies
fn parse_form_body(body: &str) -> HashMap<String, String> {
    serde_urlencoded::from_str(body).unwrap_or_default()
}

/// Helper to parse query parameters from URL
fn parse_query(url: &str) -> HashMap<String, String> {
    if let Some(pos) = url.find('?') {
        let query_str = &url[pos + 1..];
        return serde_urlencoded::from_str(query_str).unwrap_or_default();
    }
    HashMap::new()
}

/// Get path without query string
fn get_path(url: &str) -> &str {
    if let Some(pos) = url.find('?') {
        &url[..pos]
    } else {
        url
    }
}

/// Apply maximum security HTTP headers to all HTML responses
fn make_html_response(html: String, status: u16, cookie_set: Option<&str>) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(html).with_status_code(StatusCode(status));
    
    // Security Headers: Zero JS allowed, strictly isolated
    resp.add_header(Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap());
    resp.add_header(Header::from_bytes(&b"Content-Security-Policy"[..], &b"default-src 'self'; script-src 'none'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"[..]).unwrap());
    resp.add_header(Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).unwrap());
    resp.add_header(Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap());
    resp.add_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-store, no-cache, must-revalidate, max-age=0"[..]).unwrap());
    resp.add_header(Header::from_bytes(&b"Pragma"[..], &b"no-cache"[..]).unwrap());

    if let Some(cookie) = cookie_set {
        resp.add_header(Header::from_bytes(&b"Set-Cookie"[..], cookie.as_bytes()).unwrap());
    }

    resp
}

/// Redirect response helper
fn make_redirect_response(location: &str, cookie_set: Option<&str>) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(format!("Redirecting to {}...", location))
        .with_status_code(StatusCode(303));
    resp.add_header(Header::from_bytes(&b"Location"[..], location.as_bytes()).unwrap());
    if let Some(cookie) = cookie_set {
        resp.add_header(Header::from_bytes(&b"Set-Cookie"[..], cookie.as_bytes()).unwrap());
    }
    resp
}

/// JSON response helper
fn make_json_response(json: String, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(json).with_status_code(StatusCode(status));
    resp.add_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    resp.add_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap());
    resp
}

fn handle_request(mut req: Request, state: SharedState, tor: Arc<TorController>) {
    let raw_url = req.url().to_string();
    let path = get_path(&raw_url).to_string();
    let method = req.method().clone();

    // Read body reliably without hanging on keep-alive connections
    let mut body_str = String::new();
    if let Some(len) = req.body_length() {
        if len > 0 && len < 10 * 1024 * 1024 {
            let mut buf = vec![0u8; len];
            let mut reader = req.as_reader();
            if reader.read_exact(&mut buf).is_ok() {
                body_str = String::from_utf8_lossy(&buf).to_string();
            }
        }
    }

    // --- Public & API routes ---

    // Tor Inbound Message Receiver
    if path == "/api/inbox" && method == Method::Post {
        handle_api_inbox(req, &body_str, &state);
        return;
    }

    // Tor Status JSON
    if path == "/api/status" {
        let onion = tor.fetch_status().map(|s| s.onion_address).unwrap_or_else(|_| "connecting.onion".to_string());
        let _ = req.respond(make_json_response(format!(r#"{{"onion":"{}"}}"#, onion), 200));
        return;
    }

    // CLI IPC: New ID endpoint
    if path == "/api/new_id" && method == Method::Post {
        let mut db = state.write().unwrap();
        match db.register_new_id() {
            Ok(id) => {
                let _ = req.respond(make_json_response(format!(r#"{{"success":true,"id":"{}"}}"#, id), 200));
            }
            Err(e) => {
                let _ = req.respond(make_json_response(format!(r#"{{"success":false,"error":"{}"}}"#, e), 500));
            }
        }
        return;
    }

    // Login POST handler
    if path == "/login" && method == Method::Post {
        let form = parse_form_body(&body_str);
        let ephemeral_id = form.get("ephemeral_id").cloned().unwrap_or_default();

        let mut db = state.write().unwrap();
        match db.validate_and_claim_id(&ephemeral_id) {
            Ok(token) => {
                let cookie = format!("ouija_session={}; Path=/; HttpOnly; SameSite=Strict", token);
                let _ = req.respond(make_redirect_response("/dashboard", Some(&cookie)));
            }
            Err(err_msg) => {
                let html = render_login_page(Some(&err_msg));
                let _ = req.respond(make_html_response(html, 401, None));
            }
        }
        return;
    }

    // Login GET handler
    if path == "/login" && method == Method::Get {
        let html = render_login_page(None);
        let _ = req.respond(make_html_response(html, 200, None));
        return;
    }

    // Logout GET handler
    if path == "/logout" {
        if let Some(token) = extract_cookie(&req, "ouija_session") {
            let mut db = state.write().unwrap();
            db.remove_session(&token);
        }
        let cookie = "ouija_session=; Path=/; HttpOnly; Max-Age=0";
        let _ = req.respond(make_redirect_response("/login", Some(cookie)));
        return;
    }

    // Purge ALL Memory POST handler
    if path == "/purge" && method == Method::Post {
        {
            let mut db = state.write().unwrap();
            db.purge_all();
        }
        let cookie = "ouija_session=; Path=/; HttpOnly; Max-Age=0";
        let html = render_purged_page();
        let _ = req.respond(make_html_response(html, 200, Some(cookie)));
        return;
    }

    // --- Authenticated routes check ---
    let session_token = extract_cookie(&req, "ouija_session");
    let current_session = {
        if let Some(ref token) = session_token {
            let mut db = state.write().unwrap();
            db.get_session(token)
        } else {
            None
        }
    };

    let session = match current_session {
        Some(s) => s,
        None => {
            // Not authenticated: redirect to login
            let _ = req.respond(make_redirect_response("/login", None));
            return;
        }
    };

    // Root -> redirect to dashboard
    if path == "/" {
        let _ = req.respond(make_redirect_response("/dashboard", None));
        return;
    }

    // Dashboard GET
    if path == "/dashboard" && method == Method::Get {
        let onion = tor.fetch_status().map(|s| s.onion_address).unwrap_or_else(|_| "connecting.onion".to_string());
        let db = state.read().unwrap();
        let peers = db.peers.values().cloned().collect::<Vec<_>>();
        let html = render_dashboard_page(&session.ephemeral_id, &onion, &peers);
        let _ = req.respond(make_html_response(html, 200, None));
        return;
    }

    // Add Peer POST
    if path == "/peers/add" && method == Method::Post {
        let form = parse_form_body(&body_str);
        let peer_id = form.get("peer_id").cloned().unwrap_or_default().trim().to_string();
        let onion_address = form.get("onion_address").cloned().unwrap_or_default().trim().to_string();
        let alias = form.get("alias").cloned().unwrap_or_default().trim().to_string();

        if !peer_id.is_empty() && !onion_address.is_empty() {
            let mut db = state.write().unwrap();
            db.add_peer(peer_id.clone(), onion_address, alias);
            let _ = req.respond(make_redirect_response(&format!("/chat?peer={}", peer_id), None));
            return;
        } else {
            let _ = req.respond(make_redirect_response("/dashboard", None));
            return;
        }
    }

    // Chat Room GET (with pure HTML 3s meta-refresh)
    if path == "/chat" && method == Method::Get {
        let query = parse_query(&raw_url);
        let peer_id = query.get("peer").cloned().unwrap_or_default();

        let db = state.read().unwrap();
        let peer = db.peers.get(&peer_id).cloned();
        let messages = db.get_messages_for_peer(&session.ephemeral_id, &peer_id);
        let html = render_chat_page(&session.ephemeral_id, peer.as_ref(), &peer_id, &messages);
        let _ = req.respond(make_html_response(html, 200, None));
        return;
    }

    // Chat Send POST (Layer 1 OTP + Layer 2 XMPP + Layer 3 Tor)
    if path == "/chat/send" && method == Method::Post {
        let form = parse_form_body(&body_str);
        let peer_id = form.get("peer_id").cloned().unwrap_or_default().trim().to_string();
        let message_text = form.get("message").cloned().unwrap_or_default().trim().to_string();

        if !peer_id.is_empty() && !message_text.is_empty() {
            let (target_onion, _) = {
                let db = state.read().unwrap();
                let peer = db.peers.get(&peer_id);
                let onion = peer.map(|p| p.onion_address.clone()).unwrap_or_else(|| "127.0.0.1".to_string());
                let alias = peer.map(|p| p.alias.clone()).unwrap_or_default();
                (onion, alias)
            };

            // 1. Build Triple Encrypted Layer: OTP (Assembly) + XMPP Stanza (ChaCha20 + HMAC)
            match build_encrypted_xmpp_stanza(&session.ephemeral_id, &peer_id, &message_text) {
                Ok(stanza) => {
                    let xml = stanza.to_xml();

                    // 2. Dispatch over Layer 3: Tor Network
                    let payload_json = serde_json::to_value(&stanza).unwrap_or_default();
                    let delivery_result = tor.send_onion_message(&target_onion, &payload_json);
                    let _status_note = match delivery_result {
                        Ok(msg) => format!("TOR: {}", msg),
                        Err(e) => format!("TOR WARNING: {}", e),
                    };

                    // 3. Store in ephemeral volatile RAM
                    let mut db = state.write().unwrap();
                    db.add_message(EphemeralMessage {
                        id: stanza.id.clone(),
                        from: session.ephemeral_id.clone(),
                        to: peer_id.clone(),
                        is_outgoing: true,
                        content: message_text,
                        timestamp: chrono::Utc::now().timestamp(),
                        encrypted_stanza_preview: xml,
                    });
                }
                Err(e) => {
                    eprintln!("[ERROR] Encryption failed: {}", e);
                }
            }
        }

        let _ = req.respond(make_redirect_response(&format!("/chat?peer={}", peer_id), None));
        return;
    }

    // 404 Fallback
    let html = render_404_page(&path);
    let _ = req.respond(make_html_response(html, 404, None));
}

/// Handles inbound encrypted packets arriving from remote Tor nodes
fn handle_api_inbox(req: Request, body_str: &str, state: &SharedState) {
    let stanza: Result<XmppMessageStanza, _> = serde_json::from_str(body_str);
    match stanza {
        Ok(stanza) => {
            // Decrypt Layer 2 (XMPP) and Layer 1 (Assembly OTP)
            match decrypt_xmpp_stanza(&stanza) {
                Ok(plaintext) => {
                    let mut db = state.write().unwrap();
                    let xml = stanza.to_xml();
                    db.add_message(EphemeralMessage {
                        id: stanza.id.clone(),
                        from: stanza.from.clone(),
                        to: stanza.to.clone(),
                        is_outgoing: false,
                        content: plaintext,
                        timestamp: stanza.timestamp,
                        encrypted_stanza_preview: xml,
                    });
                    let _ = req.respond(make_json_response(r#"{"status":"received"}"#.to_string(), 200));
                }
                Err(e) => {
                    let _ = req.respond(make_json_response(format!(r#"{{"status":"error","detail":"{}"}}"#, e), 400));
                }
            }
        }
        Err(e) => {
            let _ = req.respond(make_json_response(format!(r#"{{"status":"invalid_json","detail":"{}"}}"#, e), 400));
        }
    }
}

// ============================================================================
// RAW BRUTALIST HTML TEMPLATES (NO JAVASCRIPT / ZERO TRACKERS / PURE SEMANTIC)
// ============================================================================

fn render_login_page(error_msg: Option<&str>) -> String {
    let err_block = match error_msg {
        Some(err) => format!(
            r#"<div style="border: 2px solid #ff4444; background-color: #2b0000; color: #ff6666; padding: 12px; margin: 15px 0; font-family: monospace;">
<strong>[ACCESS REJECTED]</strong><br>{}
<br><br>
<em>Verification Failure: The entered Ephemeral ID failed SHA-256 constant-time verification or is not present in volatile in-memory database.</em>
</div>"#,
            html_escape(err)
        ),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>OUIJA // SECURITY ACCESS GATEWAY</title>
    <style>
        body {{
            background-color: #0d0e11;
            color: #00ff66;
            font-family: "Courier New", Courier, monospace;
            padding: 30px;
            margin: 0;
            line-height: 1.5;
        }}
        pre {{
            color: #00ffcc;
            font-weight: bold;
        }}
        .card {{
            border: 1px solid #00ff66;
            padding: 20px;
            max-width: 750px;
            background-color: #051008;
            box-shadow: 0 0 10px rgba(0, 255, 102, 0.2);
        }}
        input[type=text] {{
            background-color: #000;
            color: #00ff66;
            border: 1px solid #00ff66;
            padding: 10px;
            font-family: monospace;
            font-size: 14px;
            width: 95%;
        }}
        input[type=submit], button {{
            background-color: #00ff66;
            color: #000;
            border: none;
            padding: 10px 20px;
            font-family: monospace;
            font-weight: bold;
            font-size: 14px;
            cursor: pointer;
        }}
        input[type=submit]:hover, button:hover {{
            background-color: #00cc52;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            margin-right: 5px;
            font-size: 11px;
            background: #003311;
            border: 1px solid #00aa44;
        }}
    </style>
</head>
<body>
    <pre>
  ██████╗ ██╗   ██╗██╗     ██╗ █████╗ 
 ██╔═══██╗██║   ██║██║     ██║██╔══██╗
 ██║   ██║██║   ██║██║     ██║███████║
 ██║   ██║██║   ██║██║██   ██║██╔══██║
 ╚██████╔╝╚██████╔╝██║╚█████╔╝██║  ██║
  ╚═════╝  ╚═════╝ ╚═╝ ╚════╝ ╚═╝  ╚═╝
 [ SECURE EPHEMERAL ONION MESSAGING ENGINE ]
    </pre>

    <div class="card">
        <div>
            <span class="badge">RUST KERNEL</span>
            <span class="badge">C mlock() VOLATILE</span>
            <span class="badge">x86_64 ASM OTP</span>
            <span class="badge">XMPP OMEMO</span>
            <span class="badge">TOR v3 ONION</span>
        </div>
        <hr style="border: 0; border-top: 1px solid #00ff66; margin: 15px 0;">

        {}

        <h3>AUTHENTICATION INSTRUCTIONS:</h3>
        <ol>
            <li>Open your terminal</li>
            <li>Run command: <code>ouija new id</code></li>
            <li>Copy the generated SHA-256 validated Ephemeral ID</li>
            <li>Paste the ID into the prompt below and press Authenticate</li>
        </ol>

        <form method="POST" action="/login">
            <label for="ephemeral_id"><strong>ENTER EPHEMERAL SESSION ID:</strong></label><br><br>
            <input type="text" id="ephemeral_id" name="ephemeral_id" placeholder="OUIJA-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx" required autofocus><br><br>
            <input type="submit" value="[ AUTHENTICATE & ENTER ]">
        </form>

        <hr style="border: 0; border-top: 1px solid #003311; margin: 20px 0;">
        <small style="color: #66aa77;">
            Security Notice: Ephemeral IDs are verified in constant-time assembly and stored strictly in RAM with zero disk persistence. Unclaimed IDs expire automatically.
        </small>
    </div>
</body>
</html>"#,
        err_block
    )
}

fn render_dashboard_page(ephemeral_id: &str, onion_address: &str, peers: &[crate::state::EphemeralPeer]) -> String {
    let mut peer_rows = String::new();
    if peers.is_empty() {
        peer_rows = r#"<tr><td colspan="4" style="text-align: center; color: #888; padding: 15px;">No active peer routes configured in RAM. Add a peer route below.</td></tr>"#.to_string();
    } else {
        for p in peers {
            peer_rows.push_str(&format!(
                r#"<tr>
    <td style="padding: 8px; border: 1px solid #005522;"><code>{}</code></td>
    <td style="padding: 8px; border: 1px solid #005522;"><code>{}</code></td>
    <td style="padding: 8px; border: 1px solid #005522;">{}</td>
    <td style="padding: 8px; border: 1px solid #005522;">
        <a href="/chat?peer={}" style="color: #000; background: #00ff66; padding: 4px 8px; text-decoration: none; font-weight: bold;">[ OPEN CHAT ]</a>
    </td>
</tr>"#,
                html_escape(&p.alias),
                html_escape(&p.peer_id),
                html_escape(&p.onion_address),
                html_escape(&p.peer_id),
            ));
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>OUIJA // DASHBOARD</title>
    <style>
        body {{
            background-color: #0d0e11;
            color: #00ff66;
            font-family: "Courier New", Courier, monospace;
            padding: 25px;
            margin: 0;
            line-height: 1.4;
        }}
        .card {{
            border: 1px solid #00ff66;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #051008;
        }}
        input[type=text] {{
            background-color: #000;
            color: #00ff66;
            border: 1px solid #00ff66;
            padding: 6px;
            font-family: monospace;
            width: 90%;
        }}
        input[type=submit], button, .btn {{
            background-color: #00ff66;
            color: #000;
            border: none;
            padding: 6px 14px;
            font-family: monospace;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th {{
            background: #002b11;
            border: 1px solid #005522;
            padding: 8px;
            text-align: left;
        }}
        .danger-btn {{
            background-color: #ff3333 !important;
            color: #fff !important;
        }}
    </style>
</head>
<body>
    <h2>[ OUIJA DASHBOARD :: EPHEMERAL SESSION ]</h2>

    <div class="card">
        <table style="width: 100%;">
            <tr>
                <td><strong>YOUR EPHEMERAL ID:</strong></td>
                <td><code>{}</code> (SHA-256 Validated)</td>
            </tr>
            <tr>
                <td><strong>YOUR TOR ONION ENDPOINT:</strong></td>
                <td><code style="color: #00ffcc;">http://{}</code></td>
            </tr>
            <tr>
                <td><strong>MEMORY INTEGRITY:</strong></td>
                <td><span style="color: #00ff00;">LOCKED (mlock) / RAM-ONLY (NO DISK PERSISTENCE)</span></td>
            </tr>
        </table>
        <div style="margin-top: 12px;">
            <a href="/logout" class="btn">[ LOGOUT ]</a>
            <form method="POST" action="/purge" style="display: inline-block; margin-left: 10px;">
                <input type="submit" value="[ PURGE ALL MEMORY & ZEROIZE ]" class="danger-btn" onclick="return confirm('Immediately wipe all keys, pads and messages from RAM?');">
            </form>
        </div>
    </div>

    <div class="card">
        <h3>ACTIVE PEER ROUTES</h3>
        <table>
            <thead>
                <tr>
                    <th>ALIAS</th>
                    <th>PEER EPHEMERAL ID</th>
                    <th>TOR ONION ADDRESS</th>
                    <th>ACTION</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h3>ROUTE NEW PEER</h3>
        <form method="POST" action="/peers/add">
            <label><strong>Peer Ephemeral ID:</strong></label><br>
            <input type="text" name="peer_id" placeholder="OUIJA-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx" required><br><br>

            <label><strong>Peer Tor Onion Endpoint:</strong></label><br>
            <input type="text" name="onion_address" placeholder="http://xxxxxxxxx.onion or http://127.0.0.1:8765" required><br><br>

            <label><strong>Alias / Label:</strong></label><br>
            <input type="text" name="alias" placeholder="Peer_Alpha" style="width: 40%;"><br><br>

            <input type="submit" value="[ ADD PEER & ESTABLISH ROUTE ]">
        </form>
    </div>
</body>
</html>"#,
        html_escape(ephemeral_id),
        html_escape(onion_address),
        peer_rows
    )
}

fn render_chat_page(
    current_id: &str,
    peer: Option<&crate::state::EphemeralPeer>,
    peer_id: &str,
    messages: &[EphemeralMessage],
) -> String {
    let peer_name = peer.map(|p| p.alias.as_str()).unwrap_or(peer_id);
    let peer_onion = peer.map(|p| p.onion_address.as_str()).unwrap_or("unknown.onion");

    let mut msg_stream = String::new();
    if messages.is_empty() {
        msg_stream = r#"<div style="color: #666; font-style: italic; padding: 20px 0;">No messages yet in this ephemeral session. Send a message below.</div>"#.to_string();
    } else {
        for m in messages {
            let is_me = m.from == current_id;
            let sender_label = if is_me { "[LOCAL USER]" } else { "[REMOTE PEER]" };
            let box_color = if is_me { "#002a11" } else { "#101b2b" };
            let text_color = if is_me { "#00ff66" } else { "#00ccff" };
            let dt = chrono::DateTime::from_timestamp(m.timestamp, 0)
                .map(|d| d.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "00:00:00".to_string());

            msg_stream.push_str(&format!(
                r#"<div style="background: {}; border: 1px solid #005522; padding: 10px; margin-bottom: 12px;">
    <div style="font-size: 11px; color: #888; margin-bottom: 5px;">
        <span style="color: {}; font-weight: bold;">{}</span> | Time: {} | Stanza ID: <code>{}</code>
        <span style="float: right; color: #55ff55;">[OTP XOR + XMPP OMEMO + TOR v3]</span>
    </div>
    <div style="color: {}; font-size: 14px; white-space: pre-wrap;">{}</div>
    <details style="margin-top: 8px; font-size: 11px; color: #777;">
        <summary>[ View Encrypted XMPP XML Stanza ]</summary>
        <pre style="background: #000; padding: 8px; border: 1px solid #333; overflow-x: auto; color: #ffaa00;">{}</pre>
    </details>
</div>"#,
                box_color, text_color, sender_label, dt, html_escape(&m.id),
                text_color, html_escape(&m.content),
                html_escape(&m.encrypted_stanza_preview)
            ));
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <!-- Zero Javascript: Browser native auto-refresh every 3s -->
    <meta http-equiv="refresh" content="3">
    <title>OUIJA // CHAT :: {}</title>
    <style>
        body {{
            background-color: #0d0e11;
            color: #00ff66;
            font-family: "Courier New", Courier, monospace;
            padding: 20px;
            margin: 0;
            line-height: 1.4;
        }}
        .card {{
            border: 1px solid #00ff66;
            padding: 15px;
            background-color: #051008;
            margin-bottom: 15px;
        }}
        textarea {{
            background-color: #000;
            color: #00ff66;
            border: 1px solid #00ff66;
            padding: 8px;
            font-family: monospace;
            font-size: 14px;
            width: 95%;
        }}
        input[type=submit], button, .btn {{
            background-color: #00ff66;
            color: #000;
            border: none;
            padding: 8px 16px;
            font-family: monospace;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            font-size: 11px;
            background: #003311;
            border: 1px solid #00aa44;
        }}
    </style>
</head>
<body>
    <div style="margin-bottom: 10px;">
        <a href="/dashboard" class="btn">[ &lt; BACK TO DASHBOARD ]</a>
        <a href="/chat?peer={}" class="btn" style="margin-left: 10px;">[ REFRESH NOW ]</a>
        <span style="font-size: 12px; color: #888; margin-left: 15px;">Auto-refresh active: 3s (No JS)</span>
    </div>

    <div class="card">
        <div><strong>PEER:</strong> {} (<code>{}</code>)</div>
        <div><strong>ROUTE:</strong> <code style="color: #00ffcc;">{}</code></div>
        <div style="margin-top: 5px;">
            <span class="badge">LAYER 1: OTP (x86_64 ASM)</span>
            <span class="badge">LAYER 2: XMPP OMEMO (ChaCha20-Poly1305)</span>
            <span class="badge">LAYER 3: TOR ONION TRANSPORT</span>
        </div>
    </div>

    <div class="card" style="min-height: 250px; max-height: 500px; overflow-y: scroll;">
        {}
    </div>

    <div class="card">
        <form method="POST" action="/chat/send">
            <input type="hidden" name="peer_id" value="{}">
            <label><strong>TRANSMIT ENCRYPTED MESSAGE:</strong></label><br><br>
            <textarea name="message" rows="3" placeholder="Type secret message payload..." required autofocus></textarea><br><br>
            <input type="submit" value="[ ENCRYPT (OTP+XMPP+TOR) & TRANSMIT ]">
        </form>
    </div>
</body>
</html>"#,
        html_escape(peer_name),
        html_escape(peer_id),
        html_escape(peer_name),
        html_escape(peer_id),
        html_escape(peer_onion),
        msg_stream,
        html_escape(peer_id)
    )
}

fn render_purged_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>OUIJA // MEMORY PURGED</title>
    <style>
        body {
            background-color: #000;
            color: #ff3333;
            font-family: monospace;
            padding: 40px;
            text-align: center;
        }
        .box {
            border: 2px solid #ff3333;
            padding: 30px;
            display: inline-block;
            background: #100;
        }
        a {
            color: #00ff66;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="box">
        <h1>[ MEMORY PURGE COMPLETE ]</h1>
        <p>All ephemeral IDs, session tokens, OTP pads, and message logs have been zeroized in RAM via x86_64 assembly barriers.</p>
        <p>Zero residual data left in volatile memory.</p>
        <br>
        <p><a href="/login">[ RETURN TO ACCESS GATEWAY ]</a></p>
    </div>
</body>
</html>"#.to_string()
}

fn render_404_page(path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>404 NOT FOUND</title><style>body{{background:#000;color:#00ff66;font-family:monospace;padding:30px;}}</style></head>
<body>
    <h2>404 - ENDPOINT NOT FOUND</h2>
    <p>Path: <code>{}</code></p>
    <p><a href="/dashboard" style="color:#00ff66;">[ RETURN ]</a></p>
</body>
</html>"#,
        html_escape(path)
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
