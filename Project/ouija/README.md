# 👁️ OUIJA // High-Security Ephemeral Onion Messaging Engine

> **Architecture Low-System & Sécurité Maximale** : Rust + x86_64 Assembly + C/C++ Hardening + Python Tor Engine.  
> **Interface Browser Brutaliste** : 100% HTML pur (Zero JavaScript / Zero CDN / Zero Tracker).  
> **Triple Chiffrement Imbriqué** : Layer 1 (OTP ASM) $\subset$ Layer 2 (XMPP OMEMO) $\subset$ Layer 3 (Tor v3 Onion).

---

## 🔒 Spécifications Techniques & Sécurité

1. **Persistance Zéro (Volatile RAM Only)** :
   - Aucune donnée n'est jamais écrite sur disque.
   - Verrouillage mémoire via `mlock(2)` (C POSIX) empêchant le swapping des clés et pads vers la partition d'échange.
   - Protection du processus via `prctl(PR_SET_DUMPABLE, 0)` et `setrlimit(RLIMIT_CORE, 0)` contre l'inspection mémoire et les core dumps.

2. **Primitives Cryptographiques en Assembleur x86_64 (`native/asm/ouija_crypto_x86_64.s`)** :
   - `ouija_otp_xor_asm` : Chiffrement One-Time Pad par XOR 64-bit en temps constant avec barrière mémoire `mfence`.
   - `ouija_ct_memcmp_asm` : Comparaison mémoire en temps constant pour prévenir toute attaque par canal auxiliaire (timing side-channel) lors de la validation des hashs SHA-256 et des signatures HMAC.
   - `ouija_secure_memzero_asm` : Nettoyage sécurisé de la mémoire avec barrières `mfence`, immunisé contre les optimisations de compilateur.

3. **Validation SHA-256 des Identifiants Éphémères** :
   - Commande CLI : `ouija new id`
   - Format : `OUIJA-<TOKEN_HEX_32>-<SHA256_CHECKSUM_16>`
   - Enregistrement immédiat dans la base temporaire en RAM avec TTL d'expiration.
   - Rejet strict (HTTP 401) si l'ID ne respecte pas le SHA-256 ou s'il n'est pas présent dans la RAM.

4. **Triple Couche de Chiffrement Imbriquée** :
   - **Couche 1 (Interne)** : **One-Time Pad (OTP)** généré via entropie CSPRNG Linux `getrandom(2)` et calculé en assembleur x86_64.
   - **Couche 2 (Protocolaire)** : **Stanza XMPP XML** au standard OMEMO (`urn:xmpp:ouija:omemo:v1`) avec enveloppe authentifiée ChaCha20-Poly1305 + signature HMAC-SHA256 et horodatage anti-rejeu.
   - **Couche 3 (Transport)** : **Réseau Tor** (Hidden Service v3 `.onion` + routage SOCKS5 via le contrôleur Python).

5. **Interface Navigateur (HTML Brutaliste sans JavaScript)** :
   - Accessible sur `http://127.0.0.1:8765`
   - En-têtes HTTP de sécurité stricts : `Content-Security-Policy: default-src 'self'; script-src 'none';`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.
   - Rafraîchissement automatique du salon de discussion via `<meta http-equiv="refresh" content="3">` (natif navigateur, zéro script).

---

## 📁 Structure du Projet

```
/run/media/xmv22/EVERDRIVE/Project/ouija/
├── Cargo.toml                     # Configuration Cargo & dépendances Rust
├── build.rs                       # Compilation du C & de l'Assembleur x86_64
├── Makefile                       # Commandes de build, test et exécution
├── install.sh                     # Script d'installation globale dans ~/.local/bin/ouija
├── src/
│   ├── main.rs                    # Point d'entrée, durcissement mémoire, orchestration
│   ├── cli.rs                     # Traitement des commandes CLI ("ouija new id", status, purge)
│   ├── server.rs                  # Serveur HTTP brut, rendu HTML brutaliste sans JS
│   ├── state.rs                   # Base de données éphémère en RAM avec auto-expiration
│   ├── ffi.rs                     # Liens FFI Rust vers C et Assembleur
│   ├── tor_client.rs              # Client de communication avec le sous-système Tor
│   └── crypto/
│       ├── mod.rs                 # Interface cryptographique unifiée
│       ├── sha256_validator.rs    # Validation cryptographique SHA-256 en temps constant
│       ├── otp_layer.rs           # Moteur One-Time Pad adossé à l'Assembleur
│       └── xmpp_layer.rs          # Formatage & chiffrement des stanzas XML XMPP
├── native/
│   ├── include/
│   │   ├── ouija_core.h           # En-tête C des fonctions de durcissement et ASM
│   │   └── ouija_cpp_sandbox.hpp  # Sandbox RAII C++ pour tampons verrouillés mlock
│   ├── src/
│   │   └── ouija_secure_mem.c     # Implémentation C : mlock, PR_SET_DUMPABLE, getrandom
│   └── asm/
│       └── ouija_crypto_x86_64.s  # Primitives en Assembleur x86_64 pur (OTP XOR, memzero, memcmp)
├── tor/
│   └── ouija_tor_manager.py       # Contrôleur Tor, Hidden Service v3 et proxy SOCKS5
└── tests/
    └── integration_test.sh        # Suite de tests d'intégration complète (100% passés)
```

---

## 🚀 Utilisation Rapide

### 1. Démarrer le démon Ouija
```bash
ouija start
```
*Le serveur s'ouvre sur `http://127.0.0.1:8765` et affiche l'adresse Onion Tor.*

### 2. Générer une nouvelle session éphémère (dans le terminal)
```bash
ouija new id
```
Sortie :
```text
================================================================
[OUIJA SECURITY] EPHEMERAL SESSION ID GENERATED & REGISTERED
================================================================
ID: OUIJA-01b65dfd29bcb5a85583ba6a20f9697d-3381d34e1bd8396f
SHA-256 Checksum: VALID (Verified via x86_64 Assembly)
Storage: Ephemeral RAM Database (TTL: 30 minutes)
Web Gateway: http://127.0.0.1:8765/login
================================================================
```

### 3. Connexion sur le Dashboard HTML
- Ouvrez votre navigateur sur : `http://127.0.0.1:8765`
- Collez votre ID éphémère.
- Le serveur vérifie le SHA-256 en assembleur et l'existence en RAM.

### 4. Router un pair et discuter
- Sur le Dashboard, entrez l'ID éphémère du pair et son adresse Onion (ex: `http://xxxx.onion` ou `http://127.0.0.1:8765`).
- Cliquez sur **[ OPEN CHAT ]**.
- Tapez votre message : il est automatiquement chiffré par **OTP (Assembleur) -> Stanza XMPP XML (ChaCha20-Poly1305) -> Tor v3 Onion**.

### 5. Purge Instantanée de la Mémoire
En ligne de commande ou depuis le bouton rouge du Dashboard :
```bash
ouija purge
```
*Toutes les clés, tampons OTP et historiques sont instantanément écrasés à zéro en mémoire vive via l'instruction assembleur `ouija_secure_memzero_asm`.*
