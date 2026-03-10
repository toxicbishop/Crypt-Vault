# CryptVault — Secure File Sharing System with Encryption

A hybrid **C++ + x64 Assembly** encryption tool with a **blockchain-backed tamper-proof audit trail** and **P2P multi-user network**. Built from scratch with zero external dependencies.

> _"322 MB/s via AES-NI hardware acceleration. Blockchain audit log. Full CLI. No install."_

![CryptVault CLI](Assets/CRYPTVAULT.png?v=3)

---

## Why CryptVault?

|                        | VeraCrypt | GPG | 7-Zip | **CryptVault** |
| ---------------------- | --------- | --- | ----- | -------------- |
| AES-256 Encryption     | ✅        | ✅  | ✅    | ✅             |
| Hardware ASM (AES-NI)  | ❌        | ❌  | ❌    | ✅             |
| CPUID Auto-Detection   | ❌        | ❌  | ❌    | ✅             |
| Blockchain Audit Trail | ❌        | ❌  | ❌    | ✅             |
| HMAC Tamper Detection  | ❌        | ❌  | ❌    | ✅             |
| P2P Multi-User Network | ❌        | ❌  | ❌    | ✅             |
| Zero Dependencies      | ❌        | ❌  | ✅    | ✅             |
| Full CLI Scripting     | ❌        | ✅  | ✅    | ✅             |

---

## Team

| Name         | USN        | Role                                                                                    |
| ------------ | ---------- | --------------------------------------------------------------------------------------- |
| **Pranav**   | 1KG23CB038 | Cryptography Engineer — AES-256-CBC engine, PKCS7 padding, x64 ASM AES block operations |
| **Rohith R** | 1KG23CB044 | Project Lead & Architecture — System structure, class hierarchy, application flow       |
| **Syed**     | 1KG23CB052 | Security & Key Management — SHA-256, PBKDF2, HMAC, x64 ASM secure_memzero               |
| **Supreeth** | 1KG23CB051 | Utilities & Testing — Batch processing, file operations, SHA-256 hashing                |

---

## Features

### Encryption Engine

- **AES-256-CBC** — Industry-standard 256-bit symmetric encryption
- **x64 Assembly path** — Uses Intel AES-NI hardware instructions when available
- **CPUID auto-detection** — Automatically falls back to C++ on unsupported hardware
- **PBKDF2-SHA256** — 100,000 iterations with random salt (brute-force resistant)
- **HMAC-SHA256** — Encrypt-then-MAC pattern detects tampering before decryption
- **Random IV + Salt** — Every encryption produces unique ciphertext

### Security

- **Secure password input** — Masked input prevents shoulder surfing
- **Password confirmation** — Double-entry prevents typo disasters
- **Constant-time HMAC comparison** — Prevents timing attacks
- **Secure memory wipe** — Keys zeroed from memory after use (ASM)

### File Operations

- **File encryption/decryption** — Any file type: text, images, binaries
- **Text encryption** — Quick inline encrypt/decrypt with hex output
- **Batch processing** — Encrypt or decrypt multiple files at once
- **SHA-256 file hashing** — Verify file integrity

### Blockchain Audit Trail

- **Tamper-proof operation log** — Every encrypt/decrypt/delete recorded on-chain
- **SHA-256 hash chaining** — Modifying any block invalidates all subsequent blocks
- **Proof-of-work mining** — Makes retroactive tampering computationally expensive
- **Digital signatures** — Each block signed with the node's private key
- **HTML report export** — Generate audit reports for compliance (HIPAA, legal, finance)

### P2P Multi-User Network

- **Cross-platform** — Windows (winsock2) and Linux (POSIX sockets) from same codebase
- **Longest-chain consensus** — Same rule as Bitcoin: longest valid chain wins
- **Block gossip** — New blocks automatically broadcast to all connected peers
- **Auto chain sync** — New nodes sync the latest chain on connect
- **Peer discovery** — Simple `peers.txt` configuration

---

## Build

### Windows

```bash
g++ -std=c++17 -O2 -o crypt-vault.exe \
    Crypt-Vault.cpp blockchain_audit.cpp p2p_node.cpp -lws2_32
```

### Linux

```bash
g++ -std=c++17 -O2 -o crypt-vault \
    Crypt-Vault.cpp blockchain_audit.cpp p2p_node.cpp -lpthread
```

### Platform Support

| Platform | Status      | Notes                     |
| -------- | ----------- | ------------------------- |
| Windows  | ✅ Full     | Native winsock2           |
| Linux    | ✅ Full     | POSIX sockets + pthreads  |
| macOS    | ⚠️ Untested | Should work, not verified |

### Dependencies

- **Windows**: `ws2_32.lib` — ships with every Windows installation
- **Linux**: `pthread` — ships with every Linux distro
- No external libraries required

---

## Usage

```bash
./crypt-vault       # Linux
.\crypt-vault.exe   # Windows
```

### Menu

| #   | Feature                      |
| --- | ---------------------------- |
| 1   | 🔒 Encrypt a file            |
| 2   | 🔓 Decrypt a file            |
| 3   | 🔤 Encrypt text (quick)      |
| 4   | 🔤 Decrypt text (quick)      |
| 5   | 📂 Batch encrypt files       |
| 6   | 📂 Batch decrypt files       |
| 7   | 👁️ View file content         |
| 8   | 📈 File statistics           |
| 9   | #️⃣ SHA-256 file hash         |
| 10  | ⛓️ View blockchain audit log |
| 11  | 🔍 Validate chain integrity  |
| 12  | 📡 P2P network status        |
| 13  | 📚 About                     |
| 14  | 🚪 Exit                      |

---

## How Encryption Works

1. Enter a **password** (masked with `*`) and confirm it
2. A **random 16-byte salt** is generated
3. **PBKDF2-SHA256** derives a 64-byte key (100,000 iterations)
   - First 32 bytes → AES-256 encryption key
   - Last 32 bytes → HMAC authentication key
4. A **random 16-byte IV** is generated
5. Data is **PKCS7-padded** and encrypted with **AES-256-CBC**
6. **HMAC-SHA256** is computed over `salt + IV + ciphertext`
7. Output: `[salt][IV][ciphertext][HMAC]` saved as `.enc`

---

## How the Blockchain Works

Every operation (encrypt, decrypt, delete, key exchange) creates a new block:

```
Block #N
├── index
├── timestamp
├── operation       (ENCRYPT / DECRYPT / DELETE / KEY_EXCHANGE)
├── filename
├── file SHA-256 hash
├── HMAC verified?
├── signer public key
├── digital signature
├── previous block hash  ← links to Block #N-1
└── block hash           ← SHA-256 of all above
```

Changing any field in any block breaks all hashes after it — **tamper detected instantly**.

---

## P2P Multi-User Setup

### 1. Create `peers.txt` next to your binary

```
# peers.txt — one IP:PORT per line, # for comments
192.168.1.10:8333    # Team Member 1 (Windows)
192.168.1.11:8333    # Team Member 2 (Windows)
192.168.1.12:8333    # Team Member 3 (Linux)
192.168.1.13:8333    # Team Member 4 (Linux)
```

### 2. Run on each machine

```bash
.\crypt-vault.exe    # Each team member runs their own node
```

### 3. What happens automatically

- Each node gets a unique identity (`identity.key`) on first run
- Nodes connect to peers, sync the latest chain
- Every encryption operation is signed and broadcast to all peers
- All nodes independently validate each block
- Tamper one node's chain — the other three reject it

### Localhost Testing (same machine, two terminals)

```bash
# Terminal 1
./test_p2p node_a 8333

# Terminal 2
./test_p2p node_b 8334
```

---

## Security Notes

- **AES-256** has 2²⁵⁶ possible keys — computationally impossible to brute force
- **PBKDF2 (100k iterations)** makes password guessing extremely slow
- **HMAC verification** happens BEFORE decryption — tampered files rejected immediately
- **Constant-time comparison** prevents timing attacks on HMAC verification
- **CBC mode** ensures identical plaintext blocks produce different ciphertext
- **Random salt + IV** means the same file encrypted twice produces completely different output
- **Security depends on password strength** — use long, complex passphrases

---

## Domain

**Cybersecurity / Information Security** — Applied Cryptography & Secure Communication

---

## License

[GPL-3.0](LICENSE)
