# Crypt Vault — AES-256-CBC Encryption Tool

A powerful, self-contained file and text encryption tool built in C++ using **AES-256-CBC** — the same encryption standard used by governments and financial institutions worldwide.


![Crypt Vault CLI](Assets/CRYPTVAULT.png?v=3)

## Team Members and Roles

| Name | USN | Role |
|---|---|---|
| **Pranav** | 1KG23CB038 |  Cryptography Engineer — Implemented AES-256-CBC encryption/decryption engine, PKCS7 padding, and x64 assembly AES block operations (xor_block, CBC chaining) |
| **Rohith R** | 1KG23CB044 |  Project Lead & Core Architecture — Designed the overall system structure, class hierarchy, and application flow|
| **Syed** | 1KG23CB052 |  Security & Key Management — Implemented SHA-256 key derivation, random IV generation, password strength validation, and x64 assembly security primitives (secure_memzero, SHA-256 rounds) |
| **Supreeth** | 1KG23CB051 |  Utilities & Testing — Developed batch processing, file operations, SHA-256 hashing utility, and testing |

## Features

- **AES-256-CBC Encryption** — Industry-standard 256-bit symmetric encryption
- **PBKDF2-SHA256 Key Derivation** — 100,000 iterations with random salt (brute-force resistant)
- **HMAC-SHA256 Authentication** — Encrypt-then-MAC pattern detects tampering before decryption
- **Secure Password Input** — Masked input (asterisks) prevents shoulder surfing
- **Password Confirmation** — Double-entry on encryption prevents typo disasters
- **File Encryption/Decryption** — Encrypt any file type (text, images, binaries)
- **Text Encryption/Decryption** — Quick inline text encrypt/decrypt (hex output)
- **Batch Processing** — Encrypt or decrypt multiple files at once
- **SHA-256 File Hashing** — Verify file integrity
- **Password Strength Indicator** — Real-time feedback on password quality
- **Random IV** — Every encryption produces unique ciphertext
## Platform Support
| Platform | Status        | Notes                    |
|----------|---------------|--------------------------|
| Windows  | ✅ Full       | Native winsock2          |
| Linux    | ✅ Full       | POSIX sockets + pthreads |
| macOS    | ⚠️ Untested   | Should work, not tested  |

## Dependencies
- Windows: ws2_32.lib (ships with every Windows install)
- Linux: pthread (ships with every Linux distro)
- No external libraries required

---

## 5-Day Sprint Plan
```text
Day 1 → network_layer.h  (platform abstraction)
        identity.h        (cross-platform node ID)

Day 2 → p2p_node.h/cpp   (server + client sockets)
        peers.txt loader

Day 3 → Message protocol  (serialize/deserialize blocks)
        broadcast on encrypt/decrypt

Day 4 → Consensus         (longest chain rule)
        chain sync on connect

Day 5 → Test with 2 nodes on localhost
        Then test Windows ↔ Linux across LAN
```

## To Build The EXE File

```bash
# Windows
g++ -std=c++17 -O2 -o crypt-vault.exe Crypt-Vault.cpp blockchain_audit.cpp p2p_node.cpp -lws2_32

# Linux/macOS
g++ -std=c++17 -O2 -o crypt-vault Crypt-Vault.cpp blockchain_audit.cpp p2p_node.cpp -lpthread
```

## Usage

```bash
./crypt-vault      # Linux/Mac
.\crypt-vault.exe  # Windows
```

This launches an interactive menu:

| # | Feature |
|---|---------|
| 1 | 🔒 Encrypt a file |
| 2 | 🔓 Decrypt a file |
| 3 | 🔤 Encrypt text (quick) |
| 4 | 🔤 Decrypt text (quick) |
| 5 | 📂 Batch encrypt files |
| 6 | 📂 Batch decrypt files |
| 7 | 👁️ View file content |
| 8 | 📈 File statistics |
| 9 | #️⃣ SHA-256 file hash |
| 10 | 📚 About |
| 11 | 🚪 Exit |

## How It Works

1. You enter a **password** (masked with `*`) and confirm it
2. A **random 16-byte salt** is generated
3. **PBKDF2-SHA256** derives a 64-byte key (100,000 iterations)
   - First 32 bytes → AES-256 encryption key
   - Last 32 bytes → HMAC authentication key
4. A **random 16-byte IV** is generated
5. Data is **PKCS7-padded** and encrypted with **AES-256-CBC**
6. **HMAC-SHA256** is computed over `salt + IV + ciphertext`
7. Output = `[salt][IV][ciphertext][HMAC]` saved as `.enc`

## Security Notes

- **AES-256** has 2²⁵⁶ possible keys — computationally impossible to brute force
- **PBKDF2 (100k iterations)** makes password guessing extremely slow
- **HMAC verification** happens BEFORE decryption — tampered files are rejected immediately
- **Constant-time comparison** prevents timing attacks on HMAC verification
- **CBC mode** chains blocks so identical plaintext blocks produce different ciphertext
- **Random salt + IV** ensures the same file encrypted twice produces completely different output
- **Your security depends on password strength** — use long, complex passphrases!

## GPL-3.0 License

[LICENSE](LICENSE)