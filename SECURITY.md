# Security Policy

## Supported Versions

Currently, only the latest release of **Crypt-Vault** receives security updates. We strongly recommend always running the latest version from the main branch or the latest official release.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

Security is a core priority for Crypt-Vault. If you discover a security vulnerability within this project, please DO NOT report it by publicly creating a GitHub issue.

Instead, please send an email to the project maintainer(s). 

* **Maintainer Email:** [Insert Email Address Here]

Please include the following information in your report:
* A description of the vulnerability and its impact.
* Steps to reproduce the vulnerability (a proof of concept is highly appreciated).
* Any potential mitigation or remediation steps you recommend.

You should receive a response acknowledging receipt of your report within 48 hours. We ask for a reasonable grace period to investigate and patch the vulnerability before public disclosure.

## Security Model

Crypt-Vault is designed as a local, command-line tool to encrypt and decrypt files and text using AES-256-CBC and password-based key derivation (PBKDF2/SHA-256).

### What Crypt-Vault Protects Against:
* **Data at Rest:** Crypt-Vault protects your files and text from unauthorized access by agents who do not possess the correct password or keyfile.
* **Brute-Force Resistance:** By utilizing strong key derivation, the tool adds practical resistance against offline password guessing.

### Out of Scope (What Crypt-Vault Does NOT Protect Against):
* **Compromised Operating Systems:** If the host system running Crypt-Vault is infected with malware, keyloggers, or memory dumpers, your plaintext passwords and decrypted data may be captured.
* **Shoulder Surfing:** Physical access or observation of your screen while entering passwords.
* **Availability Attacks:** Crypt-Vault does not protect against an attacker deleting or corrupting the encrypted files (it provides confidentiality, but you are responsible for backups).
* **Network Interception:** If you transfer an unencrypted file over an insecure network before encrypting it with Crypt-Vault, the data may be compromised. Always encrypt data before transmitting it over untrusted mediums.
