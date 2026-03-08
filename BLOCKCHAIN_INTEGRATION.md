# Blockchain Audit Integration - Quick Start

## What's New
The blockchain audit logging system has been successfully integrated into Crypt-Vault. Your encryption and decryption operations are now automatically recorded in a tamper-evident blockchain ledger.

## Files Added/Modified

### New Files:
- **blockchain_audit.h** - Complete blockchain module (self-contained header)
- All functionality from blockchain_audit.cpp is now available through the header

### Modified Files:
- **Crypt-Vault.cpp** - Integrated blockchain logging into main application

## Features

### Automatic Logging
Every encryption and decryption operation now automatically creates a block in the audit chain:
- Operation type (ENCRYPT/DECRYPT)
- Filename
- File hash (SHA-256)
- Timestamp
- File size
- Processing duration
- Algorithm used
- HMAC verification status

### New Menu Option (Option 10)
Access the blockchain audit menu to:
1. **View Full Audit Log** - Display all recorded blocks with details
2. **Validate Chain Integrity** - Check if the audit log has been tampered with
3. **Search by Filename** - Find all operations related to a specific file
4. **View Statistics** - Summary of operations (encryptions, decryptions, etc.)
5. **Export HTML Report** - Generate an HTML report (audit_report.html)

## How It Works

### Blockchain Properties:
- **Genesis Block**: First block created when blockchain initializes
- **Chain Linking**: Each new block contains the hash of the previous block
- **Proof of Work**: Mining with 2 leading-zero difficulty for integrity
- **Tamper Detection**: Any modification invalidates the chain forward
- **Persistence**: Saved to `crypt_audit.chain` file

### Files Created:
- **crypt_audit.chain** - Persistent blockchain ledger (created on first run)
- **audit_report.html** - Optional HTML export (generated on demand)

## Usage Example

```
1. Encrypt a file:
   - Select option 1 (Encrypt file)
   - Complete the encryption - it's automatically logged to blockchain
   - Block gets mined and added to the chain

2. View audit log:
   - Select option 10 (Audit)
   - Choose option 1 (View Full Audit Log)
   - See all recorded operations with hashes and timestamps

3. Verify integrity:
   - Select option 10 (Audit)
   - Choose option 2 (Validate Chain Integrity)
   - Get confirmation that no tampering has occurred
```

## Security Notes

✅ **Proof of Work**: Blocks are mined with a proof-of-work scheme, making tampering computationally expensive

✅ **SHA-256 Hashing**: Both file content and blockchain use SHA-256 for integrity

✅ **Timestamp Recording**: Each operation is timestamped for complete audit trail

✅ **Device ID**: Machine fingerprint is stored (currently simplified - can be enhanced)

## Verification

To verify the blockchain is working:
1. Encrypt or decrypt a file
2. Navigate to option 10 (Audit) → option 1 (View Full Audit Log)
3. You should see your operation recorded with a mined block hash
4. Run validation (option 2) to confirm chain integrity

## Notes

- Blockchain file (`crypt_audit.chain`) is human-readable and stored in the working directory
- Each operation adds a new block (mining takes ~50-200ms depending on difficulty setting)
- Export to HTML for presentation or archival purposes
- Chain grows indefinitely - consider periodic archival for very long-running systems

## Next Steps (Optional Enhancements)

- Implement RSA key exchange logging
- Add secure delete operation logging
- Connect to external blockchain for distributed audit trail
- Implement key rotation audit
- Add user authentication tracking
