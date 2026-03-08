/*
 * ============================================================
 *  CryptVault — Blockchain Audit Log System (Header)
 *  blockchain_audit.h
 *
 *  Provides tamper-evident audit logging using blockchain:
 *  - Each operation creates a Block with previous block's hash
 *  - Proof-of-work mining for integrity assurance
 *  - Tamper detection when chain is loaded/validated
 *  - Persistence to disk and HTML export capabilities
 * ============================================================
 */

#ifndef BLOCKCHAIN_AUDIT_H
#define BLOCKCHAIN_AUDIT_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <chrono>

using namespace std;

// ─────────────────────────────────────────────────────────────
//  SHA-256 UTILITIES
// ─────────────────────────────────────────────────────────────

namespace SHA256 {
    string hash(const string& input);
}

// ─────────────────────────────────────────────────────────────
//  ENUMS & STRUCTURES
// ─────────────────────────────────────────────────────────────

enum class AuditOperation {
    ENCRYPT,
    DECRYPT,
    KEY_EXCHANGE,
    SECURE_DELETE,
    DIRECTORY_ENCRYPT,
    TAMPER_ALERT,
    SYSTEM_START
};

string operationToString(AuditOperation op);

struct AuditRecord {
    AuditOperation  operation;
    string          filename;
    string          fileHash;
    string          deviceID;
    string          timestamp;
    bool            hmacVerified;
    long long       fileSizeBytes;
    double          durationMs;
    string          algorithm;
};

struct Block {
    int             index;
    string          previousHash;
    string          blockHash;
    AuditRecord     record;
    long long       nonce;

    string toString() const;
};

// ─────────────────────────────────────────────────────────────
//  BLOCKCHAIN CLASS
// ─────────────────────────────────────────────────────────────

class CryptVaultBlockchain {
private:
    vector<Block>   chain;
    string          chainFile;
    int             difficulty;

    string getTimestamp();
    string getDeviceID();
    string mineBlock(Block& block);
    Block createGenesisBlock();

public:
    CryptVaultBlockchain(const string& file = "crypt_audit.chain", int diff = 2);
    Block addRecord(const AuditRecord& record);
    bool validateChain();
    void saveChain();
    bool loadChain();
    void printAuditLog();
    void searchByFile(const string& filename);
    void printStats();
    void exportHTMLReport(const string& outFile = "audit_report.html");
    int getChainSize() const;
};

// ─────────────────────────────────────────────────────────────
//  LOGGING HELPERS
// ─────────────────────────────────────────────────────────────

void logEncryption(CryptVaultBlockchain& bc,
                   const string& filename,
                   const string& fileHash,
                   long long fileSize,
                   double durationMs,
                   bool hmacOk,
                   const string& algo = "AES-256");

void logDecryption(CryptVaultBlockchain& bc,
                   const string& filename,
                   const string& fileHash,
                   long long fileSize,
                   double durationMs,
                   bool hmacOk);

void logKeyExchange(CryptVaultBlockchain& bc,
                    const string& targetDevice);

void logSecureDelete(CryptVaultBlockchain& bc,
                     const string& filename,
                     const string& fileHash);

#endif // BLOCKCHAIN_AUDIT_H
