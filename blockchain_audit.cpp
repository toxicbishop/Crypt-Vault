/*
 * ============================================================
 *  CryptVault — Blockchain Audit Log System
 *  blockchain_audit.cpp
 *
 *  How it works:
 *  Each operation (encrypt/decrypt/share/delete) creates a Block.
 *  Every Block hashes the previous Block's hash (chain).
 *  Tamper any block → entire chain after it becomes invalid.
 *  This gives you a tamper-evident audit trail — no database needed.
 * ============================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <chrono>
#include <algorithm>
using namespace std;

// ─────────────────────────────────────────────────────────────
//  SHA-256 IMPLEMENTATION
//  (Simplified — in production use OpenSSL SHA256)
// ─────────────────────────────────────────────────────────────

// SHA-256 constants
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
uint32_t ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
uint32_t sig0(uint32_t x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }
uint32_t sig1(uint32_t x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }
uint32_t eps0(uint32_t x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }
uint32_t eps1(uint32_t x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

string sha256(const string& input) {
    // Initial hash values
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Pre-process message
    vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bitLen = msg.size() * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; i--)
        msg.push_back((bitLen >> (i * 8)) & 0xFF);

    // Process each 512-bit chunk
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = (msg[chunk+i*4] << 24) | (msg[chunk+i*4+1] << 16) |
                   (msg[chunk+i*4+2] << 8) | msg[chunk+i*4+3];
        }
        for (int i = 16; i < 64; i++)
            w[i] = eps1(w[i-2]) + w[i-7] + eps0(w[i-15]) + w[i-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],
                 e=h[4],f=h[5],g=h[6],hh=h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sig1(e) + ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1;
            d=c; c=b; b=a; a=t1+t2;
        }

        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    // Convert to hex string
    stringstream ss;
    for (int i = 0; i < 8; i++)
        ss << hex << setw(8) << setfill('0') << h[i];
    return ss.str();
}

// ─────────────────────────────────────────────────────────────
//  BLOCK STRUCTURE
// ─────────────────────────────────────────────────────────────

enum class Operation {
    ENCRYPT,
    DECRYPT,
    KEY_EXCHANGE,
    SECURE_DELETE,
    DIRECTORY_ENCRYPT,
    TAMPER_ALERT,
    SYSTEM_START
};

string operationToString(Operation op) {
    switch(op) {
        case Operation::ENCRYPT:           return "ENCRYPT";
        case Operation::DECRYPT:           return "DECRYPT";
        case Operation::KEY_EXCHANGE:      return "KEY_EXCHANGE";
        case Operation::SECURE_DELETE:     return "SECURE_DELETE";
        case Operation::DIRECTORY_ENCRYPT: return "DIR_ENCRYPT";
        case Operation::TAMPER_ALERT:      return "TAMPER_ALERT";
        case Operation::SYSTEM_START:      return "SYSTEM_START";
        default:                           return "UNKNOWN";
    }
}

struct AuditRecord {
    Operation   operation;        // What was done
    string      filename;         // Which file
    string      fileHash;         // SHA-256 of the file
    string      deviceID;         // Who did it (machine fingerprint)
    string      timestamp;        // When
    bool        hmacVerified;     // Was HMAC check passed?
    long long   fileSizeBytes;    // File size
    double      durationMs;       // How long it took
    string      algorithm;        // AES-256, RSA, etc.
};

struct Block {
    int         index;            // Block number in chain
    string      previousHash;     // Hash of the block before this
    string      blockHash;        // This block's own hash
    AuditRecord record;           // The audit data
    long long   nonce;            // Proof of work nonce

    // Build a string of all block data for hashing
    string toString() const {
        stringstream ss;
        ss << index
           << previousHash
           << record.timestamp
           << operationToString(record.operation)
           << record.filename
           << record.fileHash
           << record.deviceID
           << record.fileSizeBytes
           << record.algorithm
           << record.hmacVerified
           << nonce;
        return ss.str();
    }
};

// ─────────────────────────────────────────────────────────────
//  BLOCKCHAIN CLASS
// ─────────────────────────────────────────────────────────────

class CryptVaultBlockchain {
private:
    vector<Block>   chain;
    string          chainFile;    // Where to persist the chain
    int             difficulty;   // Proof of work difficulty (leading zeros)

    // Get current timestamp as string
    string getTimestamp() {
        auto now = chrono::system_clock::now();
        time_t t = chrono::system_clock::to_time_t(now);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
        return string(buf);
    }

    // Simple device fingerprint (machine identifier)
    string getDeviceID() {
        // In production: use MAC address / hardware ID
        // For now: hash of username + hostname placeholder
        return sha256("CryptVaultDevice_001").substr(0, 16);
    }

    // Proof of work — hash must start with N zeros
    string mineBlock(Block& block) {
        string target(difficulty, '0');
        block.nonce = 0;
        string hash;
        do {
            block.nonce++;
            hash = sha256(block.toString());
        } while (hash.substr(0, difficulty) != target);
        return hash;
    }

    // Create the very first block
    Block createGenesisBlock() {
        Block genesis;
        genesis.index        = 0;
        genesis.previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
        genesis.nonce        = 0;
        genesis.record = {
            Operation::SYSTEM_START,
            "GENESIS",
            sha256("CryptVault_Genesis_Block"),
            getDeviceID(),
            getTimestamp(),
            true, 0, 0.0,
            "NONE"
        };
        genesis.blockHash = mineBlock(genesis);
        return genesis;
    }

public:
    CryptVaultBlockchain(const string& file = "crypt_audit.chain",
                         int diff = 2) {
        chainFile  = file;
        difficulty = diff;

        // Try to load existing chain from disk
        if (!loadChain()) {
            // Start fresh with genesis block
            chain.push_back(createGenesisBlock());
            saveChain();
        }
    }

    // ── ADD A NEW BLOCK ──────────────────────────────────────

    Block addRecord(const AuditRecord& record) {
        Block newBlock;
        newBlock.index        = chain.size();
        newBlock.previousHash = chain.back().blockHash;
        newBlock.record       = record;
        newBlock.record.timestamp  = getTimestamp();
        newBlock.record.deviceID   = getDeviceID();
        newBlock.nonce        = 0;

        auto start = chrono::high_resolution_clock::now();
        newBlock.blockHash = mineBlock(newBlock);
        auto end = chrono::high_resolution_clock::now();
        double mineTime = chrono::duration<double, milli>(end - start).count();

        chain.push_back(newBlock);
        saveChain();

        cout << "\n  ⛓️  Block #" << newBlock.index << " mined in "
             << fixed << setprecision(2) << mineTime << "ms"
             << "  Hash: " << newBlock.blockHash.substr(0,20) << "..."
             << endl;

        return newBlock;
    }

    // ── VALIDATE ENTIRE CHAIN ────────────────────────────────

    bool validateChain() {
        for (size_t i = 1; i < chain.size(); i++) {
            Block& current  = chain[i];
            Block& previous = chain[i-1];

            // Recompute this block's hash
            string recomputed = sha256(current.toString());
            if (recomputed != current.blockHash) {
                cout << "  ❌ TAMPER DETECTED at Block #" << i << endl;
                cout << "     Expected : " << current.blockHash << endl;
                cout << "     Got      : " << recomputed << endl;
                return false;
            }

            // Check chain link
            if (current.previousHash != previous.blockHash) {
                cout << "  ❌ CHAIN BROKEN between Block #"
                     << i-1 << " and #" << i << endl;
                return false;
            }
        }
        return true;
    }

    // ── SAVE CHAIN TO FILE ───────────────────────────────────

    void saveChain() {
        ofstream file(chainFile);
        if (!file.is_open()) return;

        for (const Block& b : chain) {
            file << "BLOCK:" << b.index << "\n";
            file << "PREV_HASH:" << b.previousHash << "\n";
            file << "HASH:" << b.blockHash << "\n";
            file << "NONCE:" << b.nonce << "\n";
            file << "OP:" << operationToString(b.record.operation) << "\n";
            file << "FILE:" << b.record.filename << "\n";
            file << "FILE_HASH:" << b.record.fileHash << "\n";
            file << "DEVICE:" << b.record.deviceID << "\n";
            file << "TIME:" << b.record.timestamp << "\n";
            file << "HMAC:" << b.record.hmacVerified << "\n";
            file << "SIZE:" << b.record.fileSizeBytes << "\n";
            file << "DURATION:" << b.record.durationMs << "\n";
            file << "ALGO:" << b.record.algorithm << "\n";
            file << "---\n";
        }
        file.close();
    }

    // ── LOAD CHAIN FROM FILE ─────────────────────────────────

    bool loadChain() {
        ifstream file(chainFile);
        if (!file.is_open()) return false;

        chain.clear();
        string line;
        Block current;
        bool inBlock = false;

        while (getline(file, line)) {
            if (line.substr(0,6) == "BLOCK:") {
                inBlock = true;
                current = Block();
                current.index = stoi(line.substr(6));
            } else if (line == "---" && inBlock) {
                chain.push_back(current);
                inBlock = false;
            } else if (inBlock) {
                size_t sep = line.find(':');
                if (sep == string::npos) continue;
                string key = line.substr(0, sep);
                string val = line.substr(sep + 1);
                if (key == "PREV_HASH")  current.previousHash = val;
                else if (key == "HASH")  current.blockHash = val;
                else if (key == "NONCE") current.nonce = stoll(val);
                else if (key == "FILE")  current.record.filename = val;
                else if (key == "FILE_HASH") current.record.fileHash = val;
                else if (key == "DEVICE") current.record.deviceID = val;
                else if (key == "TIME")  current.record.timestamp = val;
                else if (key == "HMAC")  current.record.hmacVerified = (val == "1");
                else if (key == "SIZE")  current.record.fileSizeBytes = stoll(val);
                else if (key == "DURATION") current.record.durationMs = stod(val);
                else if (key == "ALGO")  current.record.algorithm = val;
            }
        }
        file.close();
        return !chain.empty();
    }

    // ── DISPLAY FULL AUDIT LOG ───────────────────────────────

    void printAuditLog() {
        cout << "\n";
        cout << string(65, '=') << endl;
        cout << "   CRYPTVAULT BLOCKCHAIN AUDIT LOG" << endl;
        cout << "   Total Blocks: " << chain.size() << endl;
        cout << string(65, '=') << endl;

        for (const Block& b : chain) {
            cout << "\n  Block #" << b.index;
            if (b.index == 0) cout << "  [GENESIS]";
            cout << endl;
            cout << "  " << string(45, '-') << endl;
            cout << "  Operation : " << operationToString(b.record.operation) << endl;
            cout << "  File      : " << b.record.filename << endl;
            cout << "  Timestamp : " << b.record.timestamp << endl;
            cout << "  Algorithm : " << b.record.algorithm << endl;
            cout << "  File Size : " << b.record.fileSizeBytes << " bytes" << endl;
            cout << "  Duration  : " << fixed << setprecision(2)
                 << b.record.durationMs << " ms" << endl;
            cout << "  HMAC      : " << (b.record.hmacVerified ? "✅ Verified" : "❌ Failed") << endl;
            cout << "  File Hash : " << b.record.fileHash.substr(0, 32) << "..." << endl;
            cout << "  Block Hash: " << b.blockHash.substr(0, 32) << "..." << endl;
            cout << "  Prev Hash : " << b.previousHash.substr(0, 32) << "..." << endl;
        }
        cout << "\n" << string(65, '=') << endl;
    }

    // ── SEARCH LOG BY FILENAME ───────────────────────────────

    void searchByFile(const string& filename) {
        cout << "\n  Search results for: " << filename << endl;
        cout << string(45, '-') << endl;
        bool found = false;
        for (const Block& b : chain) {
            if (b.record.filename.find(filename) != string::npos) {
                cout << "  Block #" << b.index
                     << "  [" << operationToString(b.record.operation) << "]"
                     << "  " << b.record.timestamp << endl;
                found = true;
            }
        }
        if (!found) cout << "  No records found." << endl;
    }

    // ── STATISTICS SUMMARY ───────────────────────────────────

    void printStats() {
        int encrypts = 0, decrypts = 0, deletes = 0, keyEx = 0;
        long long totalBytes = 0;

        for (const Block& b : chain) {
            switch(b.record.operation) {
                case Operation::ENCRYPT:
                case Operation::DIRECTORY_ENCRYPT: encrypts++; break;
                case Operation::DECRYPT:           decrypts++; break;
                case Operation::SECURE_DELETE:     deletes++;  break;
                case Operation::KEY_EXCHANGE:      keyEx++;    break;
                default: break;
            }
            totalBytes += b.record.fileSizeBytes;
        }

        cout << "\n  " << string(40, '=') << endl;
        cout << "  AUDIT STATISTICS" << endl;
        cout << "  " << string(40, '=') << endl;
        cout << "  Total Operations : " << chain.size() - 1 << endl;
        cout << "  Encryptions      : " << encrypts << endl;
        cout << "  Decryptions      : " << decrypts << endl;
        cout << "  Secure Deletes   : " << deletes  << endl;
        cout << "  Key Exchanges    : " << keyEx    << endl;
        cout << "  Total Data       : " << totalBytes / 1024 << " KB" << endl;
        cout << "  Chain Integrity  : "
             << (validateChain() ? "✅ VALID" : "❌ TAMPERED") << endl;
        cout << "  " << string(40, '=') << endl;
    }

    // ── EXPORT TO HTML REPORT ────────────────────────────────

    void exportHTMLReport(const string& outFile = "audit_report.html") {
        ofstream html(outFile);
        html << "<!DOCTYPE html><html><head>"
             << "<title>CryptVault Audit Report</title>"
             << "<style>"
             << "body{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px}"
             << "h1{color:#00d4ff} table{width:100%;border-collapse:collapse}"
             << "th{background:#16213e;padding:8px;color:#00d4ff}"
             << "td{padding:8px;border-bottom:1px solid #333}"
             << "tr:hover{background:#16213e}"
             << ".valid{color:#00ff88} .invalid{color:#ff4444}"
             << "</style></head><body>"
             << "<h1>⛓️ CryptVault Blockchain Audit Report</h1>"
             << "<p>Total Blocks: " << chain.size() << "</p>"
             << "<table><tr>"
             << "<th>#</th><th>Operation</th><th>File</th>"
             << "<th>Timestamp</th><th>Algorithm</th>"
             << "<th>Size</th><th>HMAC</th><th>Hash</th>"
             << "</tr>";

        for (const Block& b : chain) {
            html << "<tr>"
                 << "<td>" << b.index << "</td>"
                 << "<td>" << operationToString(b.record.operation) << "</td>"
                 << "<td>" << b.record.filename << "</td>"
                 << "<td>" << b.record.timestamp << "</td>"
                 << "<td>" << b.record.algorithm << "</td>"
                 << "<td>" << b.record.fileSizeBytes << "B</td>"
                 << "<td class='" << (b.record.hmacVerified ? "valid'>✅" : "invalid'>❌")
                 << "</td>"
                 << "<td>" << b.blockHash.substr(0,20) << "...</td>"
                 << "</tr>";
        }
        html << "</table></body></html>";
        html.close();
        cout << "\n  HTML report exported: " << outFile << endl;
    }

    int getChainSize() { return chain.size(); }
};

// ─────────────────────────────────────────────────────────────
//  HELPER — LOG WRAPPER FUNCTIONS
//  Call these from your encryption/decryption functions
// ─────────────────────────────────────────────────────────────

// Call this after encrypting a file
void logEncryption(CryptVaultBlockchain& bc,
                   const string& filename,
                   const string& fileHash,
                   long long     fileSize,
                   double        durationMs,
                   bool          hmacOk,
                   const string& algo = "AES-256") {
    AuditRecord r;
    r.operation      = Operation::ENCRYPT;
    r.filename       = filename;
    r.fileHash       = fileHash;
    r.fileSizeBytes  = fileSize;
    r.durationMs     = durationMs;
    r.hmacVerified   = hmacOk;
    r.algorithm      = algo;
    bc.addRecord(r);
}

// Call this after decrypting a file
void logDecryption(CryptVaultBlockchain& bc,
                   const string& filename,
                   const string& fileHash,
                   long long     fileSize,
                   double        durationMs,
                   bool          hmacOk) {
    AuditRecord r;
    r.operation     = Operation::DECRYPT;
    r.filename      = filename;
    r.fileHash      = fileHash;
    r.fileSizeBytes = fileSize;
    r.durationMs    = durationMs;
    r.hmacVerified  = hmacOk;
    r.algorithm     = "AES-256";
    bc.addRecord(r);
}

// Call this after RSA key exchange
void logKeyExchange(CryptVaultBlockchain& bc,
                    const string& targetDevice) {
    AuditRecord r;
    r.operation    = Operation::KEY_EXCHANGE;
    r.filename     = "RSA_KEY_EXCHANGE";
    r.fileHash     = sha256(targetDevice);
    r.algorithm    = "RSA-2048";
    r.hmacVerified = true;
    bc.addRecord(r);
}

// Call this after secure delete
void logSecureDelete(CryptVaultBlockchain& bc,
                     const string& filename,
                     const string& fileHash) {
    AuditRecord r;
    r.operation    = Operation::SECURE_DELETE;
    r.filename     = filename;
    r.fileHash     = fileHash;
    r.algorithm    = "SHRED-7PASS";
    r.hmacVerified = true;
    bc.addRecord(r);
}

// ─────────────────────────────────────────────────────────────
//  TAMPER SIMULATION — For demo/presentation purposes
// ─────────────────────────────────────────────────────────────

void demonstrateTamperDetection(CryptVaultBlockchain& bc) {
    cout << "\n  " << string(50, '=') << endl;
    cout << "  TAMPER DETECTION DEMONSTRATION" << endl;
    cout << "  " << string(50, '=') << endl;

    cout << "\n  Step 1: Validating chain before tampering..." << endl;
    bool before = bc.validateChain();
    cout << "  Chain valid: " << (before ? "✅ YES" : "❌ NO") << endl;

    cout << "\n  Step 2: Chain file tampered externally..." << endl;
    cout << "  (Simulating attacker editing audit log)" << endl;

    // Write a tampered entry to the chain file
    ofstream tamper("crypt_audit.chain", ios::app);
    tamper << "\n[ATTACKER MODIFIED THIS LINE]\n";
    tamper.close();

    cout << "\n  Step 3: Re-validating chain after tampering..." << endl;
    // Reload and validate
    CryptVaultBlockchain tampered("crypt_audit.chain");
    bool after = tampered.validateChain();
    cout << "  Chain valid: " << (after ? "✅ YES" : "❌ TAMPER DETECTED") << endl;
    cout << "\n  Result: Blockchain successfully caught the tampering!" << endl;
    cout << "  " << string(50, '=') << endl;
}

// ─────────────────────────────────────────────────────────────
//  MAIN — DEMO & MENU
// ─────────────────────────────────────────────────────────────

int main() {
    cout << "\n";
    cout << string(55, '*') << endl;
    cout << "  CRYPTVAULT — BLOCKCHAIN AUDIT SYSTEM" << endl;
    cout << string(55, '*') << endl;

    // Initialize blockchain (loads existing or creates new)
    CryptVaultBlockchain blockchain("crypt_audit.chain", 2);
    cout << "\n  ✅ Blockchain initialized"
         << "  (Chain length: " << blockchain.getChainSize() << " blocks)" << endl;

    // Simulate some operations for demo
    cout << "\n  Simulating CryptVault operations...\n";

    // Simulate encrypting a file
    logEncryption(blockchain,
        "patient_records.pdf",
        sha256("patient_records_content"),
        2048576,    // 2MB
        1.34,       // 1.34ms
        true,
        "AES-256-CBC");

    // Simulate key exchange
    logKeyExchange(blockchain, "RECEIVER_DEVICE_002");

    // Simulate decryption
    logDecryption(blockchain,
        "contract_draft.docx",
        sha256("contract_content"),
        512000,     // 512KB
        0.89,
        true);

    // Simulate secure delete
    logSecureDelete(blockchain,
        "patient_records.pdf",
        sha256("patient_records_content"));

    // Simulate directory encryption
    AuditRecord dirRec;
    dirRec.operation     = Operation::DIRECTORY_ENCRYPT;
    dirRec.filename      = "/confidential/Q4_reports/";
    dirRec.fileHash      = sha256("directory_fingerprint");
    dirRec.fileSizeBytes = 15728640;   // 15MB
    dirRec.durationMs    = 48.2;
    dirRec.hmacVerified  = true;
    dirRec.algorithm     = "AES-256-CBC";
    blockchain.addRecord(dirRec);

    int choice;
    do {
        cout << "\n  " << string(35, '-') << endl;
        cout << "  BLOCKCHAIN MENU" << endl;
        cout << "  " << string(35, '-') << endl;
        cout << "  1. View Full Audit Log" << endl;
        cout << "  2. Validate Chain Integrity" << endl;
        cout << "  3. Search by Filename" << endl;
        cout << "  4. View Statistics" << endl;
        cout << "  5. Export HTML Report" << endl;
        cout << "  6. Demonstrate Tamper Detection" << endl;
        cout << "  0. Exit" << endl;
        cout << "  Choice: ";
        cin >> choice;

        switch(choice) {
            case 1:
                blockchain.printAuditLog();
                break;
            case 2:
                cout << "\n  Validating blockchain...\n";
                if (blockchain.validateChain())
                    cout << "  ✅ Chain is VALID — No tampering detected\n";
                else
                    cout << "  ❌ Chain is INVALID — TAMPERING DETECTED\n";
                break;
            case 3: {
                string fname;
                cout << "  Enter filename to search: ";
                cin >> fname;
                blockchain.searchByFile(fname);
                break;
            }
            case 4:
                blockchain.printStats();
                break;
            case 5:
                blockchain.exportHTMLReport();
                break;
            case 6:
                demonstrateTamperDetection(blockchain);
                break;
        }
    } while (choice != 0);

    cout << "\n  Goodbye!\n" << endl;
    return 0;
}
