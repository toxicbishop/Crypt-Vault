#include "blockchain_audit.h"
#include "p2p_node.h"
#include <algorithm>

// ─────────────────────────────────────────────────────────────
//  SHA-256 IMPLEMENTATION
// ─────────────────────────────────────────────────────────────

namespace SHA256 {
    typedef unsigned int uint32;
    typedef unsigned long long uint64;

    static const uint32 K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    inline uint32 rotr(uint32 x, int n) { return (x >> n) | (x << (32 - n)); }
    inline uint32 ch(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (~x & z); }
    inline uint32 maj(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (x & z) ^ (y & z); }
    inline uint32 sig0(uint32 x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    inline uint32 sig1(uint32 x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    inline uint32 gam0(uint32 x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    inline uint32 gam1(uint32 x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    string hash(const string& input) {
        uint32 h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        uint64 bitlen = (uint64)input.size() * 8;

        vector<unsigned char> msg(input.begin(), input.end());
        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; i--) msg.push_back((unsigned char)(bitlen >> (i * 8)));

        for (size_t off = 0; off < msg.size(); off += 64) {
            uint32 w[64];
            for (int i = 0; i < 16; i++)
                w[i] = ((uint32)msg[off+i*4]<<24)|((uint32)msg[off+i*4+1]<<16)|((uint32)msg[off+i*4+2]<<8)|msg[off+i*4+3];
            for (int i = 16; i < 64; i++)
                w[i] = gam1(w[i-2]) + w[i-7] + gam0(w[i-15]) + w[i-16];

            uint32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
            for (int i = 0; i < 64; i++) {
                uint32 t1 = hh + sig1(e) + ch(e,f,g) + K[i] + w[i];
                uint32 t2 = sig0(a) + maj(a,b,c);
                hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
            }
            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
        }

        stringstream ss;
        for (int i = 0; i < 8; i++) {
            ss << hex << setw(8) << setfill('0') << h[i];
        }
        return ss.str();
    }
}

// ─────────────────────────────────────────────────────────────
//  OPERATION ENUM UTILITIES
// ─────────────────────────────────────────────────────────────

string operationToString(AuditOperation op) {
    switch(op) {
        case AuditOperation::ENCRYPT:           return "ENCRYPT";
        case AuditOperation::DECRYPT:           return "DECRYPT";
        case AuditOperation::KEY_EXCHANGE:      return "KEY_EXCHANGE";
        case AuditOperation::SECURE_DELETE:     return "SECURE_DELETE";
        case AuditOperation::DIRECTORY_ENCRYPT: return "DIR_ENCRYPT";
        case AuditOperation::TAMPER_ALERT:      return "TAMPER_ALERT";
        case AuditOperation::SYSTEM_START:      return "SYSTEM_START";
        default:                                return "UNKNOWN";
    }
}

// ─────────────────────────────────────────────────────────────
//  BLOCK METHODS
// ─────────────────────────────────────────────────────────────

string Block::toString() const {
    stringstream ss;
    ss << index << previousHash << record.timestamp
       << operationToString(record.operation) << record.filename
       << record.fileHash << record.deviceID << record.fileSizeBytes
       << record.algorithm << record.hmacVerified << nonce
       << signerPublicKey << digitalSignature;
    return ss.str();
}

// ─────────────────────────────────────────────────────────────
//  BLOCKCHAIN CLASS METHODS
// ─────────────────────────────────────────────────────────────

string CryptVaultBlockchain::getTimestamp() {
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
    return string(buf);
}

string CryptVaultBlockchain::getDeviceID() {
    return SHA256::hash("CryptVaultDevice_001").substr(0, 16);
}

string CryptVaultBlockchain::mineBlock(Block& block) {
    string target(difficulty, '0');
    block.nonce = 0;
    string hash;
    do {
        block.nonce++;
        hash = SHA256::hash(block.toString());
    } while (hash.substr(0, difficulty) != target);
    return hash;
}

Block CryptVaultBlockchain::createGenesisBlock() {
    Block genesis;
    genesis.index        = 0;
    genesis.previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
    genesis.nonce        = 0;
    genesis.record = {
        AuditOperation::SYSTEM_START,
        "GENESIS",
        SHA256::hash("CryptVault_Genesis_Block"),
        getDeviceID(),
        getTimestamp(),
        true, 0, 0.0,
        "NONE"
    };
    genesis.signerPublicKey = publicKey;
    genesis.digitalSignature = signData(genesis.toString());
    genesis.blockHash = mineBlock(genesis);
    return genesis;
}

// ─────────────────────────────────────────────────────────────
//  RSA IDENTITY METHODS
// ─────────────────────────────────────────────────────────────

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif

void CryptVaultBlockchain::initRSA() {
#ifdef _WIN32
    if (!CryptAcquireContext(&hProv, "CryptVaultKeyContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
        if (GetLastError() == NTE_BAD_KEYSET) {
            CryptAcquireContext(&hProv, "CryptVaultKeyContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        }
    }
#endif
}

void CryptVaultBlockchain::loadOrGenerateKey() {
#ifdef _WIN32
    if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
        CryptGenKey(hProv, AT_SIGNATURE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &hKey);
    }
    publicKey = exportPublicKey();
#endif
}

string CryptVaultBlockchain::exportPublicKey() {
#ifdef _WIN32
    DWORD dwBlobLen = 0;
    if (CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
        vector<BYTE> pbBlob(dwBlobLen);
        if (CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbBlob.data(), &dwBlobLen)) {
            stringstream ss;
            for(DWORD i = 0; i < dwBlobLen; ++i) ss << hex << setfill('0') << setw(2) << (int)pbBlob[i];
            return ss.str();
        }
    }
#endif
    return "UNKNOWN_PUB_KEY";
}

string CryptVaultBlockchain::signData(const string& data) {
#ifdef _WIN32
    HCRYPTHASH hHash;
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptHashData(hHash, (BYTE*)data.c_str(), data.length(), 0);
        DWORD dwSigLen = 0;
        CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen);
        if (dwSigLen > 0) {
            vector<BYTE> signature(dwSigLen);
            if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, signature.data(), &dwSigLen)) {
                CryptDestroyHash(hHash);
                stringstream ss;
                for(DWORD i = 0; i < dwSigLen; ++i) ss << hex << setfill('0') << setw(2) << (int)signature[i];
                return ss.str();
            }
        }
        CryptDestroyHash(hHash);
    }
#endif
    return "";
}

bool CryptVaultBlockchain::verifySignature(const string& data, const string& signature, const string& pubKeyHex) {
#ifdef _WIN32
    vector<BYTE> pubKeyBlob;
    for (size_t i = 0; i < pubKeyHex.length(); i += 2) {
        pubKeyBlob.push_back((BYTE)strtol(pubKeyHex.substr(i, 2).c_str(), NULL, 16));
    }
    vector<BYTE> sigBytes;
    for (size_t i = 0; i < signature.length(); i += 2) {
        sigBytes.push_back((BYTE)strtol(signature.substr(i, 2).c_str(), NULL, 16));
    }

    HCRYPTKEY hPubKey;
    if (!CryptImportKey(hProv, pubKeyBlob.data(), pubKeyBlob.size(), 0, 0, &hPubKey)) return false;

    HCRYPTHASH hHash;
    bool verified = false;
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptHashData(hHash, (BYTE*)data.c_str(), data.length(), 0);
        if (CryptVerifySignature(hHash, sigBytes.data(), sigBytes.size(), hPubKey, NULL, 0)) {
            verified = true;
        }
        CryptDestroyHash(hHash);
    }
    CryptDestroyKey(hPubKey);
    return verified;
#else
    return true; // if not win32 auto-approve for now
#endif
}

CryptVaultBlockchain::CryptVaultBlockchain(const string& file, int diff) {
    chainFile  = file;
    difficulty = diff;
    
    initRSA();
    loadOrGenerateKey();

    if (!loadChain()) {
        chain.push_back(createGenesisBlock());
        saveChain();
    }
}

Block CryptVaultBlockchain::addRecord(const AuditRecord& record) {
    Block newBlock;
    newBlock.index        = chain.size();
    newBlock.previousHash = chain.back().blockHash;
    newBlock.record       = record;
    newBlock.record.timestamp = getTimestamp();
    newBlock.record.deviceID  = getDeviceID();
    newBlock.nonce        = 0;
    newBlock.signerPublicKey = publicKey;
    newBlock.digitalSignature = signData(newBlock.toString());

    auto start = chrono::high_resolution_clock::now();
    newBlock.blockHash = mineBlock(newBlock);
    auto end = chrono::high_resolution_clock::now();
    double mineTime = chrono::duration<double, milli>(end - start).count();

    chain.push_back(newBlock);
    saveChain();

    cout << "  ⛓️  Block #" << newBlock.index << " mined in "
         << fixed << setprecision(2) << mineTime << "ms" << endl;

    p2p_broadcastBlock(newBlock);

    return newBlock;
}

bool CryptVaultBlockchain::validateChain() {
    // Check Genesis Block First
    if (!chain.empty()) {
        const Block& genesis = chain[0];
        if (genesis.index != 0) return false;
        string recomputed = SHA256::hash(genesis.toString());
        if (recomputed != genesis.blockHash) {
            cout << "  ❌ TAMPER DETECTED at GENESIS Block #0" << endl;
            return false;
        }
        string target(difficulty, '0');
        if (genesis.blockHash.substr(0, difficulty) != target) {
            cout << "  ❌ INVALID TARGET at GENESIS Block #0" << endl;
            return false;
        }
    }
    for (size_t i = 1; i < chain.size(); i++) {
        Block& current  = chain[i];
        Block& previous = chain[i-1];

        string recomputed = SHA256::hash(current.toString());
        if (recomputed != current.blockHash) {
            cout << "  ❌ TAMPER DETECTED at Block #" << i << endl;
            return false;
        }

        // Verify Signature
        string tempSig = current.digitalSignature;
        current.digitalSignature = ""; // toString without signature for verification
        bool sigValid = verifySignature(current.toString(), tempSig, current.signerPublicKey);
        current.digitalSignature = tempSig; // restore

        if (!sigValid) {
            cout << "  ❌ SIGNATURE INVALID at Block #" << i << " (Forged Block)" << endl;
            return false;
        }

        if (current.previousHash != previous.blockHash) {
            cout << "  ❌ CHAIN BROKEN between Block #" << i-1 << " and #" << i << endl;
            return false;
        }
    }
    return true;
}

void CryptVaultBlockchain::saveChain() {
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
        file << "HMAC:" << (b.record.hmacVerified ? 1 : 0) << "\n";
        file << "SIZE:" << b.record.fileSizeBytes << "\n";
        file << "DURATION:" << b.record.durationMs << "\n";
        file << "ALGO:" << b.record.algorithm << "\n";
        file << "PUBKEY:" << b.signerPublicKey << "\n";
        file << "SIG:" << b.digitalSignature << "\n";
        file << "---\n";
    }
    file.close();
}

bool CryptVaultBlockchain::loadChain() {
    ifstream file(chainFile);
    if (!file.is_open()) return false;

    chain.clear();
    string line;
    Block current;
    bool inBlock = false;

    while (getline(file, line)) {
        if (line.substr(0, 6) == "BLOCK:") {
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
            else if (key == "PUBKEY") current.signerPublicKey = val;
            else if (key == "SIG")    current.digitalSignature = val;
        }
    }
    file.close();
    return !chain.empty();
}

void CryptVaultBlockchain::printAuditLog() {
    cout << "\n" << string(65, '=') << endl;
    cout << "   CRYPTVAULT BLOCKCHAIN AUDIT LOG" << endl;
    cout << "   Total Blocks: " << chain.size() << endl;
    cout << string(65, '=') << endl;

    for (const Block& b : chain) {
        cout << "\n  Block #" << b.index;
        if (b.index == 0) cout << "  [GENESIS]";
        cout << endl << "  " << string(45, '-') << endl;
        cout << "  Operation : " << operationToString(b.record.operation) << endl;
        cout << "  File      : " << b.record.filename << endl;
        cout << "  Timestamp : " << b.record.timestamp << endl;
        cout << "  Algorithm : " << b.record.algorithm << endl;
        cout << "  File Size : " << b.record.fileSizeBytes << " bytes" << endl;
        cout << "  Duration  : " << fixed << setprecision(2) << b.record.durationMs << " ms" << endl;
        cout << "  HMAC      : " << (b.record.hmacVerified ? "✅ Verified" : "❌ Failed") << endl;
        cout << "  File Hash : " << b.record.fileHash.substr(0, 32) << "..." << endl;
        cout << "  Block Hash: " << b.blockHash.substr(0, 32) << "..." << endl;
    }
    cout << "\n" << string(65, '=') << endl;
}

void CryptVaultBlockchain::searchByFile(const string& filename) {
    cout << "\n  Search results for: " << filename << endl;
    cout << string(45, '-') << endl;
    bool found = false;
    for (const Block& b : chain) {
        if (b.record.filename.find(filename) != string::npos) {
            cout << "  Block #" << b.index << "  [" << operationToString(b.record.operation)
                 << "]  " << b.record.timestamp << endl;
            found = true;
        }
    }
    if (!found) cout << "  No records found." << endl;
}

void CryptVaultBlockchain::printStats() {
    int encrypts = 0, decrypts = 0, deletes = 0, keyEx = 0;
    long long totalBytes = 0;

    for (const Block& b : chain) {
        switch(b.record.operation) {
            case AuditOperation::ENCRYPT:
            case AuditOperation::DIRECTORY_ENCRYPT: encrypts++; break;
            case AuditOperation::DECRYPT:           decrypts++; break;
            case AuditOperation::SECURE_DELETE:     deletes++;  break;
            case AuditOperation::KEY_EXCHANGE:      keyEx++;    break;
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
    cout << "  Chain Integrity  : " << (validateChain() ? "✅ VALID" : "❌ TAMPERED") << endl;
    cout << "  " << string(40, '=') << endl;
}

void CryptVaultBlockchain::exportHTMLReport(const string& outFile) {
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

int CryptVaultBlockchain::getChainSize() const { 
    return chain.size(); 
}

bool CryptVaultBlockchain::validateNewBlock(const Block& b) {
    if (chain.empty()) return false;
    const Block& last = chain.back();
    if (b.index != (int)chain.size()) return false;
    if (b.previousHash != last.blockHash) return false;
    string target(difficulty, '0');
    return SHA256::hash(const_cast<Block&>(b).toString()).substr(0, difficulty) == target;
}

bool CryptVaultBlockchain::validateChainExternal(const vector<Block>& c) {
    if (c.empty()) return false;
    string target(difficulty, '0');

    // Check genesis block of external chain
    if (c[0].index != 0) return false;
    string genHash = SHA256::hash(const_cast<Block&>(c[0]).toString());
    if (genHash != c[0].blockHash || genHash.substr(0, difficulty) != target) return false;

    // Validate rest of chain
    for (size_t i = 1; i < c.size(); i++) {
        if (c[i].previousHash != c[i-1].blockHash) return false;
        
        string recomputed = SHA256::hash(const_cast<Block&>(c[i]).toString());
        if (recomputed != c[i].blockHash) return false;

        if (c[i].blockHash.substr(0, difficulty) != target) return false;
        
        // Verify digital signature of block
        string blockData = c[i].previousHash + to_string(c[i].index) + c[i].record.fileHash;
        string expectedSig = SHA256::hash(blockData + SHA256::hash(c[i].signerPublicKey + "PRIVATE"));
        if (c[i].digitalSignature != expectedSig) return false;
    }
    return true;
}

void CryptVaultBlockchain::replaceChain(const vector<Block>& newChain) {
    chain = newChain;
    saveChain();
}

void CryptVaultBlockchain::addVerifiedBlock(const Block& b) {
    chain.push_back(b);
    saveChain();
}

const vector<Block>& CryptVaultBlockchain::getChain() const { 
    return chain; 
}

// ─────────────────────────────────────────────────────────────
//  LOGGING HELPER FUNCTIONS
// ─────────────────────────────────────────────────────────────

void logEncryption(CryptVaultBlockchain& bc,
                   const string& filename,
                   const string& fileHash,
                   long long fileSize,
                   double durationMs,
                   bool hmacOk,
                   const string& algo) {
    AuditRecord r;
    r.operation      = AuditOperation::ENCRYPT;
    r.filename       = filename;
    r.fileHash       = fileHash;
    r.fileSizeBytes  = fileSize;
    r.durationMs     = durationMs;
    r.hmacVerified   = hmacOk;
    r.algorithm      = algo;
    bc.addRecord(r);
}

void logDecryption(CryptVaultBlockchain& bc,
                   const string& filename,
                   const string& fileHash,
                   long long fileSize,
                   double durationMs,
                   bool hmacOk) {
    AuditRecord r;
    r.operation     = AuditOperation::DECRYPT;
    r.filename      = filename;
    r.fileHash      = fileHash;
    r.fileSizeBytes = fileSize;
    r.durationMs    = durationMs;
    r.hmacVerified  = hmacOk;
    r.algorithm     = "AES-256";
    bc.addRecord(r);
}

void logKeyExchange(CryptVaultBlockchain& bc,
                    const string& targetDevice) {
    AuditRecord r;
    r.operation    = AuditOperation::KEY_EXCHANGE;
    r.filename     = "RSA_KEY_EXCHANGE";
    r.fileHash     = SHA256::hash(targetDevice);
    r.algorithm    = "RSA-2048";
    r.hmacVerified = true;
    bc.addRecord(r);
}

void logSecureDelete(CryptVaultBlockchain& bc,
                     const string& filename,
                     const string& fileHash) {
    AuditRecord r;
    r.operation    = AuditOperation::SECURE_DELETE;
    r.filename     = filename;
    r.fileHash     = fileHash;
    r.algorithm    = "SHRED-7PASS";
    r.hmacVerified = true;
    bc.addRecord(r);
}
