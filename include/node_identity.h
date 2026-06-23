#pragma once
/*
 * ================================================================
 *  CryptVault — node_identity.h
 *  Cross-platform node identity using machine fingerprint + SHA-256
 *
 *  Each CryptVault instance gets a unique persistent NodeID derived
 *  from hardware identifiers. Saved to identity.key on first run.
 *  Loaded from identity.key on subsequent runs.
 *
 *  NOTE: Uses your existing sha256() from blockchain_audit.cpp
 * ================================================================
 */

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;

#include "../include/blockchain_audit.h"
inline string sha256(const string& input) { return AuditSHA256::hash(input); }

// ── MACHINE FINGERPRINT ──────────────────────────────────────

// Cross-platform hostname / machine identifier
inline string getMachineFingerprint() {
    string fp = "";

#ifdef _WIN32
    // Windows: ComputerName + Username
    char compName[256] = {0};
    char userName[256] = {0};
    DWORD sz1 = sizeof(compName);
    DWORD sz2 = sizeof(userName);
    GetComputerNameA(compName, &sz1);
    GetUserNameA(userName, &sz2);
    fp = string(compName) + "_" + string(userName);
#else
    // Linux/macOS: hostname
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    fp = string(hostname);

    // Add username if available
    const char* user = getenv("USER");
    if (!user) user = getenv("LOGNAME");
    if (user) fp += string("_") + user;
#endif

    return fp.empty() ? "UNKNOWN_NODE" : fp;
}

// ── NODE IDENTITY STRUCTURE ──────────────────────────────────

struct NodeIdentity {
    string nodeID;        // Unique ID for this node (sha256-derived)
    string publicKey;     // Simplified public key (sha256 of nodeID)
    string privateKey;    // Simplified private key (never transmitted)
    string displayName;   // Human-readable name from peers.txt

    // Sign a piece of data — simplified HMAC-style signing
    string sign(const string& data) const {
        return sha256(data + privateKey);
    }

    // Verify a signature made by this node
    bool verify(const string& data, const string& signature) const {
        return sha256(data + privateKey) == signature;
    }

    // Verify a signature using only public key
    static bool verifyWithPublicKey(const string& data,
                                    const string& signature,
                                    const string& pubKey) {
        return sha256(data + sha256(pubKey + "PRIVATE")) == signature;
    }

    string shortID() const {
        return nodeID.substr(0, 12) + "...";
    }
};

// ── PERSISTENCE ───────────────────────────────────────────────

const string IDENTITY_FILE = "identity.key";

#include <sys/stat.h>
#include <fcntl.h>
#include "crypto_utils.h"

// Save identity to disk
inline void saveIdentity(const NodeIdentity& id, const string& password) {
    string serialized = "NODE_ID:" + id.nodeID + "\n" +
                        "PUBLIC_KEY:" + id.publicKey + "\n" +
                        "PRIVATE_KEY:" + id.privateKey + "\n" +
                        "DISPLAY_NAME:" + id.displayName + "\n";
    vector<unsigned char> plaintext(serialized.begin(), serialized.end());
    
    AESCipher cipher;
    cipher.setKey(password);
    vector<unsigned char> encrypted = cipher.encrypt(plaintext);

    ofstream f(IDENTITY_FILE, ios::binary);
    if (!f.is_open()) {
        cerr << "  [ID] WARNING: Cannot save identity to disk" << endl;
        return;
    }
    f.write("CVPI", 4);
    char version = 0x01;
    f.write(&version, 1);
    f.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    f.close();

    if (chmod(IDENTITY_FILE.c_str(), 0600) != 0) {
        cerr << "  [ID] WARNING: Could not set strict permissions on identity.key" << endl;
    }
}

// Load identity from disk
inline bool loadIdentity(NodeIdentity& id, const string& password) {
    ifstream f(IDENTITY_FILE, ios::binary | ios::ate);
    if (!f.is_open()) return false;

    streamsize size = f.tellg();
    if (size <= 5) return false;
    
    f.seekg(0, ios::beg);
    char magic[4];
    f.read(magic, 4);
    if (strncmp(magic, "CVPI", 4) != 0) {
        cerr << "  [ID] ERROR: identity.key missing magic bytes! Please delete it and restart." << endl;
        return false;
    }
    char version;
    f.read(&version, 1);
    if (version != 0x01) {
        cerr << "  [ID] ERROR: Unsupported identity.key version!" << endl;
        return false;
    }

    size -= 5;
    vector<unsigned char> encrypted(size);
    f.read(reinterpret_cast<char*>(encrypted.data()), size);
    f.close();

    AESCipher cipher;
    cipher.setKey(password);
    vector<unsigned char> plaintext = cipher.decrypt(encrypted);
    if (plaintext.empty()) {
        cerr << "  [ID] ERROR: Incorrect password for identity.key!" << endl;
        return false;
    }
    string data(plaintext.begin(), plaintext.end());

    stringstream ss(data);
    string line;
    while (getline(ss, line)) {
        size_t sep = line.find(':');
        if (sep == string::npos) continue;
        string key = line.substr(0, sep);
        string val = line.substr(sep + 1);
        if (key == "NODE_ID")       id.nodeID      = val;
        else if (key == "PUBLIC_KEY")  id.publicKey   = val;
        else if (key == "PRIVATE_KEY") id.privateKey  = val;
        else if (key == "DISPLAY_NAME") id.displayName = val;
    }
    return !id.nodeID.empty();
}

// Create or load node identity
inline NodeIdentity initIdentity(const string& password, const string& displayName = "") {
    NodeIdentity id;

    if (loadIdentity(id, password)) {
        if (!displayName.empty()) id.displayName = displayName;
        cout << "  🔑 Node identity loaded: " << id.shortID() << endl;
        return id;
    }

    string fp      = getMachineFingerprint();
    string seed    = sha256(fp + "CRYPTVAULT_SEED_2024");

    id.nodeID      = sha256(seed + "NODE_ID");
    id.publicKey   = sha256(seed + "PUBLIC");
    id.privateKey  = sha256(seed + "PRIVATE");
    id.displayName = displayName.empty() ? fp : displayName;

    saveIdentity(id, password);

    cout << "  🆕 New node identity created: " << id.shortID() << endl;
    return id;
}
