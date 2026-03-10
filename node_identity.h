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

#include "blockchain_audit.h"
inline string sha256(const string& input) { return SHA256::hash(input); }

// ── MACHINE FINGERPRINT ──────────────────────────────────────

// Cross-platform hostname / machine identifier
string getMachineFingerprint() {
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
    // In Month 4 upgrade: replace with real RSA/ECDSA via OpenSSL
    string sign(const string& data) const {
        return sha256(data + privateKey);
    }

    // Verify a signature made by this node
    bool verify(const string& data, const string& signature) const {
        return sha256(data + privateKey) == signature;
    }

    // Verify a signature using only public key
    // (simplified — real version uses asymmetric crypto)
    static bool verifyWithPublicKey(const string& data,
                                    const string& signature,
                                    const string& pubKey) {
        // In real implementation: RSA verify
        // Here: anyone with pubKey can verify (symmetric simplification)
        return sha256(data + sha256(pubKey + "PRIVATE")) == signature;
    }

    string shortID() const {
        return nodeID.substr(0, 12) + "...";
    }
};

// ── PERSISTENCE ───────────────────────────────────────────────

const string IDENTITY_FILE = "identity.key";

// Save identity to disk
void saveIdentity(const NodeIdentity& id) {
    ofstream f(IDENTITY_FILE);
    if (!f.is_open()) {
        cerr << "  [ID] WARNING: Cannot save identity to disk" << endl;
        return;
    }
    f << "NODE_ID:"      << id.nodeID     << "\n";
    f << "PUBLIC_KEY:"   << id.publicKey  << "\n";
    f << "PRIVATE_KEY:"  << id.privateKey << "\n";
    f << "DISPLAY_NAME:" << id.displayName<< "\n";
    f.close();
}

// Load identity from disk
bool loadIdentity(NodeIdentity& id) {
    ifstream f(IDENTITY_FILE);
    if (!f.is_open()) return false;

    string line;
    while (getline(f, line)) {
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
NodeIdentity initIdentity(const string& displayName = "") {
    NodeIdentity id;

    // Try loading existing identity first
    if (loadIdentity(id)) {
        if (!displayName.empty()) id.displayName = displayName;
        cout << "  🔑 Node identity loaded: " << id.shortID() << endl;
        return id;
    }

    // Create new identity from machine fingerprint
    string fp      = getMachineFingerprint();
    string seed    = sha256(fp + "CRYPTVAULT_SEED_2024");

    id.nodeID      = sha256(seed + "NODE_ID");
    id.publicKey   = sha256(seed + "PUBLIC");
    id.privateKey  = sha256(seed + "PRIVATE");  // Never leave this machine
    id.displayName = displayName.empty() ? fp : displayName;

    saveIdentity(id);

    cout << "  🆕 New node identity created: " << id.shortID() << endl;
    return id;
}
