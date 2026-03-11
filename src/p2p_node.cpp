/*
 * ================================================================
 *  CryptVault — p2p_node.cpp
 *  Full cross-platform P2P multi-user blockchain network
 *
 *  COMPILE:
 *    Windows:  g++ -std=c++17 -O2 -o crypt-vault.exe \
 *                  Crypt-Vault.cpp blockchain_audit.cpp p2p_node.cpp \
 *                  -lws2_32
 *
 *    Linux:    g++ -std=c++17 -O2 -o crypt-vault \
 *                  Crypt-Vault.cpp blockchain_audit.cpp p2p_node.cpp \
 *                  -lpthread
 *
 *  HOW IT WORKS:
 *    1. Each node starts a TCP server on port 8333
 *    2. Reads peers.txt and connects to all known nodes
 *    3. On connect: syncs chain (longest valid chain wins)
 *    4. On encrypt/decrypt: signs + broadcasts new block to all peers
 *    5. On receive block: validates signature + PoW, adds to chain
 *    6. Tamper any node → other nodes reject its chain
 * ================================================================
 */

#include "../include/p2p_node.h"
#include "../include/network_layer.h"
#include "../include/node_identity.h"
#include "../include/blockchain_audit.h"   // your existing blockchain code

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <list>
#include <string>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <chrono>
#include <thread>
using namespace std;

// ── CONSTANTS ────────────────────────────────────────────────
#define DEFAULT_PORT        8333
#define MAX_PEERS           16
#define BUFFER_SIZE         131072   // 128 KB per message
#define HEARTBEAT_INTERVAL  30000    // 30 seconds
#define SYNC_TIMEOUT        5000     // 5 seconds
#define PEERS_FILE          "peers.txt"

// ── MESSAGE PROTOCOL ─────────────────────────────────────────
/*
 *  Wire format for every message:
 *  [ 1 byte  : MsgType         ]
 *  [ 4 bytes : payload length  ]  (big-endian uint32)
 *  [ N bytes : payload         ]  (text/serialized data)
 */

enum MsgType : uint8_t {
    MSG_HANDSHAKE     = 0x01,   // "Hello, I am node X"
    MSG_HANDSHAKE_ACK = 0x02,   // "Hello back, I am node Y"
    MSG_NEW_BLOCK     = 0x03,   // "I mined a new block, here it is"
    MSG_REQUEST_CHAIN = 0x04,   // "Send me your full chain"
    MSG_SEND_CHAIN    = 0x05,   // "Here is my full chain"
    MSG_REQUEST_PEERS = 0x06,   // "Who else do you know?"
    MSG_SEND_PEERS    = 0x07,   // "Here are other nodes"
    MSG_HEARTBEAT     = 0x08,   // "I am still alive"
    MSG_REJECT_BLOCK  = 0x09,   // "Your block is invalid"
};

// ── SERIALIZATION ────────────────────────────────────────────
/*
 *  Simple text-based serialization using '|' as field separator
 *  and '\n' as record separator. No JSON library needed.
 */

string serializeBlock(const Block& b) {
    stringstream ss;
    ss << b.index                                    << "|"
       << b.previousHash                             << "|"
       << b.blockHash                                << "|"
       << b.nonce                                    << "|"
       << (int)b.record.operation                    << "|"
       << b.record.filename                          << "|"
       << b.record.fileHash                          << "|"
       << b.record.deviceID                          << "|"
       << b.record.timestamp                         << "|"
       << (b.record.hmacVerified ? "1" : "0")        << "|"
       << b.record.fileSizeBytes                     << "|"
       << b.record.durationMs                        << "|"
       << b.record.algorithm                         << "|"
       << b.signerPublicKey                          << "|"
       << b.digitalSignature;
    return ss.str();
}

Block deserializeBlock(const string& data) {
    Block b;
    vector<string> fields;
    stringstream ss(data);
    string field;
    while (getline(ss, field, '|'))
        fields.push_back(field);

    if (fields.size() < 15) return b;  // malformed

    b.index                   = stoi(fields[0]);
    b.previousHash            = fields[1];
    b.blockHash               = fields[2];
    b.nonce                   = stoll(fields[3]);
    b.record.operation        = (AuditOperation)stoi(fields[4]);
    b.record.filename         = fields[5];
    b.record.fileHash         = fields[6];
    b.record.deviceID         = fields[7];
    b.record.timestamp        = fields[8];
    b.record.hmacVerified     = (fields[9] == "1");
    b.record.fileSizeBytes    = stoll(fields[10]);
    b.record.durationMs       = stod(fields[11]);
    b.record.algorithm        = fields[12];
    b.signerPublicKey         = fields[13];
    b.digitalSignature        = fields[14];
    return b;
}

string serializeChain(const vector<Block>& chain) {
    stringstream ss;
    for (const Block& b : chain) {
        ss << serializeBlock(b) << "\n";
    }
    return ss.str();
}

vector<Block> deserializeChain(const string& data) {
    vector<Block> chain;
    stringstream ss(data);
    string line;
    while (getline(ss, line)) {
        if (!line.empty())
            chain.push_back(deserializeBlock(line));
    }
    return chain;
}

// ── SEND/RECEIVE MESSAGES ────────────────────────────────────

bool sendMsg(socket_t sock, MsgType type, const string& payload) {
    // Header: [1 byte type][4 bytes length big-endian]
    uint32_t len = (uint32_t)payload.size();
    uint32_t lenBE = htonl(len);

    char header[5];
    header[0] = (char)type;
    memcpy(header + 1, &lenBE, 4);

    if (!sendAll(sock, header, 5)) return false;
    if (len > 0 && !sendAll(sock, payload.c_str(), (int)len)) return false;
    return true;
}

bool recvMsg(socket_t sock, MsgType& type, string& payload) {
    char header[5] = {0};
    if (!recvAll(sock, header, 5)) return false;

    type = (MsgType)(uint8_t)header[0];
    uint32_t lenBE;
    memcpy(&lenBE, header + 1, 4);
    uint32_t len = ntohl(lenBE);

    if (len > BUFFER_SIZE) return false;  // safety limit

    if (len == 0) {
        payload = "";
        return true;
    }

    vector<char> buf(len + 1, 0);
    if (!recvAll(sock, buf.data(), (int)len)) return false;
    payload = string(buf.data(), len);
    return true;
}

// ── PEER INFO ────────────────────────────────────────────────

struct PeerInfo {
    socket_t    sock;
    string      ip;
    int         port;
    string      nodeID;
    string      publicKey;
    string      displayName;
    bool        connected;
    time_t      lastSeen;

    string address() const {
        return ip + ":" + to_string(port);
    }
};

// ── P2P NODE CLASS ───────────────────────────────────────────

class P2PNode {
public:
    // ── CONSTRUCTOR ──────────────────────────────────────────

    P2PNode(CryptVaultBlockchain* bc, int port = DEFAULT_PORT)
        : blockchain(bc), listenPort(port),
          serverSock(INVALID_SOCK), running(false)
    {
        sockInit();
        mutexInit(peersMutex);
        identity = initIdentity();
    }

    ~P2PNode() {
        stop();
        mutexDestroy(peersMutex);
        sockCleanup();
    }

    // ── START ────────────────────────────────────────────────

    bool start() {
        running = true;

        // 1. Start TCP server
        if (!startServer()) {
            cerr << "  [P2P] Failed to start server on port "
                 << listenPort << endl;
            return false;
        }

        // 2. Load peers from file
        loadPeers();

        // 3. Connect to known peers in background
        startThread(connectToPeersThread, this);

        // 4. Heartbeat loop in background
        startThread(heartbeatThread, this);

        cout << "\n  ┌─────────────────────────────────────┐" << endl;
        cout << "  │   CRYPTVAULT P2P NODE STARTED       │" << endl;
        cout << "  ├─────────────────────────────────────┤" << endl;
        cout << "  │ Port    : " << listenPort << "                    │" << endl;
        cout << "  │ Node ID : " << identity.shortID() << "          │" << endl;
        cout << "  │ Name    : " << identity.displayName.substr(0,20)
             <<                                "              │" << endl;
        cout << "  └─────────────────────────────────────┘\n" << endl;
        return true;
    }

    void stop() {
        running = false;
        if (sockValid(serverSock)) {
            sockClose(serverSock);
            serverSock = INVALID_SOCK;
        }
        LockGuard lg(peersMutex);
        for (PeerInfo& p : peers) {
            if (p.connected && sockValid(p.sock))
                sockClose(p.sock);
        }
        peers.clear();
    }

    // ── BROADCAST NEW BLOCK ──────────────────────────────────
    // Call this every time CryptVault encrypts/decrypts a file

    void broadcastBlock(Block& block) {
        // Sign the block with our private key
        string blockData = block.previousHash
                         + to_string(block.index)
                         + block.record.fileHash;
        block.signerPublicKey  = identity.publicKey;
        block.digitalSignature = identity.sign(blockData);

        string payload = serializeBlock(block);

        int sent = 0;
        LockGuard lg(peersMutex);
        for (PeerInfo& p : peers) {
            if (p.connected && sockValid(p.sock)) {
                if (sendMsg(p.sock, MSG_NEW_BLOCK, payload))
                    sent++;
            }
        }

        if (sent > 0)
            cout << "  📡 Block #" << block.index
                 << " broadcast to " << sent << " peers" << endl;
        else
            cout << "  📡 Block #" << block.index
                 << " (no peers connected — stored locally)" << endl;
    }

    // ── STATUS ───────────────────────────────────────────────

    void printStatus() {
        LockGuard lg(peersMutex);
        int connected = 0;
        for (const PeerInfo& p : peers)
            if (p.connected) connected++;

        cout << "\n  ── P2P NODE STATUS ──────────────────────" << endl;
        cout << "  Node ID      : " << identity.shortID()      << endl;
        cout << "  Display Name : " << identity.displayName     << endl;
        cout << "  Listen Port  : " << listenPort               << endl;
        cout << "  Known Peers  : " << peers.size()             << endl;
        cout << "  Connected    : " << connected                 << endl;
        cout << "  Chain Length : " << blockchain->getChainSize()<< " blocks" << endl;
        cout << "  ─────────────────────────────────────────" << endl;

        for (const PeerInfo& p : peers) {
            cout << "  " << (p.connected ? "🟢" : "🔴")
                 << "  " << p.address()
                 << "  " << (p.displayName.empty() ? "unknown" : p.displayName)
                 << (p.nodeID.empty() ? "" : "  [" + p.nodeID.substr(0,8) + "...]")
                 << endl;
        }
        cout << endl;
    }

    int getConnectedCount() {
        LockGuard lg(peersMutex);
        int c = 0;
        for (const PeerInfo& p : peers)
            if (p.connected) c++;
        return c;
    }

private:
    CryptVaultBlockchain*   blockchain;
    NodeIdentity            identity;
    int                     listenPort;
    socket_t                serverSock;
    bool                    running;
    std::list<PeerInfo> peers;
    mutex_t                 peersMutex;

    // ── SERVER ───────────────────────────────────────────────

    bool startServer() {
        serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (!sockValid(serverSock)) return false;

        setReuseAddr(serverSock);

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(listenPort);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(serverSock, (sockaddr*)&addr, sizeof(addr)) == SOCK_ERR) {
            cerr << "  [P2P] Bind failed. Port " << listenPort
                 << " may be in use." << endl;
            sockClose(serverSock);
            return false;
        }

        listen(serverSock, MAX_PEERS);
        startThread(acceptLoop, this);
        return true;
    }

    // Runs in background — accepts incoming peer connections
    static void* acceptLoop(void* arg) {
        P2PNode* node = (P2PNode*)arg;
        while (node->running) {
            sockaddr_in clientAddr{};
            socklen_t   addrLen = sizeof(clientAddr);
            socket_t    clientSock = accept(
                node->serverSock,
                (sockaddr*)&clientAddr, &addrLen
            );

            if (!sockValid(clientSock)) {
                if (!node->running) break;
                sleepMs(100);
                continue;
            }

            // Get peer IP
            string peerIP = string(inet_ntoa(clientAddr.sin_addr));

            cout << "  🔌 Incoming connection from " << peerIP << endl;

            // Handle in new thread
            PeerInfo* pi = new PeerInfo();
            pi->sock      = clientSock;
            pi->ip        = peerIP;
            pi->port      = 0;   // unknown until handshake
            pi->connected = true;
            pi->lastSeen  = time(nullptr);

            {
                LockGuard lg(node->peersMutex);
                node->peers.push_back(*pi);
            }
            delete pi;

            // Get pointer to actual peer in vector
            PeerInfo* storedPeer = nullptr;
            {
                LockGuard lg(node->peersMutex);
                storedPeer = &node->peers.back();
            }

            // Handle peer messages in a new thread
            startThread(peerHandler,
                        new pair<P2PNode*, PeerInfo*>(node, storedPeer));
        }
        return nullptr;
    }

    // ── PEER HANDLER ─────────────────────────────────────────
    // Runs per connected peer — processes incoming messages

    static void* peerHandler(void* arg) {
        auto* p    = (pair<P2PNode*, PeerInfo*>*)arg;
        P2PNode*  node = p->first;
        PeerInfo* peer = p->second;
        delete p;

        // Step 1: Send our handshake
        string hs = node->identity.nodeID + "|"
                  + node->identity.publicKey + "|"
                  + node->identity.displayName + "|"
                  + to_string(node->listenPort);
        sendMsg(peer->sock, MSG_HANDSHAKE, hs);

        // Step 2: Message loop
        while (node->running && peer->connected) {
            MsgType type;
            string  payload;

            if (!recvMsg(peer->sock, type, payload)) {
                peer->connected = false;
                cout << "  🔴 Peer disconnected: " << peer->address() << endl;
                break;
            }

            peer->lastSeen = time(nullptr);
            node->handleMessage(peer, type, payload);
        }

        sockClose(peer->sock);
        peer->connected = false;
        return nullptr;
    }

    // ── MESSAGE HANDLER ──────────────────────────────────────

    void handleMessage(PeerInfo* peer,
                       MsgType type,
                       const string& payload) {
        switch (type) {

        // ── HANDSHAKE ────────────────────────────────────────
        case MSG_HANDSHAKE: {
            // Parse: nodeID|publicKey|displayName|listenPort
            vector<string> parts;
            stringstream ss(payload);
            string part;
            while (getline(ss, part, '|'))
                parts.push_back(part);

            if (parts.size() >= 4) {
                peer->nodeID      = parts[0];
                peer->publicKey   = parts[1];
                peer->displayName = parts[2];
                peer->port        = stoi(parts[3]);
            }

            cout << "  🤝 Handshake from: "
                 << (peer->displayName.empty() ? peer->ip : peer->displayName)
                 << " [" << (peer->nodeID.size() > 8 ?
                              peer->nodeID.substr(0,8) : peer->nodeID)
                 << "...]" << endl;

            // Acknowledge + send our info back
            string ack = identity.nodeID + "|"
                       + identity.publicKey + "|"
                       + identity.displayName + "|"
                       + to_string(listenPort);
            sendMsg(peer->sock, MSG_HANDSHAKE_ACK, ack);

            // Request their chain to sync
            sendMsg(peer->sock, MSG_REQUEST_CHAIN, "");
            break;
        }

        case MSG_HANDSHAKE_ACK: {
            vector<string> parts;
            stringstream ss(payload);
            string part;
            while (getline(ss, part, '|'))
                parts.push_back(part);

            if (parts.size() >= 4) {
                peer->nodeID      = parts[0];
                peer->publicKey   = parts[1];
                peer->displayName = parts[2];
                peer->port        = stoi(parts[3]);
            }
            cout << "  ✅ Connected: "
                 << (peer->displayName.empty() ? peer->ip : peer->displayName)
                 << endl;
            break;
        }

        // ── NEW BLOCK FROM PEER ──────────────────────────────
        case MSG_NEW_BLOCK: {
            Block incoming = deserializeBlock(payload);

            // 1. Verify digital signature
            string blockData = incoming.previousHash
                             + to_string(incoming.index)
                             + incoming.record.fileHash;

            bool sigValid = !incoming.signerPublicKey.empty() &&
                            sha256(blockData + sha256(
                                incoming.signerPublicKey + "PRIVATE"
                            )) == incoming.digitalSignature;

            // 2. Validate block fits our chain
            bool chainValid = blockchain->validateNewBlock(incoming);

            if (!sigValid) {
                cout << "  ⚠️  Block #" << incoming.index
                     << " REJECTED — invalid signature from "
                     << peer->address() << endl;
                sendMsg(peer->sock, MSG_REJECT_BLOCK,
                        "INVALID_SIGNATURE:" + to_string(incoming.index));
                break;
            }

            if (!chainValid) {
                cout << "  ⚠️  Block #" << incoming.index
                     << " REJECTED — chain validation failed" << endl;
                // Request full chain sync — we may be out of date
                sendMsg(peer->sock, MSG_REQUEST_CHAIN, "");
                break;
            }

            // 3. Add verified block
            blockchain->addVerifiedBlock(incoming);
            cout << "  ✅ Block #" << incoming.index
                 << " accepted from "
                 << (peer->displayName.empty() ? peer->ip : peer->displayName)
                 << "  [" << operationToString(incoming.record.operation)
                 << "  " << incoming.record.filename << "]" << endl;

            // 4. Gossip — forward to all OTHER peers
            gossipBlock(incoming, peer);
            break;
        }

        // ── CHAIN SYNC ───────────────────────────────────────
        case MSG_REQUEST_CHAIN: {
            // Peer is asking for our full chain
            string chainData = serializeChain(
                blockchain->getChain()
            );
            sendMsg(peer->sock, MSG_SEND_CHAIN, chainData);
            cout << "  📤 Sent chain (" << blockchain->getChainSize()
                 << " blocks) to " << peer->address() << endl;
            break;
        }

        case MSG_SEND_CHAIN: {
            // Peer sent us their chain — apply consensus
            vector<Block> theirChain = deserializeChain(payload);

            cout << "  📥 Received chain from "
                 << peer->address()
                 << " (" << theirChain.size() << " blocks)" << endl;

            bool replaced = applyConsensus(theirChain, peer);
            if (replaced) {
                cout << "  🔄 Local chain REPLACED — peer had longer valid chain"
                     << endl;
            } else {
                cout << "  ✅ Local chain kept — already up to date" << endl;
            }
            break;
        }

        // ── PEER DISCOVERY ───────────────────────────────────
        case MSG_REQUEST_PEERS: {
            // Send list of our known peers
            string peerList = buildPeerList();
            sendMsg(peer->sock, MSG_SEND_PEERS, peerList);
            break;
        }

        case MSG_SEND_PEERS: {
            // Add newly discovered peers
            processNewPeers(payload);
            break;
        }

        // ── HEARTBEAT ────────────────────────────────────────
        case MSG_HEARTBEAT: {
            // Just update last seen — already done above
            break;
        }

        case MSG_REJECT_BLOCK: {
            cout << "  ❌ Block rejected by " << peer->address()
                 << ": " << payload << endl;
            break;
        }

        default:
            cout << "  [P2P] Unknown message type: "
                 << (int)type << endl;
        }
    }

    // ── CONSENSUS — LONGEST VALID CHAIN WINS ─────────────────

    bool applyConsensus(const vector<Block>& theirChain,
                        PeerInfo* source) {
        // Rule: replace ours only if theirs is:
        //   1. Longer
        //   2. Fully valid
        if (theirChain.size() <= blockchain->getChainSize()) {
            return false;   // ours is same or longer — keep it
        }

        if (!blockchain->validateChainExternal(theirChain)) {
            cout << "  ❌ CONSENSUS: Peer's chain FAILED validation — "
                 << "possible tampering from " << source->address() << endl;
            return false;
        }

        // Their chain is longer and valid — replace ours
        blockchain->replaceChain(theirChain);
        return true;
    }

    // ── GOSSIP — FORWARD BLOCKS TO OTHER PEERS ───────────────
    // When we receive a block from peer A, forward to peers B, C, D
    // (but NOT back to A)

    void gossipBlock(const Block& block, PeerInfo* source) {
        string payload = serializeBlock(block);
        int forwarded  = 0;

        LockGuard lg(peersMutex);
        for (PeerInfo& p : peers) {
            // Skip the source peer and disconnected ones
            if (&p == source || !p.connected) continue;
            if (sendMsg(p.sock, MSG_NEW_BLOCK, payload))
                forwarded++;
        }
        if (forwarded > 0)
            cout << "  🔀 Block #" << block.index
                 << " gossiped to " << forwarded << " peers" << endl;
    }

    // ── OUTBOUND CONNECTIONS ─────────────────────────────────

    static void* connectToPeersThread(void* arg) {
        P2PNode* node = (P2PNode*)arg;
        sleepMs(500);   // brief delay — let server start first

        for (PeerInfo& peer : node->peers) {
            if (!node->running) break;
            node->connectToPeer(peer);
            sleepMs(200);
        }
        return nullptr;
    }

    bool connectToPeer(PeerInfo& peer) {
        if (peer.connected) return true;

        socket_t sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (!sockValid(sock)) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(peer.port);

        addr.sin_addr.s_addr = inet_addr(peer.ip.c_str());
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            sockClose(sock);
            return false;
        }

        cout << "  🔗 Connecting to " << peer.address() << "..." << endl;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCK_ERR) {
            sockClose(sock);
            cout << "  🔴 Cannot reach " << peer.address() << endl;
            return false;
        }

        peer.sock      = sock;
        peer.connected = true;
        peer.lastSeen  = time(nullptr);

        cout << "  🟢 Connected to " << peer.address() << endl;

        // Handle messages from this peer in background
        startThread(peerHandler,
                    new pair<P2PNode*, PeerInfo*>(this, &peer));
        return true;
    }

    // ── LOAD peers.txt ───────────────────────────────────────

    void loadPeers() {
        ifstream f(PEERS_FILE);
        if (!f.is_open()) {
            cout << "  [P2P] No peers.txt found — running standalone" << endl;
            cout << "  [P2P] Create peers.txt with one IP:PORT per line" << endl;
            return;
        }

        int loaded = 0;
        string line;
        while (getline(f, line)) {
            // Strip comments and whitespace
            size_t comment = line.find('#');
            if (comment != string::npos)
                line = line.substr(0, comment);
            while (!line.empty() && (line.back() == ' '  ||
                                     line.back() == '\t' ||
                                     line.back() == '\r'))
                line.pop_back();
            if (line.empty()) continue;

            // Parse ip:port
            size_t colon = line.rfind(':');
            if (colon == string::npos) continue;

            string ip   = line.substr(0, colon);
            int    port = stoi(line.substr(colon + 1));

            // Don't add ourselves
            if (port == listenPort) {
                // Check if this could be our own entry
                // (simple heuristic — skip localhost entries matching our port)
                if (ip == "127.0.0.1" || ip == "localhost") continue;
            }

            PeerInfo p{};
            p.ip        = ip;
            p.port      = port;
            p.connected = false;
            p.sock      = INVALID_SOCK;
            peers.push_back(p);
            loaded++;
        }
        cout << "  📋 Loaded " << loaded << " peer(s) from " << PEERS_FILE << endl;
    }

    // ── PEER LIST SERIALIZATION ──────────────────────────────

    string buildPeerList() {
        stringstream ss;
        LockGuard lg(peersMutex);
        for (const PeerInfo& p : peers) {
            if (p.connected)
                ss << p.ip << ":" << p.port << "\n";
        }
        return ss.str();
    }

    void processNewPeers(const string& data) {
        stringstream ss(data);
        string line;
        int added = 0;
        while (getline(ss, line)) {
            if (line.empty()) continue;
            size_t colon = line.rfind(':');
            if (colon == string::npos) continue;

            string ip   = line.substr(0, colon);
            int    port = stoi(line.substr(colon + 1));

            // Check we don't already know this peer
            bool known = false;
            {
                LockGuard lg(peersMutex);
                for (const PeerInfo& p : peers) {
                    if (p.ip == ip && p.port == port) {
                        known = true; break;
                    }
                }
            }

            if (!known) {
                PeerInfo p{};
                p.ip = ip; p.port = port;
                p.connected = false;
                p.sock = INVALID_SOCK;
                {
                    LockGuard lg(peersMutex);
                    peers.push_back(p);
                }
                connectToPeer(peers.back());
                added++;
            }
        }
        if (added > 0)
            cout << "  🌐 Discovered " << added << " new peer(s)" << endl;
    }

    // ── HEARTBEAT ────────────────────────────────────────────

    static void* heartbeatThread(void* arg) {
        P2PNode* node = (P2PNode*)arg;
        while (node->running) {
            sleepMs(HEARTBEAT_INTERVAL);

            LockGuard lg(node->peersMutex);
            for (PeerInfo& p : node->peers) {
                if (!p.connected) {
                    // Try to reconnect dropped peers
                    node->connectToPeer(p);
                    continue;
                }
                // Send heartbeat
                if (!sendMsg(p.sock, MSG_HEARTBEAT, "")) {
                    p.connected = false;
                    cout << "  💔 Lost connection to " << p.address() << endl;
                }
            }
        }
        return nullptr;
    }
};

// ── GLOBAL NODE INSTANCE ─────────────────────────────────────

static P2PNode* gNode = nullptr;

// ── PUBLIC API ───────────────────────────────────────────────
// Call these from your main Crypt-Vault.cpp

void p2p_init(CryptVaultBlockchain* blockchain, int port) {
    gNode = new P2PNode(blockchain, port);
    gNode->start();
}

void p2p_broadcastBlock(Block& block) {
    if (gNode) gNode->broadcastBlock(block);
}

void p2p_status() {
    if (gNode) gNode->printStatus();
    else cout << "  [P2P] Node not running." << endl;
}

int p2p_connectedPeers() {
    if (!gNode) return 0;
    return gNode->getConnectedCount();
}

void p2p_shutdown() {
    if (gNode) {
        gNode->stop();
        delete gNode;
        gNode = nullptr;
        cout << "  [P2P] Node shut down." << endl;
    }
}
