/*
 * ================================================================
 *  CryptVault — test_p2p_localhost.cpp
 *  Tests two nodes on the same machine before LAN testing
 *
 *  COMPILE:
 *    Windows:
 *      g++ -std=c++17 -O2 -o test_p2p.exe test_p2p_localhost.cpp
 *          blockchain_audit.cpp p2p_node.cpp -lws2_32
 *
 *    Linux:
 *      g++ -std=c++17 -O2 -o test_p2p test_p2p_localhost.cpp
 *          blockchain_audit.cpp p2p_node.cpp -lpthread
 *
 *  RUN (two terminals):
 *    Terminal 1:  ./test_p2p node_a 8333
 *    Terminal 2:  ./test_p2p node_b 8334
 *
 *  WHAT THIS TESTS:
 *    - Node A encrypts a file → broadcasts block
 *    - Node B receives + validates block
 *    - Both nodes show identical chain lengths
 *    - Tamper Node A's chain → Node B rejects it
 * ================================================================
 */

#include "p2p_node.h"
#include "blockchain_audit.h"
#include <iostream>
#include <string>
#include <fstream>
using namespace std;

// Create a peers.txt pointing to the other localhost node
void setupLocalhostPeers(int myPort) {
    int otherPort = (myPort == 8333) ? 8334 : 8333;
    ofstream f("peers.txt");
    f << "# Localhost test peers\n";
    f << "127.0.0.1:" << otherPort << "  # other test node\n";
    f.close();
    cout << "  [TEST] peers.txt → 127.0.0.1:" << otherPort << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: ./test_p2p <node_name> <port>" << endl;
        cout << "  Terminal 1: ./test_p2p node_a 8333" << endl;
        cout << "  Terminal 2: ./test_p2p node_b 8334" << endl;
        return 1;
    }

    string nodeName = argv[1];
    int    port     = stoi(argv[2]);

    // Use separate chain files per node
    string chainFile = "chain_" + nodeName + ".dat";

    cout << "\n  ════════════════════════════════════" << endl;
    cout << "  CRYPTVAULT P2P LOCALHOST TEST" << endl;
    cout << "  Node: " << nodeName << "  Port: " << port << endl;
    cout << "  ════════════════════════════════════\n" << endl;

    // Setup localhost peers.txt
    setupLocalhostPeers(port);

    // Init blockchain
    CryptVaultBlockchain blockchain(chainFile, 2);
    cout << "  Chain loaded: " << blockchain.getChainSize() << " blocks\n";

    // Start P2P node
    p2p_init(&blockchain, port);
    sleepMs(1000);   // wait for connections

    // Interactive test menu
    cout << "\n  TEST MENU:" << endl;
    cout << "  [1] Simulate file encryption (add + broadcast block)" << endl;
    cout << "  [2] View local chain" << endl;
    cout << "  [3] Network status" << endl;
    cout << "  [4] Validate chain integrity" << endl;
    cout << "  [0] Exit\n" << endl;

    int choice;
    int fileCounter = 1;

    do {
        cout << "  > ";
        cin >> choice;

        switch (choice) {
        case 1: {
            // Simulate an encryption operation
            string filename = nodeName + "_file_" +
                              to_string(fileCounter++) + ".txt";

            AuditRecord r;
            r.operation      = Operation::ENCRYPT;
            r.filename       = filename;
            r.fileHash       = sha256(filename + "content");
            r.fileSizeBytes  = 1024 * fileCounter;
            r.durationMs     = 1.5;
            r.hmacVerified   = true;
            r.algorithm      = "AES-256-CBC";

            cout << "\n  Encrypting: " << filename << endl;
            Block b = blockchain.addRecord(r);
            // p2p_broadcastBlock is called inside addRecord()

            cout << "  Block #" << b.index << " mined + broadcast\n" << endl;
            break;
        }
        case 2:
            blockchain.printAuditLog();
            break;
        case 3:
            p2p_status();
            break;
        case 4: {
            bool valid = blockchain.validateChain();
            cout << "  Chain integrity: "
                 << (valid ? "✅ VALID" : "❌ TAMPERED") << "\n" << endl;
            break;
        }
        }
    } while (choice != 0);

    p2p_shutdown();
    return 0;
}
