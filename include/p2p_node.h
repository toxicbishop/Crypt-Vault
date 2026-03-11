#pragma once
/*
 * ================================================================
 *  CryptVault — p2p_node.h
 *  Public API header for the P2P network layer
 *
 *  Include this in Crypt-Vault.cpp to use the network layer.
 * ================================================================
 */

#include "../include/blockchain_audit.h"

// ── BLOCK EXTENSIONS ─────────────────────────────────────────
/*
 *  Add these fields to your existing Block struct in blockchain_audit.h:
 *
 *  struct Block {
 *      int         index;
 *      string      previousHash;
 *      string      blockHash;
 *      AuditRecord record;
 *      long long   nonce;
 *      string      signerPublicKey;    ← ADD THIS
 *      string      digitalSignature;  ← ADD THIS
 *  };
 */

// ── BLOCKCHAIN EXTENSIONS ────────────────────────────────────
/*
 *  Add these methods to CryptVaultBlockchain in blockchain_audit.h:
 *
 *  // Validate a single incoming block (fits end of chain?)
 *  bool validateNewBlock(const Block& b) {
 *      if (chain.empty()) return false;
 *      const Block& last = chain.back();
 *      if (b.index != (int)chain.size()) return false;
 *      if (b.previousHash != last.blockHash) return false;
 *      // Verify proof of work
 *      string target(difficulty, '0');
 *      return sha256(const_cast<Block&>(b).toString()).substr(0, difficulty) == target;
 *  }
 *
 *  // Validate an externally received chain
 *  bool validateChainExternal(const vector<Block>& c) {
 *      for (size_t i = 1; i < c.size(); i++) {
 *          if (c[i].previousHash != c[i-1].blockHash) return false;
 *          string recomputed = sha256(const_cast<Block&>(c[i]).toString());
 *          if (recomputed != c[i].blockHash) return false;
 *      }
 *      return true;
 *  }
 *
 *  // Replace our chain with a validated longer one
 *  void replaceChain(const vector<Block>& newChain) {
 *      chain = newChain;
 *      saveChain();
 *  }
 *
 *  // Add a block that was already validated externally
 *  void addVerifiedBlock(const Block& b) {
 *      chain.push_back(b);
 *      saveChain();
 *  }
 *
 *  // Get a copy of the chain for sending to peers
 *  const vector<Block>& getChain() const { return chain; }
 */

// ── PUBLIC P2P API ───────────────────────────────────────────

// Initialize and start the P2P node
// Call once at startup in main()
void p2p_init(CryptVaultBlockchain* blockchain,
              int port = 8333);

// Broadcast a newly mined block to all connected peers
// Call this inside CryptVaultBlockchain::addRecord() after mining
void p2p_broadcastBlock(Block& block);

// Print connection status and peer list
void p2p_status();

// How many peers are currently connected?
int p2p_connectedPeers();

// Cleanly shut down the P2P node
void p2p_shutdown();

// ── HOW TO INTEGRATE INTO Crypt-Vault.cpp ────────────────────
/*
 *  1. In main(), after creating blockchain:
 *
 *     CryptVaultBlockchain blockchain("crypt_audit.chain");
 *     p2p_init(&blockchain, 8333);
 *
 *  2. In CryptVaultBlockchain::addRecord(), after adding block:
 *
 *     chain.push_back(newBlock);
 *     saveChain();
 *     p2p_broadcastBlock(newBlock);   ← add this line
 *     return newBlock;
 *
 *  3. Add to your menu:
 *
 *     case 'N': p2p_status(); break;
 *
 *  4. In your exit/cleanup:
 *
 *     p2p_shutdown();
 *
 *  That's it. The rest is automatic.
 */

// ── peers.txt FORMAT ─────────────────────────────────────────
/*
 *  Place peers.txt next to your binary.
 *  One peer per line: IP:PORT
 *  Lines starting with # are comments.
 *
 *  Example:
 *
 *  # CryptVault Network — Team nodes
 *  192.168.1.10:8333    # Pranav   (Windows)
 *  192.168.1.11:8333    # Rohith   (Windows)
 *  192.168.1.12:8333    # Syed     (Linux)
 *  192.168.1.13:8333    # Supreeth (Linux)
 *
 *  For localhost testing (2 nodes same machine):
 *  127.0.0.1:8334
 *  127.0.0.1:8335
 */
