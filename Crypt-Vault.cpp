/*
 * Crypt Vault — AES-256-CBC Encryption Tool (C++ Version)
 *
 * Features:
 * - AES-256-CBC file & text encryption/decryption
 * - SHA-256 password-based key derivation
 * - PKCS7 padding, random IV via Windows CryptoAPI
 * - Batch processing, file stats, SHA-256 hashing
 * - No external dependencies
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <limits>
#include <ctime>
#include <sys/stat.h>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>  // For _getch() secure password input
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <cstdlib>
#include <termios.h>
#include <unistd.h>
#endif

#include "blockchain_audit.h"

using namespace std;

// ═══════════════════════════════════════════════════════════
// SHA-256 Implementation
// ═══════════════════════════════════════════════════════════

namespace SHA256Impl {
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

    vector<unsigned char> hash(const unsigned char* data, size_t len) {
        uint32 h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        uint64 bitlen = (uint64)len * 8;

        // Padding
        vector<unsigned char> msg(data, data + len);
        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; i--) msg.push_back((unsigned char)(bitlen >> (i * 8)));

        // Process blocks
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

        vector<unsigned char> result(32);
        for (int i = 0; i < 8; i++) {
            result[i*4]=(h[i]>>24)&0xff; result[i*4+1]=(h[i]>>16)&0xff;
            result[i*4+2]=(h[i]>>8)&0xff; result[i*4+3]=h[i]&0xff;
        }
        return result;
    }

    vector<unsigned char> hash(const string& s) {
        return hash((const unsigned char*)s.data(), s.size());
    }

    string toHex(const vector<unsigned char>& h) {
        stringstream ss;
        for (auto b : h) ss << hex << setfill('0') << setw(2) << (int)b;
        return ss.str();
    }
}

// ═══════════════════════════════════════════════════════════
// AES-256 Implementation
// ═══════════════════════════════════════════════════════════

namespace AES256Impl {
    static const unsigned char sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    static const unsigned char rsbox[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    static const unsigned char rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

    static unsigned char xtime(unsigned char x) { return (x<<1) ^ ((x>>7) & 1 ? 0x1b : 0); }
    static unsigned char gmul(unsigned char a, unsigned char b) {
        unsigned char p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return p;
    }

    struct Context {
        unsigned char roundKey[240];
        int Nr; // 14 rounds for AES-256

        void keyExpansion(const unsigned char key[32]) {
            Nr = 14;
            int Nk = 8;
            memcpy(roundKey, key, 32);
            for (int i = Nk; i < 4 * (Nr + 1); i++) {
                unsigned char temp[4];
                memcpy(temp, roundKey + (i-1)*4, 4);
                if (i % Nk == 0) {
                    unsigned char t = temp[0];
                    temp[0] = sbox[temp[1]] ^ rcon[i/Nk];
                    temp[1] = sbox[temp[2]];
                    temp[2] = sbox[temp[3]];
                    temp[3] = sbox[t];
                } else if (i % Nk == 4) {
                    for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
                }
                for (int j = 0; j < 4; j++)
                    roundKey[i*4+j] = roundKey[(i-Nk)*4+j] ^ temp[j];
            }
        }

        void addRoundKey(unsigned char state[4][4], int round) {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[j][i] ^= roundKey[round*16 + i*4 + j];
        }

        void subBytes(unsigned char state[4][4]) {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i][j] = sbox[state[i][j]];
        }

        void invSubBytes(unsigned char state[4][4]) {
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i][j] = rsbox[state[i][j]];
        }

        void shiftRows(unsigned char state[4][4]) {
            unsigned char t;
            t = state[1][0]; state[1][0]=state[1][1]; state[1][1]=state[1][2]; state[1][2]=state[1][3]; state[1][3]=t;
            t = state[2][0]; state[2][0]=state[2][2]; state[2][2]=t; t=state[2][1]; state[2][1]=state[2][3]; state[2][3]=t;
            t = state[3][3]; state[3][3]=state[3][2]; state[3][2]=state[3][1]; state[3][1]=state[3][0]; state[3][0]=t;
        }

        void invShiftRows(unsigned char state[4][4]) {
            unsigned char t;
            t = state[1][3]; state[1][3]=state[1][2]; state[1][2]=state[1][1]; state[1][1]=state[1][0]; state[1][0]=t;
            t = state[2][0]; state[2][0]=state[2][2]; state[2][2]=t; t=state[2][1]; state[2][1]=state[2][3]; state[2][3]=t;
            t = state[3][0]; state[3][0]=state[3][1]; state[3][1]=state[3][2]; state[3][2]=state[3][3]; state[3][3]=t;
        }

        void mixColumns(unsigned char state[4][4]) {
            for (int i = 0; i < 4; i++) {
                unsigned char a[4]; memcpy(a, &state[0][i], 1); a[0]=state[0][i]; a[1]=state[1][i]; a[2]=state[2][i]; a[3]=state[3][i];
                state[0][i] = gmul(a[0],2)^gmul(a[1],3)^a[2]^a[3];
                state[1][i] = a[0]^gmul(a[1],2)^gmul(a[2],3)^a[3];
                state[2][i] = a[0]^a[1]^gmul(a[2],2)^gmul(a[3],3);
                state[3][i] = gmul(a[0],3)^a[1]^a[2]^gmul(a[3],2);
            }
        }

        void invMixColumns(unsigned char state[4][4]) {
            for (int i = 0; i < 4; i++) {
                unsigned char a[4] = {state[0][i],state[1][i],state[2][i],state[3][i]};
                state[0][i] = gmul(a[0],14)^gmul(a[1],11)^gmul(a[2],13)^gmul(a[3],9);
                state[1][i] = gmul(a[0],9)^gmul(a[1],14)^gmul(a[2],11)^gmul(a[3],13);
                state[2][i] = gmul(a[0],13)^gmul(a[1],9)^gmul(a[2],14)^gmul(a[3],11);
                state[3][i] = gmul(a[0],11)^gmul(a[1],13)^gmul(a[2],9)^gmul(a[3],14);
            }
        }

        void encryptBlock(unsigned char block[16]) {
            unsigned char state[4][4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[j][i] = block[i*4+j];

            addRoundKey(state, 0);
            for (int round = 1; round < Nr; round++) {
                subBytes(state); shiftRows(state); mixColumns(state); addRoundKey(state, round);
            }
            subBytes(state); shiftRows(state); addRoundKey(state, Nr);

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    block[i*4+j] = state[j][i];
        }

        void decryptBlock(unsigned char block[16]) {
            unsigned char state[4][4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[j][i] = block[i*4+j];

            addRoundKey(state, Nr);
            for (int round = Nr - 1; round > 0; round--) {
                invShiftRows(state); invSubBytes(state); addRoundKey(state, round); invMixColumns(state);
            }
            invShiftRows(state); invSubBytes(state); addRoundKey(state, 0);

            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    block[i*4+j] = state[j][i];
        }
    };
}

// ═══════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════

bool generateRandomBytes(unsigned char* buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    BOOL result = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);
    return result != 0;
#else
    ifstream rnd("/dev/urandom", ios::binary);
    if (!rnd.is_open()) return false;
    rnd.read((char*)buf, len);
    return rnd.good();
#endif
}

vector<unsigned char> pkcs7Pad(const vector<unsigned char>& data) {
    size_t padLen = 16 - (data.size() % 16);
    vector<unsigned char> padded = data;
    padded.insert(padded.end(), padLen, (unsigned char)padLen);
    return padded;
}

bool pkcs7Unpad(vector<unsigned char>& data) {
    if (data.empty() || data.size() % 16 != 0) return false;
    unsigned char pad = data.back();
    if (pad < 1 || pad > 16) return false;
    for (size_t i = data.size() - pad; i < data.size(); i++)
        if (data[i] != pad) return false;
    data.resize(data.size() - pad);
    return true;
}

string bytesToHex(const unsigned char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; i++) ss << hex << setfill('0') << setw(2) << (int)data[i];
    return ss.str();
}

vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned char b = (unsigned char)strtol(hex.substr(i, 2).c_str(), nullptr, 16);
        bytes.push_back(b);
    }
    return bytes;
}

// ═══════════════════════════════════════════════════════════
// Security Primitives (HMAC, PBKDF2, Memory Safety)
// ═══════════════════════════════════════════════════════════

// Secure memory wipe - prevents compiler optimization
void secure_memzero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

// Constant-time comparison to prevent timing attacks
bool constant_time_compare(const unsigned char* a, const unsigned char* b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// HMAC-SHA256 implementation
vector<unsigned char> hmac_sha256(const unsigned char* key, size_t keyLen, 
                                   const unsigned char* data, size_t dataLen) {
    const size_t BLOCK_SIZE = 64;
    unsigned char keyBlock[BLOCK_SIZE] = {0};
    
    // If key > block size, hash it first
    if (keyLen > BLOCK_SIZE) {
        auto h = SHA256Impl::hash(key, keyLen);
        memcpy(keyBlock, h.data(), 32);
    } else {
        memcpy(keyBlock, key, keyLen);
    }
    
    // Create inner and outer padded keys
    unsigned char ipad[BLOCK_SIZE], opad[BLOCK_SIZE];
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = keyBlock[i] ^ 0x36;
        opad[i] = keyBlock[i] ^ 0x5c;
    }
    
    // Inner hash: H(ipad || data)
    vector<unsigned char> inner(ipad, ipad + BLOCK_SIZE);
    inner.insert(inner.end(), data, data + dataLen);
    auto innerHash = SHA256Impl::hash(inner.data(), inner.size());
    
    // Outer hash: H(opad || innerHash)
    vector<unsigned char> outer(opad, opad + BLOCK_SIZE);
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());
    
    return SHA256Impl::hash(outer.data(), outer.size());
}

// PBKDF2-SHA256 key derivation
void pbkdf2_sha256(const string& password, const unsigned char* salt, size_t saltLen,
                   int iterations, unsigned char* output, size_t dkLen) {
    const size_t HASH_LEN = 32;
    size_t blocks = (dkLen + HASH_LEN - 1) / HASH_LEN;
    
    for (size_t block = 1; block <= blocks; block++) {
        // U1 = HMAC(password, salt || INT(block))
        vector<unsigned char> saltBlock(salt, salt + saltLen);
        saltBlock.push_back((block >> 24) & 0xFF);
        saltBlock.push_back((block >> 16) & 0xFF);
        saltBlock.push_back((block >> 8) & 0xFF);
        saltBlock.push_back(block & 0xFF);
        
        auto U = hmac_sha256((unsigned char*)password.data(), password.size(),
                             saltBlock.data(), saltBlock.size());
        vector<unsigned char> T = U;
        
        // Iterate: T = U1 ^ U2 ^ ... ^ Uc
        for (int i = 1; i < iterations; i++) {
            U = hmac_sha256((unsigned char*)password.data(), password.size(),
                           U.data(), U.size());
            for (size_t j = 0; j < HASH_LEN; j++) T[j] ^= U[j];
        }
        
        // Copy result block
        size_t offset = (block - 1) * HASH_LEN;
        size_t copyLen = min(HASH_LEN, dkLen - offset);
        memcpy(output + offset, T.data(), copyLen);
    }
}

// ═══════════════════════════════════════════════════════════
// AES Cipher Class (PBKDF2 + HMAC-SHA256 Authentication)
// File format: salt(16) + iv(16) + ciphertext + hmac(32)
// ═══════════════════════════════════════════════════════════

class AESCipher {
private:
    string storedPassword;
    unsigned char encKey[32];
    unsigned char authKey[32];
    AES256Impl::Context ctx;
    
    static const int SALT_SIZE = 16;
    static const int IV_SIZE = 16;
    static const int HMAC_SIZE = 32;
    static const int PBKDF2_ITERATIONS = 100000;

    // Derive encryption and authentication keys from password + salt
    void deriveKeys(const unsigned char* salt) {
        unsigned char derived[64];
        pbkdf2_sha256(storedPassword, salt, SALT_SIZE, PBKDF2_ITERATIONS, derived, 64);
        memcpy(encKey, derived, 32);      // First 32 bytes for encryption
        memcpy(authKey, derived + 32, 32); // Last 32 bytes for authentication
        secure_memzero(derived, 64);
        ctx.keyExpansion(encKey);
    }

    // Compute HMAC over salt + iv + ciphertext
    vector<unsigned char> computeHMAC(const unsigned char* data, size_t len) {
        return hmac_sha256(authKey, 32, data, len);
    }

    // Constant-time HMAC verification
    bool verifyHMAC(const unsigned char* data, size_t dataLen, const unsigned char* expectedHmac) {
        auto computed = computeHMAC(data, dataLen);
        return constant_time_compare(computed.data(), expectedHmac, HMAC_SIZE);
    }

public:
    void setKey(const string& password) {
        storedPassword = password;
    }

    vector<unsigned char> encrypt(const vector<unsigned char>& plaintext) {
        // Generate random salt and IV
        unsigned char salt[SALT_SIZE];
        unsigned char iv[IV_SIZE];
        if (!generateRandomBytes(salt, SALT_SIZE) || !generateRandomBytes(iv, IV_SIZE)) {
            cerr << "Error: Could not generate random salt/IV" << endl;
            return {};
        }

        // Derive keys from password + salt
        deriveKeys(salt);

        // Pad plaintext
        auto padded = pkcs7Pad(plaintext);

        // Build result: salt + iv + ciphertext (HMAC added at end)
        vector<unsigned char> result;
        result.insert(result.end(), salt, salt + SALT_SIZE);
        result.insert(result.end(), iv, iv + IV_SIZE);

        // CBC encrypt
        unsigned char prev[16];
        memcpy(prev, iv, 16);
        for (size_t i = 0; i < padded.size(); i += 16) {
            unsigned char block[16];
            for (int j = 0; j < 16; j++) block[j] = padded[i+j] ^ prev[j];
            ctx.encryptBlock(block);
            result.insert(result.end(), block, block + 16);
            memcpy(prev, block, 16);
        }

        // Compute and append HMAC over salt + iv + ciphertext
        auto hmac = computeHMAC(result.data(), result.size());
        result.insert(result.end(), hmac.begin(), hmac.end());

        // Secure cleanup
        secure_memzero(salt, SALT_SIZE);
        secure_memzero(iv, IV_SIZE);
        
        return result;
    }

    vector<unsigned char> decrypt(const vector<unsigned char>& ciphertext) {
        // Minimum size: salt(16) + iv(16) + one block(16) + hmac(32) = 80 bytes
        if (ciphertext.size() < 80) return {};
        
        size_t dataLen = ciphertext.size() - HMAC_SIZE;
        if ((dataLen - SALT_SIZE - IV_SIZE) % 16 != 0) return {};

        // Extract components
        const unsigned char* salt = ciphertext.data();
        const unsigned char* iv = ciphertext.data() + SALT_SIZE;
        const unsigned char* encData = ciphertext.data() + SALT_SIZE + IV_SIZE;
        const unsigned char* hmac = ciphertext.data() + dataLen;
        size_t encLen = dataLen - SALT_SIZE - IV_SIZE;

        // Derive keys from password + salt
        deriveKeys(salt);

        // Verify HMAC BEFORE decryption (Encrypt-then-MAC)
        if (!verifyHMAC(ciphertext.data(), dataLen, hmac)) {
            cerr << "\n❌ HMAC verification failed - file tampered or wrong password" << endl;
            return {};
        }

        // CBC decrypt
        vector<unsigned char> result;
        unsigned char prev[16];
        memcpy(prev, iv, 16);

        for (size_t i = 0; i < encLen; i += 16) {
            unsigned char block[16];
            memcpy(block, encData + i, 16);
            unsigned char enc[16];
            memcpy(enc, block, 16);
            ctx.decryptBlock(block);
            for (int j = 0; j < 16; j++) block[j] ^= prev[j];
            result.insert(result.end(), block, block + 16);
            memcpy(prev, enc, 16);
        }

        if (!pkcs7Unpad(result)) return {};
        return result;
    }

    bool encryptFile(const string& inputFile, const string& outputFile) {
        ifstream in(inputFile, ios::binary);
        if (!in.is_open()) { cerr << "\n❌ Error: Cannot open '" << inputFile << "'" << endl; return false; }
        vector<unsigned char> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();

        auto enc = encrypt(data);
        if (enc.empty()) { cerr << "\n❌ Encryption failed" << endl; return false; }

        ofstream out(outputFile, ios::binary);
        if (!out.is_open()) { cerr << "\n❌ Error: Cannot create '" << outputFile << "'" << endl; return false; }
        out.write((char*)enc.data(), enc.size());
        out.close();
        return true;
    }

    bool decryptFile(const string& inputFile, const string& outputFile) {
        ifstream in(inputFile, ios::binary);
        if (!in.is_open()) { cerr << "\n❌ Error: Cannot open '" << inputFile << "'" << endl; return false; }
        vector<unsigned char> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();

        auto dec = decrypt(data);
        if (dec.empty()) { cerr << "\n❌ Decryption failed (wrong password or corrupt file)" << endl; return false; }

        ofstream out(outputFile, ios::binary);
        if (!out.is_open()) { cerr << "\n❌ Error: Cannot create '" << outputFile << "'" << endl; return false; }
        out.write((char*)dec.data(), dec.size());
        out.close();
        return true;
    }

    string encryptText(const string& text) {
        vector<unsigned char> data(text.begin(), text.end());
        auto enc = encrypt(data);
        return bytesToHex(enc.data(), enc.size());
    }

    string decryptText(const string& hexCipher) {
        auto data = hexToBytes(hexCipher);
        auto dec = decrypt(data);
        if (dec.empty()) return "";
        return string(dec.begin(), dec.end());
    }

    void displayFileContent(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) { cerr << "\n❌ Error: Cannot open '" << filename << "'" << endl; return; }
        cout << "\n📄 Content of '" << filename << "':" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        string line; int lineCount = 0;
        while (getline(file, line) && lineCount < 50) { cout << line << endl; lineCount++; }
        if (!file.eof()) cout << "\n... (truncated, showing first 50 lines) ..." << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        file.close();
    }

    void showFileStats(const string& filename) {
        struct stat st;
        if (stat(filename.c_str(), &st) != 0) { cerr << "\n❌ Error: Cannot stat '" << filename << "'" << endl; return; }
        ifstream file(filename, ios::binary);
        if (!file.is_open()) return;
        int charCount=0, letterCount=0, numberCount=0, lineCount=0;
        char ch;
        while (file.get(ch)) {
            charCount++;
            if (isalpha((unsigned char)ch)) letterCount++;
            if (isdigit((unsigned char)ch)) numberCount++;
            if (ch == '\n') lineCount++;
        }
        file.close();
        cout << "\n📈 File Statistics for '" << filename << "':" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "📏 File size:      " << st.st_size << " bytes" << endl;
        cout << "📝 Total chars:    " << charCount << endl;
        cout << "🔤 Letters:        " << letterCount << endl;
        cout << "🔢 Numbers:        " << numberCount << endl;
        cout << "📄 Lines:          " << lineCount << endl;
    }

    string hashFile(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file.is_open()) return "";
        vector<unsigned char> data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
        return SHA256Impl::toHex(SHA256Impl::hash(data.data(), data.size()));
    }
};

// ═══════════════════════════════════════════════════════════
// File Helper
// ═══════════════════════════════════════════════════════════

class FileHelper {
public:
    static string addEncExtension(const string& f) { return f + ".enc"; }
    static string removeEncExtension(const string& f) {
        if (f.length() > 4 && f.substr(f.length()-4) == ".enc") return f.substr(0, f.length()-4);
        return f;
    }
    static bool hasEncExtension(const string& f) { return f.length() > 4 && f.substr(f.length()-4) == ".enc"; }
    static bool fileExists(const string& f) { ifstream file(f); return file.good(); }
};

// ═══════════════════════════════════════════════════════════
// Application Class
// ═══════════════════════════════════════════════════════════

class CryptVaultApp {
private:
    AESCipher cipher;
    CryptVaultBlockchain blockchain;  // Blockchain audit logging

    void getLineTrim(string& s) {
        getline(cin, s);
        while (!s.empty() && (s.back() == '\r' || s.back() == ' ')) s.pop_back();
    }

    void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }

    void enableVirtualTerminal() {
        #ifdef _WIN32
        // Enable UTF-8 console output
        SetConsoleOutputCP(65001);
        // Enable ANSI escape sequences
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
            SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        #endif
    }

    void displayBanner() {
        // ANSI color codes for styling
        const string ORANGE = "\033[38;5;208m";
        const string GRAY = "\033[38;5;245m";
        const string CYAN = "\033[38;5;44m";
        const string RESET = "\033[0m";
        const string BOLD = "\033[1m";

        cout << ORANGE;
        cout << R"(
   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗    ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝    ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║       ██║   ██║███████║██║   ██║██║     ██║   
  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║       ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
  ╚██████╗██║  ██║   ██║   ██║        ██║        ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝         ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
)" << RESET << endl;
        cout << GRAY << "                    AES-256-CBC Encryption Tool • Secure File Protection" << RESET << endl;
        cout << GRAY << "             SHA-256 Key Derivation • PKCS7 Padding • Windows CryptoAPI" << RESET << endl;
        cout << endl;
    }

    void displayMenu() {
        // ANSI color codes
        const string CYAN = "\033[38;5;44m";
        const string GREEN = "\033[38;5;82m";
        const string YELLOW = "\033[38;5;220m";
        const string GRAY = "\033[38;5;245m";
        const string WHITE = "\033[38;5;255m";
        const string RESET = "\033[0m";

        displayBanner();

        cout << GRAY << "  Type a " << CYAN << "number" << GRAY << " to select a command" << RESET << endl;
        cout << GRAY << "  Press " << CYAN << "11" << GRAY << " to exit the application" << RESET << endl;
        cout << endl;
        cout << GREEN << "  →" << RESET << endl;
        cout << endl;

        cout << WHITE << "  ─── CORE OPERATIONS ───────────────────────────────────────" << RESET << endl;
        cout << CYAN << "   1" << GRAY << "  encrypt    " << WHITE << "Encrypt a file with AES-256" << RESET << endl;
        cout << CYAN << "   2" << GRAY << "  decrypt    " << WHITE << "Decrypt an encrypted file" << RESET << endl;
        cout << CYAN << "   3" << GRAY << "  enc-text   " << WHITE << "Quick text encryption" << RESET << endl;
        cout << CYAN << "   4" << GRAY << "  dec-text   " << WHITE << "Quick text decryption" << RESET << endl;
        cout << endl;

        cout << WHITE << "  ─── BATCH OPERATIONS ──────────────────────────────────────" << RESET << endl;
        cout << CYAN << "   5" << GRAY << "  batch-enc  " << WHITE << "Encrypt multiple files at once" << RESET << endl;
        cout << CYAN << "   6" << GRAY << "  batch-dec  " << WHITE << "Decrypt multiple files at once" << RESET << endl;
        cout << endl;

        cout << WHITE << "  ─── UTILITIES ─────────────────────────────────────────────" << RESET << endl;
        cout << CYAN << "   7" << GRAY << "  view       " << WHITE << "View file content" << RESET << endl;
        cout << CYAN << "   8" << GRAY << "  stats      " << WHITE << "Show file statistics" << RESET << endl;
        cout << CYAN << "   9" << GRAY << "  hash       " << WHITE << "Calculate SHA-256 hash" << RESET << endl;
        cout << CYAN << "  10" << GRAY << "  audit      " << WHITE << "Blockchain audit log" << RESET << endl;
        cout << CYAN << "  11" << GRAY << "  about      " << WHITE << "About Crypt Vault" << RESET << endl;
        cout << CYAN << "  12" << GRAY << "  exit       " << YELLOW << "Exit application" << RESET << endl;
        cout << endl;
        cout << GRAY << "  ─────────────────────────────────────────────────────────────" << RESET << endl;
        cout << endl;
    }

    // Secure password input - masks characters with asterisks
    string getSecureInput() {
        string input;
#ifdef _WIN32
        char ch;
        while ((ch = _getch()) != '\r' && ch != '\n') {
            if (ch == '\b' || ch == 127) {  // Backspace
                if (!input.empty()) {
                    input.pop_back();
                    cout << "\b \b" << flush;  // Erase asterisk
                }
            } else if (ch >= 32) {  // Printable characters
                input += ch;
                cout << '*' << flush;
            }
        }
        cout << endl;
#else
        // POSIX: disable echo
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ECHO | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        
        char ch;
        while (read(STDIN_FILENO, &ch, 1) == 1 && ch != '\n' && ch != '\r') {
            if (ch == 127 || ch == '\b') {  // Backspace
                if (!input.empty()) {
                    input.pop_back();
                    cout << "\b \b" << flush;
                }
            } else if (ch >= 32) {
                input += ch;
                cout << '*' << flush;
            }
        }
        cout << endl;
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);  // Restore terminal
#endif
        return input;
    }

    string getPassword(const string& prompt = "Enter password: ") {
        cout << prompt << flush;
        string password = getSecureInput();
        
        if (password.empty()) { cout << "❌ Password cannot be empty." << endl; return ""; }

        // Password strength indicator
        int score = 0;
        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;
        bool hasUpper=false, hasLower=false, hasDigit=false, hasSpecial=false;
        for (char c : password) {
            if (isupper(c)) hasUpper=true;
            else if (islower(c)) hasLower=true;
            else if (isdigit(c)) hasDigit=true;
            else hasSpecial=true;
        }
        if (hasUpper && hasLower) score++;
        if (hasDigit) score++;
        if (hasSpecial) score++;

        string strength;
        if (score <= 1) strength = "🔴 Weak";
        else if (score <= 3) strength = "🟡 Medium";
        else strength = "🟢 Strong";
        cout << "   Password strength: " << strength << endl;

        return password;
    }

    // Password with confirmation - for encryption operations
    string getPasswordWithConfirmation() {
        string password = getPassword("Enter password: ");
        if (password.empty()) return "";
        
        cout << "Confirm password: " << flush;
        string confirm = getSecureInput();
        
        if (password != confirm) {
            cout << "❌ Passwords do not match!" << endl;
            return "";
        }
        cout << "   ✓ Passwords match" << endl;
        return password;
    }

    void batchEncrypt() {
        cout << "\n📂 BATCH ENCRYPT FILES" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        int numFiles;
        cout << "How many files to encrypt? ";
        if (!(cin >> numFiles) || numFiles < 1) {
            cout << "❌ Invalid number." << endl;
            cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); return;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        string pw = getPasswordWithConfirmation();
        if (pw.empty()) return;
        cipher.setKey(pw);

        vector<string> files(numFiles);
        for (int i = 0; i < numFiles; i++) { cout << "Enter filename " << (i+1) << ": "; getLineTrim(files[i]); }

        cout << "\n🔄 Processing..." << endl;
        int ok = 0;
        for (const auto& f : files) {
            if (FileHelper::fileExists(f)) {
                clock_t t = clock();
                if (cipher.encryptFile(f, FileHelper::addEncExtension(f))) {
                    cout << "✅ " << f << " → " << FileHelper::addEncExtension(f)
                         << " (" << fixed << setprecision(4) << (double)(clock()-t)/CLOCKS_PER_SEC << "s)" << endl;
                    ok++;
                }
            } else cout << "❌ " << f << " (not found)" << endl;
        }
        cout << "\n🎉 Done! " << ok << "/" << numFiles << " files encrypted." << endl;
    }

    void batchDecrypt() {
        cout << "\n📂 BATCH DECRYPT FILES" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        int numFiles;
        cout << "How many files to decrypt? ";
        if (!(cin >> numFiles) || numFiles < 1) {
            cout << "❌ Invalid number." << endl;
            cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); return;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        string pw = getPassword();
        if (pw.empty()) return;
        cipher.setKey(pw);

        vector<string> files(numFiles);
        for (int i = 0; i < numFiles; i++) { cout << "Enter filename " << (i+1) << ": "; getLineTrim(files[i]); }

        cout << "\n🔄 Processing..." << endl;
        int ok = 0;
        for (const auto& f : files) {
            string outF = FileHelper::hasEncExtension(f) ? FileHelper::removeEncExtension(f) : "decrypted_" + f;
            if (FileHelper::fileExists(f)) {
                clock_t t = clock();
                if (cipher.decryptFile(f, outF)) {
                    cout << "✅ " << f << " → " << outF
                         << " (" << fixed << setprecision(4) << (double)(clock()-t)/CLOCKS_PER_SEC << "s)" << endl;
                    ok++;
                }
            } else cout << "❌ " << f << " (not found)" << endl;
        }
        cout << "\n🎉 Done! " << ok << "/" << numFiles << " files decrypted." << endl;
    }

    void displayAuditMenu() {
        const string CYAN = "\033[38;5;44m";
        const string GREEN = "\033[38;5;82m";
        const string GRAY = "\033[38;5;245m";
        const string WHITE = "\033[38;5;255m";
        const string RESET = "\033[0m";

        cout << "\n" << WHITE << "  ─── BLOCKCHAIN AUDIT LOG ───\n" << RESET << endl;
        cout << CYAN << "   1" << GRAY << "  view       " << WHITE << "Display full audit log" << RESET << endl;
        cout << CYAN << "   2" << GRAY << "  validate   " << WHITE << "Validate chain integrity" << RESET << endl;
        cout << CYAN << "   3" << GRAY << "  search     " << WHITE << "Search by filename" << RESET << endl;
        cout << CYAN << "   4" << GRAY << "  stats      " << WHITE << "View audit statistics" << RESET << endl;
        cout << CYAN << "   5" << GRAY << "  export     " << WHITE << "Export HTML report" << RESET << endl;
        cout << CYAN << "   0" << GRAY << "  back       " << WHITE << "Return to main menu" << RESET << endl;
        cout << endl;

        int choice;
        cout << GRAY << "  Selection: " << RESET; cin >> choice; cin.ignore();

        switch (choice) {
            case 1:
                blockchain.printAuditLog();
                break;
            case 2:
                cout << "\n  Validating blockchain integrity..." << endl;
                if (blockchain.validateChain())
                    cout << "  ✅ Chain is VALID — No tampering detected" << endl;
                else
                    cout << "  ❌ Chain is INVALID — TAMPERING DETECTED!" << endl;
                break;
            case 3: {
                string fname;
                cout << "\n  Enter filename to search: ";
                getLineTrim(fname);
                blockchain.searchByFile(fname);
                break;
            }
            case 4:
                blockchain.printStats();
                break;
            case 5:
                blockchain.exportHTMLReport("audit_report.html");
                break;
        }
    }

    void showAbout() {
        cout << "\n📚 ABOUT CRYPT VAULT" << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
        cout << "\nCrypt Vault uses AES-256-CBC, an industry-standard" << endl;
        cout << "symmetric encryption algorithm used by governments" << endl;
        cout << "and financial institutions worldwide." << endl << endl;
        cout << "🔑 How it works:" << endl;
        cout << "  1. Your password is hashed via SHA-256 → 256-bit key" << endl;
        cout << "  2. A random 16-byte IV is generated per encryption" << endl;
        cout << "  3. Data is padded (PKCS7) and encrypted in CBC mode" << endl;
        cout << "  4. IV is prepended to the ciphertext (not secret)" << endl << endl;
        cout << "✅ Security features:" << endl;
        cout << "  • AES-256: 2^256 possible keys (unbreakable by brute force)" << endl;
        cout << "  • CBC mode: each block depends on the previous" << endl;
        cout << "  • Random IV: same plaintext encrypts differently each time" << endl;
        cout << "  • PKCS7 padding: handles arbitrary-length data" << endl << endl;
        cout << "⚠️  Remember: security depends on your password strength!" << endl;
    }

public:
    void run() {
        enableVirtualTerminal();
        
        // ANSI color codes
        const string CYAN = "\033[38;5;44m";
        const string GREEN = "\033[38;5;82m";
        const string RED = "\033[38;5;196m";
        const string YELLOW = "\033[38;5;220m";
        const string GRAY = "\033[38;5;245m";
        const string RESET = "\033[0m";
        
        int choice;
        string inputFile, outputFile, text, pw;

        while (true) {
            clearScreen();
            displayMenu();
            cout << GREEN << "  → " << RESET;
            if (!(cin >> choice)) {
                cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << RED << "\n  ✗ Invalid input! Press Enter to continue..." << RESET; cin.get(); continue;
            }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            if (choice == 12) { 
                cout << CYAN << "\n  ✓ Thank you for using Crypt Vault. Goodbye!\n" << RESET << endl;
                break; 
            }

            switch (choice) {
                case 1: { // Encrypt file
                    cout << CYAN << "\n  ─── ENCRYPT FILE ───\n" << RESET << endl;
                    cout << GRAY << "  input file  → " << RESET; getLineTrim(inputFile);
                    cout << GRAY << "  output file → " << RESET; getLineTrim(outputFile);
                    if (outputFile.empty()) { outputFile = FileHelper::addEncExtension(inputFile); cout << GRAY << "  (auto: " << outputFile << ")" << RESET << endl; }
                    pw = getPasswordWithConfirmation();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    clock_t start = clock();
                    if (cipher.encryptFile(inputFile, outputFile)) {
                        double duration = (double)(clock()-start)/CLOCKS_PER_SEC;
                        cout << GREEN << "\n  ✓ File encrypted successfully!" << RESET << endl;
                        cout << GRAY << "  ⏱ Time: " << fixed << setprecision(4) << duration << "s" << RESET << endl;
                        cipher.showFileStats(outputFile);
                        
                        // Log to blockchain
                        string fileHash = cipher.hashFile(inputFile);
                        struct stat st;
                        long long fileSize = (stat(inputFile.c_str(), &st) == 0) ? st.st_size : 0;
                        logEncryption(blockchain, inputFile, fileHash, fileSize, duration * 1000, true);
                    }
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                }
                case 2: { // Decrypt file
                    cout << CYAN << "\n  ─── DECRYPT FILE ───\n" << RESET << endl;
                    cout << GRAY << "  input file  → " << RESET; getLineTrim(inputFile);
                    cout << GRAY << "  output file → " << RESET; getLineTrim(outputFile);
                    if (outputFile.empty()) {
                        outputFile = FileHelper::hasEncExtension(inputFile) ? FileHelper::removeEncExtension(inputFile) : "decrypted.txt";
                        cout << GRAY << "  (auto: " << outputFile << ")" << RESET << endl;
                    }
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    clock_t start = clock();
                    if (cipher.decryptFile(inputFile, outputFile)) {
                        double duration = (double)(clock()-start)/CLOCKS_PER_SEC;
                        cout << GREEN << "\n  ✓ File decrypted successfully!" << RESET << endl;
                        cout << GRAY << "  ⏱ Time: " << fixed << setprecision(4) << duration << "s" << RESET << endl;
                        cipher.showFileStats(outputFile);
                        
                        // Log to blockchain
                        string fileHash = cipher.hashFile(outputFile);
                        struct stat st;
                        long long fileSize = (stat(outputFile.c_str(), &st) == 0) ? st.st_size : 0;
                        logDecryption(blockchain, inputFile, fileHash, fileSize, duration * 1000, true);
                    }
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                }
                case 3: // Encrypt text
                    cout << CYAN << "\n  ─── ENCRYPT TEXT ───\n" << RESET << endl;
                    cout << GRAY << "  plaintext → " << RESET; getLineTrim(text);
                    pw = getPasswordWithConfirmation();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    cout << GREEN << "\n  ✓ Encrypted: " << RESET << cipher.encryptText(text) << endl;
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 4: // Decrypt text
                    cout << CYAN << "\n  ─── DECRYPT TEXT ───\n" << RESET << endl;
                    cout << GRAY << "  ciphertext (hex) → " << RESET; getLineTrim(text);
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    { string result = cipher.decryptText(text);
                      if (result.empty()) cout << RED << "\n  ✗ Decryption failed (wrong password or invalid data)" << RESET << endl;
                      else cout << GREEN << "\n  ✓ Decrypted: " << RESET << result << endl;
                    }
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 5: batchEncrypt(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 6: batchDecrypt(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 7: // View file
                    cout << CYAN << "\n  ─── VIEW FILE ───\n" << RESET << endl;
                    cout << GRAY << "  filename → " << RESET; getLineTrim(inputFile);
                    cipher.displayFileContent(inputFile);
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 8: // File stats
                    cout << CYAN << "\n  ─── FILE STATISTICS ───\n" << RESET << endl;
                    cout << GRAY << "  filename → " << RESET; getLineTrim(inputFile);
                    cipher.showFileStats(inputFile);
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 9: // SHA-256 hash
                    cout << CYAN << "\n  ─── SHA-256 HASH ───\n" << RESET << endl;
                    cout << GRAY << "  filename → " << RESET; getLineTrim(inputFile);
                    { string h = cipher.hashFile(inputFile);
                      if (h.empty()) cerr << RED << "\n  ✗ Cannot open file." << RESET << endl;
                      else cout << GREEN << "\n  ✓ SHA-256: " << RESET << h << endl;
                    }
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 10: displayAuditMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                case 11: showAbout(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                default:
                    cout << RED << "\n  ✗ Invalid choice! Please select 1-12." << RESET << endl;
                    cout << GRAY << "  Press Enter to continue..." << RESET; cin.get();
            }
        }
    }
};

// Program Entry Point
int main() {
    CryptVaultApp app;
    app.run();
    return 0;
}