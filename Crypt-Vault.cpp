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
#else
#include <cstdlib>
#endif

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
// AES Cipher Class
// ═══════════════════════════════════════════════════════════

class AESCipher {
private:
    unsigned char key[32];
    AES256Impl::Context ctx;

public:
    void setKey(const string& password) {
        auto hash = SHA256Impl::hash(password);
        memcpy(key, hash.data(), 32);
        ctx.keyExpansion(key);
    }

    vector<unsigned char> encrypt(const vector<unsigned char>& plaintext) {
        auto padded = pkcs7Pad(plaintext);
        unsigned char iv[16];
        if (!generateRandomBytes(iv, 16)) {
            cerr << "Error: Could not generate random IV" << endl;
            return {};
        }

        vector<unsigned char> result(iv, iv + 16);
        unsigned char prev[16];
        memcpy(prev, iv, 16);

        for (size_t i = 0; i < padded.size(); i += 16) {
            unsigned char block[16];
            for (int j = 0; j < 16; j++) block[j] = padded[i+j] ^ prev[j];
            ctx.encryptBlock(block);
            result.insert(result.end(), block, block + 16);
            memcpy(prev, block, 16);
        }
        return result;
    }

    vector<unsigned char> decrypt(const vector<unsigned char>& ciphertext) {
        if (ciphertext.size() < 32 || (ciphertext.size() - 16) % 16 != 0) return {};

        unsigned char prev[16];
        memcpy(prev, ciphertext.data(), 16);

        vector<unsigned char> result;
        for (size_t i = 16; i < ciphertext.size(); i += 16) {
            unsigned char block[16];
            memcpy(block, &ciphertext[i], 16);
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

    void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }

    void displayMenu() {
        cout << "\n";
        cout << "╔════════════════════════════════════════════════════╗" << endl;
        cout << "║                                                    ║" << endl;
        cout << "║     🔐 CRYPT VAULT — AES-256 ENCRYPTION 🔐       ║" << endl;
        cout << "║                                                    ║" << endl;
        cout << "╚════════════════════════════════════════════════════╝" << endl << endl;
        cout << "  📝 CORE OPERATIONS" << endl;
        cout << "  1. 🔒 Encrypt a file" << endl;
        cout << "  2. 🔓 Decrypt a file" << endl;
        cout << "  3. 🔤 Encrypt text (quick)" << endl;
        cout << "  4. 🔤 Decrypt text (quick)" << endl << endl;
        cout << "  📦 BATCH OPERATIONS" << endl;
        cout << "  5. 📂 Batch encrypt multiple files" << endl;
        cout << "  6. 📂 Batch decrypt multiple files" << endl << endl;
        cout << "  🛠️  UTILITIES" << endl;
        cout << "  7. 👁️  View file content" << endl;
        cout << "  8. 📈 File statistics" << endl;
        cout << "  9. #️⃣  SHA-256 file hash" << endl;
        cout << "  10. 📚 About Crypt Vault" << endl;
        cout << "  11. 🚪 Exit" << endl << endl;
        cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl << endl;
    }

    string getPassword(const string& prompt = "Enter password: ") {
        string password;
        cout << prompt;
        getline(cin, password);
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

        string pw = getPassword();
        if (pw.empty()) return;
        cipher.setKey(pw);

        vector<string> files(numFiles);
        for (int i = 0; i < numFiles; i++) { cout << "Enter filename " << (i+1) << ": "; getline(cin, files[i]); }

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
        for (int i = 0; i < numFiles; i++) { cout << "Enter filename " << (i+1) << ": "; getline(cin, files[i]); }

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
        int choice;
        string inputFile, outputFile, text, pw;

        while (true) {
            clearScreen();
            displayMenu();
            cout << "Enter your choice (1-11): ";
            if (!(cin >> choice)) {
                cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "\n❌ Invalid input! Press Enter to continue..."; cin.get(); continue;
            }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            if (choice == 11) { cout << "\n👋 Thank you for using Crypt Vault! Goodbye!" << endl; break; }

            switch (choice) {
                case 1: { // Encrypt file
                    cout << "\n📝 ENCRYPT FILE" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter input filename: "; getline(cin, inputFile);
                    cout << "Enter output filename (or Enter for auto): "; getline(cin, outputFile);
                    if (outputFile.empty()) { outputFile = FileHelper::addEncExtension(inputFile); cout << "Output: " << outputFile << endl; }
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    clock_t start = clock();
                    if (cipher.encryptFile(inputFile, outputFile)) {
                        cout << "\n✅ File encrypted successfully!" << endl;
                        cout << "⏱️  Time: " << fixed << setprecision(4) << (double)(clock()-start)/CLOCKS_PER_SEC << " seconds" << endl;
                        cipher.showFileStats(outputFile);
                    }
                    cout << "\nPress Enter to continue..."; cin.get(); break;
                }
                case 2: { // Decrypt file
                    cout << "\n🔓 DECRYPT FILE" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter input filename: "; getline(cin, inputFile);
                    cout << "Enter output filename (or Enter for auto): "; getline(cin, outputFile);
                    if (outputFile.empty()) {
                        outputFile = FileHelper::hasEncExtension(inputFile) ? FileHelper::removeEncExtension(inputFile) : "decrypted.txt";
                        cout << "Output: " << outputFile << endl;
                    }
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    clock_t start = clock();
                    if (cipher.decryptFile(inputFile, outputFile)) {
                        cout << "\n✅ File decrypted successfully!" << endl;
                        cout << "⏱️  Time: " << fixed << setprecision(4) << (double)(clock()-start)/CLOCKS_PER_SEC << " seconds" << endl;
                        cipher.showFileStats(outputFile);
                    }
                    cout << "\nPress Enter to continue..."; cin.get(); break;
                }
                case 3: // Encrypt text
                    cout << "\n🔤 ENCRYPT TEXT" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter text to encrypt: "; getline(cin, text);
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    cout << "\n🔒 Encrypted (hex): " << cipher.encryptText(text) << endl;
                    cout << "\nPress Enter to continue..."; cin.get(); break;

                case 4: // Decrypt text
                    cout << "\n🔤 DECRYPT TEXT" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter hex ciphertext: "; getline(cin, text);
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    { string result = cipher.decryptText(text);
                      if (result.empty()) cout << "\n❌ Decryption failed (wrong password or invalid data)" << endl;
                      else cout << "\n🔓 Decrypted: " << result << endl;
                    }
                    cout << "\nPress Enter to continue..."; cin.get(); break;

                case 5: batchEncrypt(); cout << "\nPress Enter to continue..."; cin.get(); break;
                case 6: batchDecrypt(); cout << "\nPress Enter to continue..."; cin.get(); break;

                case 7: // View file
                    cout << "\n👁️  VIEW FILE CONTENT" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter filename: "; getline(cin, inputFile);
                    cipher.displayFileContent(inputFile);
                    cout << "\nPress Enter to continue..."; cin.get(); break;

                case 8: // File stats
                    cout << "\n📈 FILE STATISTICS" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter filename: "; getline(cin, inputFile);
                    cipher.showFileStats(inputFile);
                    cout << "\nPress Enter to continue..."; cin.get(); break;

                case 9: // SHA-256 hash
                    cout << "\n#️⃣  SHA-256 FILE HASH" << endl;
                    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << endl;
                    cout << "Enter filename: "; getline(cin, inputFile);
                    { string h = cipher.hashFile(inputFile);
                      if (h.empty()) cerr << "\n❌ Cannot open file." << endl;
                      else cout << "\n🔑 SHA-256: " << h << endl;
                    }
                    cout << "\nPress Enter to continue..."; cin.get(); break;

                case 10: showAbout(); cout << "\nPress Enter to continue..."; cin.get(); break;

                default:
                    cout << "\n❌ Invalid choice! Please select 1-11." << endl;
                    cout << "Press Enter to continue..."; cin.get();
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