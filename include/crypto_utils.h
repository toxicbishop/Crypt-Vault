#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <filesystem>
#include "../src/eth_logger.hpp"
extern std::unique_ptr<EthLogger> ethLogger;

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

    class Hasher {
        uint32 states[8];
        unsigned char buffer[64];
        uint64 bitlen;
        size_t bufferLen;
        void processBlock(const unsigned char* b) {
            uint32 w[64];
            for (int i = 0; i < 16; i++)
                w[i] = ((uint32)b[i*4]<<24)|((uint32)b[i*4+1]<<16)|((uint32)b[i*4+2]<<8)|b[i*4+3];
            for (int i = 16; i < 64; i++)
                w[i] = gam1(w[i-2]) + w[i-7] + gam0(w[i-15]) + w[i-16];
            uint32 a=states[0],b1=states[1],c=states[2],d=states[3],e=states[4],f=states[5],g=states[6],hh=states[7];
            for (int i = 0; i < 64; i++) {
                uint32 t1 = hh + sig1(e) + ch(e,f,g) + K[i] + w[i];
                uint32 t2 = sig0(a) + maj(a,b1,c);
                hh=g; g=f; f=e; e=d+t1; d=c; c=b1; b1=a; a=t1+t2;
            }
            states[0]+=a;states[1]+=b1;states[2]+=c;states[3]+=d;states[4]+=e;states[5]+=f;states[6]+=g;states[7]+=hh;
        }
    public:
        Hasher() { reset(); }
        void reset() {
            states[0]=0x6a09e667; states[1]=0xbb67ae85; states[2]=0x3c6ef372; states[3]=0xa54ff53a;
            states[4]=0x510e527f; states[5]=0x9b05688c; states[6]=0x1f83d9ab; states[7]=0x5be0cd19;
            bitlen = 0; bufferLen = 0;
        }
        void update(const unsigned char* data, size_t len) {
            for (size_t i = 0; i < len; i++) {
                buffer[bufferLen++] = data[i];
                if (bufferLen == 64) {
                    processBlock(buffer);
                    bitlen += 512;
                    bufferLen = 0;
                }
            }
        }
        vector<unsigned char> final() {
            uint64 totalBitLen = bitlen + bufferLen * 8;
            buffer[bufferLen++] = 0x80;
            if (bufferLen > 56) {
                while (bufferLen < 64) buffer[bufferLen++] = 0x00;
                processBlock(buffer);
                bufferLen = 0;
            }
            while (bufferLen < 56) buffer[bufferLen++] = 0x00;
            for (int i = 7; i >= 0; i--) buffer[56 + (7 - i)] = (unsigned char)(totalBitLen >> (i * 8));
            processBlock(buffer);
            vector<unsigned char> res(32);
            for (int i = 0; i < 8; i++) {
                res[i*4]=(states[i]>>24)&0xff; res[i*4+1]=(states[i]>>16)&0xff;
                res[i*4+2]=(states[i]>>8)&0xff; res[i*4+3]=states[i]&0xff;
            }
            return res;
        }
    };

    static inline vector<unsigned char> hash(const unsigned char* data, size_t len) {
        Hasher h;
        h.update(data, len);
        return h.final();
    }
    static inline vector<unsigned char> hash(const string& s) {
        return hash((const unsigned char*)s.data(), s.size());
    }
    static string toHex(const vector<unsigned char>& h) {
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
inline bool generateRandomBytes(unsigned char* buf, size_t len) {
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
inline vector<unsigned char> pkcs7Pad(const vector<unsigned char>& data) {
    size_t padLen = 16 - (data.size() % 16);
    vector<unsigned char> padded = data;
    padded.insert(padded.end(), padLen, (unsigned char)padLen);
    return padded;
}
inline bool pkcs7Unpad(vector<unsigned char>& data) {
    if (data.empty() || data.size() % 16 != 0) return false;
    unsigned char pad = data.back();
    if (pad < 1 || pad > 16) return false;
    for (size_t i = data.size() - pad; i < data.size(); i++)
        if (data[i] != pad) return false;
    data.resize(data.size() - pad);
    return true;
}
inline string bytesToHex(const unsigned char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; i++) ss << hex << setfill('0') << setw(2) << (int)data[i];
    return ss.str();
}
inline vector<unsigned char> hexToBytes(const string& hex) {
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
inline void secure_memzero(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}
// Constant-time comparison to prevent timing attacks
inline bool constant_time_compare(const unsigned char* a, const unsigned char* b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}
// HMAC-SHA256 Context for incremental hashing
class HMAC_SHA256 {
    SHA256Impl::Hasher inner, outer;
public:
    HMAC_SHA256(const unsigned char* key, size_t keyLen) {
        const size_t BLOCK_SIZE = 64;
        unsigned char keyBlock[BLOCK_SIZE] = {0};
        if (keyLen > BLOCK_SIZE) {
            auto h = SHA256Impl::hash(key, keyLen);
            memcpy(keyBlock, h.data(), 32);
        } else {
            memcpy(keyBlock, key, keyLen);
        }
        unsigned char ipad[BLOCK_SIZE], opad[BLOCK_SIZE];
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            ipad[i] = keyBlock[i] ^ 0x36;
            opad[i] = keyBlock[i] ^ 0x5c;
        }
        inner.update(ipad, BLOCK_SIZE);
        outer.update(opad, BLOCK_SIZE);
        secure_memzero(keyBlock, BLOCK_SIZE);
    }
    void update(const unsigned char* data, size_t len) {
        inner.update(data, len);
    }
    vector<unsigned char> final() {
        auto ih = inner.final();
        outer.update(ih.data(), ih.size());
        return outer.final();
    }
};

// HMAC-SHA256 high-level utility
inline vector<unsigned char> hmac_sha256(const unsigned char* key, size_t keyLen, 
                                   const unsigned char* data, size_t dataLen) {
    HMAC_SHA256 ctx(key, keyLen);
    ctx.update(data, dataLen);
    return ctx.final();
}
// PBKDF2-SHA256 key derivation
inline void pbkdf2_sha256(const string& password, const unsigned char* salt, size_t saltLen,
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
// Progress Bar
// ═══════════════════════════════════════════════════════════

class ProgressBar {
    size_t total, current;
    int barWidth;
    chrono::steady_clock::time_point startTime;
public:
    ProgressBar(size_t t, int w = 40) : total(t), current(0), barWidth(w) {
        startTime = chrono::steady_clock::now();
    }
    void update(size_t bytes) {
        current += bytes;
        if (total == 0) return;
        double frac = (double)current / total;
        int filled = (int)(frac * barWidth);
        auto now = chrono::steady_clock::now();
        double elapsed = chrono::duration<double>(now - startTime).count();
        double speed = elapsed > 0 ? (current / 1048576.0) / elapsed : 0;
        double eta = speed > 0 && current < total ? ((total - current) / 1048576.0) / speed : 0;
        cout << "\r  [";
        for (int i = 0; i < barWidth; i++) cout << (i < filled ? "#" : ".");
        cout << "] " << (int)(frac * 100) << "% | "
             << fixed << setprecision(1) << speed << " MB/s | ETA " << (int)eta << "s" << flush;
    }
    void finish() {
        auto now = chrono::steady_clock::now();
        double elapsed = chrono::duration<double>(now - startTime).count();
        double speed = elapsed > 0 ? (total / 1048576.0) / elapsed : 0;
        cout << "\r  [";
        for (int i = 0; i < barWidth; i++) cout << "#";
        cout << "] 100% | " << fixed << setprecision(1) << speed << " MB/s | Done!     " << endl;
    }
};

// ═══════════════════════════════════════════════════════════
// Secure Delete (Shred)
// ═══════════════════════════════════════════════════════════

class SecureDelete {
public:
    static bool shredFile(const string& filename, int passes = 3) {
        struct stat st;
        if (stat(filename.c_str(), &st) != 0) {
            cerr << "\n  Error: Cannot access '" << filename << "'" << endl;
            return false;
        }
        long long fileSize = st.st_size;
        
        std::array<uint8_t, 32> hash = {0};
        if (ethLogger) {
            ifstream inHash(filename, ios::binary);
            if (inHash.is_open()) {
                SHA256Impl::Hasher hasher;
                vector<char> hBuf(131072);
                while (inHash.read(hBuf.data(), hBuf.size()) || inHash.gcount() > 0) {
                    hasher.update((const unsigned char*)hBuf.data(), inHash.gcount());
                }
                auto tempHash = hasher.final();
                std::copy_n(tempHash.begin(), std::min((size_t)32, tempHash.size()), hash.begin());
            }
        }

        fstream file(filename, ios::in | ios::out | ios::binary);
        if (!file.is_open()) return false;

        vector<unsigned char> buffer(min((long long)131072, fileSize)); // Larger buffer [128KB]
        ProgressBar progress(fileSize * (passes + 1), 30); 
        
        for (int pass = 0; pass < passes; pass++) {
            file.seekp(0, ios::beg);
            long long remaining = fileSize;
            while (remaining > 0) {
                size_t chunk = min((size_t)remaining, buffer.size());
                if (pass % 3 == 0) memset(buffer.data(), 0x00, chunk);
                else if (pass % 3 == 1) memset(buffer.data(), 0xFF, chunk);
                else generateRandomBytes(buffer.data(), chunk);
                
                file.write((char*)buffer.data(), chunk);
                file.flush();
                remaining -= chunk;
                progress.update(chunk);
            }
        }
        
        if (passes % 3 != 1) {
             file.seekp(0, ios::beg);
             long long remaining = fileSize;
             while (remaining > 0) {
                 size_t chunk = min((size_t)remaining, buffer.size());
                 memset(buffer.data(), 0x00, chunk);
                 file.write((char*)buffer.data(), chunk);
                 file.flush();
                 remaining -= chunk;
                 progress.update(chunk/2); 
             }
        }

        progress.finish();
        secure_memzero(buffer.data(), buffer.size());
        file.close();

        string currentName = filename;
        size_t lastSlash = filename.find_last_of("\\/");
        string dir = (lastSlash == string::npos) ? "" : filename.substr(0, lastSlash + 1);

        for (int i = 0; i < 3; i++) {
            unsigned char randArr[8];
            generateRandomBytes(randArr, 8);
            string tempName = dir + bytesToHex(randArr, 8);
            if (rename(currentName.c_str(), tempName.c_str()) == 0) {
                currentName = tempName;
            }
        }

        bool success = remove(currentName.c_str()) == 0;
        if (success && ethLogger) {
            try {
                auto txHash = ethLogger->logOperation(hash, EthLogger::OpType::DELETE_FILE, std::filesystem::path(filename).filename().string());
                cout << "\n[Ethereum] Logged - tx: " << txHash.substr(0, 18) << "..." << endl;
            } catch (const exception& e) {
                cerr << "\n[Ethereum] Audit log failed: " << e.what() << endl;
            }
        }
        return success;
    }
};

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#endif

// ═══════════════════════════════════════════════════════════
// File Locker (Cross-Platform)
// Uses .lock files with flock/LockFileEx to prevent concurrent access
// ═══════════════════════════════════════════════════════════
class FileLocker {
    string lockPath;
#ifdef _WIN32
    HANDLE hLock;
#else
    int fd;
#endif
public:
    FileLocker(const string& targetFile) : lockPath(targetFile + ".lock") {
#ifdef _WIN32
        hLock = CreateFileA(lockPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (hLock != INVALID_HANDLE_VALUE) {
            OVERLAPPED overlapped;
            memset(&overlapped, 0, sizeof(OVERLAPPED));
            LockFileEx(hLock, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped);
        }
#else
        fd = open(lockPath.c_str(), O_CREAT | O_RDWR, 0666);
        if (fd >= 0) flock(fd, LOCK_EX);
#endif
    }
    ~FileLocker() {
#ifdef _WIN32
        if (hLock != INVALID_HANDLE_VALUE) {
            OVERLAPPED overlapped;
            memset(&overlapped, 0, sizeof(OVERLAPPED));
            UnlockFileEx(hLock, 0, MAXDWORD, MAXDWORD, &overlapped);
            CloseHandle(hLock);
        }
#else
        if (fd >= 0) {
            flock(fd, LOCK_UN);
            close(fd);
            remove(lockPath.c_str());
        }
#endif
    }
    bool isLocked() const {
#ifdef _WIN32
        return hLock != INVALID_HANDLE_VALUE;
#else
        return fd >= 0;
#endif
    }
};

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
    ~AESCipher() {
        if (!storedPassword.empty()) {
            secure_memzero(&storedPassword[0], storedPassword.capacity());
        }
        secure_memzero(encKey, 32);
        secure_memzero(authKey, 32);
    }
    void setKey(const string& password) {
        storedPassword.reserve(256);
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
        
        in.seekg(0, ios::end);
        long long fileSize = in.tellg();
        in.seekg(0, ios::beg);

        unsigned char salt[SALT_SIZE], iv[IV_SIZE];
        if (!generateRandomBytes(salt, SALT_SIZE) || !generateRandomBytes(iv, IV_SIZE)) return false;
        deriveKeys(salt);
        
        ofstream out(outputFile, ios::binary);
        if (!out.is_open()) { cerr << "\n❌ Error: Cannot create '" << outputFile << "'" << endl; return false; }

        out.write("CVPF", 4);
        char version = 0x02;
        out.write(&version, 1);
        out.write((char*)salt, SALT_SIZE);
        out.write((char*)iv, IV_SIZE);
        
        long long placeholdersOffset = out.tellp();
        char zeroes[64] = {0};
        out.write(zeroes, 64);

        HMAC_SHA256 hmac(authKey, 32);
        hmac.update((const unsigned char*)"CVPF", 4);
        hmac.update((const unsigned char*)&version, 1);
        hmac.update(salt, SALT_SIZE);
        hmac.update(iv, IV_SIZE);

        SHA256Impl::Hasher ptHasher;

        ProgressBar progress(fileSize, 30);
        unsigned char prev[16]; memcpy(prev, iv, 16);
        vector<unsigned char> buffer(131072); // 128KB buffer

        while (in.read((char*)buffer.data(), buffer.size()) || in.gcount() > 0) {
            size_t bytesRead = in.gcount();
            ptHasher.update((const unsigned char*)buffer.data(), bytesRead);
            vector<unsigned char> chunk(buffer.begin(), buffer.begin() + bytesRead);
            if (in.eof()) chunk = pkcs7Pad(chunk);
            
            for (size_t i = 0; i < chunk.size(); i += 16) {
                unsigned char block[16];
                for (int j = 0; j < 16; j++) block[j] = chunk[i+j] ^ prev[j];
                ctx.encryptBlock(block);
                out.write((char*)block, 16);
                hmac.update(block, 16);
                memcpy(prev, block, 16);
            }
            if (in.eof()) break;
            progress.update(bytesRead);
        }
        auto ptHash = ptHasher.final();
        hmac.update(ptHash.data(), 32);
        auto h = hmac.final();

        out.seekp(placeholdersOffset, ios::beg);
        if (!out) {
            in.close(); out.close(); remove(outputFile.c_str());
            cerr << "\n❌ Error: seekp failed — header injection unsuccessful" << endl;
            return false;
        }
        
        out.write((char*)h.data(), 32);
        out.write((char*)ptHash.data(), 32);
        if (!out) {
            in.close(); out.close(); remove(outputFile.c_str());
            cerr << "\n❌ Error: Failed to write hashes to header" << endl;
            return false;
        }

        progress.finish();
        in.close(); out.close();

        if (ethLogger) {
            try {
                std::array<uint8_t, 32> ptHashArr = {0};
                std::copy_n(ptHash.begin(), std::min((size_t)32, ptHash.size()), ptHashArr.begin());
                auto txHash = ethLogger->logOperation(ptHashArr, EthLogger::OpType::ENCRYPT, std::filesystem::path(inputFile).filename().string());
                cout << "\n[Ethereum] Logged - tx: " << txHash.substr(0, 18) << "..." << endl;
            } catch (const exception& e) {
                cerr << "\n[Ethereum] Audit log failed: " << e.what() << endl;
            }
        }
        return true;
    }

    bool decryptFile(const string& inputFile, const string& outputFile) {
        FileLocker lockIn(inputFile);
        FileLocker lockOut(outputFile);
        if (!lockIn.isLocked() || !lockOut.isLocked()) {
            cerr << "\n❌ Error: File is locked by another process" << endl;
            return false;
        }

        ifstream in(inputFile, ios::binary);
        if (!in.is_open()) { cerr << "\n❌ Error: Cannot open '" << inputFile << "'" << endl; return false; }
        
        in.seekg(0, ios::end);
        long long totalSize = in.tellg();
        in.seekg(0, ios::beg);

        char magic[4] = {0};
        in.read(magic, 4);
        bool isV2 = (strncmp(magic, "CVPF", 4) == 0);

        long long ciphertextLen = 0;
        unsigned char expectedHmac[HMAC_SIZE];
        unsigned char expectedPtHash[32] = {0};
        unsigned char salt[SALT_SIZE], iv[IV_SIZE];

        if (isV2) {
            char version;
            in.read(&version, 1);
            if (version != 0x02) { cerr << "\n❌ Error: Unsupported version" << endl; return false; }
            in.read((char*)salt, SALT_SIZE);
            in.read((char*)iv, IV_SIZE);
            in.read((char*)expectedHmac, HMAC_SIZE);
            in.read((char*)expectedPtHash, 32);
            ciphertextLen = totalSize - 4 - 1 - SALT_SIZE - IV_SIZE - HMAC_SIZE - 32;
        } else {
            in.seekg(0, ios::beg);
            if (totalSize < (SALT_SIZE + IV_SIZE + HMAC_SIZE)) return false;
            ciphertextLen = totalSize - SALT_SIZE - IV_SIZE - HMAC_SIZE;
            in.read((char*)salt, SALT_SIZE);
            in.read((char*)iv, IV_SIZE);
        }

        deriveKeys(salt);

        // --- Pass 1: HMAC Verification ---
        cout << "  [1/2] Verifying Integrity..." << endl;
        HMAC_SHA256 hmac(authKey, 32);
        if (isV2) {
            char version = 0x02;
            hmac.update((const unsigned char*)"CVPF", 4);
            hmac.update((const unsigned char*)&version, 1);
        }
        hmac.update(salt, SALT_SIZE);
        hmac.update(iv, IV_SIZE);

        long long dataStartOffset = in.tellg();
        vector<unsigned char> buffer(131072); // 128KB
        long long remaining = ciphertextLen;
        while (remaining > 0) {
            size_t toRead = (size_t)min((long long)buffer.size(), remaining);
            in.read((char*)buffer.data(), toRead);
            hmac.update(buffer.data(), toRead);
            remaining -= toRead;
        }

        if (isV2) {
            hmac.update(expectedPtHash, 32);
        } else {
            in.read((char*)expectedHmac, HMAC_SIZE);
        }

        auto computedHmac = hmac.final();
        if (!constant_time_compare(computedHmac.data(), expectedHmac, HMAC_SIZE)) {
            cerr << "\n❌ HMAC verification failed - file tampered or wrong password" << endl;
            return false;
        }

        // --- Pass 2: Decryption ---
        cout << "  [2/2] Decrypting Content..." << endl;
        in.clear(); // Reset EOF
        in.seekg(dataStartOffset, ios::beg);
        
        string tempOutFile = outputFile + ".tmp";
        ofstream out(tempOutFile, ios::binary);
        if (!out.is_open()) return false;

        SHA256Impl::Hasher ptHasher;
        ProgressBar progress(ciphertextLen, 30);
        unsigned char prev[16]; memcpy(prev, iv, 16);
        
        remaining = ciphertextLen;
        vector<unsigned char> lastBlock;
        while (remaining > 0) {
            size_t toRead = (size_t)min((long long)buffer.size(), remaining);
            in.read((char*)buffer.data(), toRead);
            for (size_t i = 0; i < toRead; i += 16) {
                unsigned char block[16], enc[16];
                memcpy(block, buffer.data() + i, 16);
                memcpy(enc, block, 16);
                ctx.decryptBlock(block);
                for (int j = 0; j < 16; j++) block[j] ^= prev[j];
                memcpy(prev, enc, 16);
                
                if (remaining <= 16 && i + 16 >= toRead) {
                    lastBlock.assign(block, block + 16);
                } else {
                    out.write((char*)block, 16);
                    ptHasher.update(block, 16);
                }
            }
            remaining -= toRead;
            progress.update(toRead);
        }

        if (!pkcs7Unpad(lastBlock)) {
            out.close();
            remove(tempOutFile.c_str());
            return false;
        }
        
        out.write((char*)lastBlock.data(), lastBlock.size());
        ptHasher.update(lastBlock.data(), lastBlock.size());
        
        out.close();
        in.close();
        progress.finish();

        auto computedPtHash = ptHasher.final();
        if (isV2) {
            if (memcmp(computedPtHash.data(), expectedPtHash, 32) != 0) {
                remove(tempOutFile.c_str());
                cerr << "\n❌ Integrity check failed: decrypted content does not match original." << endl;
                return false;
            }
        }
        
        remove(outputFile.c_str());
        if (rename(tempOutFile.c_str(), outputFile.c_str()) != 0) {
            cerr << "\n❌ Failed to rename temp file." << endl;
            return false;
        }

        if (ethLogger) {
            try {
                std::array<uint8_t, 32> computedPtHashArr = {0};
                std::copy_n(computedPtHash.begin(), std::min((size_t)32, computedPtHash.size()), computedPtHashArr.begin());
                auto txHash = ethLogger->logOperation(computedPtHashArr, EthLogger::OpType::DECRYPT, std::filesystem::path(inputFile).filename().string());
                cout << "\n[Ethereum] Logged - tx: " << txHash.substr(0, 18) << "..." << endl;
            } catch (const exception& e) {
                cerr << "\n[Ethereum] Audit log failed: " << e.what() << endl;
            }
        }

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
