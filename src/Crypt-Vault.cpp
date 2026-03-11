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
#include <thread>
#include <mutex>
#include <chrono>
#include <cmath>
#include <map>
#include <numeric>
#include <zlib.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <conio.h>  // For _getch() secure password input
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <cstdlib>
#include <termios.h>
#include <unistd.h>
#endif

// Polyfill for C++17 <filesystem> using native Win32 API to support GCC 6.3.0
struct FsCompat {
    static bool is_directory(const std::string& path) {
        struct stat st;
        return (stat(path.c_str(), &st) == 0 && (st.st_mode & S_IFDIR));
    }
    static bool exists(const std::string& path) {
        struct stat st;
        return (stat(path.c_str(), &st) == 0);
    }
    static std::string extension(const std::string& path) {
        size_t dot = path.find_last_of('.');
        if (dot == std::string::npos) return "";
        return path.substr(dot);
    }
    static void get_files_recursive(const std::string& dir, std::vector<std::string>& files) {
#ifdef _WIN32
        std::string search = dir + "\\*";
        WIN32_FIND_DATAA fd;
        HANDLE hFind = ::FindFirstFileA(search.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string name = fd.cFileName;
                if (name == "." || name == "..") continue;
                std::string fullPath = dir + "\\" + name;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    get_files_recursive(fullPath, files);
                } else {
                    files.push_back(fullPath);
                }
            } while (::FindNextFileA(hFind, &fd));
            ::FindClose(hFind);
        }
#endif
    }
};


#include "../include/blockchain_audit.h"
#include "../include/p2p_node.h"
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

    static vector<unsigned char> hash(const unsigned char* data, size_t len) {
        Hasher h;
        h.update(data, len);
        return h.final();
    }
    static vector<unsigned char> hash(const string& s) {
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
vector<unsigned char> hmac_sha256(const unsigned char* key, size_t keyLen, 
                                   const unsigned char* data, size_t dataLen) {
    HMAC_SHA256 ctx(key, keyLen);
    ctx.update(data, dataLen);
    return ctx.final();
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

        return remove(currentName.c_str()) == 0;
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
        
        in.seekg(0, ios::end);
        long long fileSize = in.tellg();
        in.seekg(0, ios::beg);

        unsigned char salt[SALT_SIZE], iv[IV_SIZE];
        if (!generateRandomBytes(salt, SALT_SIZE) || !generateRandomBytes(iv, IV_SIZE)) return false;
        deriveKeys(salt);
        
        ofstream out(outputFile, ios::binary);
        if (!out.is_open()) { cerr << "\n❌ Error: Cannot create '" << outputFile << "'" << endl; return false; }

        out.write((char*)salt, SALT_SIZE);
        out.write((char*)iv, IV_SIZE);

        HMAC_SHA256 hmac(authKey, 32);
        hmac.update(salt, SALT_SIZE);
        hmac.update(iv, IV_SIZE);

        ProgressBar progress(fileSize, 30);
        unsigned char prev[16]; memcpy(prev, iv, 16);
        vector<unsigned char> buffer(131072); // 128KB buffer

        while (in.read((char*)buffer.data(), buffer.size()) || in.gcount() > 0) {
            size_t bytesRead = in.gcount();
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
        auto h = hmac.final();
        out.write((char*)h.data(), HMAC_SIZE);
        progress.finish();
        in.close(); out.close();
        return true;
    }

    bool decryptFile(const string& inputFile, const string& outputFile) {
        ifstream in(inputFile, ios::binary);
        if (!in.is_open()) { cerr << "\n❌ Error: Cannot open '" << inputFile << "'" << endl; return false; }
        
        in.seekg(0, ios::end);
        long long totalSize = in.tellg();
        in.seekg(0, ios::beg);

        if (totalSize < (SALT_SIZE + IV_SIZE + HMAC_SIZE)) return false;
        long long ciphertextLen = totalSize - SALT_SIZE - IV_SIZE - HMAC_SIZE;

        unsigned char salt[SALT_SIZE], iv[IV_SIZE];
        in.read((char*)salt, SALT_SIZE);
        in.read((char*)iv, IV_SIZE);
        deriveKeys(salt);

        // --- Pass 1: HMAC Verification ---
        cout << "  [1/2] Verifying Integrity..." << endl;
        HMAC_SHA256 hmac(authKey, 32);
        hmac.update(salt, SALT_SIZE);
        hmac.update(iv, IV_SIZE);

        vector<unsigned char> buffer(131072); // 128KB
        long long remaining = ciphertextLen;
        while (remaining > 0) {
            size_t toRead = (size_t)min((long long)buffer.size(), remaining);
            in.read((char*)buffer.data(), toRead);
            hmac.update(buffer.data(), toRead);
            remaining -= toRead;
        }

        unsigned char expectedHmac[HMAC_SIZE];
        in.read((char*)expectedHmac, HMAC_SIZE);
        auto computedHmac = hmac.final();
        if (!constant_time_compare(computedHmac.data(), expectedHmac, HMAC_SIZE)) {
            cerr << "\n❌ HMAC verification failed - file tampered or wrong password" << endl;
            return false;
        }

        // --- Pass 2: Decryption ---
        cout << "  [2/2] Decrypting Content..." << endl;
        in.clear(); // Reset EOF
        in.seekg(SALT_SIZE + IV_SIZE, ios::beg);
        ofstream out(outputFile, ios::binary);
        if (!out.is_open()) return false;

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
                
                if (remaining - (long long)toRead == 0 && (i + 16) == toRead) {
                    lastBlock.assign(block, block + 16);
                } else {
                    out.write((char*)block, 16);
                }
                memcpy(prev, enc, 16);
            }
            remaining -= toRead;
            progress.update(toRead);
        }
        
        if (!pkcs7Unpad(lastBlock)) {
            cerr << "\n❌ Padding error - likely wrong password" << endl;
            return false;
        }
        out.write((char*)lastBlock.data(), lastBlock.size());
        
        progress.finish();
        in.close(); out.close();
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
// P2P Network Server
// ═══════════════════════════════════════════════════════════
// P2P logic is implemented in p2p_node.cpp / network_layer.h




// ═══════════════════════════════════════════════════════════
// Simple Compressor (zlib)
// ═══════════════════════════════════════════════════════════

class SimpleCompressor {
public:
    static bool compressFile(const string& src, const string& dst) {
        ifstream in(src, ios::binary | ios::ate);
        if (!in.is_open()) return false;
        long long szOff = in.tellg();
        uint32_t sz = (szOff > 0xFFFFFFFF) ? 0xFFFFFFFF : (uint32_t)szOff;
        in.seekg(0, ios::beg);

        ofstream out(dst, ios::binary);
        if (!out.is_open()) return false;

        out.write("CVZ\x01", 4);
        for (int i = 0; i < 4; i++) out.put((sz >> (i * 8)) & 0xFF);

        z_stream zs; memset(&zs, 0, sizeof(zs));
        if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) return false;
        
        vector<unsigned char> inB(131072), outB(131072);
        int flush;
        do {
            in.read((char*)inB.data(), inB.size());
            zs.avail_in = (uInt)in.gcount();
            flush = in.eof() ? Z_FINISH : Z_NO_FLUSH;
            zs.next_in = inB.data();
            do {
                zs.avail_out = (uInt)outB.size();
                zs.next_out = outB.data();
                deflate(&zs, flush);
                out.write((char*)outB.data(), outB.size() - zs.avail_out);
            } while (zs.avail_out == 0);
        } while (flush != Z_FINISH);
        deflateEnd(&zs);
        return true;
    }

    static bool decompressFile(const string& src, const string& dst) {
        ifstream in(src, ios::binary);
        ofstream out(dst, ios::binary);
        if (!in || !out) return false;
        char hdr[4]; in.read(hdr, 4);
        if (memcmp(hdr, "CVZ\x01", 4) != 0) return false;
        in.ignore(4); // Skip size 

        z_stream zs; memset(&zs, 0, sizeof(zs));
        if (inflateInit(&zs) != Z_OK) return false;

        vector<unsigned char> inB(131072), outB(131072);
        int ret;
        do {
            in.read((char*)inB.data(), inB.size());
            zs.avail_in = (uInt)in.gcount();
            if (zs.avail_in == 0) break;
            zs.next_in = inB.data();
            do {
                zs.avail_out = (uInt)outB.size();
                zs.next_out = outB.data();
                ret = inflate(&zs, Z_NO_FLUSH);
                out.write((char*)outB.data(), outB.size() - zs.avail_out);
            } while (zs.avail_out == 0);
        } while (ret != Z_STREAM_END);
        inflateEnd(&zs);
        return ret == Z_STREAM_END;
    }

    static vector<unsigned char> compress(const vector<unsigned char>& input) {
        if (input.empty()) return {};
        uLongf cL = compressBound(input.size());
        vector<unsigned char> res(8 + cL);
        memcpy(res.data(), "CVZ\x01", 4);
        uint32_t sz = (uint32_t)input.size();
        for (int i=0; i<4; i++) res[4+i] = (sz >> (i*8)) & 0xFF;
        if (::compress(res.data()+8, &cL, input.data(), input.size()) != Z_OK) return input;
        res.resize(8 + cL);
        return res;
    }
    static vector<unsigned char> decompress(const vector<unsigned char>& input) {
        if (input.size() < 8 || memcmp(input.data(), "CVZ\x01", 4) != 0) return {};
        uint32_t sz = 0;
        for (int i=0; i<4; i++) sz |= ((uint32_t)input[4+i]) << (i*8);
        vector<unsigned char> res(sz);
        uLongf dL = sz;
        if (uncompress(res.data(), &dL, input.data() + 8, input.size() - 8) != Z_OK) return {};
        res.resize(dL);
        return res;
    }
    static bool isCompressed(const vector<unsigned char>& d) {
        return d.size() >= 4 && memcmp(d.data(), "CVZ\x01", 4) == 0;
    }
};

// ═══════════════════════════════════════════════════════════
// Key File Manager (2FA Support)
// ═══════════════════════════════════════════════════════════

class KeyFileManager {
public:
    static bool generateKeyFile(const string& filename) {
        unsigned char kd[32];
        if (!generateRandomBytes(kd, 32)) return false;
        ofstream f(filename, ios::binary);
        if (!f.is_open()) return false;
        f.write("CVKF", 4); f.write((char*)kd, 32); f.close();
        secure_memzero(kd, 32);
        return true;
    }
    static vector<unsigned char> readKeyFile(const string& filename) {
        ifstream f(filename, ios::binary);
        if (!f.is_open()) return {};
        char magic[4]; f.read(magic, 4);
        if (string(magic, 4) != "CVKF") return {};
        vector<unsigned char> kd(32);
        f.read((char*)kd.data(), 32); f.close();
        return kd;
    }
    static string combineWithPassword(const string& pw, const vector<unsigned char>& kf) {
        auto h = SHA256Impl::hash(kf.data(), kf.size());
        string combined = pw;
        for (auto b : h) combined += (char)b;
        return combined;
    }
};

// ═══════════════════════════════════════════════════════════
// Password Generator
// ═══════════════════════════════════════════════════════════

class PasswordGenerator {
public:
    static string generate(int length = 24) {
        string cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
        string pw(length, ' ');
        vector<unsigned char> rnd(length);
        generateRandomBytes(rnd.data(), length);
        for (int i = 0; i < length; i++) pw[i] = cs[rnd[i] % cs.size()];
        unsigned char r;
        if (length >= 4) {
            generateRandomBytes(&r, 1); pw[0] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[r%26];
            generateRandomBytes(&r, 1); pw[1] = "abcdefghijklmnopqrstuvwxyz"[r%26];
            generateRandomBytes(&r, 1); pw[2] = "0123456789"[r%10];
            generateRandomBytes(&r, 1); pw[3] = "!@#$%^&*()-_=+[]{}|;:,.<>?"[r%26];
        }
        for (int i = length-1; i > 0; i--) {
            generateRandomBytes(&r, 1); swap(pw[i], pw[r%(i+1)]);
        }
        return pw;
    }
    static double entropy(const string& p) {
        int cs = 0; bool u=0,l=0,d=0,s=0;
        for (char c : p) { if (isupper(c)) u=1; else if (islower(c)) l=1; else if (isdigit(c)) d=1; else s=1; }
        if (u) cs+=26; if (l) cs+=26; if (d) cs+=10; if (s) cs+=32;
        return cs > 0 ? p.length() * log2(cs) : 0;
    }
};

// ═══════════════════════════════════════════════════════════
// Config File
// ═══════════════════════════════════════════════════════════

class Config {
    map<string, string> settings;
    string configFile;
    void setDefaults() {
        settings["pbkdf2_iterations"]="100000"; settings["shred_passes"]="3";
        settings["compression"]="off"; settings["auto_shred_source"]="off";
        settings["password_length"]="24"; settings["show_progress"]="on";
    }
public:
    Config(const string& f = "cryptvault.conf") : configFile(f) { setDefaults(); load(); }
    void load() {
        ifstream f(configFile); if (!f.is_open()) return;
        string line;
        while (getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            size_t eq = line.find('='); if (eq == string::npos) continue;
            string k = line.substr(0, eq), v = line.substr(eq+1);
            while (!k.empty() && k.back()==' ') k.pop_back();
            while (!v.empty() && v.front()==' ') v = v.substr(1);
            while (!v.empty() && (v.back()=='\r'||v.back()=='\n'||v.back()==' ')) v.pop_back();
            if (!k.empty()) settings[k] = v;
        }
    }
    void save() {
        ofstream f(configFile); if (!f.is_open()) return;
        f << "# CryptVault Configuration\n\n";
        for (const auto& pair : settings) f << pair.first << " = " << pair.second << "\n";
    }
    string get(const string& k) const { auto it=settings.find(k); return it!=settings.end()?it->second:""; }
    int getInt(const string& k) const { try{return stoi(get(k));}catch(...){return 0;} }
    bool getBool(const string& k) const { string v=get(k); return v=="on"||v=="true"||v=="1"; }
    void set(const string& k, const string& v) { settings[k]=v; }
    void display() const {
        cout << "\n  --- CURRENT SETTINGS ---\n" << endl;
        int i=1;
        for (const auto& pair : settings) cout << "  " << i++ << "  " << setw(22) << left << pair.first << pair.second << endl;
        cout << endl;
    }
    const map<string,string>& getAll() const { return settings; }
};

// ═══════════════════════════════════════════════════════════
// Encryption Log / History
// ═══════════════════════════════════════════════════════════

class EncryptionLog {
    string logFile;
public:
    EncryptionLog(const string& f = "cryptvault.log") : logFile(f) {}
    void log(const string& op, const string& fn, long long sz, double ms, bool ok) {
        ofstream f(logFile, ios::app); if (!f.is_open()) return;
        auto now = chrono::system_clock::now();
        time_t t = chrono::system_clock::to_time_t(now);
        char buf[64]; strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
        f << "[" << buf << "] " << (ok?"OK   ":"FAIL ") << setw(12) << left << op
          << " " << fn << " " << sz << "B " << fixed << setprecision(2) << ms << "ms\n";
    }
    void display(int mx = 50) {
        ifstream f(logFile);
        if (!f.is_open()) { cout << "\n  No log found." << endl; return; }
        vector<string> lines; string line;
        while (getline(f, line)) if (!line.empty()) lines.push_back(line);
        cout << "\n  --- ENCRYPTION LOG (" << lines.size() << " entries) ---\n" << endl;
        int start = max(0, (int)lines.size() - mx);
        for (int i = start; i < (int)lines.size(); i++) cout << "  " << lines[i] << endl;
        cout << endl;
    }
};

// ═══════════════════════════════════════════════════════════
// Performance Benchmarks
// ═══════════════════════════════════════════════════════════

void runBenchmarks() {
    cout << "\n  --- PERFORMANCE BENCHMARKS ---\n" << endl;
    AESCipher bc; bc.setKey("BenchmarkPassword123!@#");
    struct TC { string name; size_t sz; };
    vector<TC> tests = {{"1 KB",1024},{"64 KB",65536},{"1 MB",1048576},{"10 MB",10485760}};
    cout << "  " << setw(12) << left << "Size" << setw(14) << "Encrypt"
         << setw(14) << "Decrypt" << "Throughput" << endl;
    cout << "  " << string(52, '-') << endl;
    for (auto& t : tests) {
        vector<unsigned char> data(t.sz);
        generateRandomBytes(data.data(), min(data.size(), (size_t)4096));
        for (size_t i = 4096; i < data.size(); i++) data[i] = data[i%4096];
        auto t1 = chrono::high_resolution_clock::now();
        auto enc = bc.encrypt(data);
        auto t2 = chrono::high_resolution_clock::now();
        double eMs = chrono::duration<double, milli>(t2-t1).count();
        auto t3 = chrono::high_resolution_clock::now();
        auto dec = bc.decrypt(enc);
        auto t4 = chrono::high_resolution_clock::now();
        double dMs = chrono::duration<double, milli>(t4-t3).count();
        double tp = (t.sz / 1048576.0) / (eMs / 1000.0);
        cout << "  " << setw(12) << left << t.name << setw(14) << (to_string((int)eMs)+" ms")
             << setw(14) << (to_string((int)dMs)+" ms") << fixed << setprecision(1) << tp << " MB/s" << endl;
    }
    unsigned char salt[16], der[64]; generateRandomBytes(salt, 16);
    auto p1 = chrono::high_resolution_clock::now();
    pbkdf2_sha256("BenchmarkPW", salt, 16, 100000, der, 64);
    auto p2 = chrono::high_resolution_clock::now();
    cout << "\n  PBKDF2-SHA256 (100k): " << fixed << setprecision(0)
         << chrono::duration<double,milli>(p2-p1).count() << " ms" << endl;
    vector<unsigned char> hd(1048576); unsigned char hk[32]; generateRandomBytes(hk, 32);
    auto h1 = chrono::high_resolution_clock::now();
    hmac_sha256(hk, 32, hd.data(), hd.size());
    auto h2 = chrono::high_resolution_clock::now();
    double hMs = chrono::duration<double,milli>(h2-h1).count();
    cout << "  HMAC-SHA256 (1 MB): " << fixed << setprecision(1) << hMs << " ms ("
         << (1.0/(hMs/1000.0)) << " MB/s)" << endl << endl;
}

// ═══════════════════════════════════════════════════════════
// Progress Bar
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// RSA Key Manager (Wrap AES Password)
// ═══════════════════════════════════════════════════════════
class RSAKeyManager {
public:
    static bool generateKeyPair(const string& pubFile, const string& privFile) {
#ifdef _WIN32
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return false;
        }
        
        // Generate 2048-bit RSA key exchange pair
        if (!CryptGenKey(hProv, AT_KEYEXCHANGE, 2048 << 16 | CRYPT_EXPORTABLE, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }
        
        // Export Public Key
        DWORD pubLen = 0;
        CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &pubLen);
        vector<BYTE> pubBlob(pubLen);
        if (CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pubBlob.data(), &pubLen)) {
            ofstream out(pubFile, ios::binary);
            if (out.is_open()) {
                out.write((char*)pubBlob.data(), pubLen);
                out.close();
            }
        }
        
        // Export Private Key
        DWORD privLen = 0;
        CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &privLen);
        vector<BYTE> privBlob(privLen);
        if (CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, privBlob.data(), &privLen)) {
            ofstream out(privFile, ios::binary);
            if (out.is_open()) {
                out.write((char*)privBlob.data(), privLen);
                out.close();
            }
        }
        
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return true;
#else
        cerr << "  RSA key wrapping is only supported on Windows currently." << endl;
        return false;
#endif
    }

    static bool wrapPassword(const string& password, const string& pubFile, string& wrappedOut) {
#ifdef _WIN32
        ifstream in(pubFile, ios::binary);
        if (!in.is_open()) return false;
        
        vector<BYTE> pubBlob((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();
        
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;
        
        if (!CryptImportKey(hProv, pubBlob.data(), pubBlob.size(), 0, 0, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }
        
        vector<BYTE> data(password.begin(), password.end());
        DWORD dataLen = data.size();
        DWORD bufLen = dataLen;
        
        CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufLen, 0);
        data.resize(bufLen);
        
        if (CryptEncrypt(hKey, 0, TRUE, 0, data.data(), &dataLen, bufLen)) {
            stringstream ss;
            for(size_t i=0; i<dataLen; i++) {
                ss << hex << setw(2) << setfill('0') << (int)data[i];
            }
            wrappedOut = ss.str();
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return true;
        }
        
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
#else
        return false;
#endif
    }

    static bool unwrapPassword(const string& wrappedHex, const string& privFile, string& unwrappedOut) {
#ifdef _WIN32
        ifstream in(privFile, ios::binary);
        if (!in.is_open()) return false;
        
        vector<BYTE> privBlob((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();
        
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        
        if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return false;
        
        if (!CryptImportKey(hProv, privBlob.data(), privBlob.size(), 0, 0, &hKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }
        
        vector<BYTE> data;
        for (size_t i = 0; i < wrappedHex.length(); i += 2) {
            string byteString = wrappedHex.substr(i, 2);
            char byte = (char) strtol(byteString.c_str(), NULL, 16);
            data.push_back(byte);
        }
        
        DWORD dataLen = data.size();
        
        if (CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &dataLen)) {
            unwrappedOut = string((char*)data.data(), dataLen);
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            return true;
        }
        
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
#else
        return false;
#endif
    }
};
class CryptVaultApp {
private:
    AESCipher cipher;
    CryptVaultBlockchain blockchain;  // Blockchain audit logging
    Config config;
    EncryptionLog encLog;
    void getLineTrim(string& s) {
        getline(cin, s);
        while (!s.empty() && (s.back() == '\r' || s.back() == ' ')) s.pop_back();
    }
    // After reading filename from user input, strip surrounding quotes
    void stripQuotes(string& path) {
        if (path.size() >= 2 && path.front() == '"' && path.back()  == '"') {
            path = path.substr(1, path.size() - 2);
        }
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
        cout << GRAY << "  Press " << CYAN << "25" << GRAY << " to exit the application" << RESET << endl;
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
        cout << CYAN << "  11" << GRAY << "  network    " << WHITE << "P2P Network Status" << RESET << endl;
        cout << CYAN << "  12" << GRAY << "  about      " << WHITE << "About Crypt Vault" << RESET << endl;
        cout << endl;
        cout << WHITE << "  --- FILE OPERATIONS -----------------------------------------------" << RESET << endl;
        cout << CYAN << "  13" << GRAY << "  dir-enc    " << WHITE << "Encrypt entire directory" << RESET << endl;
        cout << CYAN << "  14" << GRAY << "  dir-dec    " << WHITE << "Decrypt entire directory" << RESET << endl;
        cout << CYAN << "  15" << GRAY << "  shred      " << WHITE << "Secure delete (shred)" << RESET << endl;
        cout << CYAN << "  16" << GRAY << "  compress   " << WHITE << "Compress + Encrypt" << RESET << endl;
        cout << CYAN << "  17" << GRAY << "  preview    " << WHITE << "Decrypt preview" << RESET << endl;
        cout << endl;
        cout << WHITE << "  --- SECURITY TOOLS ------------------------------------------------" << RESET << endl;
        cout << CYAN << "  18" << GRAY << "  keygen     " << WHITE << "Generate key file (2FA)" << RESET << endl;
        cout << CYAN << "  19" << GRAY << "  genpass    " << WHITE << "Random password gen" << RESET << endl;
        cout << endl;
        cout << WHITE << "  --- SYSTEM --------------------------------------------------------" << RESET << endl;
        cout << CYAN << "  20" << GRAY << "  log        " << WHITE << "View encryption log" << RESET << endl;
        cout << CYAN << "  21" << GRAY << "  settings   " << WHITE << "Configuration settings" << RESET << endl;
        cout << CYAN << "  22" << GRAY << "  benchmark  " << WHITE << "Performance benchmarks" << RESET << endl;
        cout << CYAN << "  25" << GRAY << "  exit       " << YELLOW << "Exit application" << RESET << endl;
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
        for (int i = 0; i < numFiles; i++) { cout << "Enter filename " << (i+1) << ": "; getLineTrim(files[i]); stripQuotes(files[i]); }
        cout << "\n🔄 Processing..." << endl;
        int ok = 0;
        for (const auto& f : files) {
            if (FileHelper::fileExists(f)) {
                clock_t t = clock();
                if (cipher.encryptFile(f, FileHelper::addEncExtension(f))) {
                    cout << "✅ " << f << " → " << FileHelper::addEncExtension(f)
                         << " (" << fixed << setprecision(4) << (double)(clock()-t)/CLOCKS_PER_SEC << "s)" << endl;
                    
                    // Log to blockchain
                    string fileHash = cipher.hashFile(f);
                    struct stat st;
                    long long fileSize = (stat(f.c_str(), &st) == 0) ? st.st_size : 0;
                    logEncryption(blockchain, f, fileHash, fileSize, ((double)(clock()-t)/CLOCKS_PER_SEC) * 1000, true);
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
        for (int i = 0; i < numFiles; i++) { cout << "Enter filename " << (i+1) << ": "; getLineTrim(files[i]); stripQuotes(files[i]); }
        cout << "\n🔄 Processing..." << endl;
        int ok = 0;
        for (const auto& f : files) {
            string outF = FileHelper::hasEncExtension(f) ? FileHelper::removeEncExtension(f) : "decrypted_" + f;
            if (FileHelper::fileExists(f)) {
                clock_t t = clock();
                if (cipher.decryptFile(f, outF)) {
                    cout << "✅ " << f << " → " << outF
                         << " (" << fixed << setprecision(4) << (double)(clock()-t)/CLOCKS_PER_SEC << "s)" << endl;
                    
                    // Log to blockchain
                    string fileHash = cipher.hashFile(outF);
                    struct stat st;
                    long long fileSize = (stat(outF.c_str(), &st) == 0) ? st.st_size : 0;
                    logDecryption(blockchain, f, fileHash, fileSize, ((double)(clock()-t)/CLOCKS_PER_SEC) * 1000, true);
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
                getLineTrim(fname); stripQuotes(fname);
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
    // ─── Directory Encryption ────────────────────────────────
    void encryptDirectory() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m", YELLOW = "\033[38;5;220m";
        cout << CYAN << "\n  --- ENCRYPT DIRECTORY ---\n" << RESET << endl;
        string dirPath;
        cout << GRAY << "  directory path -> " << RESET; getLineTrim(dirPath); stripQuotes(dirPath);
        if (!FsCompat::exists(dirPath) || !FsCompat::is_directory(dirPath)) {
            cerr << "\n  Error: '" << dirPath << "' is not a valid directory" << endl; return;
        }

        cout << GRAY << "  Shred source files after encryption? (y/n): " << RESET;
        string shredChoice; getLineTrim(shredChoice);
        bool shouldShred = (shredChoice == "y" || shredChoice == "Y");

        string pw = getPasswordWithConfirmation();
        if (pw.empty()) return;
        cipher.setKey(pw);
        int total = 0, ok = 0;
        auto start = chrono::high_resolution_clock::now();
        vector<string> files; FsCompat::get_files_recursive(dirPath, files);
        
        cout << GRAY << "\n  Found " << files.size() << " items. Processing..." << RESET << endl;
        for (const string& fpath : files) {
            if (FileHelper::hasEncExtension(fpath)) continue;
            
            // Skip common junk files
            string base = fpath.substr(fpath.find_last_of("\\/") + 1);
            if (base == ".DS_Store" || base == "Thumbs.db" || base == "desktop.ini") continue;

            total++;
            string outPath = FileHelper::addEncExtension(fpath);
            
            cout << "\n  [" << ok+1 << "/" << total << "] Encrypting: " << base << endl;
            if (cipher.encryptFile(fpath, outPath)) {
                string fHash = cipher.hashFile(fpath);
                struct stat st; long long fSize = (stat(fpath.c_str(), &st)==0) ? st.st_size : 0;
                encLog.log("DIR_ENCRYPT", fpath, fSize, 0, true);
                logEncryption(blockchain, fpath, fHash, fSize, 0, true);
                
                if (shouldShred) {
                    SecureDelete::shredFile(fpath, config.getInt("shred_passes"));
                }
                ok++;
            } else {
                cerr << RED << "  FAILED: " << fpath << RESET << endl;
            }
        }
        auto end = chrono::high_resolution_clock::now();
        double elapsed = chrono::duration<double>(end - start).count();
        cout << GREEN << "\n  Done! " << RESET << ok << "/" << total << " files processed in "
             << fixed << setprecision(2) << elapsed << "s" << endl;
    }
    void decryptDirectory() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- DECRYPT DIRECTORY ---\n" << RESET << endl;
        string dirPath;
        cout << GRAY << "  directory path -> " << RESET; getLineTrim(dirPath); stripQuotes(dirPath);
        if (!FsCompat::exists(dirPath) || !FsCompat::is_directory(dirPath)) {
            cerr << "\n  Error: '" << dirPath << "' is not a valid directory" << endl; return;
        }

        cout << GRAY << "  Delete encrypted files after success? (y/n): " << RESET;
        string deleteChoice; getLineTrim(deleteChoice);
        bool shouldDelete = (deleteChoice == "y" || deleteChoice == "Y");

        string pw = getPassword();
        if (pw.empty()) return;
        cipher.setKey(pw);
        int total = 0, ok = 0;
        auto start = chrono::high_resolution_clock::now();
        vector<string> files; FsCompat::get_files_recursive(dirPath, files);
        
        cout << GRAY << "\n  Found " << files.size() << " items. Processing..." << RESET << endl;
        for (const string& fpath : files) {
            if (!FileHelper::hasEncExtension(fpath)) continue;
            total++;
            string base = fpath.substr(fpath.find_last_of("\\/") + 1);
            string outPath = FileHelper::removeEncExtension(fpath);
            
            cout << "\n  [" << ok+1 << "/" << total << "] Decrypting: " << base << endl;
            if (cipher.decryptFile(fpath, outPath)) {
                encLog.log("DIR_DECRYPT", fpath, 0, 0, true);
                if (shouldDelete) {
                    SecureDelete::shredFile(fpath, 1); // Fast shred for .enc files
                }
                ok++;
            } else {
                 cerr << RED << "  FAILED: " << fpath << RESET << endl;
            }
        }
        auto end = chrono::high_resolution_clock::now();
        double elapsed = chrono::duration<double>(end - start).count();
        cout << GREEN << "\n  Done! " << RESET << ok << "/" << total << " files processed in "
             << fixed << setprecision(2) << elapsed << "s" << endl;
    }
    // ─── Secure Delete ───────────────────────────────────────
    void secureDeleteMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m";
        const string RED = "\033[38;5;196m", GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- SECURE DELETE (SHRED) ---\n" << RESET << endl;
        string filename;
        cout << GRAY << "  filename -> " << RESET; getLineTrim(filename); stripQuotes(filename);
        if (!FileHelper::fileExists(filename)) {
            cerr << RED << "\n  File not found!" << RESET << endl; return;
        }
        cout << RED << "\n  WARNING: This will permanently destroy '" << filename << "'!" << RESET << endl;
        cout << GRAY << "  Type 'YES' to confirm: " << RESET;
        string confirm; getLineTrim(confirm);
        if (confirm != "YES") { cout << "  Cancelled." << endl; return; }
        int passes = config.getInt("shred_passes");
        if (passes < 1) passes = 3;
        string fHash = cipher.hashFile(filename);
        cout << "\n  Shredding with " << passes << " passes..." << endl;
        if (SecureDelete::shredFile(filename, passes)) {
            cout << GREEN << "\n  File securely destroyed!" << RESET << endl;
            logSecureDelete(blockchain, filename, fHash);
            encLog.log("SHRED", filename, 0, 0, true);
        } else {
            cerr << RED << "\n  Shredding failed!" << RESET << endl;
        }
    }
    // ─── Compress + Encrypt ──────────────────────────────────
    void compressAndEncrypt() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- COMPRESS + ENCRYPT ---\n" << RESET << endl;
        string filename;
        cout << GRAY << "  input file -> " << RESET; getLineTrim(filename); stripQuotes(filename);
        string pw = getPasswordWithConfirmation();
        if (pw.empty()) return;
        cipher.setKey(pw);
        ifstream in(filename, ios::binary);
        if (!in.is_open()) { cerr << "\n  Cannot open file" << endl; return; }
        vector<unsigned char> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();
        size_t origSize = data.size();
        auto compressed = SimpleCompressor::compress(data);
        size_t compSize = compressed.size();
        double ratio = origSize > 0 ? (1.0 - (double)compSize / origSize) * 100 : 0;
        cout << GRAY << "  Compressed: " << origSize << " -> " << compSize
             << " bytes (" << fixed << setprecision(1) << ratio << "% reduction)" << RESET << endl;
        auto encrypted = cipher.encrypt(compressed);
        string outFile = filename + ".cvz";
        ofstream out(outFile, ios::binary);
        out.write((char*)encrypted.data(), encrypted.size());
        out.close();
        cout << GREEN << "\n  Saved: " << outFile << RESET << endl;
        encLog.log("COMPRESS_ENC", filename, origSize, 0, true);
    }
    // ─── Decrypt Preview ─────────────────────────────────────
    void decryptPreview() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- DECRYPT PREVIEW (memory only) ---\n" << RESET << endl;
        string filename;
        cout << GRAY << "  encrypted file -> " << RESET; getLineTrim(filename); stripQuotes(filename);
        string pw = getPassword();
        if (pw.empty()) return;
        cipher.setKey(pw);
        ifstream in(filename, ios::binary);
        if (!in.is_open()) { cerr << "\n  Cannot open file" << endl; return; }
        vector<unsigned char> data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        in.close();
        auto dec = cipher.decrypt(data);
        if (dec.empty()) { cerr << "\n  Decryption failed" << endl; return; }
        // Check if text or binary
        bool isBinary = false;
        for (size_t i = 0; i < min(dec.size(), (size_t)512); i++) {
            if (dec[i] == 0) { isBinary = true; break; }
        }
        cout << GREEN << "\n  Preview (" << dec.size() << " bytes, "
             << (isBinary ? "binary" : "text") << "):" << RESET << endl;
        cout << "  " << string(50, '-') << endl;
        if (isBinary) {
            for (size_t i = 0; i < min(dec.size(), (size_t)256); i++) {
                if (i % 16 == 0 && i > 0) cout << endl;
                if (i % 16 == 0) cout << "  " << hex << setw(8) << setfill('0') << i << "  ";
                cout << hex << setw(2) << setfill('0') << (int)dec[i] << " ";
            }
            cout << "\n"; // dec isn't printable directly, and clashes with std::dec
        } else {
            int lines = 0;
            for (size_t i = 0; i < dec.size() && lines < 50; i++) {
                cout << (char)dec[i];
                if (dec[i] == '\n') lines++;
            }
            if (lines >= 50) cout << "\n  ... (truncated)" << endl;
        }
        cout << "  " << string(50, '-') << endl;
        secure_memzero(dec.data(), dec.size());
    }
    // ─── Key File Generation ─────────────────────────────────
    void generateKeyFileMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- GENERATE KEY FILE (2FA) ---\n" << RESET << endl;
        string filename;
        cout << GRAY << "  key file name -> " << RESET; getLineTrim(filename); stripQuotes(filename);
        if (filename.empty()) filename = "cryptvault.keyfile";
        if (KeyFileManager::generateKeyFile(filename)) {
            cout << GREEN << "\n  Key file created: " << filename << RESET << endl;
            cout << GRAY << "  Keep this file safe! You'll need it + your password to decrypt." << RESET << endl;
        } else {
            cerr << "\n  Failed to generate key file" << endl;
        }
    }
    // ─── Password Generator Menu ─────────────────────────────
    void generatePasswordMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- PASSWORD GENERATOR ---\n" << RESET << endl;
        int len = config.getInt("password_length");
        if (len < 8) len = 24;
        cout << GRAY << "  Length (default " << len << "): " << RESET;
        string lenStr; getLineTrim(lenStr);
        if (!lenStr.empty()) { try { len = stoi(lenStr); } catch (...) {} }
        if (len < 4) len = 4; if (len > 128) len = 128;
        string pw = PasswordGenerator::generate(len);
        double ent = PasswordGenerator::entropy(pw);
        cout << GREEN << "\n  Generated: " << RESET << pw << endl;
        cout << GRAY << "  Length: " << pw.length() << " chars" << RESET << endl;
        cout << GRAY << "  Entropy: " << fixed << setprecision(1) << ent << " bits" << RESET << endl;
        string strength;
        if (ent < 40) strength = "Weak"; else if (ent < 60) strength = "Fair";
        else if (ent < 80) strength = "Good"; else if (ent < 100) strength = "Strong";
        else strength = "Excellent";
        cout << GRAY << "  Strength: " << strength << RESET << endl;
    }
    // ─── Settings Menu ───────────────────────────────────────
    void settingsMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- SETTINGS ---\n" << RESET << endl;
        config.display();
        cout << GRAY << "  Enter setting name (or 'save' to save, 'back' to return): " << RESET;
        string key; getLineTrim(key);
        if (key == "back" || key.empty()) return;
        if (key == "save") { config.save(); cout << GREEN << "  Settings saved!" << RESET << endl; return; }
        cout << GRAY << "  New value for '" << key << "': " << RESET;
        string val; getLineTrim(val);
        config.set(key, val);
        config.save();
        cout << GREEN << "  Updated: " << key << " = " << val << RESET << endl;
    }


    // ─── Directory Encryption ────────────────────────────────
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
        void rsaGenerateKeysMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- GENERATE RSA KEY PAIR ---\n" << RESET << endl;
        
        string pubFile, privFile;
        cout << GRAY << "  Public key filename (e.g. public.pem) -> " << RESET; getLineTrim(pubFile); stripQuotes(pubFile);
        if(pubFile.empty()) pubFile = "public.pem";
        
        cout << GRAY << "  Private key filename (e.g. private.pem) -> " << RESET; getLineTrim(privFile); stripQuotes(privFile);
        if(privFile.empty()) privFile = "private.pem";
        
        if (RSAKeyManager::generateKeyPair(pubFile, privFile)) {
            cout << GREEN << "\n  RSA Key Pair generated successfully!" << RESET << endl;
            cout << "  Share " << pubFile << " with the sender." << endl;
            cout << "  Keep " << privFile << " absolutely safe!" << endl;
        } else {
            cerr << RED << "\n  Error generating RSA keys." << RESET << endl;
        }
    }

    void rsaWrapMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- RSA WRAP PASSWORD ---\n" << RESET << endl;
        
        string pubFile, password, wrapped;
        cout << GRAY << "  Recipient's Public Key file -> " << RESET; getLineTrim(pubFile); stripQuotes(pubFile);
        password = getPasswordWithConfirmation();
        if(password.empty()) return;
        
        if (RSAKeyManager::wrapPassword(password, pubFile, wrapped)) {
            cout << GREEN << "\n  Password Wrapped Successfully!" << RESET << endl;
            cout << GRAY << "  Wrapped Data (Hex):\n" << RESET << wrapped << endl;
            cout << "\n  Send this hex string to the recipient." << endl;
        } else {
            cerr << RED << "\n  Failed to wrap password with provided public key." << RESET << endl;
        }
    }

    void rsaUnwrapMenu() {
        const string CYAN = "\033[38;5;44m", GREEN = "\033[38;5;82m", RED = "\033[38;5;196m";
        const string GRAY = "\033[38;5;245m", RESET = "\033[0m";
        cout << CYAN << "\n  --- RSA UNWRAP PASSWORD ---\n" << RESET << endl;
        
        string privFile, wrappedHex, unwrapped;
        cout << GRAY << "  Your Private Key file -> " << RESET; getLineTrim(privFile); stripQuotes(privFile);
        cout << GRAY << "  Wrapped Password (Hex) -> " << RESET; getLineTrim(wrappedHex);
        
        if (RSAKeyManager::unwrapPassword(wrappedHex, privFile, unwrapped)) {
            cout << GREEN << "\n  Password Unwrapped Successfully!" << RESET << endl;
            cout << GRAY << "  Sender's Password:\n" << RESET << unwrapped << endl;
        } else {
            cerr << RED << "\n  Failed to unwrap password with provided private key." << RESET << endl;
        }
    }

    void run() {
        p2p_init(&blockchain, 8333);
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
            if (choice == 25) { 
                cout << CYAN << "\n  ✓ Thank you for using Crypt Vault. Goodbye!\n" << RESET << endl;
                break; 
            }
            switch (choice) {
                case 1: { // Encrypt file
                    cout << CYAN << "\n  ─── ENCRYPT FILE ───\n" << RESET << endl;
                    cout << GRAY << "  input file  → " << RESET; getLineTrim(inputFile); stripQuotes(inputFile);
                    cout << GRAY << "  output file → " << RESET; getLineTrim(outputFile); stripQuotes(outputFile);
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
                    cout << GRAY << "  input file  → " << RESET; getLineTrim(inputFile); stripQuotes(inputFile);
                    cout << GRAY << "  output file → " << RESET; getLineTrim(outputFile); stripQuotes(outputFile);
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
                case 3: { // Encrypt text
                    cout << CYAN << "\n  ─── ENCRYPT TEXT ───\n" << RESET << endl;
                    cout << GRAY << "  plaintext → " << RESET; getLineTrim(text);
                    pw = getPasswordWithConfirmation();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    clock_t encStart = clock();
                    string encryptedText = cipher.encryptText(text);
                    double encDuration = (double)(clock()-encStart)/CLOCKS_PER_SEC;
                    
                    cout << GREEN << "\n  ✓ Encrypted: " << RESET << encryptedText << endl;
                    
                    // Log to blockchain
                    string textHash = SHA256::hash(text);
                    logEncryption(blockchain, "TEXT_DATA", textHash, text.length(), encDuration * 1000, true);
                    
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                }
                case 4: { // Decrypt text
                    cout << CYAN << "\n  ─── DECRYPT TEXT ───\n" << RESET << endl;
                    cout << GRAY << "  ciphertext (hex) → " << RESET; getLineTrim(text);
                    pw = getPassword();
                    if (pw.empty()) break;
                    cipher.setKey(pw);
                    clock_t decStart = clock();
                    string result = cipher.decryptText(text);
                    double decDuration = (double)(clock()-decStart)/CLOCKS_PER_SEC;
                    if (result.empty()) {
                        cout << RED << "\n  ✗ Decryption failed (wrong password or invalid data)" << RESET << endl;
                    } else {
                        cout << GREEN << "\n  ✓ Decrypted: " << RESET << result << endl;
                        // Log to blockchain
                        string textHash = SHA256::hash(result);
                        logDecryption(blockchain, "TEXT_DATA", textHash, result.length(), decDuration * 1000, true);
                    }
                    
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                }
                case 5: batchEncrypt(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 6: batchDecrypt(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 7: // View file
                    cout << CYAN << "\n  ─── VIEW FILE ───\n" << RESET << endl;
                    cout << GRAY << "  filename → " << RESET; getLineTrim(inputFile); stripQuotes(inputFile);
                    cipher.displayFileContent(inputFile);
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 8: // File stats
                    cout << CYAN << "\n  ─── FILE STATISTICS ───\n" << RESET << endl;
                    cout << GRAY << "  filename → " << RESET; getLineTrim(inputFile); stripQuotes(inputFile);
                    cipher.showFileStats(inputFile);
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 9: // SHA-256 hash
                    cout << CYAN << "\n  ─── SHA-256 HASH ───\n" << RESET << endl;
                    cout << GRAY << "  filename → " << RESET; getLineTrim(inputFile); stripQuotes(inputFile);
                    { string h = cipher.hashFile(inputFile);
                      if (h.empty()) cerr << RED << "\n  ✗ Cannot open file." << RESET << endl;
                      else cout << GREEN << "\n  ✓ SHA-256: " << RESET << h << endl;
                    }
                    cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 10: displayAuditMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 11: p2p_status(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 12: showAbout(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 13: encryptDirectory(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 14: decryptDirectory(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 15: secureDeleteMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 16: compressAndEncrypt(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 17: decryptPreview(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 18: generateKeyFileMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 19: generatePasswordMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 20: encLog.display(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 21: settingsMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                                case 22: runBenchmarks(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 23: rsaGenerateKeysMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 24: rsaWrapMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;
                case 25: rsaUnwrapMenu(); cout << GRAY << "\n  Press Enter to continue..." << RESET; cin.get(); break;

                default:
                    cout << RED << "\n  ✗ Invalid choice! Please select 1-25." << RESET << endl;
                    cout << GRAY << "  Press Enter to continue..." << RESET; cin.get();
            }
        }
        p2p_shutdown();
    }
};
// Program Entry Point
int main(int argc, char* argv[]) {
    if (argc > 1) {
        string cmd = argv[1];
        
        if (cmd == "--help" || cmd == "-h") {
             cout << "CryptVault CLI Usage:\n"
                  << "  --encrypt <file> [-p <password>] [-o <output>]\n"
                  << "  --decrypt <file> [-p <password>] [-o <output>]\n"
                  << "  --compress <file> [-p <password>] [-o <output>]\n"
                  << "  --preview <file> [-p <password>]\n"
                  << "  --encrypt-dir <dir> [-p <password>]\n"
                  << "  --decrypt-dir <dir> [-p <password>]\n"
                  << "  --batch-enc <file1,file2,...> [-p <password>]\n"
                  << "  --batch-dec <file1,file2,...> [-p <password>]\n"
                  << "  --shred <file> [--passes <n>]\n"
                  << "  --hash <file>\n"
                  << "  --stats <file>\n"
                  << "  --benchmark\n"
                  << "  --keygen <file>\n"
                  << "  --genpass [length]\n";
            return 0;
        }
        
        AESCipher cipher;
        
        if (cmd == "--genpass") {
            int len = (argc > 2) ? stoi(argv[2]) : 24;
            cout << PasswordGenerator::generate(len) << endl;
            return 0;
        }
        if (cmd == "--benchmark") {
            runBenchmarks();
            return 0;
        }
        if (cmd == "--shred" && argc > 2) {
            string file = argv[2];
            int passes = 3;
            for (int i = 3; i < argc; i++) {
                if (string(argv[i]) == "--passes" && i + 1 < argc) passes = stoi(argv[++i]);
            }
            return SecureDelete::shredFile(file, passes) ? 0 : 1;
        }
        if (cmd == "--hash" && argc > 2) {
            string hash = cipher.hashFile(argv[2]);
            if (!hash.empty()) { cout << hash << endl; return 0; }
            return 1;
        }
        if (cmd == "--stats" && argc > 2) {
            cipher.showFileStats(argv[2]);
            return 0;
        }
        if (cmd == "--keygen" && argc > 2) {
            return KeyFileManager::generateKeyFile(argv[2]) ? 0 : 1;
        }
        if (cmd == "--encrypt" || cmd == "--decrypt" || cmd == "--encrypt-dir" || cmd == "--decrypt-dir") {
            if (argc < 3) { cerr << "Missing target" << endl; return 1; }
            string target = argv[2], pw, out;
            for (int i = 3; i < argc; i++) {
                if (string(argv[i]) == "-p" && i + 1 < argc) pw = argv[++i];
                if (string(argv[i]) == "-o" && i + 1 < argc) out = argv[++i];
            }
            if (pw.empty()) { cerr << "Password required (-p <password>)" << endl; return 1; }
            cipher.setKey(pw);
            if (cmd == "--encrypt") {
                if (out.empty()) out = target + ".enc";
                return cipher.encryptFile(target, out) ? 0 : 1;
            }
            if (cmd == "--decrypt") {
                if (out.empty()) out = target + ".dec";
                return cipher.decryptFile(target, out) ? 0 : 1;
            }
            if (cmd == "--compress") {
                if (out.empty()) out = target + ".cvz";
                string tmp = target + ".tmp_c";
                if (!SimpleCompressor::compressFile(target, tmp)) return 1;
                bool ok = cipher.encryptFile(tmp, out);
                remove(tmp.c_str());
                return ok ? 0 : 1;
            }
            if (cmd == "--preview") {
                string tmp = target + ".tmp_p";
                if (!cipher.decryptFile(target, tmp)) { remove(tmp.c_str()); return 1; }
                ifstream f(tmp, ios::binary);
                if (f.is_open()) {
                    vector<unsigned char> data(1024);
                    f.read((char*)data.data(), 1024);
                    size_t bytes = (size_t)f.gcount();
                    f.close();
                    
                    bool isBinary = false;
                    for (size_t i = 0; i < min(bytes, (size_t)512); i++) if (data[i] == 0) { isBinary = true; break; }
                    
                    if (isBinary) {
                        for (size_t i = 0; i < min(bytes, (size_t)256); i++) 
                            cout << hex << setw(2) << setfill('0') << (int)data[i] << (i % 16 == 15 ? "\n" : " ");
                    } else {
                        cout << string((char*)data.data(), min(bytes, (size_t)1024)) << endl;
                    }
                }
                remove(tmp.c_str());
                return 0;
            }
            if (cmd == "--encrypt-dir") {
                int ok=0;
                vector<string> files; FsCompat::get_files_recursive(target, files);
                for (const auto& f : files) {
                    if (!FileHelper::hasEncExtension(f)) {
                        if (cipher.encryptFile(f, f + ".enc")) ok++;
                    }
                }
                return ok > 0 ? 0 : 1;
            }
            if (cmd == "--decrypt-dir") {
                int ok=0;
                vector<string> files; FsCompat::get_files_recursive(target, files);
                for (const auto& f : files) {
                    if (FileHelper::hasEncExtension(f)) {
                        string dec = FileHelper::removeEncExtension(f);
                        if (cipher.decryptFile(f, dec)) ok++;
                    }
                }
                return ok > 0 ? 0 : 1;
            }
            if (cmd == "--batch-enc" || cmd == "--batch-dec") {
                stringstream ss(target); string f;
                while (getline(ss, f, ',')) {
                    if (cmd == "--batch-enc") cipher.encryptFile(f, f + ".enc");
                    else cipher.decryptFile(f, FileHelper::removeEncExtension(f));
                }
                return 0;
            }
        }
        cerr << "Unknown command." << endl; return 1;
    }
    CryptVaultApp app;
    app.run();
    return 0;
}

