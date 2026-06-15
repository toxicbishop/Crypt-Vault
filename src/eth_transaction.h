#pragma once
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include "vendor/keccak/keccak.h"
#include "vendor/secp256k1/include/secp256k1.h"
#include "vendor/secp256k1/include/secp256k1_recovery.h"

// -- RLP encoding -------------------------------------------------------------
static void rlpEncodeLength(std::vector<uint8_t>& out, size_t len, uint8_t offset) {
    if (len < 56) {
        out.push_back(static_cast<uint8_t>(offset + len));
    } else {
        std::vector<uint8_t> lenBytes;
        size_t tmp = len;
        while (tmp > 0) { lenBytes.insert(lenBytes.begin(), tmp & 0xFF); tmp >>= 8; }
        out.push_back(static_cast<uint8_t>(offset + 55 + lenBytes.size()));
        out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    }
}

static void rlpEncodeBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& data) {
    if (data.size() == 1 && data[0] < 0x80) {
        out.push_back(data[0]);
    } else {
        rlpEncodeLength(out, data.size(), 0x80);
        out.insert(out.end(), data.begin(), data.end());
    }
}

static std::vector<uint8_t> rlpEncodeList(const std::vector<std::vector<uint8_t>>& preEncodedFields) {
    std::vector<uint8_t> payload;
    for (auto& f : preEncodedFields) {
        payload.insert(payload.end(), f.begin(), f.end());
    }
    std::vector<uint8_t> out;
    rlpEncodeLength(out, payload.size(), 0xC0);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

static std::vector<uint8_t> minimalBigEndian(uint64_t value) {
    if (value == 0) return {};
    std::vector<uint8_t> out;
    while (value > 0) { out.insert(out.begin(), value & 0xFF); value >>= 8; }
    return out;
}

static std::vector<uint8_t> rlpBytes(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out;
    rlpEncodeBytes(out, data);
    return out;
}

struct EthTransaction {
    uint64_t nonce;
    uint64_t gasPriceWei;
    uint64_t gasLimit;
    std::string to;
    uint64_t value;
    std::vector<uint8_t> data;
    uint64_t chainId;
};

static std::string signTransaction(const EthTransaction& tx, const std::array<uint8_t, 32>& privateKey) {
    auto hexToBytes = [](const std::string& hex) {
        std::vector<uint8_t> out;
        std::string h = hex.substr(hex.find("0x") == 0 ? 2 : 0);
        for (size_t i = 0; i < h.size(); i += 2)
            out.push_back(static_cast<uint8_t>(std::stoul(h.substr(i,2), nullptr, 16)));
        return out;
    };

    std::vector<std::vector<uint8_t>> fields = {
        rlpBytes(minimalBigEndian(tx.nonce)),
        rlpBytes(minimalBigEndian(tx.gasPriceWei)),
        rlpBytes(minimalBigEndian(tx.gasLimit)),
        rlpBytes(hexToBytes(tx.to)),
        rlpBytes(minimalBigEndian(tx.value)),
        rlpBytes(tx.data),
        rlpBytes(minimalBigEndian(tx.chainId)),
        rlpBytes({}),
        rlpBytes({})
    };

    auto rlpUnsigned = rlpEncodeList(fields);
    auto hash = keccak256(rlpUnsigned.data(), rlpUnsigned.size());

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash.data(), privateKey.data(), nullptr, nullptr))
        throw std::runtime_error("secp256k1 signing failed");

    uint8_t sigBytes[64]; int recoveryId;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sigBytes, &recoveryId, &sig);
    secp256k1_context_destroy(ctx);

    uint64_t v = tx.chainId * 2 + 35 + recoveryId;

    std::vector<uint8_t> r(sigBytes, sigBytes + 32);
    std::vector<uint8_t> s(sigBytes + 32, sigBytes + 64);

    while (r.size() > 1 && r[0] == 0) r.erase(r.begin());
    while (s.size() > 1 && s[0] == 0) s.erase(s.begin());

    std::vector<std::vector<uint8_t>> signedFields = {
        rlpBytes(minimalBigEndian(tx.nonce)),
        rlpBytes(minimalBigEndian(tx.gasPriceWei)),
        rlpBytes(minimalBigEndian(tx.gasLimit)),
        rlpBytes(hexToBytes(tx.to)),
        rlpBytes(minimalBigEndian(tx.value)),
        rlpBytes(tx.data),
        rlpBytes(minimalBigEndian(v)),
        rlpBytes(r),
        rlpBytes(s)
    };

    auto rlpSigned = rlpEncodeList(signedFields);

    std::ostringstream out;
    out << "0x";
    for (auto b : rlpSigned)
        out << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return out.str();
}
