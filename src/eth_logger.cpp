#include "eth_logger.hpp"
#include "eth_transaction.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "vendor/httplib.h"
#include "vendor/json.hpp"
#include "vendor/secp256k1/include/secp256k1.h"
#include <iostream>

using json = nlohmann::json;

EthLogger::EthLogger(const std::string& rpcUrl, const std::string& privKeyHex, const std::string& contractAddr) {
    auto pos = rpcUrl.find("://");
    std::string url = (pos != std::string::npos) ? rpcUrl.substr(pos + 3) : rpcUrl;
    pos = url.find('/');
    if (pos != std::string::npos) {
        _rpcHost = "https://" + url.substr(0, pos);
        _rpcPath = url.substr(pos);
    } else {
        _rpcHost = "https://" + url;
        _rpcPath = "/";
    }

    _contractAddress = contractAddr;

    std::string h = privKeyHex.substr(privKeyHex.find("0x") == 0 ? 2 : 0);
    for (size_t i = 0; i < 32; i++) {
        _privateKey[i] = static_cast<uint8_t>(std::stoul(h.substr(i*2, 2), nullptr, 16));
    }
    _walletAddress = deriveAddress(_privateKey);
}

std::string EthLogger::deriveAddress(const std::array<uint8_t, 32>& privKey) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data())) {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Invalid private key");
    }
    uint8_t serialized[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);

    auto hash = keccak256(serialized + 1, 64);
    std::ostringstream ss;
    ss << "0x";
    for (int i = 12; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::vector<uint8_t> EthLogger::buildCalldata(const std::array<uint8_t, 32>& fileHash, OpType op, const std::string& metadata) {
    // Keccak256 of "logOperation(bytes32,uint8,string)" is 0xa6a74b4b...
    std::string sig = "logOperation(bytes32,uint8,string)";
    auto sigHash = keccak256(reinterpret_cast<const uint8_t*>(sig.c_str()), sig.size());
    std::vector<uint8_t> calldata;
    calldata.insert(calldata.end(), sigHash.begin(), sigHash.begin() + 4);

    // Arg 1: fileHash (32 bytes)
    calldata.insert(calldata.end(), fileHash.begin(), fileHash.end());

    // Arg 2: op (uint8 padded to 32 bytes)
    for(int i=0; i<31; i++) calldata.push_back(0);
    calldata.push_back(static_cast<uint8_t>(op));

    // Arg 3: metadata string offset (32 bytes) -> 0x60
    for(int i=0; i<31; i++) calldata.push_back(0);
    calldata.push_back(0x60);

    // String length
    for(int i=0; i<28; i++) calldata.push_back(0);
    uint32_t len = metadata.size();
    calldata.push_back((len >> 24) & 0xFF);
    calldata.push_back((len >> 16) & 0xFF);
    calldata.push_back((len >> 8) & 0xFF);
    calldata.push_back(len & 0xFF);

    // String bytes padded to 32 byte boundary
    calldata.insert(calldata.end(), metadata.begin(), metadata.end());
    while (calldata.size() % 32 != 4) calldata.push_back(0);

    return calldata;
}

std::vector<uint8_t> EthLogger::buildAnchorCalldata(uint64_t blockHeight, const std::string& blockHashHex) {
    // anchorChain(uint256,bytes32) -> keccak256 is 0x6e241776...
    std::string sig = "anchorChain(uint256,bytes32)";
    auto sigHash = keccak256(reinterpret_cast<const uint8_t*>(sig.c_str()), sig.size());
    std::vector<uint8_t> calldata;
    calldata.insert(calldata.end(), sigHash.begin(), sigHash.begin() + 4);

    // Arg 1: blockHeight
    for(int i=0; i<24; i++) calldata.push_back(0);
    for(int i=7; i>=0; i--) calldata.push_back((blockHeight >> (i*8)) & 0xFF);

    // Arg 2: blockHashHex to bytes32
    std::string h = blockHashHex.substr(blockHashHex.find("0x") == 0 ? 2 : 0);
    for(size_t i=0; i<32; i++) {
        calldata.push_back(static_cast<uint8_t>(std::stoul(h.substr(i*2, 2), nullptr, 16)));
    }

    return calldata;
}

std::string EthLogger::logOperation(
    const std::array<uint8_t, 32>& fileHash,
    OpType op,
    const std::string& metadata)
{
    auto calldata = buildCalldata(fileHash, op, metadata);
    uint64_t nonce = getNonce();
    EthTransaction tx {
        .nonce        = nonce,
        .gasPriceWei  = getGasPrice(),
        .gasLimit     = 150000,
        .to           = _contractAddress,
        .value        = 0,
        .data         = calldata,
        .chainId      = 11155111 
    };
    auto rawTx = signTransaction(tx, _privateKey);
    return sendRawTransaction(rawTx);
}

std::string EthLogger::anchorChain(uint64_t blockHeight, const std::string& blockHashHex) {
    auto calldata = buildAnchorCalldata(blockHeight, blockHashHex);
    uint64_t nonce = getNonce();
    EthTransaction tx {
        .nonce        = nonce,
        .gasPriceWei  = getGasPrice(),
        .gasLimit     = 100000,
        .to           = _contractAddress,
        .value        = 0,
        .data         = calldata,
        .chainId      = 11155111 
    };
    auto rawTx = signTransaction(tx, _privateKey);
    return sendRawTransaction(rawTx);
}

uint64_t EthLogger::getNonce() {
    json req = {
        {"jsonrpc", "2.0"}, {"method", "eth_getTransactionCount"},
        {"params", {_walletAddress, "pending"}}, {"id", 1}
    };
    auto res = rpcCall(req);
    return std::stoull(res["result"].get<std::string>(), nullptr, 16);
}

uint64_t EthLogger::getGasPrice() {
    json req = {
        {"jsonrpc", "2.0"}, {"method", "eth_gasPrice"},
        {"params", json::array()}, {"id", 1}
    };
    auto res = rpcCall(req);
    return std::stoull(res["result"].get<std::string>(), nullptr, 16);
}

std::string EthLogger::sendRawTransaction(const std::string& rawTx) {
    json req = {
        {"jsonrpc", "2.0"}, {"method", "eth_sendRawTransaction"},
        {"params", {rawTx}}, {"id", 1}
    };
    auto res = rpcCall(req);
    if (res.contains("error"))
        throw std::runtime_error("Ethereum RPC error: " +
            res["error"]["message"].get<std::string>());
    return res["result"].get<std::string>();
}

json EthLogger::rpcCall(const json& body) {
    httplib::Client cli(_rpcHost);
    cli.set_connection_timeout(10);
    auto res = cli.Post(_rpcPath, body.dump(), "application/json");
    if (!res || res->status != 200)
        throw std::runtime_error("HTTP error: " +
            std::to_string(res ? res->status : 0));
    return json::parse(res->body);
}
