#pragma once
#include <string>
#include <array>
#include <vector>
#include <cstdint>
#include "vendor/json.hpp"

class EthLogger {
public:
    enum class OpType { ENCRYPT = 0, DECRYPT = 1, DELETE_FILE = 2 };

    EthLogger(const std::string& rpcUrl, const std::string& privKeyHex, const std::string& contractAddr);

    std::string logOperation(const std::array<uint8_t, 32>& fileHash, OpType op, const std::string& metadata);
    std::string anchorChain(uint64_t blockHeight, const std::string& blockHashHex);

private:
    std::string _rpcHost;
    std::string _rpcPath;
    std::string _contractAddress;
    std::string _walletAddress;
    std::array<uint8_t, 32> _privateKey;

    uint64_t getNonce();
    uint64_t getGasPrice();
    std::string sendRawTransaction(const std::string& rawTx);
    nlohmann::json rpcCall(const nlohmann::json& body);
    std::vector<uint8_t> buildCalldata(const std::array<uint8_t, 32>& fileHash, OpType op, const std::string& metadata);
    std::vector<uint8_t> buildAnchorCalldata(uint64_t blockHeight, const std::string& blockHashHex);
    std::string deriveAddress(const std::array<uint8_t, 32>& privKey);
};
