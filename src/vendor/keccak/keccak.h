#pragma once
#include <cstdint>
#include <array>

std::array<uint8_t, 32> keccak256(const uint8_t* data, size_t len);
