#include <string.h>
#include <limits>
#include <array>
#include <openssl/sha.h>
#include "pow.hpp"
#include "base64.hpp"

const int BYTE_LEN = 8;
const int NONCE_TRIALS = 1000;
using uint64Bytes = std::array<uint8_t, BYTE_LEN>;

// This enforces that the result array has the most significant byte at index 0
void u64ToU8Array(uint64_t numberVal, uint64Bytes &result) {
    for (int idx = result.size() - 1; idx >= 0; idx--) {
        // Grab the least significant byte
        result[idx] = numberVal & (uint64_t)0xFF;
        // Bitshift right one byte
        numberVal >>= BYTE_LEN;
    }
}

bool addWillOverflow(uint64_t x, uint64_t add) {
    return std::numeric_limits<uint64_t>::max() - x < add;
}

bool multWillOverflow(uint64_t left, uint64_t right) {
    return left != 0 && (std::numeric_limits<std::uint64_t>::max() / left < right);
}

bool checkPoW(std::string &nonce, std::string &timestamp, std::string &ttl, std::string &recipient, std::vector<uint8_t> &data) {
    std::vector<uint8_t> payload;
    payload.reserve(timestamp.size() + ttl.size() + recipient.size() + data.size());
    payload.insert(std::end(payload), std::begin(timestamp), std::end(timestamp));
    payload.insert(std::end(payload), std::begin(ttl), std::end(ttl));
    payload.insert(std::end(payload), std::begin(recipient), std::end(recipient));
    payload.insert(std::end(payload), std::begin(data), std::end(data));

    bool overflow = addWillOverflow(payload.size(), BYTE_LEN);
    if (overflow)
        return false;
    uint64_t totalLen = payload.size() + BYTE_LEN;
    overflow = multWillOverflow(stoi(ttl), totalLen);
    if (overflow)
        return false;
    uint64_t ttlMult = stoi(ttl) * totalLen;
    uint64_t innerFrac = ttlMult / std::numeric_limits<uint16_t>::max();
    overflow = addWillOverflow(totalLen, innerFrac);
    if (overflow)
        return false;
    uint64_t lenPlusInnerFrac = totalLen + innerFrac;
    overflow = multWillOverflow(NONCE_TRIALS, lenPlusInnerFrac);
    if (overflow)
        return false;
    uint64_t denominator = NONCE_TRIALS * lenPlusInnerFrac;
    uint64_t targetNum = std::numeric_limits<uint64_t>::max() / denominator;

    uint64Bytes target;
    u64ToU8Array(targetNum, target);

    uint8_t hashResult[SHA512_DIGEST_LENGTH];
    // Initial hash
    SHA512(payload.data(), payload.size(), hashResult);
    // Convert nonce to binary
    std::string decodedNonce = base64_decode(nonce);
    // Convert decoded nonce string into uint8_t vector. Will have length 8
    std::vector<uint8_t> innerPayload;
    innerPayload.reserve(decodedNonce.size() + SHA512_DIGEST_LENGTH);
    innerPayload.insert(std::end(innerPayload), std::begin(decodedNonce), std::end(decodedNonce));
    innerPayload.insert(std::end(innerPayload), hashResult, hashResult + SHA512_DIGEST_LENGTH);
    // Final hash
    SHA512(innerPayload.data(), innerPayload.size(), hashResult);
    return memcmp(hashResult, target.data(), BYTE_LEN) < 0;
}
