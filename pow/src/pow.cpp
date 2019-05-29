#include "pow.hpp"
#include "utils.hpp"

#include <array>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <iomanip>
#include <limits>
#include <openssl/sha.h>
#include <sstream>
#include <string.h>

const int BYTE_LEN = 8;
using uint64Bytes = std::array<uint8_t, BYTE_LEN>;

// This enforces that the result array has the most significant byte at index 0
void u64ToU8Array(uint64_t numberVal, uint64Bytes& result) {
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
    return left != 0 &&
           (std::numeric_limits<std::uint64_t>::max() / left < right);
}

bool checkPoW(const std::string& nonce, const std::string& timestamp,
              const std::string& ttl, const std::string& recipient,
              const std::string& data, std::string& messageHash,
              const int& difficulty) {
    const std::string payload = timestamp + ttl + recipient + data;

    bool overflow = addWillOverflow(payload.size(), BYTE_LEN);
    if (overflow)
        return false;
    uint64_t ttlInt;
    if (!util::parseTTL(ttl, ttlInt))
        return false;
    // ttl is in milliseconds, but target calculation wants seconds
    ttlInt = ttlInt / 1000;
    uint64_t totalLen = payload.size() + BYTE_LEN;
    overflow = multWillOverflow(ttlInt, totalLen);
    if (overflow)
        return false;
    uint64_t ttlMult = ttlInt * totalLen;
    uint64_t innerFrac = ttlMult / std::numeric_limits<uint16_t>::max();
    overflow = addWillOverflow(totalLen, innerFrac);
    if (overflow)
        return false;
    uint64_t lenPlusInnerFrac = totalLen + innerFrac;
    overflow = multWillOverflow(difficulty, lenPlusInnerFrac);
    if (overflow)
        return false;
    uint64_t denominator = difficulty * lenPlusInnerFrac;
    uint64_t targetNum = std::numeric_limits<uint64_t>::max() / denominator;

    uint64Bytes target;
    u64ToU8Array(targetNum, target);

    uint8_t hashResult[SHA512_DIGEST_LENGTH];
    // Initial hash
    SHA512((const unsigned char*)payload.data(), payload.size(), hashResult);
    // Convert nonce to binary
    std::string decodedNonce = boost::beast::detail::base64_decode(nonce);
    // Convert decoded nonce string into uint8_t vector. Will have length 8
    std::vector<uint8_t> innerPayload;
    innerPayload.reserve(decodedNonce.size() + SHA512_DIGEST_LENGTH);
    innerPayload.insert(std::end(innerPayload), std::begin(decodedNonce),
                        std::end(decodedNonce));
    innerPayload.insert(std::end(innerPayload), hashResult,
                        hashResult + SHA512_DIGEST_LENGTH);
    // Final hash
    SHA512(innerPayload.data(), innerPayload.size(), hashResult);
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        ss << std::setw(2) << static_cast<unsigned>(hashResult[i]);
    messageHash = ss.str();

    return memcmp(hashResult, target.data(), BYTE_LEN) < 0;
}
