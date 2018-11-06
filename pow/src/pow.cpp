#include "pow.hpp"

#include <array>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <iomanip>
#include <limits>
#include <openssl/sha.h>
#include <string.h>

const int BYTE_LEN = 8;
const int NONCE_TRIALS = 1000;
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

// Base64 decode function using boost, found online
std::string base64_decode(std::string input) {
    using namespace boost::archive::iterators;
    typedef transform_width<
        binary_from_base64<remove_whitespace<std::string::const_iterator>>, 8,
        6>
        ItBinaryT;

    try {
        // If the input isn't a multiple of 4, pad with =
        size_t num_pad_chars((4 - input.size() % 4) % 4);
        input.append(num_pad_chars, '=');

        size_t pad_chars(std::count(input.begin(), input.end(), '='));
        std::replace(input.begin(), input.end(), '=', 'A');
        std::string output(ItBinaryT(input.begin()), ItBinaryT(input.end()));
        output.erase(output.end() - pad_chars, output.end());
        return output;
    } catch (std::exception const&) {
        return std::string("");
    }
}

bool checkPoW(const std::string& nonce, const std::string& timestamp,
              const std::string& ttl, const std::string& recipient,
              const std::vector<uint8_t>& data, std::string& messageHash) {
    std::vector<uint8_t> payload;
    payload.reserve(timestamp.size() + ttl.size() + recipient.size() +
                    data.size());
    payload.insert(std::end(payload), std::begin(timestamp),
                   std::end(timestamp));
    payload.insert(std::end(payload), std::begin(ttl), std::end(ttl));
    payload.insert(std::end(payload), std::begin(recipient),
                   std::end(recipient));
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
