#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace research::cryptography {

// Minimal RC4 implementation — no external dependencies.
// Used to decrypt the remotely-fetched Sliver beacon shellcode.

inline void Rc4Crypt(const uint8_t* input, std::size_t length, uint8_t* output,
                      const std::vector<uint8_t>& key) {
    std::size_t key_length = key.size();
    if (key_length == 0 || length == 0) {
        return;
    }

    // KSA — key scheduling algorithm
    std::array<uint8_t, 256> s;
    for (int i = 0; i < 256; ++i) {
        s[i] = static_cast<uint8_t>(i);
    }

    std::size_t j = 0;
    for (std::size_t i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % key_length]) % 256;
        std::swap(s[i], s[j]);
    }

    // PRGA — pseudo-random generation algorithm
    std::size_t i_idx = 0;
    j = 0;
    for (std::size_t n = 0; n < length; ++n) {
        i_idx = (i_idx + 1) % 256;
        j = (j + s[i_idx]) % 256;
        std::swap(s[i_idx], s[j]);
        output[n] = input[n] ^ s[(s[i_idx] + s[j]) % 256];
    }
}

// Convenience: in-place decryption of a std::vector.
inline void Rc4DecryptInPlace(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& key) {
    Rc4Crypt(buffer.data(), buffer.size(), buffer.data(), key);
}

// Convenience: in-place decryption from a string key.
inline void Rc4DecryptInPlace(std::vector<uint8_t>& buffer, const char* key_str) {
    std::size_t key_len = std::char_traits<char>::length(key_str);
    std::vector<uint8_t> key(key_len);
    std::memcpy(key.data(), key_str, key_len);
    Rc4Crypt(buffer.data(), buffer.size(), buffer.data(), key);
}

} // namespace research::cryptography
