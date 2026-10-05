// Copyright (c) 2026 WAM Coin developers
// Distributed under the MIT software license, see COPYING.
//
// ===============================================================================
//  rx/wam -- RandomX over Bitcoin-style 80-byte header
// ===============================================================================
//
//  WAM Coin uses RandomX proof of work with a Bitcoin-style block header
//  (80 bytes, little-endian integers) instead of Monero's blob format.
//  This adapter implements WAM mining within xmrig's RandomX framework.
//
//  Key differences from standard RandomX (Monero):
//  - Header: 80 bytes (Bitcoin format) vs. Monero blob
//  - Nonce position: bytes 76-79 (little-endian) vs. byte 39 in Monero
//  - Block template: pool sends coinbase parts + merkle branch (Stratum-style)
//  - RandomX seed: rotates every 2048 blocks with 64-block lag
//

#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <array>

namespace xmrig {

// Type aliases for WAM-specific data
using Bytes = std::vector<uint8_t>;

// 256-bit target stored as 32 big-endian bytes
struct WamTarget {
    uint8_t bytes[32];
    
    bool operator<=(const WamTarget& other) const {
        return std::memcmp(bytes, other.bytes, 32) <= 0;
    }
};

// Byte order utilities
inline void WriteLE32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

inline uint32_t ReadBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline void PowHashToBigEndian(const uint8_t hashLE[32], uint8_t out[32]) {
    for (int i = 0; i < 32; i++) out[i] = hashLE[31 - i];
}

// WAM block template from stratum pool
struct WamBlockTemplate {
    std::string jobId;
    uint8_t prevHash[32] = {};
    Bytes coinb1;                          // First half of coinbase
    Bytes coinb2;                          // Second half of coinbase
    std::vector<std::array<uint8_t, 32>> merkleBranch;  // Merkle branch for root
    uint32_t version = 0;
    uint32_t nbits = 0;  // Difficulty encoding
    uint32_t ntime = 0;
    Bytes seed;          // 32-byte RandomX key
    Bytes extranonce1;   // Pool's nonce prefix
    int extranonce2Size = 4;
    int64_t height = 0;
    bool cleanJobs = false;
    bool valid = false;
};

// Hex encoding/decoding
inline std::string ToHex(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

inline std::string ToHex(const Bytes& b) {
    return ToHex(b.data(), b.size());
}

inline bool ParseHex(const std::string& hex, Bytes& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = digit(hex[i]);
        int lo = digit(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return true;
}

// SHA-256 and SHA256d for merkle root computation
class SHA256 {
public:
    SHA256() { Reset(); }
    
    void Reset() {
        m_h[0] = 0x6a09e667; m_h[1] = 0xbb67ae85;
        m_h[2] = 0x3c6ef372; m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f; m_h[5] = 0x9b05688c;
        m_h[6] = 0x1f83d9ab; m_h[7] = 0x5be0cd19;
        m_buflen = 0;
        m_total = 0;
    }
    
    void Update(const uint8_t* data, size_t len) {
        m_total += len;
        
        if (m_buflen > 0) {
            size_t take = 64 - m_buflen;
            if (take > len) take = len;
            std::memcpy(m_buf + m_buflen, data, take);
            m_buflen += take;
            data += take;
            len -= take;
            if (m_buflen == 64) {
                Transform(m_buf);
                m_buflen = 0;
            }
        }
        
        while (len >= 64) {
            Transform(data);
            data += 64;
            len -= 64;
        }
        
        if (len > 0) {
            std::memcpy(m_buf, data, len);
            m_buflen = len;
        }
    }
    
    void Final(uint8_t out[32]) {
        const uint64_t bits = m_total * 8;
        
        uint8_t pad[72];
        std::memset(pad, 0, sizeof(pad));
        pad[0] = 0x80;
        const size_t padlen = (m_buflen < 56) ? (56 - m_buflen) : (120 - m_buflen);
        Update(pad, padlen);
        m_total -= padlen;
        
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; i++) lenbuf[i] = uint8_t(bits >> (56 - i * 8));
        Update(lenbuf, 8);
        
        for (int i = 0; i < 8; i++) {
            out[i * 4 + 0] = uint8_t(m_h[i] >> 24);
            out[i * 4 + 1] = uint8_t(m_h[i] >> 16);
            out[i * 4 + 2] = uint8_t(m_h[i] >> 8);
            out[i * 4 + 3] = uint8_t(m_h[i]);
        }
    }
    
private:
    static uint32_t Ror(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }
    
    void Transform(const uint8_t* chunk);
    
    uint32_t m_h[8];
    uint8_t m_buf[64];
    size_t m_buflen;
    uint64_t m_total;
};

inline void SHA256d(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t first[32];
    SHA256 a; a.Update(data, len); a.Final(first);
    SHA256 b; b.Update(first, 32); b.Final(out);
}

inline void SHA256dPair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    uint8_t joined[64];
    std::memcpy(joined, left, 32);
    std::memcpy(joined + 32, right, 32);
    SHA256d(joined, 64, out);
}

// Target utilities
inline bool MeetsTarget(const uint8_t hashBE[32], const WamTarget& target) {
    return std::memcmp(hashBE, target.bytes, 32) <= 0;
}

inline double ChainDifficulty(uint32_t bits) {
    const int shift = int(bits >> 24);
    const double mantissa = double(bits & 0x007fffffu);
    if (mantissa <= 0) return 0;
    double d = double(0x0000ffff) / mantissa;
    for (int i = 29; i > shift; i--) d *= 256.0;
    for (int i = shift; i > 29; i--) d /= 256.0;
    return d;
}

inline WamTarget BitsToTarget(uint32_t bits) {
    WamTarget t;
    std::memset(t.bytes, 0, 32);
    
    const uint32_t exponent = bits >> 24;
    const uint32_t mantissa = bits & 0x007FFFFF;
    
    if (exponent <= 3) {
        const uint32_t shifted = mantissa >> (8 * (3 - exponent));
        t.bytes[29] = uint8_t(shifted >> 16);
        t.bytes[30] = uint8_t(shifted >> 8);
        t.bytes[31] = uint8_t(shifted);
        return t;
    }
    
    const int lowIndex = 32 - int(exponent);
    for (int k = 0; k < 3; k++) {
        const int idx = lowIndex + k;
        if (idx < 0 || idx >= 32) continue;
        t.bytes[idx] = uint8_t(mantissa >> (8 * (2 - k)));
    }
    return t;
}

// Build 80-byte Bitcoin header from WAM block template
inline void BuildWamHeader(const WamBlockTemplate& tmpl, const Bytes& extranonce2, uint8_t header[80]) {
    // Assemble coinbase: coinb1 | extranonce1 | extranonce2 | coinb2
    Bytes coinbase;
    coinbase.reserve(tmpl.coinb1.size() + tmpl.extranonce1.size() + extranonce2.size() + tmpl.coinb2.size());
    coinbase.insert(coinbase.end(), tmpl.coinb1.begin(), tmpl.coinb1.end());
    coinbase.insert(coinbase.end(), tmpl.extranonce1.begin(), tmpl.extranonce1.end());
    coinbase.insert(coinbase.end(), extranonce2.begin(), extranonce2.end());
    coinbase.insert(coinbase.end(), tmpl.coinb2.begin(), tmpl.coinb2.end());
    
    // Merkle root: SHA256d(coinbase), then fold through branch
    uint8_t root[32];
    SHA256d(coinbase.data(), coinbase.size(), root);
    
    for (const std::array<uint8_t, 32>& node : tmpl.merkleBranch) {
        uint8_t next[32];
        SHA256dPair(root, node.data(), next);
        std::memcpy(root, next, 32);
    }
    
    // Write 80-byte header in Bitcoin format (all little-endian)
    // Bytes 0-3: version
    WriteLE32(header + 0, tmpl.version);
    // Bytes 4-35: previous block hash (already in header order)
    std::memcpy(header + 4, tmpl.prevHash, 32);
    // Bytes 36-67: merkle root
    std::memcpy(header + 36, root, 32);
    // Bytes 68-71: timestamp
    WriteLE32(header + 68, tmpl.ntime);
    // Bytes 72-75: difficulty bits
    WriteLE32(header + 72, tmpl.nbits);
    // Bytes 76-79: nonce (will be filled by miner)
    WriteLE32(header + 76, 0);
}

class RxWamHeader
{
public:
    static constexpr uint32_t HEADER_SIZE = 80;
    static constexpr uint32_t NONCE_OFFSET = 76;
    static constexpr uint32_t NONCE_SIZE = 4;

    static inline uint32_t getNonce(const uint8_t *header)
    {
        return *reinterpret_cast<const uint32_t*>(header + NONCE_OFFSET);
    }

    static inline void setNonce(uint8_t *header, uint32_t nonce)
    {
        *reinterpret_cast<uint32_t*>(header + NONCE_OFFSET) = nonce;
    }

    static bool buildHeader(
        uint8_t *header,
        uint32_t version,
        const uint8_t *prevBlockHash,
        const uint8_t *merkleRoot,
        uint32_t time,
        uint32_t bits,
        uint32_t nonce)
    {
        if (!header || !prevBlockHash || !merkleRoot) {
            return false;
        }

        std::memset(header, 0, HEADER_SIZE);
        *reinterpret_cast<uint32_t*>(header + 0) = version;
        std::memcpy(header + 4, prevBlockHash, 32);
        std::memcpy(header + 36, merkleRoot, 32);
        *reinterpret_cast<uint32_t*>(header + 68) = time;
        *reinterpret_cast<uint32_t*>(header + 72) = bits;
        *reinterpret_cast<uint32_t*>(header + 76) = nonce;

        return true;
    }

    static inline bool isValid(const uint8_t *header)
    {
        return header != nullptr;
    }
};

} // namespace xmrig
