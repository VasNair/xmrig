/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XMRIG_RX_WAM_HEADER_H
#define XMRIG_RX_WAM_HEADER_H


#include <cstdint>
#include <cstring>


namespace xmrig {


/**
 * @brief WAM block header encoding
 *
 * WAM uses Bitcoin-style 80-byte block headers for RandomX mining.
 * This differs from Monero's approach where the nonce is at byte 39.
 * In WAM's Bitcoin header, the nonce occupies bytes 76-79.
 *
 * Bitcoin header layout (80 bytes):
 *   0-3:   version (4 bytes, little-endian)
 *   4-35:  previous block hash (32 bytes)
 *  36-67:  merkle root (32 bytes)
 *  68-71:  time (4 bytes, little-endian)
 *  72-75:  bits/difficulty (4 bytes, little-endian)
 *  76-79:  nonce (4 bytes, little-endian) ← WAM mining happens here
 */
class RxWamHeader
{
public:
    static constexpr uint32_t HEADER_SIZE = 80;
    static constexpr uint32_t NONCE_OFFSET = 76;
    static constexpr uint32_t NONCE_SIZE = 4;

    /**
     * Extract nonce from Bitcoin header at bytes 76-79 (little-endian)
     */
    static inline uint32_t getNonce(const uint8_t *header)
    {
        return *reinterpret_cast<const uint32_t*>(header + NONCE_OFFSET);
    }

    /**
     * Set nonce in Bitcoin header at bytes 76-79 (little-endian)
     */
    static inline void setNonce(uint8_t *header, uint32_t nonce)
    {
        *reinterpret_cast<uint32_t*>(header + NONCE_OFFSET) = nonce;
    }

    /**
     * Convert stratum job to 80-byte Bitcoin header
     * The pool sends: coinbase1, coinbase2, merkle_branch[], version, bits, time, nonce
     * We reassemble them into a complete 80-byte header
     */
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

        // Zero out the header first
        std::memset(header, 0, HEADER_SIZE);

        // Bytes 0-3: version (little-endian)
        *reinterpret_cast<uint32_t*>(header + 0) = version;

        // Bytes 4-35: previous block hash (32 bytes, as-is from stratum)
        std::memcpy(header + 4, prevBlockHash, 32);

        // Bytes 36-67: merkle root (32 bytes, as-is from stratum)
        std::memcpy(header + 36, merkleRoot, 32);

        // Bytes 68-71: time (little-endian)
        *reinterpret_cast<uint32_t*>(header + 68) = time;

        // Bytes 72-75: bits/difficulty (little-endian)
        *reinterpret_cast<uint32_t*>(header + 72) = bits;

        // Bytes 76-79: nonce (little-endian)
        *reinterpret_cast<uint32_t*>(header + 76) = nonce;

        return true;
    }

    /**
     * Verify header structure is sound
     */
    static inline bool isValid(const uint8_t *header)
    {
        return header != nullptr;
    }
};


} /* namespace xmrig */


#endif /* XMRIG_RX_WAM_HEADER_H */
