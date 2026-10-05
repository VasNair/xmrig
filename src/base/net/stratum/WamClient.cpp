/* XMRig
 * Copyright (c) 2026 venturasellers-debug
 * Copyright 2018-2025 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2025 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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

#include <cstring>
#include <cassert>

#include "base/net/stratum/WamClient.h"
#include "base/tools/Cvt.h"
#include "base/crypto/sha3.h"

namespace xmrig {

/**
 * Helper: reverse byte order for big-endian to little-endian conversion.
 */
static void ReverseBytes(uint8_t* out, const uint8_t* in, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        out[i] = in[len - 1 - i];
    }
}

/**
 * Helper: write a 32-bit little-endian integer to buffer.
 */
static inline void WriteLE32(uint8_t* buf, uint32_t v) {
    buf[0] = uint8_t(v);
    buf[1] = uint8_t(v >> 8);
    buf[2] = uint8_t(v >> 16);
    buf[3] = uint8_t(v >> 24);
}

/**
 * Parse WAM stratum job and build the 80-byte Bitcoin header.
 *
 * WAM's mining.notify format (extended from Monero stratum):
 *   0: job_id
 *   1: prevhash (big-endian, as block hash)
 *   2: coinb1 (hex, first half of coinbase)
 *   3: coinb2 (hex, second half of coinbase)
 *   4: merkle_branch (array of hashes)
 *   5: version (big-endian hex)
 *   6: bits/nbits (big-endian hex)
 *   7: ntime (big-endian hex)
 *   8: clean_jobs
 *   9: randomx_seed (hex, little-endian - WAM extension)
 *
 * The job builder reconstructs an 80-byte Bitcoin header:
 *   0-3:   version (LE)
 *   4-35:  prevhash (reversed to LE)
 *   36-67: merkle root (set to zero as placeholder)
 *   68-71: ntime (LE)
 *   72-75: nbits (LE)
 *   76-79: nonce (filled per attempt)
 *
 * NOTE: The merkle root computation requires the full coinbase
 * (coinb1 | extranonce1 | extranonce2 | coinb2), which is only
 * known at work time. This implementation sets it to zero as a
 * placeholder. Real deployment must integrate with the worker
 * to compute the merkle root fresh for each extranonce2.
 */
bool WamClient::parseJob(const rapidjson::Value& params, int* code)
{
    if (!params.IsArray() || params.Size() < 10) {
        LOG(NOTICE, YELLOW("WAM mining.notify has fewer than 10 parameters"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    const char* job_id = params[0].GetString();
    if (!job_id) {
        LOG(NOTICE, YELLOW("WAM job_id is not a string"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    // Parse prevhash (big-endian block hash -> little-endian header format)
    const char* prevhash_hex = params[1].GetString();
    if (!prevhash_hex || std::strlen(prevhash_hex) != 64) {
        LOG(NOTICE, YELLOW("WAM prevhash is not 64 hex chars"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }
    uint8_t prevhash_be[32];
    if (!Cvt::fromHex(prevhash_be, 32, prevhash_hex, 64)) {
        LOG(NOTICE, YELLOW("WAM prevhash is not valid hex"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    // Parse version, bits, ntime (all big-endian in the wire format)
    const char* version_hex = params[5].GetString();
    const char* bits_hex = params[6].GetString();
    const char* ntime_hex = params[7].GetString();

    if (!version_hex || std::strlen(version_hex) != 8 ||
        !bits_hex || std::strlen(bits_hex) != 8 ||
        !ntime_hex || std::strlen(ntime_hex) != 8) {
        LOG(NOTICE, YELLOW("WAM version, bits, or ntime is not 8 hex chars"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    uint8_t version_be[4], bits_be[4], ntime_be[4];
    if (!Cvt::fromHex(version_be, 4, version_hex, 8) ||
        !Cvt::fromHex(bits_be, 4, bits_hex, 8) ||
        !Cvt::fromHex(ntime_be, 4, ntime_hex, 8)) {
        LOG(NOTICE, YELLOW("WAM version, bits, or ntime is not valid hex"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    // Convert big-endian to native integers
    uint32_t version = (uint32_t(version_be[0]) << 24) | (uint32_t(version_be[1]) << 16) |
                       (uint32_t(version_be[2]) << 8) | uint32_t(version_be[3]);
    uint32_t bits = (uint32_t(bits_be[0]) << 24) | (uint32_t(bits_be[1]) << 16) |
                    (uint32_t(bits_be[2]) << 8) | uint32_t(bits_be[3]);
    uint32_t ntime = (uint32_t(ntime_be[0]) << 24) | (uint32_t(ntime_be[1]) << 16) |
                     (uint32_t(ntime_be[2]) << 8) | uint32_t(ntime_be[3]);

    // Parse clean_jobs
    bool clean_jobs = params[8].GetBool();

    // Parse RandomX seed (WAM extension, little-endian)
    const char* seed_hex = params[9].GetString();
    if (!seed_hex || std::strlen(seed_hex) != 64) {
        LOG(NOTICE, YELLOW("WAM randomx_seed is not 64 hex chars"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    if (!setSeedHash(seed_hex)) {
        LOG(NOTICE, YELLOW("WAM randomx_seed is not valid"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    // Build the 80-byte Bitcoin header.
    // Workers will vary the nonce (bytes 76-79) and hash with RandomX.

    uint8_t header[80];

    // 0-3: version (little-endian)
    WriteLE32(header + 0, version);

    // 4-35: prevhash (reverse to little-endian header format)
    ReverseBytes(header + 4, prevhash_be, 32);

    // 36-67: merkle root
    // NOTE: Setting to zero as placeholder. Real implementation must compute
    // the merkle root from coinbase + branch when the worker has the extranonce.
    std::memset(header + 36, 0, 32);

    // 68-71: ntime (little-endian)
    WriteLE32(header + 68, ntime);

    // 72-75: nbits (little-endian)
    WriteLE32(header + 72, bits);

    // 76-79: nonce (start at 0, workers will increment)
    WriteLE32(header + 76, 0);

    // Store the 80-byte header in the job blob
    const String headerHex = Cvt::toHex(header, 80);
    if (!m_job.setBlob(headerHex.data())) {
        LOG(NOTICE, YELLOW("WAM failed to set job blob"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    m_job.setId(job_id);
    m_job.setAlgorithm(Algorithm::RX_WAM);

    if (clean_jobs) {
        m_job.setDiff(m_diff);
    }

    m_state = 1;
    return true;
}

}  /* namespace xmrig */
