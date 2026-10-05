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
#include "base/crypto/sha256.h"

namespace xmrig {

static void ReverseBytes(uint8_t* out, const uint8_t* in, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        out[i] = in[len - 1 - i];
    }
}

static inline void WriteLE32(uint8_t* buf, uint32_t v) {
    buf[0] = uint8_t(v);
    buf[1] = uint8_t(v >> 8);
    buf[2] = uint8_t(v >> 16);
    buf[3] = uint8_t(v >> 24);
}

static void SHA256d(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    sha256(data, len, tmp);
    sha256(tmp, 32, out);
}

static void SHA256dPair(const uint8_t* a, const uint8_t* b, uint8_t out[32]) {
    uint8_t tmp[64];
    std::memcpy(tmp, a, 32);
    std::memcpy(tmp + 32, b, 32);
    SHA256d(tmp, 64, out);
}

bool WamClient::ComputeMerkleRoot(
    const std::vector<uint8_t>& coinb1,
    const std::vector<uint8_t>& extranonce1,
    const std::vector<uint8_t>& extranonce2,
    const std::vector<uint8_t>& coinb2,
    const std::vector<std::vector<uint8_t>>& merkle_branch,
    uint8_t out_root[32])
{
    size_t total_size = coinb1.size() + extranonce1.size() + extranonce2.size() + coinb2.size();
    if (total_size > 1024) {
        return false;
    }

    std::vector<uint8_t> coinbase;
    coinbase.reserve(total_size);
    coinbase.insert(coinbase.end(), coinb1.begin(), coinb1.end());
    coinbase.insert(coinbase.end(), extranonce1.begin(), extranonce1.end());
    coinbase.insert(coinbase.end(), extranonce2.begin(), extranonce2.end());
    coinbase.insert(coinbase.end(), coinb2.begin(), coinb2.end());

    uint8_t root[32];
    SHA256d(coinbase.data(), coinbase.size(), root);

    for (const auto& node : merkle_branch) {
        if (node.size() != 32) {
            return false;
        }
        uint8_t next[32];
        SHA256dPair(root, node.data(), next);
        std::memcpy(root, next, 32);
    }

    std::memcpy(out_root, root, 32);
    return true;
}

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

    const char* coinb1_hex = params[2].GetString();
    const char* coinb2_hex = params[3].GetString();
    if (!coinb1_hex || !coinb2_hex) {
        LOG(NOTICE, YELLOW("WAM coinbase halves are missing"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    size_t coinb1_size = std::strlen(coinb1_hex);
    size_t coinb2_size = std::strlen(coinb2_hex);
    if (coinb1_size % 2 || coinb2_size % 2) {
        LOG(NOTICE, YELLOW("WAM coinbase halves are not valid hex"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    m_coinb1.resize(coinb1_size / 2);
    m_coinb2.resize(coinb2_size / 2);
    if (!Cvt::fromHex(m_coinb1.data(), m_coinb1.size(), coinb1_hex, coinb1_size) ||
        !Cvt::fromHex(m_coinb2.data(), m_coinb2.size(), coinb2_hex, coinb2_size)) {
        LOG(NOTICE, YELLOW("WAM coinbase halves decode failed"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    const auto& branch = params[4];
    if (!branch.IsArray()) {
        LOG(NOTICE, YELLOW("WAM merkle_branch is not an array"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    m_merkle_branch.clear();
    for (rapidjson::SizeType i = 0; i < branch.Size(); ++i) {
        const char* node_hex = branch[i].GetString();
        if (!node_hex || std::strlen(node_hex) != 64) {
            LOG(NOTICE, YELLOW("WAM merkle branch node is not 64 hex chars"));
            *code = PARSE_ERR_INVALID_JOB;
            return false;
        }
        std::vector<uint8_t> node(32);
        if (!Cvt::fromHex(node.data(), 32, node_hex, 64)) {
            LOG(NOTICE, YELLOW("WAM merkle branch node decode failed"));
            *code = PARSE_ERR_INVALID_JOB;
            return false;
        }
        m_merkle_branch.push_back(node);
    }

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
        LOG(NOTICE, YELLOW("WAM version, bits, or ntime decode failed"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    uint32_t version = (uint32_t(version_be[0]) << 24) | (uint32_t(version_be[1]) << 16) |
                       (uint32_t(version_be[2]) << 8) | uint32_t(version_be[3]);
    uint32_t bits = (uint32_t(bits_be[0]) << 24) | (uint32_t(bits_be[1]) << 16) |
                    (uint32_t(bits_be[2]) << 8) | uint32_t(bits_be[3]);
    uint32_t ntime = (uint32_t(ntime_be[0]) << 24) | (uint32_t(ntime_be[1]) << 16) |
                     (uint32_t(ntime_be[2]) << 8) | uint32_t(ntime_be[3]);

    bool clean_jobs = params[8].GetBool();

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

    uint8_t header[80];
    WriteLE32(header + 0, version);
    ReverseBytes(header + 4, prevhash_be, 32);
    std::memset(header + 36, 0, 32);
    WriteLE32(header + 68, ntime);
    WriteLE32(header + 72, bits);
    WriteLE32(header + 76, 0);

    const String headerHex = Cvt::toHex(header, 80);
    if (!m_job.setBlob(headerHex.data())) {
        LOG(NOTICE, YELLOW("WAM failed to set job blob"));
        *code = PARSE_ERR_INVALID_JOB;
        return false;
    }

    m_job.setId(job_id);
    m_job.setAlgorithm(Algorithm::RX_WAM);
    m_job.setWamData(m_merkle_branch, m_coinb1, m_coinb2, m_extranonce1, std::vector<uint8_t>(), m_extranonce2_size);

    if (clean_jobs) {
        m_job.setDiff(m_diff);
    }

    m_state = 1;
    return true;
}

}  /* namespace xmrig */
