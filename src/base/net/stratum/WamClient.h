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

#ifndef XMRIG_WAM_CLIENT_H
#define XMRIG_WAM_CLIENT_H

#include "base/net/stratum/Client.h"

namespace xmrig {

/**
 * WAM Coin stratum client.
 *
 * WAM is a Bitcoin Core fork using RandomX proof of work. Its stratum protocol
 * is bitcoin-shaped, not Monero-shaped:
 *
 *   - mining.notify carries:
 *     [0] job_id
 *     [1] prevhash (big-endian block hash)
 *     [2] coinb1 (hex, first half of coinbase)
 *     [3] coinb2 (hex, second half of coinbase)
 *     [4] merkle_branch (array of 32-byte hashes)
 *     [5] version (big-endian hex)
 *     [6] bits/nbits (big-endian hex)
 *     [7] ntime (big-endian hex)
 *     [8] clean_jobs (boolean)
 *     [9] randomx_seed (hex, little-endian - WAM extension)
 *
 *   - The miner assembles an 80-byte Bitcoin header and hashes it with RandomX
 *   - The nonce is at bytes 76-79 of the header
 *   - The RandomX seed is passed as mining.notify[9]
 *
 * This client parses the WAM job format and constructs the 80-byte Bitcoin
 * header that workers will use as the RandomX input.
 */
class WamClient : public Client
{
public:
    using Client::Client;

protected:
    bool parseJob(const rapidjson::Value& params, int* code) override;
};

} /* namespace xmrig */

#endif /* XMRIG_WAM_CLIENT_H */
