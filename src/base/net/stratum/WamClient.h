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
 *   - mining.notify carries coinbase halves, merkle branch, and header fields
 *   - The RandomX seed is in mining.notify[9] (WAM extension)
 *   - The miner assembles an 80-byte Bitcoin header and hashes it with RandomX
 *   - The nonce is at bytes 76-79 of the header
 *
 * This client handles the WAM-specific job format and passes it to the workers
 * as a properly-formed 80-byte Bitcoin header.
 */
class WamClient : public Client
{
public:
    using Client::Client;

protected:
    bool parseJob(const rapidjson::Value& params, int* code) override;

private:
    void buildWamHeader();
};

} /* namespace xmrig */

#endif /* XMRIG_WAM_CLIENT_H */
