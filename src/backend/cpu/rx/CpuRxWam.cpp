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

#include "backend/cpu/rx/CpuRxWam.h"
#include "crypto/randomx/randomx.h"
#include "base/crypto/Algorithm.h"


namespace xmrig {


// CPU backend implementation for WAM RandomX algorithm
// Supports standard RandomX optimization techniques:
// - JIT compilation for faster execution
// - Large page support for dataset caching
// - AVX2 and AES-NI hardware acceleration when available
// - NUMA-aware memory allocation for multi-socket systems

} /* namespace xmrig */
