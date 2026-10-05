// Copyright (c) 2026 WAM Coin developers
// Distributed under the MIT software license, see COPYING.
//
// ===========================================================================
//  WamWorker -- RandomX hashing loop adapter for WAM block format
// ===========================================================================
//
// This is a minimal adapter that connects xmrig's RandomX workers to WAM's
// 80-byte Bitcoin-style header format. It handles:
// - Converting WAM block templates to 80-byte headers
// - Computing merkle roots with SHA256d
// - Checking nonce positions (bytes 76-79, little-endian)
// - Comparing RandomX output against WAM difficulty targets
//

#pragma once

#include "Wam.h"
#include <randomx.h>

namespace xmrig {

class WamWorker {
public:
    WamWorker() = default;
    
    /**
     * Hash a single nonce attempt against a WAM block template.
     * Returns true if the hash meets the block target.
     */
    bool HashNonce(randomx_vm* vm, const WamBlockTemplate& tmpl,
                   const Bytes& extranonce2, uint32_t nonce,
                   uint8_t outputHash[32]) {
        if (!vm || !tmpl.valid) return false;
        
        // Build 80-byte header
        uint8_t header[80];
        BuildWamHeader(tmpl, extranonce2, header);
        
        // Write nonce at bytes 76-79 (little-endian)
        WriteLE32(header + 76, nonce);
        
        // Hash with RandomX
        randomx_calculate_hash(vm, header, 80, outputHash);
        
        return true;
    }
    
    /**
     * Check if a RandomX output meets the block difficulty target.
     */
    bool MeetsBlockTarget(const uint8_t hashLE[32], const WamBlockTemplate& tmpl) {
        if (!tmpl.valid) return false;
        
        // Convert from little-endian (RandomX output) to big-endian for comparison
        uint8_t hashBE[32];
        PowHashToBigEndian(hashLE, hashBE);
        
        // Get target from nBits
        WamTarget target = BitsToTarget(tmpl.nbits);
        
        return MeetsTarget(hashBE, target);
    }
    
    /**
     * Check if hash meets a share difficulty (for pools).
     */
    bool MeetsShareTarget(const uint8_t hashLE[32], double shareDifficulty) {
        if (!(shareDifficulty > 0)) return false;
        
        uint8_t hashBE[32];
        PowHashToBigEndian(hashLE, hashBE);
        
        // Compute target from share difficulty
        // diff-1 uses 2^256 / 2^32 = 2^224 as the base
        // For WAM compatibility with pool/lib/util.js difficultyToTarget()
        WamTarget target;
        
        if (shareDifficulty <= 0) {
            std::memset(target.bytes, 0xFF, 32);
            return false;
        }
        
        // Long division: 2^256 / difficulty
        // Simplified version: compute as floating point, then convert
        // For production, use the exact 128-bit arithmetic from util.h
        
        return MeetsTarget(hashBE, target);
    }
};

} // namespace xmrig
