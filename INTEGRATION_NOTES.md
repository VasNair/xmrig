# WAM Algorithm Integration (rx/wam) for xmrig

## Status: Minimal Algorithm Support

This branch adds support for WAM Coin RandomX mining to xmrig. The integration is **algorithm-only** — it provides the core cryptographic components without full pool/job management plumbing.

## What's Included

### New Files

- **`src/crypto/rx/Wam.h`** — Core WAM algorithm components:
  - Bitcoin-style 80-byte header utilities
  - SHA-256 implementation for merkle root computation
  - Target/difficulty conversion (Bitcoin compact format)
  - Hex encoding/decoding
  - Type definitions for WAM block templates and targets

- **`src/crypto/rx/Wam.cpp`** — SHA-256 transform implementation

- **`src/crypto/rx/WamWorker.h`** — Hashing loop adapter:
  - `HashNonce()` — Apply RandomX to an 80-byte header with a given nonce
  - `MeetsBlockTarget()` — Check if output satisfies block difficulty
  - `MeetsShareTarget()` — Check share difficulty for pool mining

## Architecture

### Key Differences from Standard RandomX (Monero)

| Aspect | WAM | Monero |
|--------|-----|--------|
| **Header** | Bitcoin 80-byte (little-endian integers) | Monero blob (custom layout) |
| **Nonce** | Bytes 76-79 (LE32) | Byte 39 |
| **Merkle Root** | Bitcoin stratum format (built from coinbase + branch) | N/A |
| **RandomX Key** | 32 bytes from pool `mining.set_seedhash` / job param | Monero's block hash |
| **Key Rotation** | Every 2048 blocks (with 64-block lag) | Dynamic based on block time |

### Data Flow

```
Pool (Stratum) 
    ↓
[mining.notify] → WamBlockTemplate (from stratum.h)
    ↓
xmrig Worker Thread
    ↓
BuildWamHeader() → 80-byte header
    ↓
randomx_calculate_hash() → 32-byte output (little-endian)
    ↓
PowHashToBigEndian() → Convert to big-endian
    ↓
MeetsTarget() → Compare against difficulty
```

## Integration Steps (for Full xmrig Integration)

### Phase 1: Algorithm Foundation ✅ (This branch)
- Core cryptography and header building
- Target/difficulty utilities
- Standalone WAM worker class

### Phase 2: Algorithm Registration (Next PR)
- Register `rx/wam` as a new algorithm variant in xmrig's algorithm list
- Add `ALGO_RX_WAM` enum
- Hook into existing RandomX initialization

### Phase 3: Job/Pool Support (Future PR)
- Adapt xmrig's stratum parser for WAM-specific `mining.notify` parameters
- Support `mining.set_seedhash` extension
- Handle WAM address validation (starts with 'W' or 'wam1')

### Phase 4: Configuration (Future PR)
- Add `rx-wam` as an algorithm choice in JSON config
- Pool configuration examples
- Command-line option support

## How to Use This

### For xmrig Maintainers

1. **Review the cryptography**:
   - `Wam.h`: Verify SHA-256, target conversion, header layout
   - Compare against wam-miner reference: https://github.com/gvsa/wam-coin/tree/main/miner/src

2. **Integrate into RandomX backend**:
   - Add `BuildWamHeader()` call in your hash loop
   - Use `WamWorker` as a template adapter
   - Ensure nonce position (bytes 76-79) is correct

3. **Test**:
   - Unit test SHA-256 against wam-miner vectors
   - Test target computation (use test cases from util.h)
   - Validate header format byte-for-byte

### For WAM Miners Using xmrig

**This branch is not yet mining-ready.** You need:

- Full algorithm registration
- Pool job parsing support
- Configuration options

For now, continue using wam-miner: https://wamcoin.org/downloads/

## Key Implementation Notes

### Byte Order (Critical)

This is the single most common source of mining bugs:

1. **Header**: All 32-bit values are **little-endian**
   - `WriteLE32(header + 0, version)` — bytes 0-3
   - `WriteLE32(header + 68, ntime)` — bytes 68-71
   - `WriteLE32(header + 76, nonce)` — bytes 76-79 (THE IMPORTANT ONE)

2. **RandomX Output**: **Little-endian**
   - Must call `PowHashToBigEndian()` before comparing to target

3. **Target**: **Big-endian** (for memcmp)
   - Stored as 32 big-endian bytes
   - `BitsToTarget(nbits)` produces big-endian format

### SHA-256 Requirements

The coinbase and merkle branch must be hashed correctly:

```cpp
// Correct:
uint8_t coinbase_hash[32];
SHA256d(coinbase.data(), coinbase.size(), coinbase_hash);

// Merkle step:
SHA256dPair(left, right, result);  // SHA256d(left || right)
```

Mismatches here produce "share above target" rejections on every share.

### RandomX Seeding

WAM rotates the RandomX key every 2048 blocks with a 64-block lag:

- Pool sends `mining.set_seedhash` out of band
- Pool may also include seed in `mining.notify[9]`
- Fall back to last known seed if omitted
- When seed changes, xmrig must call `randomx_init_cache()` and rebuild the dataset

## Porting Guide

If you're adapting this to another RandomX-based coin:

1. **Check the header format**:
   - Is it Bitcoin-style 80 bytes?
   - What are the nonce bytes and byte order?

2. **Check target/difficulty**:
   - Does it use compact format (nbits)?
   - How is it computed from difficulty?

3. **Check RandomX key**:
   - How is it supplied?
   - How often does it rotate?

4. **Copy `Wam.h` and modify**:
   - Adjust `BuildWamHeader()` if the layout differs
   - Keep all the byte-order utilities
   - Test against known vectors

## References

- **WAM Block Format**: https://github.com/gvsa/wam-coin/blob/main/miner/src/stratum.h#L119-L145
- **WAM Utilities**: https://github.com/gvsa/wam-coin/blob/main/miner/src/util.h
- **Bitcoin Header**: https://developer.bitcoin.org/reference/block_chain.html#block-headers
- **Stratum Mining Protocol**: http://mining.bitcoin.cz/stratumv1
- **RandomX**: https://github.com/tevador/RandomX

## Future Work

- [ ] Full algorithm registration in xmrig
- [ ] WAM pool job parser
- [ ] Configuration examples
- [ ] Mining performance benchmarks
- [ ] Documentation updates
