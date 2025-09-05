# Poseidon Hash Library

Type‑safe, multi‑curve Poseidon hash with domain/type separation and an arkworks Poseidon sponge backend.

## Features

- Poseidon sponge (arkworks): t=3, rate=2, capacity=1
- Domain separation: per-hasher domain strings to namespace outputs
- Per-class lane tweaks: Disambiguate BaseField, ScalarField, CurvePoint (finite/infinity), and primitives via Domain‑in‑Rate tweaks (no field‑level tags)
- Primitive packing: byte‑efficient (default) or circuit‑friendly
- Multi-curve: Pallas, Vesta, BN254, BLS12-381, BLS12-377 (dynamic parameters via arkworks)
- Memory hygiene: primitive packing buffers zeroized on drop/reset

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies] 
poseidon-hash = "0.1"
```

## Quick Start

```rust
use poseidon_hash::*;
use poseidon_hash::PoseidonHasher; // brings update/digest/reset/finalize into scope
use ark_ec::AffineRepr;

// Create a namespaced hasher (recommended)
let mut hasher = PallasHasher::new_with_domain("VRF_DOMAIN"); // Domain-in-Rate is the default

// Update with different types (tags added automatically)
hasher.update(ark_pallas::Fr::from(42u64));              // scalar field
hasher.update(ark_pallas::Fq::from(100u64));             // base field
hasher.update(ark_pallas::Affine::generator());          // curve point
hasher.update(42u64);                                    // primitive
hasher.update("hello");                                  // string

let hash = hasher.digest(); // non-consuming; finalize() consumes
println!("Hash: {}", hash);
```

## Poseidon2 (Pallas)

This crate also exposes a Poseidon2 variant for the Pallas base field (Fq). It
has the same ergonomic API as the Poseidon v1 hashers and uses the same
absorb/squeeze sponge construction under the hood.

```rust
use poseidon_hash::PallasPoseidon2Hasher; // Poseidon2 permutation on Pallas Fq
use poseidon_hash::PoseidonHasher;        // brings update()/digest() into scope

let mut h = PallasPoseidon2Hasher::new();            // default params (t=3, d=5)
h.update(ark_pallas::Fq::from(42u64));               // base field
h.update(ark_pallas::Fr::from(123u64));              // scalar field (converted)
let out = h.digest();

// Optional domain separation (Domain-in-Rate)
let mut h2 = PallasPoseidon2Hasher::new_with_domain("MY_DOMAIN");
h2.update(ark_pallas::Fq::from(1u64));
let out2 = h2.digest();
```

Notes
- The Poseidon2 Pallas hasher mirrors the v1 API (update over base/scalar/points
  and primitives; digest/reset/finalize; optional domain).
- Default parameters are derived deterministically (Grain LFSR). A test vector
  (“KAT”) validates the permutation against the HorizenLabs Poseidon2 Pallas
  constants when those parameters are supplied.
- Benchmarks for Poseidon2 are available: `cargo bench --bench simple_hash_poseidon2`.

## Multi-Curve

```rust
use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

// BN254 (Ethereum)
let mut bn254_hasher = BN254Hasher::new_with_domain("BLOCK_HASH_DOMAIN");
bn254_hasher.update(ark_bn254::Fr::from(42u64));
let bn254_hash = bn254_hasher.digest();

// BLS12-381 (Ethereum 2.0)
let mut bls_hasher = BLS12_381Hasher::new_with_domain("BLOCK_HASH_DOMAIN");
bls_hasher.update(ark_bls12_381::Fr::from(42u64));
let bls_hash = bls_hasher.digest();

// Vesta (Mina)
let mut vesta_hasher = VestaHasher::new_with_domain("BLOCK_HASH_DOMAIN");
vesta_hasher.update(ark_vesta::Fq::from(123u64));
let vesta_hash = vesta_hasher.digest();
```

## Type Safety

Each curve hasher embeds its own parameters and field types:

```rust
use poseidon_hash::PallasHasher;

let mut pallas_hasher = PallasHasher::new();  // Pallas parameters
let mut bn254_hasher = BN254Hasher::new();    // BN254 parameters

// Each hasher only accepts its own curve's field types
pallas_hasher.update(ark_pallas::Fr::from(123u64));  // ✓ Pallas scalar
bn254_hasher.update(ark_bn254::Fr::from(123u64));    // ✓ BN254 scalar

// Mixing field types across curves won't compile:
// pallas_hasher.update(ark_bn254::Fr::from(123u64));  // ✗ Type error
```

## Supported Curves

| Curve | Field Bits | Usage |
|-------|------------|-------|
| **Pallas** | 255 | Mina Protocol, recursive SNARKs |
| **Vesta** | 255 | Mina Protocol (cycle with Pallas) |
| **BN254** | 254 | Ethereum, zkSNARKs |
| **BLS12-381** | Fr: 255, Fq: 381 | Ethereum 2.0, Zcash |
| **BLS12-377** | Fr: 253, Fq: 377 | Celo, recursive proofs |

<!-- Multi-curve example covered above; omitted duplicate section. -->

## Primitive Type Support

Hash basic Rust types directly:

```rust
use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

let mut hasher = PallasHasher::new();

// Integers
hasher.update(42u64);
hasher.update(-123i32);
hasher.update(0xDEADBEEFu32);

// Booleans and strings
hasher.update(true);
hasher.update("hello world");
hasher.update("test".to_string());

// Byte arrays
hasher.update(vec![1u8, 2, 3, 4]);
hasher.update(&[5u8, 6, 7, 8][..]);

let hash = hasher.digest();
```


## Running Examples

```bash
# Basic usage example
cargo run --example basic_usage

# Multi-curve demonstration  
cargo run --example multi_curve

# Primitive type support
cargo run --example primitive_types
```

## Packing Modes

Configure how primitive types are packed into field elements:

```rust
use poseidon_hash::PallasHasher;

// Byte-efficient (default) - pack multiple values per field element
let mut hasher = PallasHasher::new_with_config(PackingConfig::default());

// Circuit-friendly - one value per field element (better for ZK circuits)
let config = PackingConfig { 
    mode: PackingMode::CircuitFriendly, 
    ..Default::default() 
};
let mut circuit_hasher = PallasHasher::new_with_config(config);
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test suite
cargo test security_tests
```

## Benchmarks

This repo includes Criterion benches for Poseidon v1 and Poseidon2 (Pallas and BN254), plus external comparisons against O(1) Labs (kimchi) and Aztec (barretenberg FFI).

- Our benches:
  - Poseidon v1 (Pallas): `cargo bench --bench simple_hash`
  - Poseidon2 (Pallas): `cargo bench --bench simple_hash_poseidon2`
  - Poseidon2 (BN254): `cargo bench --bench simple_hash_poseidon2_bn254`

### Aztec Poseidon2 (BN254) benches

The Aztec benches call into barretenberg’s C++ FFI to exercise their Poseidon2 (BN254) permutation.

Prerequisites:
- CMake (>= 3.24) and Ninja
- Clang (Apple Clang on macOS is fine)

Steps:
1) Clone aztec-packages into the repo root (expected path is `./aztec-packages`):

```
git clone --depth 1 --branch next https://github.com/Usernode-Labs/aztec-packages aztec-packages
```

2) Build the required barretenberg static libraries:

```
cd aztec-packages/barretenberg/cpp
cmake --fresh --preset default

# Option A: build everything (slower)
cmake --build --preset default

# Option B: build only the needed static libs (faster)
cd build
ninja \
  lib/libcrypto_poseidon2.a \
  lib/libcrypto_schnorr.a \
  lib/libecc.a \
  lib/libenv.a \
  lib/libcrypto_pedersen_hash.a \
  lib/libcrypto_pedersen_commitment.a \
  lib/libnumeric.a \
  lib/libcommon.a -j $(sysctl -n hw.ncpu)
```

3) Run the Aztec benches:

```
cd benches/aztec
cargo bench
```

Troubleshooting:
- If you see `Expected prebuilt barretenberg at .../barretenberg/cpp/build/lib`, complete step (2) to build the static libraries.
- On macOS, install tools via Homebrew: `brew install cmake ninja`.

### Comparison report

Run the Python script to produce a consolidated Markdown report with separate Poseidon2‑only and Poseidon v1‑only tables (and a combined view at the end):

```
python3 scripts/compare_benches.py
```

This executes:
- Our v1 and v2 benches (Pallas + BN254)
- O(1) Labs kimchi benches (`benches/o1labs`)
- Aztec Poseidon2 benches (`benches/aztec`)

Output:
- `bench-comparison.md` at the repo root. If Aztec or O(1) benches are unavailable, the script skips them with a warning.

## Security

- 128-bit security level (parameterized Poseidon, t=3)
- Arkworks Poseidon sponge backend (absorb/squeeze API)
- Domain and type tags to prevent cross-type collisions
- Primitive packing buffers are zeroized on drop/reset

## Architecture

### Core Design

- **Type-safe hashers**: `PallasHasher`, `BN254Hasher`, etc. with embedded parameters
- **Generic core**: `MultiFieldHasher<F, S, G>` for advanced use cases  
- **Unified input**: Single `update()` method handles all input types
- **Sponge mode**: Standard absorb/squeeze with Poseidon permutation
- **Zero-copy**: Efficient memory usage with lazy static parameters

### Field Conversion

Current behavior:

1. If `Fr` bit size ≤ `Fq` bit size, `Fr` is converted via little‑endian bytes and absorbed as a base field element (tagged as scalar).
2. If `Fr` bit size > `Fq` bit size, this is not supported. Constructors perform a guard check and will panic for such curve configurations.

## Error Types

Internal error definitions exist (`HasherError`), but the public `update/digest` API is infallible in normal operation.

- `PointConversionFailed` – failed to extract curve point coordinates
- `NumericConversionFailed { reason }` – numeric conversion failed

## License

MIT OR Apache-2.0

## Contributing

Please ensure:
- All tests pass (`cargo test`)
- No clippy warnings (`cargo clippy`)
- Documentation builds (`cargo doc`)

## Acknowledgments

Based on *"Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"*.
Parameters derived deterministically via arkworks (Grain LFSR) with a 128-bit security target.
