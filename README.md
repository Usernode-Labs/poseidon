# Poseidon Hash Library

Type-safe, multi-curve Poseidon hash with domain/type separation and an arkworks Poseidon sponge backend.

## Features

- Poseidon sponge (arkworks): t=3, rate=2, standard 10*1 padding
- Domain separation: per-hasher domain strings to namespace outputs
- Type tags: disambiguate BaseField, ScalarField, CurvePoint (finite/infinity), and primitives
- Primitive packing: byte-efficient (default) or circuit-friendly
- Multi-curve: Pallas, Vesta, BN254, BLS12-381, BLS12-377 (embedded parameters)
- Secure memory handling: sensitive buffers zeroized on drop/reset

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
poseidon-hash = "0.1"
```

## Quick Start

```rust
use poseidon_hash::*;
use poseidon_hash::PoseidonHasher; // brings new/update/digest into scope
use ark_ec::AffineRepr;

// Create a namespaced hasher (recommended)
let mut hasher = PallasHasher::new_with_domain("VRF_DOMAIN");

// Update with different types (tags added automatically)
hasher.update(ark_pallas::Fr::from(42u64));              // scalar field
hasher.update(ark_pallas::Fq::from(100u64));             // base field
hasher.update(ark_pallas::Affine::generator());          // curve point
hasher.update(42u64);                                    // primitive
hasher.update("hello");                                  // string

let hash = hasher.digest(); // non-consuming; finalize() consumes
println!("Hash: {}", hash);
```

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
pallas_hasher.update(ark_pallas::Fr::from(123u64))?;  // ✓ Pallas scalar
bn254_hasher.update(ark_bn254::Fr::from(123u64))?;    // ✓ BN254 scalar

// Mixing field types across curves won't compile:
// pallas_hasher.update(ark_bn254::Fr::from(123u64))?;  // ✗ Type error
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Supported Curves

| Curve | Field Bits | Usage |
|-------|------------|-------|
| **Pallas** | 255 | Mina Protocol, recursive SNARKs |
| **Vesta** | 255 | Mina Protocol (cycle with Pallas) |
| **BN254** | 254 | Ethereum, zkSNARKs |
| **BLS12-381** | Fr: 255, Fq: 381 | Ethereum 2.0, Zcash |
| **BLS12-377** | Fr: 253, Fq: 377 | Celo, recursive proofs |

## Multi-Curve Support

```rust
use poseidon_hash::{BN254Hasher, BLS12_381Hasher, VestaHasher};

// BN254 (Ethereum)
let mut bn254_hasher = BN254Hasher::new();
bn254_hasher.update(ark_bn254::Fr::from(42u64));
let bn254_hash = bn254_hasher.digest();

// BLS12-381 (Ethereum 2.0)  
let mut bls_hasher = BLS12_381Hasher::new();
bls_hasher.update(ark_bls12_381::Fr::from(42u64));
let bls_hash = bls_hasher.digest();

// Vesta (Mina Protocol)
let mut vesta_hasher = VestaHasher::new();
vesta_hasher.update(ark_vesta::Fq::from(123u64));
let vesta_hash = vesta_hasher.digest();
```

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

## Security

- **128-bit security level** against known cryptographic attacks
- **Collision resistance** - Computationally infeasible to find collisions
- **Preimage resistance** - Cannot find input from hash output
- **Official parameters** - Generated using the Poseidon reference implementation
- **Memory safety** - Sensitive data is zeroized on drop

## Architecture

### Core Design

- **Type-safe hashers**: `PallasHasher`, `BN254Hasher`, etc. with embedded parameters
- **Generic core**: `MultiFieldHasher<F, S, G>` for advanced use cases  
- **Unified input**: Single `update()` method handles all input types
- **Sponge mode**: Standard absorb/squeeze with Poseidon permutation
- **Zero-copy**: Efficient memory usage with lazy static parameters

### Field Conversion

The library automatically handles different field size relationships:

1. **Same or smaller bit size**: Bytes embed directly into Fq (tagged)
2. **Fr >= Fq** (future): Decompose into limbs less than Fq and absorb with tags

## Error Types

### Error Types

- `PointConversionFailed` – Failed to extract curve point coordinates
- `NumericConversionFailed { reason }` – Numeric conversion failed

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please ensure:
- All tests pass (`cargo test`)
- No clippy warnings (`cargo clippy`)
- Documentation builds (`cargo doc`)
- Security considerations are addressed

## Acknowledgments

Based on *"Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"*.
Parameters generated using the official reference implementation with 128-bit security level.
