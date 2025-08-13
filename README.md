# Poseidon Hash Library

A high-performance, type-safe Rust implementation of the Poseidon hash function with support for multiple elliptic curves and field types.

## Features

- 🎯 **Generic over any elliptic curve** - Works with Pallas, BN254, BLS12-381, BLS12-377, Vesta, and more
- 🔧 **Multi-field input support** - Hash base field (Fq), scalar field (Fr), and curve point elements
- ⚡ **Automatic field conversion** - Sophisticated Fr ↔ Fq conversion handling different field bit sizes
- 🔒 **Type safety** - Compile-time guarantees prevent mixing fields from different curves
- 📦 **Embedded parameters** - No external files needed, parameters are compiled into the binary
- 🚀 **Zero-copy where possible** - Efficient memory usage with lazy static parameters
- 🛡️ **Cryptographically secure** - Uses official Poseidon parameters with 128-bit security

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
poseidon-hash = "0.1"
```

## Quick Start

```rust
use poseidon_hash::prelude::*;
use poseidon_hash::parameters::pallas::PALLAS_PARAMS;

// Create a hasher for the Pallas curve
let mut hasher = PallasHasher::new_from_ref(&*PALLAS_PARAMS);

// Absorb different field types
let scalar = ark_pallas::Fr::from(12345u64);
let base = ark_pallas::Fq::from(67890u64);
let point = ark_pallas::Affine::generator();

hasher.absorb(PallasInput::ScalarField(scalar));
hasher.absorb(PallasInput::BaseField(base));
hasher.absorb(PallasInput::CurvePoint(point));

// Get the hash result
let hash = hasher.squeeze();
```

## Supported Curves

| Curve | Fr bits | Fq bits | Conversion | Usage |
|-------|---------|---------|------------|-------|
| **Pallas** | 255 | 255 | Simple byte repr. | Mina Protocol, recursive SNARKs |
| **Vesta** | 255 | 255 | Simple byte repr. | Mina Protocol (cycle with Pallas) |
| **BN254** | 254 | 254 | Simple byte repr. | Ethereum, zkSNARKs |
| **BLS12-381** | 255 | 381 | Direct (Fr < Fq) | Ethereum 2.0, Zcash |
| **BLS12-377** | 253 | 377 | Direct (Fr < Fq) | Celo, recursive proofs |

## Architecture

### Core Components

- **`MultiFieldHasher<F, S, G>`** - Generic hasher over base field F, scalar field S, and curve group G
- **`FieldInput<F, S, G>`** - Type-safe enum for different input types
- **Embedded Parameters** - Cryptographically secure parameters compiled into the library

### Field Conversion

The library automatically handles three conversion scenarios:

1. **Same bit size** (most common): Simple byte representation change
2. **Fr < Fq**: Direct conversion without data loss
3. **Fr > Fq** (rare): Automatic chunking/decomposition

### Chaining Algorithm

The hasher uses proper chaining to ensure all inputs affect the output:

```
For inputs [A, B, C, D]:
1. H₁ = hash(A, B)
2. H₂ = hash(H₁, C)  
3. H₃ = hash(H₂, D)
Result: H₃
```

## Examples

### Basic Usage

```rust
use poseidon_hash::prelude::*;
use poseidon_hash::parameters::pallas::PALLAS_PARAMS;

let mut hasher = PallasHasher::new_from_ref(&*PALLAS_PARAMS);

// Hash scalar field elements
hasher.absorb(PallasInput::ScalarField(ark_pallas::Fr::from(123u64)));

// Hash base field elements  
hasher.absorb(PallasInput::BaseField(ark_pallas::Fq::from(456u64)));

// Hash curve points
let point = ark_pallas::Affine::generator();
hasher.absorb(PallasInput::CurvePoint(point));

let hash = hasher.squeeze();
```

### Multi-Curve Support

```rust
use poseidon_hash::prelude::*;
use poseidon_hash::parameters::{bn254, bls12_381};

// BN254 (Ethereum)
let mut bn254_hasher = BN254Hasher::new_from_ref(&*bn254::BN254_PARAMS);
bn254_hasher.absorb(BN254Input::ScalarField(ark_bn254::Fr::from(42u64)));
let bn254_hash = bn254_hasher.squeeze();

// BLS12-381 (Ethereum 2.0)  
let mut bls_hasher = BLS12_381Hasher::new_from_ref(&*bls12_381::BLS12_381_PARAMS);
bls_hasher.absorb(BLS12_381Input::ScalarField(ark_bls12_381::Fr::from(42u64)));
let bls_hash = bls_hasher.squeeze();
```

## Running Examples

```bash
# Basic usage example
cargo run --example basic_usage

# Multi-curve demonstration
cargo run --example multi_curve
```

## Testing

```bash
# Run all tests
cargo test

# Run library tests only
cargo test --lib
```

## Security

- **128-bit security level** against known cryptographic attacks
- **Collision resistance** - Computationally infeasible to find collisions
- **Preimage resistance** - Cannot find input from hash output
- **Proper chaining** - All inputs affect the final hash (no trivial collisions)
- **Official parameters** - Generated using the Poseidon reference implementation

## Project Structure

```
poseidon-hash/
├── src/
│   ├── lib.rs              # Library entry point
│   ├── hasher.rs           # Core hasher implementation
│   ├── types.rs            # Type aliases for curves
│   └── parameters/         # Embedded parameters
│       ├── mod.rs          # Parameter utilities
│       ├── pallas.rs       # Pallas parameters
│       ├── vesta.rs        # Vesta parameters
│       ├── bn254.rs        # BN254 parameters
│       ├── bls12_381.rs    # BLS12-381 parameters
│       └── bls12_377.rs    # BLS12-377 parameters
├── examples/
│   ├── basic_usage.rs      # Basic usage example
│   └── multi_curve.rs      # Multi-curve demo
└── Cargo.toml              # Package configuration
```

## License

MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows Rust best practices
- Documentation is updated for API changes
- Security considerations are addressed

## Acknowledgments

This implementation is based on the Poseidon hash function as described in the paper:
*"Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"*

Parameters were generated using the official reference implementation with 128-bit security level.