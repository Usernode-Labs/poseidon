# Poseidon Hash Library

A production-ready, type-safe Rust implementation of the Poseidon hash function with comprehensive error handling and support for multiple elliptic curves.

## Features

- **Type-safe curve-specific hashers** - Embedded parameters prevent parameter mix-ups at compile time
- **Multi-field input support** - Hash base field (Fq), scalar field (Fr), and curve point elements seamlessly
- **Automatic field conversion** - Sophisticated Fr ↔ Fq conversion handling different field bit sizes safely
- **Comprehensive error handling** - Proper error cascading with actionable error messages using `thiserror`
- **Embedded parameters** - Zero external dependencies, parameters compiled directly into the binary
- **Zero-copy design** - Efficient memory usage with lazy static parameters
- **Production-ready** - Extensive testing, proper error handling, and best practices
- **Cryptographically secure** - Official Poseidon parameters with 128-bit security level

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
poseidon-hash = "0.1"
```

## Quick Start

```rust
use poseidon_hash::prelude::*;
use ark_ec::AffineRepr;

// Create hasher with embedded parameters
let mut hasher = PallasHasher::new();

// Direct ergonomic API - no enum wrapping needed
hasher.update(ark_pallas::Fr::from(42u64))?;        // scalar field
hasher.update(ark_pallas::Fq::from(100u64))?;       // base field  
hasher.update(ark_pallas::Affine::generator())?;     // curve point
hasher.update(42u64)?;                               // primitive
hasher.update("hello")?;                            // string

let hash = hasher.digest()?;
println!("Hash: {}", hash);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Error Handling

```rust
use poseidon_hash::prelude::*;

let mut hasher = PallasHasher::new();
hasher.update(ark_pallas::Fq::from(42u64))?;

match hasher.digest() {
    Ok(hash) => println!("Success: {}", hash),
    Err(HasherError::PoseidonError(poseidon_err)) => {
        eprintln!("Detailed Poseidon error: {}", poseidon_err);
    },
    Err(HasherError::PointConversionFailed) => {
        eprintln!("Failed to extract curve point coordinates");
    },
    Err(HasherError::NumericConversionFailed { reason }) => {
        eprintln!("Numeric conversion failed: {}", reason);
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Type Safety

Each curve hasher embeds its own parameters and field types:

```rust
use poseidon_hash::prelude::*;

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
use poseidon_hash::prelude::*;

// BN254 (Ethereum)
let mut bn254_hasher = BN254Hasher::new();
bn254_hasher.update(ark_bn254::Fr::from(42u64))?;
let bn254_hash = bn254_hasher.digest()?;

// BLS12-381 (Ethereum 2.0)  
let mut bls_hasher = BLS12_381Hasher::new();
bls_hasher.update(ark_bls12_381::Fr::from(42u64))?;
let bls_hash = bls_hasher.digest()?;

// Vesta (Mina Protocol)
let mut vesta_hasher = VestaHasher::new();
vesta_hasher.update(ark_vesta::Fq::from(123u64))?;
let vesta_hash = vesta_hasher.digest()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Primitive Type Support

Hash basic Rust types directly:

```rust
use poseidon_hash::prelude::*;

let mut hasher = PallasHasher::new();

// Integers
hasher.update(42u64)?;
hasher.update(-123i32)?;
hasher.update(0xDEADBEEFu32)?;

// Booleans and strings
hasher.update(true)?;
hasher.update("hello world")?;
hasher.update("test".to_string())?;

// Byte arrays
hasher.update(vec![1u8, 2, 3, 4])?;
hasher.update(&[5u8, 6, 7, 8][..])?;

let hash = hasher.digest()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```


## Running Examples

```bash
# Basic usage example
cargo run --example basic_usage

# Multi-curve demonstration  
cargo run --example multi_curve

# Error handling demonstration
cargo run --example error_demo

# Primitive type support
cargo run --example primitive_types
```

## Packing Modes

Configure how primitive types are packed into field elements:

```rust
use poseidon_hash::prelude::*;

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
- **Proper chaining**: All inputs affect the final hash result
- **Zero-copy**: Efficient memory usage with lazy static parameters

### Field Conversion

The library automatically handles different field size relationships:

1. **Same bit size**: Simple byte representation change
2. **Fr < Fq**: Direct conversion without data loss  
3. **Fr > Fq**: Automatic chunking into multiple field elements

## Error Types

### `HasherError`

- **`PoseidonError`** - Cascades errors from the underlying Poseidon implementation
- **`PointConversionFailed`** - Failed to extract coordinates from curve point
- **`NumericConversionFailed { reason }`** - Safe numeric conversion failed

All errors provide actionable messages to help debugging.

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