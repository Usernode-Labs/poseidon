# Poseidon Hash Library 🔐

A production-ready, type-safe Rust implementation of the Poseidon hash function with comprehensive error handling and support for multiple elliptic curves.

## Features

- 🎯 **Type-safe curve-specific hashers** - Embedded parameters prevent parameter mix-ups at compile time
- 🔧 **Multi-field input support** - Hash base field (Fq), scalar field (Fr), and curve point elements seamlessly
- ⚡ **Automatic field conversion** - Sophisticated Fr ↔ Fq conversion handling different field bit sizes safely
- 🛡️ **Comprehensive error handling** - Proper error cascading with actionable error messages using `thiserror`
- 📦 **Embedded parameters** - Zero external dependencies, parameters compiled directly into the binary
- 🚀 **Zero-copy design** - Efficient memory usage with lazy static parameters
- ✅ **Production-ready** - Extensive testing, proper error handling, and Rust best practices
- 🔒 **Cryptographically secure** - Official Poseidon parameters with 128-bit security level

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

// Create a type-safe hasher with embedded parameters - no manual parameter passing!
let mut hasher = PallasHasher::new();

// Hash different field types with proper error handling
let scalar = ark_pallas::Fr::from(12345u64);
let base = ark_pallas::Fq::from(67890u64);
let point = ark_pallas::Affine::generator();

hasher.update(PallasInput::ScalarField(scalar))?;
hasher.update(PallasInput::BaseField(base))?;
hasher.update(PallasInput::CurvePoint(point))?;

// Get the hash result with error handling
let hash = hasher.squeeze()?;
println!("Hash: {}", hash);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Error Handling

The library provides comprehensive error handling with detailed, actionable error messages:

```rust
use poseidon_hash::prelude::*;

let mut hasher = PallasHasher::new();
hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64)))?;

match hasher.squeeze() {
    Ok(hash) => println!("Success: {}", hash),
    Err(HasherError::PoseidonError(poseidon_err)) => {
        eprintln!("Poseidon error: {}", poseidon_err); // Detailed underlying error
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

- **`PallasHasher`, `BN254Hasher`, etc.** - Type-safe, curve-specific hashers with embedded parameters
- **`MultiFieldHasher<F, S, G>`** - Generic hasher over base field F, scalar field S, and curve group G
- **`FieldInput<F, S, G>`** - Type-safe enum for different input types
- **`HasherError`** - Comprehensive error type with proper error cascading
- **Embedded Parameters** - Cryptographically secure parameters compiled into the library

### Type Safety

Each curve hasher embeds its own parameters at compile time, making it impossible to accidentally use wrong parameters:

```rust
// ✅ Type-safe - each hasher has embedded parameters
let mut pallas_hasher = PallasHasher::new();  // Uses Pallas parameters automatically
let mut bn254_hasher = BN254Hasher::new();    // Uses BN254 parameters automatically

// ❌ This would be a compile error - cannot mix field types
// pallas_hasher.update(BN254Input::ScalarField(ark_bn254::Fr::from(123u64)));
```

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
use ark_ec::AffineRepr;

let mut hasher = PallasHasher::new();

// Hash scalar field elements
hasher.update(PallasInput::ScalarField(ark_pallas::Fr::from(123u64)))?;

// Hash base field elements  
hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(456u64)))?;

// Hash curve points
let point = ark_pallas::Affine::generator();
hasher.update(PallasInput::CurvePoint(point))?;

let hash = hasher.squeeze()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Multi-Curve Support

```rust
use poseidon_hash::prelude::*;

// BN254 (Ethereum) - type-safe with embedded parameters
let mut bn254_hasher = BN254Hasher::new();
bn254_hasher.update(BN254Input::ScalarField(ark_bn254::Fr::from(42u64)))?;
let bn254_hash = bn254_hasher.squeeze()?;

// BLS12-381 (Ethereum 2.0) - completely separate type system  
let mut bls_hasher = BLS12_381Hasher::new();
bls_hasher.update(BLS12_381Input::ScalarField(ark_bls12_381::Fr::from(42u64)))?;
let bls_hash = bls_hasher.squeeze()?;

// Vesta (Mina Protocol)
let mut vesta_hasher = VestaHasher::new();
vesta_hasher.update(VestaInput::BaseField(ark_vesta::Fq::from(123u64)))?;
let vesta_hash = vesta_hasher.squeeze()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Advanced: Generic Programming

For library authors who need to be generic over curves:

```rust
use poseidon_hash::hasher::{MultiFieldHasher, FieldInput, HasherResult};
use ark_ff::PrimeField;
use ark_ec::AffineRepr;

fn hash_elements<F, S, G>(
    hasher: &mut MultiFieldHasher<F, S, G>,
    scalar: S,
    base: F,
) -> HasherResult<F> 
where
    F: PrimeField,
    S: PrimeField,
    G: AffineRepr<BaseField = F>,
{
    hasher.absorb(FieldInput::ScalarField(scalar))?;
    hasher.absorb(FieldInput::BaseField(base))?;
    hasher.squeeze()
}
```

## Running Examples

```bash
# Basic usage example
cargo run --example basic_usage

# Multi-curve demonstration  
cargo run --example multi_curve

# Error handling demonstration
cargo run --example error_demo
```

## Error Types

The library provides comprehensive error handling with three main error types:

### `HasherError`

- **`PoseidonError(PoseidonError)`** - Cascades detailed errors from the underlying Poseidon implementation
  - `InvalidNumberOfInputs` - Too many inputs for the hash function width
  - `EmptyInput` - Attempted to hash an empty input slice  
  - `InvalidInputLength` - Input length doesn't match field modulus requirements
  - And more...

- **`PointConversionFailed`** - Failed to extract coordinates from an elliptic curve point

- **`NumericConversionFailed { reason: String }`** - Safe numeric conversion failed with detailed reason

### Benefits

✅ **Actionable errors** - Know exactly what went wrong and how to fix it  
✅ **No information loss** - Full error context preserved from lower levels  
✅ **Type safety** - Catch errors at compile time where possible  
✅ **Debugging friendly** - Clear error messages with context  

## Testing

```bash
# Run all tests including error handling tests
cargo test

# Run library tests only
cargo test --lib

# Run with verbose output
cargo test -- --nocapture
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
│   ├── multi_curve.rs      # Multi-curve demo
│   └── error_demo.rs       # Error handling demo
├── generate_parameters.py  # Parameter generation script
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