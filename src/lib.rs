/*!
# Poseidon Hash Library

A production-ready, type-safe Rust implementation of the Poseidon hash function with 
comprehensive error handling and support for multiple elliptic curves.

## Features

- **Type-safe curve-specific hashers** - Embedded parameters prevent parameter mix-ups at compile time
- **Multi-field input support** - Hash base field (Fq), scalar field (Fr), and curve point elements seamlessly
- **Automatic field conversion** - Sophisticated Fr ↔ Fq conversion handling different field bit sizes safely
- **Comprehensive error handling** - Proper error cascading with actionable error messages using `thiserror`
- **Embedded parameters** - Zero external dependencies, parameters compiled directly into the binary
- **Zero-copy design** - Efficient memory usage with lazy static parameters
- **Production-ready** - Extensive testing, proper error handling, and best practices
- **Cryptographically secure** - Official Poseidon parameters with 128-bit security level

## Quick Start

```rust
use poseidon_hash::PallasHasher;
use ark_ec::AffineRepr;

// Create hasher with embedded parameters
let mut hasher = PallasHasher::new();

// Direct ergonomic API - no enum wrapping needed
hasher.update(ark_pallas::Fr::from(42u64));        // scalar field
hasher.update(ark_pallas::Fq::from(100u64));       // base field  
hasher.update(ark_pallas::Affine::generator());     // curve point
hasher.update(42u64);                               // primitive
hasher.update("hello");                            // string

let hash = hasher.digest();
println!("Hash: {}", hash);
```

## Simple API

```rust
use poseidon_hash::PallasHasher;

let mut hasher = PallasHasher::new();
hasher.update(ark_pallas::Fq::from(42u64));

let hash = hasher.digest();
println!("Hash: {}", hash);
```

## Type Safety

Each curve hasher embeds its own parameters and field types:

```rust
use poseidon_hash::{PallasHasher, BN254Hasher};

let mut pallas_hasher = PallasHasher::new();  // Pallas parameters
let mut bn254_hasher = BN254Hasher::new();    // BN254 parameters

// Each hasher only accepts its own curve's field types
pallas_hasher.update(ark_pallas::Fr::from(123u64));  // ✓ Pallas scalar
bn254_hasher.update(ark_bn254::Fr::from(123u64));    // ✓ BN254 scalar

// Mixing field types across curves won't compile:
// pallas_hasher.update(ark_bn254::Fr::from(123u64));  // ✗ Type error
```
*/

// Re-export main types at crate root for convenience
pub use hasher::{MultiFieldHasher, FieldInput, HasherError, HasherResult};
pub use parameters::SECURITY_LEVEL;
pub use primitive::{RustInput, PackingConfig, PackingMode, PaddingMode};
pub use types::PoseidonHasher;

// Re-export curve-specific hashers and input types
pub use types::{
    PallasHasher, PallasInput,
    BN254Hasher, BN254Input,
    BLS12_381Hasher, BLS12_381Input,
    BLS12_377Hasher, BLS12_377Input,
    VestaHasher, VestaInput,
};

// Public modules
pub mod hasher;
pub mod parameters;
pub mod primitive;
pub mod types;
mod tags;


#[cfg(test)]
mod tests {
    #[test]
    fn test_library_exports() {
        // Ensure main types are accessible
        use crate::parameters::SECURITY_LEVEL;
        
        // This test just ensures the library structure compiles correctly
        assert_eq!(SECURITY_LEVEL, 128);
    }
}
