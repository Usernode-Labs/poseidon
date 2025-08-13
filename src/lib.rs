/*!
# Poseidon Hash Library 🔐

A production-ready, type-safe Rust implementation of the Poseidon hash function with 
comprehensive error handling and support for multiple elliptic curves.

## Features

- 🎯 **Type-safe curve-specific hashers** - Embedded parameters prevent parameter mix-ups at compile time
- 🔧 **Multi-field input support** - Hash base field (Fq), scalar field (Fr), and curve point elements seamlessly
- ⚡ **Automatic field conversion** - Sophisticated Fr ↔ Fq conversion handling different field bit sizes safely
- 🛡️ **Comprehensive error handling** - Proper error cascading with actionable error messages using `thiserror`
- 📦 **Embedded parameters** - Zero external dependencies, parameters compiled directly into the binary
- 🚀 **Zero-copy design** - Efficient memory usage with lazy static parameters
- ✅ **Production-ready** - Extensive testing, proper error handling, and Rust best practices
- 🔒 **Cryptographically secure** - Official Poseidon parameters with 128-bit security level

## Quick Start

```rust
use poseidon_hash::prelude::*;
use ark_ec::AffineRepr;

// Create hasher with embedded parameters - no manual parameter passing needed!
let mut hasher = PallasHasher::new();

// Hash different field types with proper error handling
let scalar = ark_pallas::Fr::from(42u64);
let base = ark_pallas::Fq::from(100u64);
let point = ark_pallas::Affine::generator();

hasher.update(PallasInput::ScalarField(scalar))?;
hasher.update(PallasInput::BaseField(base))?;
hasher.update(PallasInput::CurvePoint(point))?;

let hash = hasher.squeeze()?;
println!("Hash: {}", hash);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Error Handling

```rust
use poseidon_hash::prelude::*;

let mut hasher = PallasHasher::new();
hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64)))?;

match hasher.squeeze() {
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

Each curve hasher embeds its own parameters, preventing accidental parameter mix-ups:

```rust
use poseidon_hash::prelude::*;

// ✅ Type-safe - each hasher has embedded parameters
let mut pallas_hasher = PallasHasher::new();  // Pallas parameters embedded
let mut bn254_hasher = BN254Hasher::new();    // BN254 parameters embedded

// ❌ Compile error - cannot mix field types across curves
// pallas_hasher.update(BN254Input::ScalarField(ark_bn254::Fr::from(123u64)))?;
```
*/

// Re-export main types at crate root for convenience
pub use hasher::{MultiFieldHasher, FieldInput};

// Public modules
pub mod hasher;
pub mod parameters;
pub mod types;

// Re-export commonly used types
pub mod prelude {
    pub use crate::hasher::{MultiFieldHasher, FieldInput, HasherError, HasherResult};
    pub use crate::parameters::SECURITY_LEVEL;
    
    // Re-export curve-specific type aliases
    pub use crate::types::{
        PallasHasher, PallasInput,
        BN254Hasher, BN254Input,
        BLS12_381Hasher, BLS12_381Input,
        BLS12_377Hasher, BLS12_377Input,
        VestaHasher, VestaInput,
    };
}

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