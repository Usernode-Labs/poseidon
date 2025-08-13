/*!
# Poseidon Hash Library

A type-safe, generic implementation of the Poseidon hash function supporting multiple 
elliptic curves and field types.

## Features

- Generic over any elliptic curve (Pallas, BN254, BLS12-381, etc.)
- Multi-field input support (base field Fq, scalar field Fr, curve points)
- Automatic field conversion with bit size handling
- Type safety preventing cross-curve contamination
- Embedded cryptographically secure parameters
- Zero-copy parameter access

## Quick Start

```rust
use poseidon_hash::{MultiFieldHasher, FieldInput};
use poseidon_hash::parameters::pallas::PALLAS_PARAMS;

// Create hasher with embedded parameters
let mut hasher = MultiFieldHasher::new(&PALLAS_PARAMS);

// Hash different field types
hasher.absorb(FieldInput::ScalarField(scalar));
hasher.absorb(FieldInput::BaseField(base));
hasher.absorb(FieldInput::CurvePoint(point));

let hash = hasher.squeeze();
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
    pub use crate::hasher::{MultiFieldHasher, FieldInput};
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