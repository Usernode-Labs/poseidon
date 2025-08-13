//! Curve-specific hashers with embedded parameters.
//!
//! This module provides curve-specific hashers that embed their parameters
//! at compile time, ensuring type safety and eliminating the possibility
//! of using incorrect parameters.

use crate::hasher::{MultiFieldHasher, FieldInput};
use crate::parameters::*;

// Pallas curve hasher
/// Pallas curve multi-field hasher with embedded parameters.
/// Pallas is a 255-bit curve used in the Mina Protocol for recursive SNARKs.
pub struct PallasHasher {
    inner: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>,
}

impl PallasHasher {
    /// Create a new Pallas hasher with embedded parameters.
    pub fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*pallas::PALLAS_PARAMS),
        }
    }
    
    /// Update the hasher with a field input.
    pub fn update(&mut self, input: PallasInput) {
        self.inner.absorb(input);
    }
    
    /// Squeeze the current hash result and reset the hasher.
    pub fn squeeze(&mut self) -> ark_pallas::Fq {
        self.inner.squeeze()
    }
}

impl Default for PallasHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for Pallas curve field input enum.
pub type PallasInput = FieldInput<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>;

// Vesta curve hasher
/// Vesta curve multi-field hasher with embedded parameters.
/// Vesta forms a cycle with Pallas for efficient recursive proofs.
pub struct VestaHasher {
    inner: MultiFieldHasher<ark_vesta::Fq, ark_vesta::Fr, ark_vesta::Affine>,
}

impl VestaHasher {
    /// Create a new Vesta hasher with embedded parameters.
    pub fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*vesta::VESTA_PARAMS),
        }
    }
    
    /// Update the hasher with a field input.
    pub fn update(&mut self, input: VestaInput) {
        self.inner.absorb(input);
    }
    
    /// Squeeze the current hash result and reset the hasher.
    pub fn squeeze(&mut self) -> ark_vesta::Fq {
        self.inner.squeeze()
    }
}

impl Default for VestaHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for Vesta curve field input enum.
pub type VestaInput = FieldInput<ark_vesta::Fq, ark_vesta::Fr, ark_vesta::Affine>;

// BN254 curve hasher
/// BN254 curve multi-field hasher with embedded parameters.
/// BN254 is widely used in Ethereum and zkSNARK applications.
pub struct BN254Hasher {
    inner: MultiFieldHasher<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>,
}

impl BN254Hasher {
    /// Create a new BN254 hasher with embedded parameters.
    pub fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*bn254::BN254_PARAMS),
        }
    }
    
    /// Update the hasher with a field input.
    pub fn update(&mut self, input: BN254Input) {
        self.inner.absorb(input);
    }
    
    /// Squeeze the current hash result and reset the hasher.
    pub fn squeeze(&mut self) -> ark_bn254::Fq {
        self.inner.squeeze()
    }
}

impl Default for BN254Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for BN254 curve field input enum.
pub type BN254Input = FieldInput<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>;

// BLS12-381 curve hasher
/// BLS12-381 curve multi-field hasher with embedded parameters.
/// BLS12-381 is used in Ethereum 2.0 and Zcash.
pub struct BLS12_381Hasher {
    inner: MultiFieldHasher<ark_bls12_381::Fq, ark_bls12_381::Fr, ark_bls12_381::G1Affine>,
}

impl BLS12_381Hasher {
    /// Create a new BLS12-381 hasher with embedded parameters.
    pub fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*bls12_381::BLS12_381_PARAMS),
        }
    }
    
    /// Update the hasher with a field input.
    pub fn update(&mut self, input: BLS12_381Input) {
        self.inner.absorb(input);
    }
    
    /// Squeeze the current hash result and reset the hasher.
    pub fn squeeze(&mut self) -> ark_bls12_381::Fq {
        self.inner.squeeze()
    }
}

impl Default for BLS12_381Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for BLS12-381 curve field input enum.
pub type BLS12_381Input = FieldInput<ark_bls12_381::Fq, ark_bls12_381::Fr, ark_bls12_381::G1Affine>;

// BLS12-377 curve hasher
/// BLS12-377 curve multi-field hasher with embedded parameters.
/// BLS12-377 is used in Celo and forms cycles with BW6-761.
pub struct BLS12_377Hasher {
    inner: MultiFieldHasher<ark_bls12_377::Fq, ark_bls12_377::Fr, ark_bls12_377::G1Affine>,
}

impl BLS12_377Hasher {
    /// Create a new BLS12-377 hasher with embedded parameters.
    pub fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*bls12_377::BLS12_377_PARAMS),
        }
    }
    
    /// Update the hasher with a field input.
    pub fn update(&mut self, input: BLS12_377Input) {
        self.inner.absorb(input);
    }
    
    /// Squeeze the current hash result and reset the hasher.
    pub fn squeeze(&mut self) -> ark_bls12_377::Fq {
        self.inner.squeeze()
    }
}

impl Default for BLS12_377Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for BLS12-377 curve field input enum.
pub type BLS12_377Input = FieldInput<ark_bls12_377::Fq, ark_bls12_377::Fr, ark_bls12_377::G1Affine>;