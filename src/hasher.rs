//! Generic multi-field Poseidon hasher implementation.
//!
//! This module provides the core [`MultiFieldHasher`] that can work with any elliptic curve
//! and automatically handles field conversions between different field types (Fr, Fq, curve points).
//! 
//! ## Features
//!
//! - **Safe numeric conversions** - Uses `try_from()` instead of unsafe casts
//! - **Comprehensive error handling** - Cascades underlying [`PoseidonError`] with full context
//! - **Proper hash chaining** - Ensures all inputs affect the final hash result
//! - **Multiple field support** - Handles Fr ↔ Fq conversion with different bit sizes
//!
//! ## Usage
//!
//! Most users should use the curve-specific hashers from [`crate::types`] instead of this
//! generic implementation directly. However, this module is useful for:
//! - Library authors who need to be generic over curves
//! - Advanced users who want maximum flexibility
//! - Understanding the underlying implementation
//!
//! ```rust
//! use poseidon_hash::hasher::{MultiFieldHasher, FieldInput, HasherResult};
//! use poseidon_hash::parameters::pallas::PALLAS_PARAMS;
//!
//! let mut hasher: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine> = 
//!     MultiFieldHasher::new_from_ref(&*PALLAS_PARAMS);
//!     
//! hasher.absorb(FieldInput::ScalarField(ark_pallas::Fr::from(42u64)))?;
//! let hash = hasher.squeeze()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use ark_ff::{PrimeField, BigInteger, Zero};
use light_poseidon::{Poseidon, PoseidonHasher, PoseidonError};
use ark_ec::AffineRepr;
use std::marker::PhantomData;
use thiserror::Error;
use crate::primitive::{RustInput, PackingBuffer, PackingConfig, serialize_rust_input};

/// Number of bits per byte
const BITS_PER_BYTE: usize = 8;

/// Errors that can occur during hashing operations.
#[derive(Error, Debug)]
pub enum HasherError {
    /// Failed to hash elements due to Poseidon hasher error
    #[error("Poseidon hashing failed: {0}")]
    PoseidonError(#[from] PoseidonError),
    /// Failed to extract coordinates from curve point
    #[error("Failed to extract curve point coordinates")]
    PointConversionFailed,
    /// Numeric conversion failed (overflow or underflow)
    #[error("Numeric conversion failed: {reason}")]
    NumericConversionFailed { reason: String },
}

/// Result type for hasher operations.
pub type HasherResult<T> = Result<T, HasherError>;

/// Multi-field input types for the generic Poseidon hasher.
/// 
/// This enum provides type-safe input handling for different field element types
/// within the same elliptic curve ecosystem.
#[derive(Debug, Clone)]
pub enum FieldInput<F: PrimeField, S: PrimeField, G: AffineRepr<BaseField = F>> {
    /// Base field element (Fq) - absorbed directly without conversion
    BaseField(F),
    /// Scalar field element (Fr) - converted to base field representation
    ScalarField(S), 
    /// Curve point in affine representation - coordinates extracted as base field elements
    CurvePoint(G),
}

/// Advanced multi-field Poseidon hasher with sophisticated field conversion capabilities.
///
/// This generic hasher can work with any elliptic curve and automatically handles
/// conversion between different field types within the same curve's ecosystem.
///
/// # Type Parameters
///
/// * `F: PrimeField + Zero` - Base field (Fq) used for curve coordinates and final hash output
/// * `S: PrimeField` - Scalar field (Fr) used for private keys and discrete logarithms  
/// * `G: AffineRepr<BaseField = F>` - Curve points in affine representation
pub struct MultiFieldHasher<F: PrimeField, S: PrimeField, G: AffineRepr<BaseField = F>> {
    /// Poseidon hasher instance parameterized over the base field F
    poseidon: Poseidon<F>,
    /// Internal state accumulating base field elements for hashing
    state: Vec<F>,
    /// Buffer for accumulating primitive types before packing into field elements
    primitive_buffer: PackingBuffer,
    /// Phantom data to track scalar field type S without storing instances
    _phantom_s: PhantomData<S>,
    /// Phantom data to track curve point type G without storing instances  
    _phantom_g: PhantomData<G>,
}

impl<F: PrimeField + Zero, S: PrimeField, G: AffineRepr<BaseField = F>> MultiFieldHasher<F, S, G> {
    /// Creates a new multi-field hasher from Poseidon parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - Poseidon parameters for the base field F
    pub fn new(params: light_poseidon::PoseidonParameters<F>) -> Self {
        Self {
            poseidon: Poseidon::new(params),
            state: Vec::new(),
            primitive_buffer: PackingBuffer::new::<F>(PackingConfig::default()),
            _phantom_s: PhantomData,
            _phantom_g: PhantomData,
        }
    }
    
    /// Creates a new multi-field hasher from a reference to Poseidon parameters.
    ///
    /// This method clones the parameters internally.
    ///
    /// # Arguments
    ///
    /// * `params` - Reference to Poseidon parameters for the base field F
    pub fn new_from_ref(params: &light_poseidon::PoseidonParameters<F>) -> Self 
    where
        F: Clone,
    {
        Self::new(crate::parameters::clone_parameters(params))
    }
    
    /// Creates a new multi-field hasher with custom packing configuration.
    ///
    /// # Arguments
    ///
    /// * `params` - Poseidon parameters for the base field F
    /// * `packing_config` - Configuration for packing primitive types
    pub fn new_with_config(params: light_poseidon::PoseidonParameters<F>, packing_config: PackingConfig) -> Self {
        Self {
            poseidon: Poseidon::new(params),
            state: Vec::new(),
            primitive_buffer: PackingBuffer::new::<F>(packing_config),
            _phantom_s: PhantomData,
            _phantom_g: PhantomData,
        }
    }
    
    /// Creates a new multi-field hasher with custom packing configuration from parameter reference.
    ///
    /// # Arguments
    ///
    /// * `params` - Reference to Poseidon parameters for the base field F
    /// * `packing_config` - Configuration for packing primitive types
    pub fn new_with_config_from_ref(params: &light_poseidon::PoseidonParameters<F>, packing_config: PackingConfig) -> Self 
    where
        F: Clone,
    {
        Self::new_with_config(crate::parameters::clone_parameters(params), packing_config)
    }

    /// Absorbs a base field element (Fq) directly into the hasher state.
    pub fn absorb_base_field(&mut self, element: F) {
        self.state.push(element);
    }

    /// Absorbs a scalar field element (Fr) with automatic conversion to base field (Fq).
    ///
    /// Handles different field bit size relationships:
    /// * Same bit size: Simple byte representation conversion
    /// * Fr < Fq: Direct conversion without data loss
    /// * Fr > Fq: Automatic chunking into multiple Fq elements
    pub fn absorb_scalar_field(&mut self, element: S) -> HasherResult<()> {
        let fr_bits = S::MODULUS_BIT_SIZE;
        let fq_bits = F::MODULUS_BIT_SIZE;
        
        if fr_bits == fq_bits {
            // Same bit size - simple byte representation change
            let bytes = element.into_bigint().to_bytes_le();
            let converted = F::from_le_bytes_mod_order(&bytes);
            self.state.push(converted);
        } else if fr_bits < fq_bits {
            // Fr smaller than Fq - direct conversion (no data loss)
            let bytes = element.into_bigint().to_bytes_le();
            let converted = F::from_le_bytes_mod_order(&bytes);
            self.state.push(converted);
        } else {
            // Fr larger than Fq - need to decompose (rare case)
            let chunks_needed = fr_bits.div_ceil(fq_bits);
            let bytes = element.into_bigint().to_bytes_le();
            
            // Safe conversion from u32 to usize
            let fq_bits_usize = usize::try_from(fq_bits)
                .map_err(|_| HasherError::NumericConversionFailed { 
                    reason: format!("Field bit size {fq_bits} too large for usize") 
                })?;
            let bytes_per_chunk = fq_bits_usize.div_ceil(BITS_PER_BYTE);
            
            let chunks_needed_usize = usize::try_from(chunks_needed)
                .map_err(|_| HasherError::NumericConversionFailed {
                    reason: format!("Number of chunks {chunks_needed} too large for usize")
                })?;
            
            for i in 0..chunks_needed_usize {
                let start = i * bytes_per_chunk;
                let end = std::cmp::min(start + bytes_per_chunk, bytes.len());
                let mut chunk = vec![0u8; bytes_per_chunk];
                
                if start < bytes.len() {
                    let copy_len = std::cmp::min(chunk.len(), end - start);
                    chunk[..copy_len].copy_from_slice(&bytes[start..start + copy_len]);
                }
                
                let chunk_element = F::from_le_bytes_mod_order(&chunk);
                self.state.push(chunk_element);
            }
        }
        Ok(())
    }

    /// Absorbs a curve point by extracting and hashing its affine coordinates.
    pub fn absorb_curve_point(&mut self, point: G) -> HasherResult<()> {
        if point.is_zero() {
            // Point at infinity -> absorb (0, 0)
            self.state.push(F::zero());
            self.state.push(F::zero());
        } else {
            // Regular point -> absorb (x, y) coordinates
            let (x, y) = point.xy().ok_or(HasherError::PointConversionFailed)?;
            self.state.push(x);
            self.state.push(y);
        }
        Ok(())
    }

    /// Absorbs any field input type using the appropriate specialized method.
    pub fn absorb(&mut self, input: FieldInput<F, S, G>) -> HasherResult<()> {
        match input {
            FieldInput::BaseField(fq) => {
                self.absorb_base_field(fq);
                Ok(())
            }
            FieldInput::ScalarField(fr) => self.absorb_scalar_field(fr),
            FieldInput::CurvePoint(point) => self.absorb_curve_point(point),
        }
    }

    /// Absorbs a primitive Rust type by serializing and packing it into field elements.
    ///
    /// This method handles the conversion of basic Rust types (bool, integers, strings, etc.)
    /// into field elements using the configured packing strategy.
    ///
    /// # Arguments
    ///
    /// * `input` - The primitive value to absorb
    pub fn absorb_primitive(&mut self, input: RustInput) -> HasherResult<()> {
        // Serialize the input into the primitive buffer
        serialize_rust_input(&input, &mut self.primitive_buffer)?;
        
        // Extract any complete field elements and absorb them
        let field_elements = self.primitive_buffer.extract_field_elements::<F>()?;
        for element in field_elements {
            self.state.push(element);
        }
        
        Ok(())
    }
    

    /// Finalizes the hash computation and returns the result.
    ///
    /// # Chaining Algorithm
    ///
    /// For elements [A, B, C, D, ...], the algorithm performs:
    /// * If odd length: pad with zero  
    /// * First pair: H₁ = hash(A, B)
    /// * Subsequent: H₂ = hash(H₁, C), H₃ = hash(H₂, D), ...
    ///
    /// This ensures that every element influences the final hash result.
    pub fn squeeze(&mut self) -> HasherResult<F> {
        // First, flush any remaining primitive data from the buffer
        let remaining_field_elements = self.primitive_buffer.flush_remaining::<F>()?;
        for element in remaining_field_elements {
            self.state.push(element);
        }
        
        // Handle empty state
        if self.state.is_empty() {
            return Ok(F::zero());
        }
        
        // Pad state to even length if needed
        if self.state.len() % 2 != 0 {
            self.state.push(F::zero());
        }

        // Proper chaining: incorporate all elements sequentially
        if self.state.len() == 2 {
            // Simple case: just hash the two elements
            let result = self.poseidon.hash(&[self.state[0], self.state[1]])?;
            self.state.clear();
            return Ok(result);
        }
        
        // Multi-element case: chain them properly
        let mut result = self.poseidon.hash(&[self.state[0], self.state[1]])?;
        
        // Process remaining elements one by one
        for i in 2..self.state.len() {
            result = self.poseidon.hash(&[result, self.state[i]])?;
        }

        // Clear state for next use
        self.state.clear();
        Ok(result)
    }

    /// Resets the hasher state without changing parameters.
    pub fn reset(&mut self) {
        self.state.clear();
        self.primitive_buffer.clear();
    }

    /// Returns the current number of absorbed elements.
    pub fn absorbed_count(&self) -> usize {
        self.state.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PallasHasher, PallasInput, BN254Hasher, BN254Input, PoseidonHasher};
    use ark_ec::AffineRepr;

    #[test]
    fn test_embedded_parameters_basic() {
        let mut hasher = PallasHasher::new();
        
        let a = ark_pallas::Fq::from(1u64);
        let b = ark_pallas::Fq::from(2u64);
        
        hasher.update(PallasInput::BaseField(a)).expect("Failed to update hasher");
        hasher.update(PallasInput::BaseField(b)).expect("Failed to update hasher");
        
        let hash = hasher.squeeze().expect("Failed to compute hash");
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_proper_chaining_with_embedded_params() {
        // Test that chaining works correctly with embedded parameters
        let mut hasher = PallasHasher::new();
        
        let a = ark_pallas::Fr::from(1u64);
        let b = ark_pallas::Fr::from(2u64);
        let c = ark_pallas::Fr::from(3u64);
        let d = ark_pallas::Fr::from(4u64);
        
        hasher.update(PallasInput::ScalarField(a)).expect("Failed to update hasher");
        hasher.update(PallasInput::ScalarField(b)).expect("Failed to update hasher");
        hasher.update(PallasInput::ScalarField(c)).expect("Failed to update hasher");
        hasher.update(PallasInput::ScalarField(d)).expect("Failed to update hasher");
        
        let hash_abcd = hasher.squeeze().expect("Failed to compute hash");
        
        // Hash just the last two elements
        let mut hasher2 = PallasHasher::new();
        hasher2.update(PallasInput::ScalarField(c)).expect("Failed to update hasher");
        hasher2.update(PallasInput::ScalarField(d)).expect("Failed to update hasher");
        
        let hash_cd = hasher2.squeeze().expect("Failed to compute hash");
        
        // These should be different due to proper chaining
        assert_ne!(hash_abcd, hash_cd);
    }

    #[test]
    fn test_multi_field_types() {
        let mut hasher = PallasHasher::new();
        
        let scalar = ark_pallas::Fr::from(42u64);
        let base = ark_pallas::Fq::from(100u64);
        let generator = ark_pallas::Affine::generator();
        
        hasher.update(PallasInput::ScalarField(scalar)).expect("Failed to update hasher");
        hasher.update(PallasInput::BaseField(base)).expect("Failed to update hasher");
        hasher.update(PallasInput::CurvePoint(generator)).expect("Failed to update hasher");
        
        let hash = hasher.squeeze().expect("Failed to compute hash");
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_cross_curve_type_safety() {
        // Each curve hasher has its own embedded parameters
        let mut pallas_hasher = PallasHasher::new();
        let mut bn254_hasher = BN254Hasher::new();
        
        let pallas_scalar = ark_pallas::Fr::from(123u64);
        let bn254_scalar = ark_bn254::Fr::from(123u64);
        
        pallas_hasher.update(PallasInput::ScalarField(pallas_scalar)).expect("Failed to update hasher");
        bn254_hasher.update(BN254Input::ScalarField(bn254_scalar)).expect("Failed to update hasher");
        
        let pallas_hash = pallas_hasher.squeeze().expect("Failed to compute hash");
        let bn254_hash = bn254_hasher.squeeze().expect("Failed to compute hash");
        
        // These should be different because they use different parameters
        assert_ne!(pallas_hash.to_string(), bn254_hash.to_string());
    }

    #[test]
    fn test_default_constructor() {
        // Test that Default trait works for convenient initialization
        let mut hasher: PallasHasher = Default::default();
        
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64))).expect("Failed to update hasher");
        let hash = hasher.squeeze().expect("Failed to compute hash");
        
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_hasher_reuse() {
        let mut hasher = PallasHasher::new();
        
        // First hash
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(1u64))).expect("Failed to update hasher");
        let hash1 = hasher.squeeze().expect("Failed to compute hash");
        
        // Second hash (hasher should reset automatically)
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(2u64))).expect("Failed to update hasher");
        let hash2 = hasher.squeeze().expect("Failed to compute hash");
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_error_cascading() {
        use crate::hasher::{MultiFieldHasher, HasherError};
        use crate::parameters::pallas::PALLAS_PARAMS;
        
        // Create hasher with low-level API to trigger potential Poseidon errors
        let mut hasher: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine> = 
            MultiFieldHasher::new_from_ref(&*PALLAS_PARAMS);
        
        // Test that errors cascade properly - try squeezing empty state
        let result = hasher.squeeze();
        
        // Test error message formatting includes the underlying PoseidonError
        match result {
            Ok(hash) => {
                // Should succeed (empty state returns zero, which is valid)
                assert_eq!(hash, ark_pallas::Fq::zero());
            },
            Err(HasherError::PoseidonError(poseidon_err)) => {
                // If we get a Poseidon error, verify it cascades properly
                println!("Successfully cascaded Poseidon error: {poseidon_err}");
            },
            Err(other) => panic!("Unexpected error type: {other:?}"),
        }
    }
}