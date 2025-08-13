//! Generic multi-field Poseidon hasher implementation.
//!
//! This module provides a type-safe, generic hasher that can work with any
//! elliptic curve and automatically handles field conversions.

use ark_ff::{PrimeField, BigInteger, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use ark_ec::AffineRepr;
use std::marker::PhantomData;

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
    pub fn absorb_scalar_field(&mut self, element: S) {
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
            let chunks_needed = ((fr_bits + fq_bits - 1) / fq_bits) as usize;
            let bytes = element.into_bigint().to_bytes_le();
            let bytes_per_chunk = (fq_bits as usize + 7) / 8;
            
            for i in 0..chunks_needed {
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
    }

    /// Absorbs a curve point by extracting and hashing its affine coordinates.
    pub fn absorb_curve_point(&mut self, point: G) {
        if point.is_zero() {
            // Point at infinity -> absorb (0, 0)
            self.state.push(F::zero());
            self.state.push(F::zero());
        } else {
            // Regular point -> absorb (x, y) coordinates
            let (x, y) = point.xy().unwrap();
            self.state.push(x);
            self.state.push(y);
        }
    }

    /// Absorbs any field input type using the appropriate specialized method.
    pub fn absorb(&mut self, input: FieldInput<F, S, G>) {
        match input {
            FieldInput::BaseField(fq) => self.absorb_base_field(fq),
            FieldInput::ScalarField(fr) => self.absorb_scalar_field(fr),
            FieldInput::CurvePoint(point) => self.absorb_curve_point(point),
        }
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
    pub fn squeeze(&mut self) -> F {
        // Handle empty state
        if self.state.is_empty() {
            self.state.clear();
            return F::zero();
        }
        
        // Pad state to even length if needed
        if self.state.len() % 2 != 0 {
            self.state.push(F::zero());
        }

        // Proper chaining: incorporate all elements sequentially
        if self.state.len() == 2 {
            // Simple case: just hash the two elements
            let result = self.poseidon.hash(&[self.state[0], self.state[1]]).unwrap();
            self.state.clear();
            return result;
        }
        
        // Multi-element case: chain them properly
        let mut result = self.poseidon.hash(&[self.state[0], self.state[1]]).unwrap();
        
        // Process remaining elements one by one
        for i in 2..self.state.len() {
            result = self.poseidon.hash(&[result, self.state[i]]).unwrap();
        }

        // Clear state for next use
        self.state.clear();
        result
    }

    /// Resets the hasher state without changing parameters.
    pub fn reset(&mut self) {
        self.state.clear();
    }

    /// Returns the current number of absorbed elements.
    pub fn absorbed_count(&self) -> usize {
        self.state.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::pallas::PALLAS_PARAMS;
    use crate::types::PallasHasher;

    #[test]
    fn test_hasher_basic_functionality() {
        let mut hasher = PallasHasher::new_from_ref(&PALLAS_PARAMS);
        
        let a = ark_pallas::Fq::from(1u64);
        let b = ark_pallas::Fq::from(2u64);
        
        hasher.absorb_base_field(a);
        hasher.absorb_base_field(b);
        
        let hash = hasher.squeeze();
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_proper_chaining() {
        // Test that chaining works correctly
        let mut hasher = PallasHasher::new_from_ref(&PALLAS_PARAMS);
        
        let a = ark_pallas::Fq::from(1u64);
        let b = ark_pallas::Fq::from(2u64);
        let c = ark_pallas::Fq::from(3u64);
        let d = ark_pallas::Fq::from(4u64);
        
        hasher.absorb_base_field(a);
        hasher.absorb_base_field(b);
        hasher.absorb_base_field(c);
        hasher.absorb_base_field(d);
        
        let hash_abcd = hasher.squeeze();
        
        // Hash just the last two elements
        let mut hasher2 = PallasHasher::new_from_ref(&PALLAS_PARAMS);
        hasher2.absorb_base_field(c);
        hasher2.absorb_base_field(d);
        
        let hash_cd = hasher2.squeeze();
        
        // These should be different due to proper chaining
        assert_ne!(hash_abcd, hash_cd);
    }
}