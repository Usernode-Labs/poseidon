//! Curve-specific hashers with embedded parameters.
//!
//! This module provides curve-specific hashers that embed their parameters
//! at compile time, ensuring type safety and eliminating the possibility
//! of using incorrect parameters.

use crate::hasher::{MultiFieldHasher, FieldInput};
use crate::parameters::*;
use crate::primitive::PackingConfig;
use ark_ff::PrimeField;
use zeroize::ZeroizeOnDrop;

/// Trait for curve-specific Poseidon hashers with primitive type support.
/// 
/// This trait ensures a consistent interface across all curve implementations
/// while maintaining type safety and embedding curve-specific parameters.
#[allow(private_interfaces)] // InnerHasher is intentionally private - it's an implementation detail
pub trait PoseidonHasher<F, I> 
where 
    F: PrimeField,
{
    /// Create a new hasher with default (byte-efficient) packing configuration.
    fn new() -> Self;
    
    /// Create a new hasher with custom packing configuration.
    fn new_with_config(config: PackingConfig) -> Self;
    
    /// Get a mutable reference to the inner MultiFieldHasher for delegation.
    /// This is an implementation detail and should not be used directly.
    /// Only trait implementations should provide this method.
    #[doc(hidden)]
    fn inner_mut(&mut self) -> &mut dyn InnerHasher<F, I>;
    
    /// Get an immutable reference to the inner MultiFieldHasher for delegation.
    /// This is an implementation detail and should not be used directly.
    /// Only trait implementations should provide this method.
    #[doc(hidden)]
    fn inner_ref(&self) -> &dyn InnerHasher<F, I>;
    
    /// Update the hasher with any compatible input.
    /// 
    /// This accepts field elements, curve points, primitives, or any type with a From implementation.
    fn update<T: Into<I>>(&mut self, input: T) {
        self.inner_mut().update_field_input(input.into())
    }
    
    
    /// Get the current hash result while preserving the hasher state.
    fn digest(&mut self) -> F {
        self.inner_mut().digest_result()
    }
    
    
    /// Consume the hasher and return the final hash result.
    /// Equivalent to `digest()` but takes ownership, ensuring the hasher cannot be reused.
    fn finalize(mut self) -> F where Self: Sized {
        self.digest()
    }
    
    /// Reset the hasher state without changing parameters.
    /// This method securely clears all sensitive data from memory.
    fn reset(&mut self) {
        self.inner_mut().reset_hasher()
    }
    
    /// Returns the current number of elements added.
    fn element_count(&self) -> usize {
        self.inner_ref().get_element_count()
    }
}

/// Internal trait to abstract over the MultiFieldHasher operations.
/// This allows us to provide default implementations in PoseidonHasher.
pub trait InnerHasher<F, I>
where
    F: PrimeField,
{
    /// Update the hasher with a field input
    fn update_field_input(&mut self, input: I);
    /// Compute the hash digest
    fn digest_result(&mut self) -> F;
    /// Reset the hasher state
    fn reset_hasher(&mut self);
    /// Get the current element count
    fn get_element_count(&self) -> usize;
}

// Implement InnerHasher for MultiFieldHasher to enable delegation
impl<F, S, G> InnerHasher<F, FieldInput<F, S, G>> for MultiFieldHasher<F, S, G>
where
    F: PrimeField + ark_ff::Zero + ark_crypto_primitives::sponge::Absorb,
    S: PrimeField,
    G: ark_ec::AffineRepr<BaseField = F>,
{
    fn update_field_input(&mut self, input: FieldInput<F, S, G>) {
        self.update(input)
    }
    
    
    fn digest_result(&mut self) -> F {
        self.digest()
    }
    
    fn reset_hasher(&mut self) {
        self.reset()
    }
    
    fn get_element_count(&self) -> usize {
        self.element_count()
    }
}

// Macro to define curve-specific hasher types and impls
macro_rules! define_curve_hasher {
    (
        $Hasher:ident, $Input:ident,
        fq = $fq:path,
        fr = $fr:path,
        affine = $aff:path,
        params = $params:path
    ) => {
        #[derive(ZeroizeOnDrop)]
        pub struct $Hasher {
            inner: MultiFieldHasher<$fq, $fr, $aff>,
        }

        impl PoseidonHasher<$fq, $Input> for $Hasher {
            fn new() -> Self {
                Self { inner: MultiFieldHasher::new_from_ref(&$params) }
            }

            fn new_with_config(config: PackingConfig) -> Self {
                Self { inner: MultiFieldHasher::new_with_config_from_ref(&$params, config) }
            }

            fn inner_mut(&mut self) -> &mut dyn InnerHasher<$fq, $Input> { &mut self.inner }
            fn inner_ref(&self) -> &dyn InnerHasher<$fq, $Input> { &self.inner }
        }

        impl Default for $Hasher { fn default() -> Self { <Self as PoseidonHasher<$fq, $Input>>::new() } }

        pub type $Input = FieldInput<$fq, $fr, $aff>;
        impl From<$fq> for $Input { fn from(v: $fq) -> Self { Self::BaseField(v) } }
        impl From<$fr> for $Input { fn from(v: $fr) -> Self { Self::ScalarField(v) } }
        impl From<$aff> for $Input { fn from(v: $aff) -> Self { Self::CurvePoint(v) } }

        impl $Hasher {
            pub fn new() -> Self { <Self as PoseidonHasher<$fq, $Input>>::new() }
            pub fn new_with_config(config: PackingConfig) -> Self { <Self as PoseidonHasher<$fq, $Input>>::new_with_config(config) }
            pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
                let mut h = <Self as PoseidonHasher<$fq, $Input>>::new(); h.inner.absorb_domain(domain.as_ref()); h
            }
            pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
                let mut h = <Self as PoseidonHasher<$fq, $Input>>::new_with_config(config); h.inner.absorb_domain(domain.as_ref()); h
            }
        }
    };
}

define_curve_hasher!(
    PallasHasher, PallasInput,
    fq = ark_pallas::Fq,
    fr = ark_pallas::Fr,
    affine = ark_pallas::Affine,
    params = pallas::PALLAS_PARAMS
);

define_curve_hasher!(
    VestaHasher, VestaInput,
    fq = ark_vesta::Fq,
    fr = ark_vesta::Fr,
    affine = ark_vesta::Affine,
    params = vesta::VESTA_PARAMS
);

define_curve_hasher!(
    BN254Hasher, BN254Input,
    fq = ark_bn254::Fq,
    fr = ark_bn254::Fr,
    affine = ark_bn254::G1Affine,
    params = bn254::BN254_PARAMS
);

define_curve_hasher!(
    BLS12_381Hasher, BLS12_381Input,
    fq = ark_bls12_381::Fq,
    fr = ark_bls12_381::Fr,
    affine = ark_bls12_381::G1Affine,
    params = bls12_381::BLS12_381_PARAMS
);

define_curve_hasher!(
    BLS12_377Hasher, BLS12_377Input,
    fq = ark_bls12_377::Fq,
    fr = ark_bls12_377::Fr,
    affine = ark_bls12_377::G1Affine,
    params = bls12_377::BLS12_377_PARAMS
);
