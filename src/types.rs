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

// Pallas curve hasher
/// Pallas curve multi-field hasher with embedded parameters.
/// Pallas is a 255-bit curve used in the Mina Protocol for recursive SNARKs.
/// 
/// Implements `ZeroizeOnDrop` to ensure sensitive data is cleared from memory.
#[derive(ZeroizeOnDrop)]
pub struct PallasHasher {
    inner: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>,
}

impl PoseidonHasher<ark_pallas::Fq, PallasInput> for PallasHasher {
    fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*pallas::PALLAS_PARAMS),
        }
    }
    
    fn new_with_config(config: PackingConfig) -> Self {
        Self {
            inner: MultiFieldHasher::new_with_config_from_ref(&*pallas::PALLAS_PARAMS, config),
        }
    }
    
    fn inner_mut(&mut self) -> &mut dyn InnerHasher<ark_pallas::Fq, PallasInput> {
        &mut self.inner
    }
    
    fn inner_ref(&self) -> &dyn InnerHasher<ark_pallas::Fq, PallasInput> {
        &self.inner
    }
}

impl Default for PallasHasher {
    fn default() -> Self {
        <Self as PoseidonHasher<ark_pallas::Fq, PallasInput>>::new()
    }
}

/// Type alias for Pallas curve field input enum.
pub type PallasInput = FieldInput<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>;

// Curve-specific From implementations for field types
impl From<ark_pallas::Fq> for PallasInput {
    fn from(value: ark_pallas::Fq) -> Self {
        Self::BaseField(value)
    }
}

impl From<ark_pallas::Fr> for PallasInput {
    fn from(value: ark_pallas::Fr) -> Self {
        Self::ScalarField(value)
    }
}

impl From<ark_pallas::Affine> for PallasInput {
    fn from(value: ark_pallas::Affine) -> Self {
        Self::CurvePoint(value)
    }
}

impl PallasHasher {
    pub fn new() -> Self {
        <Self as PoseidonHasher<ark_pallas::Fq, PallasInput>>::new()
    }
    pub fn new_with_config(config: PackingConfig) -> Self {
        <Self as PoseidonHasher<ark_pallas::Fq, PallasInput>>::new_with_config(config)
    }
}
impl PallasHasher {
    /// Create a new hasher namespaced with a domain string.
    pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_pallas::Fq, PallasInput>>::new();
        h.inner.absorb_domain(domain.as_ref());
        h
    }

    /// Create a new hasher with custom packing and a domain string.
    pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_pallas::Fq, PallasInput>>::new_with_config(config);
        h.inner.absorb_domain(domain.as_ref());
        h
    }
}



// Vesta curve hasher
/// Vesta curve multi-field hasher with embedded parameters.
/// Vesta forms a cycle with Pallas for efficient recursive proofs.
/// 
/// Implements `ZeroizeOnDrop` to ensure sensitive data is cleared from memory.
#[derive(ZeroizeOnDrop)]
pub struct VestaHasher {
    inner: MultiFieldHasher<ark_vesta::Fq, ark_vesta::Fr, ark_vesta::Affine>,
}

impl PoseidonHasher<ark_vesta::Fq, VestaInput> for VestaHasher {
    fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*vesta::VESTA_PARAMS),
        }
    }
    
    fn new_with_config(config: PackingConfig) -> Self {
        Self {
            inner: MultiFieldHasher::new_with_config_from_ref(&*vesta::VESTA_PARAMS, config),
        }
    }
    
    fn inner_mut(&mut self) -> &mut dyn InnerHasher<ark_vesta::Fq, VestaInput> {
        &mut self.inner
    }
    
    fn inner_ref(&self) -> &dyn InnerHasher<ark_vesta::Fq, VestaInput> {
        &self.inner
    }
}

impl Default for VestaHasher {
    fn default() -> Self {
        <Self as PoseidonHasher<ark_vesta::Fq, VestaInput>>::new()
    }
}

/// Type alias for Vesta curve field input enum.
pub type VestaInput = FieldInput<ark_vesta::Fq, ark_vesta::Fr, ark_vesta::Affine>;

// Curve-specific From implementations for field types
impl From<ark_vesta::Fq> for VestaInput {
    fn from(value: ark_vesta::Fq) -> Self {
        Self::BaseField(value)
    }
}

impl From<ark_vesta::Fr> for VestaInput {
    fn from(value: ark_vesta::Fr) -> Self {
        Self::ScalarField(value)
    }
}

impl From<ark_vesta::Affine> for VestaInput {
    fn from(value: ark_vesta::Affine) -> Self {
        Self::CurvePoint(value)
    }
}

impl VestaHasher {
    pub fn new() -> Self {
        <Self as PoseidonHasher<ark_vesta::Fq, VestaInput>>::new()
    }
    pub fn new_with_config(config: PackingConfig) -> Self {
        <Self as PoseidonHasher<ark_vesta::Fq, VestaInput>>::new_with_config(config)
    }
}
impl VestaHasher {
    pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_vesta::Fq, VestaInput>>::new();
        h.inner.absorb_domain(domain.as_ref());
        h
    }

    pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_vesta::Fq, VestaInput>>::new_with_config(config);
        h.inner.absorb_domain(domain.as_ref());
        h
    }
}

// BN254 curve hasher
/// BN254 curve multi-field hasher with embedded parameters.
/// BN254 is widely used in Ethereum and zkSNARK applications.
/// 
/// Implements `ZeroizeOnDrop` to ensure sensitive data is cleared from memory.
#[derive(ZeroizeOnDrop)]
pub struct BN254Hasher {
    inner: MultiFieldHasher<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>,
}

impl PoseidonHasher<ark_bn254::Fq, BN254Input> for BN254Hasher {
    fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*bn254::BN254_PARAMS),
        }
    }
    
    fn new_with_config(config: PackingConfig) -> Self {
        Self {
            inner: MultiFieldHasher::new_with_config_from_ref(&*bn254::BN254_PARAMS, config),
        }
    }
    
    fn inner_mut(&mut self) -> &mut dyn InnerHasher<ark_bn254::Fq, BN254Input> {
        &mut self.inner
    }
    
    fn inner_ref(&self) -> &dyn InnerHasher<ark_bn254::Fq, BN254Input> {
        &self.inner
    }
}

impl Default for BN254Hasher {
    fn default() -> Self {
        <Self as PoseidonHasher<ark_bn254::Fq, BN254Input>>::new()
    }
}

/// Type alias for BN254 curve field input enum.
pub type BN254Input = FieldInput<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>;

// Curve-specific From implementations for field types
impl From<ark_bn254::Fq> for BN254Input {
    fn from(value: ark_bn254::Fq) -> Self {
        Self::BaseField(value)
    }
}

impl From<ark_bn254::Fr> for BN254Input {
    fn from(value: ark_bn254::Fr) -> Self {
        Self::ScalarField(value)
    }
}

impl From<ark_bn254::G1Affine> for BN254Input {
    fn from(value: ark_bn254::G1Affine) -> Self {
        Self::CurvePoint(value)
    }
}

impl BN254Hasher {
    pub fn new() -> Self {
        <Self as PoseidonHasher<ark_bn254::Fq, BN254Input>>::new()
    }
    pub fn new_with_config(config: PackingConfig) -> Self {
        <Self as PoseidonHasher<ark_bn254::Fq, BN254Input>>::new_with_config(config)
    }
}
impl BN254Hasher {
    pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_bn254::Fq, BN254Input>>::new();
        h.inner.absorb_domain(domain.as_ref());
        h
    }

    pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_bn254::Fq, BN254Input>>::new_with_config(config);
        h.inner.absorb_domain(domain.as_ref());
        h
    }
}

// BLS12-381 curve hasher
/// BLS12-381 curve multi-field hasher with embedded parameters.
/// BLS12-381 is used in Ethereum 2.0 and Zcash.
/// 
/// Implements `ZeroizeOnDrop` to ensure sensitive data is cleared from memory.
#[derive(ZeroizeOnDrop)]
pub struct BLS12_381Hasher {
    inner: MultiFieldHasher<ark_bls12_381::Fq, ark_bls12_381::Fr, ark_bls12_381::G1Affine>,
}

impl PoseidonHasher<ark_bls12_381::Fq, BLS12_381Input> for BLS12_381Hasher {
    fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*bls12_381::BLS12_381_PARAMS),
        }
    }
    
    fn new_with_config(config: PackingConfig) -> Self {
        Self {
            inner: MultiFieldHasher::new_with_config_from_ref(&*bls12_381::BLS12_381_PARAMS, config),
        }
    }
    
    fn inner_mut(&mut self) -> &mut dyn InnerHasher<ark_bls12_381::Fq, BLS12_381Input> {
        &mut self.inner
    }
    
    fn inner_ref(&self) -> &dyn InnerHasher<ark_bls12_381::Fq, BLS12_381Input> {
        &self.inner
    }
}

impl Default for BLS12_381Hasher {
    fn default() -> Self {
        <Self as PoseidonHasher<ark_bls12_381::Fq, BLS12_381Input>>::new()
    }
}

/// Type alias for BLS12-381 curve field input enum.
pub type BLS12_381Input = FieldInput<ark_bls12_381::Fq, ark_bls12_381::Fr, ark_bls12_381::G1Affine>;

// Curve-specific From implementations for field types
impl From<ark_bls12_381::Fq> for BLS12_381Input {
    fn from(value: ark_bls12_381::Fq) -> Self {
        Self::BaseField(value)
    }
}

impl From<ark_bls12_381::Fr> for BLS12_381Input {
    fn from(value: ark_bls12_381::Fr) -> Self {
        Self::ScalarField(value)
    }
}

impl From<ark_bls12_381::G1Affine> for BLS12_381Input {
    fn from(value: ark_bls12_381::G1Affine) -> Self {
        Self::CurvePoint(value)
    }
}

impl BLS12_381Hasher {
    pub fn new() -> Self {
        <Self as PoseidonHasher<ark_bls12_381::Fq, BLS12_381Input>>::new()
    }
    pub fn new_with_config(config: PackingConfig) -> Self {
        <Self as PoseidonHasher<ark_bls12_381::Fq, BLS12_381Input>>::new_with_config(config)
    }
}
impl BLS12_381Hasher {
    pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_bls12_381::Fq, BLS12_381Input>>::new();
        h.inner.absorb_domain(domain.as_ref());
        h
    }

    pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_bls12_381::Fq, BLS12_381Input>>::new_with_config(config);
        h.inner.absorb_domain(domain.as_ref());
        h
    }
}

// BLS12-377 curve hasher
/// BLS12-377 curve multi-field hasher with embedded parameters.
/// BLS12-377 is used in Celo and forms cycles with BW6-761.
/// 
/// Implements `ZeroizeOnDrop` to ensure sensitive data is cleared from memory.
#[derive(ZeroizeOnDrop)]
pub struct BLS12_377Hasher {
    inner: MultiFieldHasher<ark_bls12_377::Fq, ark_bls12_377::Fr, ark_bls12_377::G1Affine>,
}

impl PoseidonHasher<ark_bls12_377::Fq, BLS12_377Input> for BLS12_377Hasher {
    fn new() -> Self {
        Self {
            inner: MultiFieldHasher::new_from_ref(&*bls12_377::BLS12_377_PARAMS),
        }
    }
    
    fn new_with_config(config: PackingConfig) -> Self {
        Self {
            inner: MultiFieldHasher::new_with_config_from_ref(&*bls12_377::BLS12_377_PARAMS, config),
        }
    }
    
    fn inner_mut(&mut self) -> &mut dyn InnerHasher<ark_bls12_377::Fq, BLS12_377Input> {
        &mut self.inner
    }
    
    fn inner_ref(&self) -> &dyn InnerHasher<ark_bls12_377::Fq, BLS12_377Input> {
        &self.inner
    }
}

impl Default for BLS12_377Hasher {
    fn default() -> Self {
        <Self as PoseidonHasher<ark_bls12_377::Fq, BLS12_377Input>>::new()
    }
}

/// Type alias for BLS12-377 curve field input enum.
pub type BLS12_377Input = FieldInput<ark_bls12_377::Fq, ark_bls12_377::Fr, ark_bls12_377::G1Affine>;

// Curve-specific From implementations for field types
impl From<ark_bls12_377::Fq> for BLS12_377Input {
    fn from(value: ark_bls12_377::Fq) -> Self {
        Self::BaseField(value)
    }
}

impl From<ark_bls12_377::Fr> for BLS12_377Input {
    fn from(value: ark_bls12_377::Fr) -> Self {
        Self::ScalarField(value)
    }
}

impl From<ark_bls12_377::G1Affine> for BLS12_377Input {
    fn from(value: ark_bls12_377::G1Affine) -> Self {
        Self::CurvePoint(value)
    }
}

impl BLS12_377Hasher {
    pub fn new() -> Self {
        <Self as PoseidonHasher<ark_bls12_377::Fq, BLS12_377Input>>::new()
    }
    pub fn new_with_config(config: PackingConfig) -> Self {
        <Self as PoseidonHasher<ark_bls12_377::Fq, BLS12_377Input>>::new_with_config(config)
    }
}

impl BLS12_377Hasher {
    pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_bls12_377::Fq, BLS12_377Input>>::new();
        h.inner.absorb_domain(domain.as_ref());
        h
    }

    pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
        let mut h = <Self as PoseidonHasher<ark_bls12_377::Fq, BLS12_377Input>>::new_with_config(config);
        h.inner.absorb_domain(domain.as_ref());
        h
    }
}
