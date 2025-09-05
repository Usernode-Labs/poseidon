//! Curve-specific hashers with embedded parameters.
//!
//! This module provides curve-specific hashers that embed their parameters
//! at compile time, ensuring type safety and eliminating the possibility
//! of using incorrect parameters.

use crate::hasher::{FieldInput, MultiFieldHasherV1};
use crate::parameters::*;
use crate::primitive::PackingConfig;
use ark_ff::PrimeField;
use zeroize::ZeroizeOnDrop;

/// Trait for curve-specific Poseidon hashers with primitive type support.
///
/// This trait ensures a consistent interface across all curve implementations
/// while maintaining type safety and embedding curve-specific parameters.
pub trait PoseidonHasher<F, I>
where
    F: PrimeField,
{
    /// Create a new hasher with default (byte-efficient) packing configuration.
    fn new() -> Self;

    /// Create a new hasher with custom packing configuration.
    fn new_with_config(config: PackingConfig) -> Self;

    // Hidden delegation hooks implemented per concrete hasher.
    #[doc(hidden)]
    fn update_field_input(&mut self, input: I);
    #[doc(hidden)]
    fn digest_result(&mut self) -> F;
    #[doc(hidden)]
    fn reset_hasher(&mut self);
    #[doc(hidden)]
    fn get_element_count(&self) -> usize;

    /// Update the hasher with any compatible input.
    /// This accepts field elements, curve points, primitives, or any type with a From implementation.
    fn update<T: Into<I>>(&mut self, input: T) {
        self.update_field_input(input.into())
    }

    /// Get the current hash result while preserving the hasher state.
    fn digest(&mut self) -> F {
        self.digest_result()
    }

    /// Consume the hasher and return the final hash result.
    /// Equivalent to `digest()` but takes ownership, ensuring the hasher cannot be reused.
    fn finalize(mut self) -> F
    where
        Self: Sized,
    {
        self.digest()
    }

    /// Reset the hasher state without changing parameters.
    /// This method securely clears all sensitive data from memory.
    fn reset(&mut self) {
        self.reset_hasher()
    }

    /// Returns the current number of elements added.
    fn element_count(&self) -> usize {
        self.get_element_count()
    }
}

// Macro to define curve-specific hasher types and impls
macro_rules! define_curve_hasher {
    (
        $Hasher:ident,
        fq = $fq:path,
        fr = $fr:path,
        affine = $aff:path,
        params = $params:path
    ) => {
        #[derive(ZeroizeOnDrop)]
        pub struct $Hasher {
            inner: MultiFieldHasherV1<$fq, $fr, $aff>,
        }

        impl PoseidonHasher<$fq, FieldInput<$fq, $fr, $aff>> for $Hasher {
            fn new() -> Self {
                Self {
                    inner: MultiFieldHasherV1::new_from_ref(&$params),
                }
            }

            fn new_with_config(config: PackingConfig) -> Self {
                Self {
                    inner: MultiFieldHasherV1::new_with_config_from_ref(&$params, config),
                }
            }

            #[inline]
            fn update_field_input(&mut self, input: FieldInput<$fq, $fr, $aff>) {
                self.inner.update(input)
            }
            #[inline]
            fn digest_result(&mut self) -> $fq {
                self.inner.digest()
            }
            #[inline]
            fn reset_hasher(&mut self) {
                self.inner.reset()
            }
            #[inline]
            fn get_element_count(&self) -> usize {
                self.inner.element_count()
            }
        }

        impl Default for $Hasher {
            fn default() -> Self {
                <Self as PoseidonHasher<$fq, FieldInput<$fq, $fr, $aff>>>::new()
            }
        }

        impl From<$fq> for FieldInput<$fq, $fr, $aff> {
            fn from(v: $fq) -> Self {
                Self::BaseField(v)
            }
        }
        impl From<$fr> for FieldInput<$fq, $fr, $aff> {
            fn from(v: $fr) -> Self {
                Self::ScalarField(v)
            }
        }
        impl From<$aff> for FieldInput<$fq, $fr, $aff> {
            fn from(v: $aff) -> Self {
                Self::CurvePoint(v)
            }
        }

        impl $Hasher {
            pub fn new() -> Self {
                <Self as PoseidonHasher<$fq, FieldInput<$fq, $fr, $aff>>>::new()
            }
            pub fn new_with_config(config: PackingConfig) -> Self {
                <Self as PoseidonHasher<$fq, FieldInput<$fq, $fr, $aff>>>::new_with_config(config)
            }
            pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
                let mut h = <Self as PoseidonHasher<$fq, FieldInput<$fq, $fr, $aff>>>::new();
                h.inner.absorb_domain(domain.as_ref());
                h
            }
            pub fn new_with_config_and_domain(
                config: PackingConfig,
                domain: impl AsRef<[u8]>,
            ) -> Self {
                let mut h =
                    <Self as PoseidonHasher<$fq, FieldInput<$fq, $fr, $aff>>>::new_with_config(
                        config,
                    );
                h.inner.absorb_domain(domain.as_ref());
                h
            }

            // Domain-in-Rate is the default; dedicated constructors removed
        }
    };
}

define_curve_hasher!(
    PallasHasher,
    fq = ark_pallas::Fq,
    fr = ark_pallas::Fr,
    affine = ark_pallas::Affine,
    params = pallas::PALLAS_PARAMS
);

define_curve_hasher!(
    VestaHasher,
    fq = ark_vesta::Fq,
    fr = ark_vesta::Fr,
    affine = ark_vesta::Affine,
    params = vesta::VESTA_PARAMS
);

// Pallas-specific variant-selecting constructors
impl PallasHasher {
    /// Create a new hasher selecting Poseidon parameters by variant (t).
    pub fn new_variant(variant: crate::parameters::pallas::PallasVariant) -> Self {
        let params = crate::parameters::pallas::pallas_params_for(variant);
        Self {
            inner: MultiFieldHasherV1::new_from_ref(params),
        }
    }

    /// Create a new hasher with custom packing config and selected variant.
    pub fn new_with_config_variant(
        config: PackingConfig,
        variant: crate::parameters::pallas::PallasVariant,
    ) -> Self {
        let params = crate::parameters::pallas::pallas_params_for(variant);
        Self {
            inner: MultiFieldHasherV1::new_with_config_from_ref(params, config),
        }
    }

    /// Create a new hasher with domain for the selected variant (Domain-in-Rate default).
    pub fn new_with_domain_variant(
        domain: impl AsRef<[u8]>,
        variant: crate::parameters::pallas::PallasVariant,
    ) -> Self {
        let params = crate::parameters::pallas::pallas_params_for(variant);
        let mut h = Self {
            inner: MultiFieldHasherV1::new_from_ref(params),
        };
        h.inner.absorb_domain(domain.as_ref());
        h
    }
}

define_curve_hasher!(
    BN254Hasher,
    fq = ark_bn254::Fq,
    fr = ark_bn254::Fr,
    affine = ark_bn254::G1Affine,
    params = bn254::BN254_PARAMS
);

define_curve_hasher!(
    BLS12_381Hasher,
    fq = ark_bls12_381::Fq,
    fr = ark_bls12_381::Fr,
    affine = ark_bls12_381::G1Affine,
    params = bls12_381::BLS12_381_PARAMS
);

define_curve_hasher!(
    BLS12_377Hasher,
    fq = ark_bls12_377::Fq,
    fr = ark_bls12_377::Fr,
    affine = ark_bls12_377::G1Affine,
    params = bls12_377::BLS12_377_PARAMS
);

// Poseidon2-specific types (explicit algorithm/version in the name)
pub mod poseidon2 {
    use super::{FieldInput, PoseidonHasher};
    use crate::ark_poseidon::ArkPoseidon2Sponge;
    use crate::hasher::MultiFieldHasherV2;
    use crate::parameters::poseidon2_pallas::{
        PALLAS_POSEIDON2_PARAMS, PALLAS_POSEIDON2_PARAMS_T4,
    };
    // BN254-specific parameters are imported in the BN254 module below.
    use crate::primitive::PackingConfig;
    use ark_crypto_primitives::sponge::CryptographicSponge;

    pub struct PallasPoseidon2Hasher {
        inner: MultiFieldHasherV2<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>,
    }

    impl
        PoseidonHasher<
            ark_pallas::Fq,
            FieldInput<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>,
        > for PallasPoseidon2Hasher
    {
        fn new() -> Self {
            Self {
                inner: MultiFieldHasherV2::new_from_ref(&*PALLAS_POSEIDON2_PARAMS),
            }
        }

        fn new_with_config(config: PackingConfig) -> Self {
            Self {
                inner: MultiFieldHasherV2::new_with_config_from_ref(
                    &*PALLAS_POSEIDON2_PARAMS,
                    config,
                ),
            }
        }

        fn update_field_input(
            &mut self,
            input: FieldInput<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine>,
        ) {
            self.inner.update(input)
        }
        fn digest_result(&mut self) -> ark_pallas::Fq {
            self.inner.digest()
        }
        fn reset_hasher(&mut self) {
            self.inner.reset()
        }
        fn get_element_count(&self) -> usize {
            self.inner.element_count()
        }
    }

    impl Default for PallasPoseidon2Hasher {
        fn default() -> Self {
            <Self as super::PoseidonHasher<_, _>>::new()
        }
    }

    impl PallasPoseidon2Hasher {
        pub fn new() -> Self {
            <Self as super::PoseidonHasher<_, _>>::new()
        }
        pub fn new_with_config(config: PackingConfig) -> Self {
            <Self as super::PoseidonHasher<_, _>>::new_with_config(config)
        }
        pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
            let mut h = <Self as super::PoseidonHasher<_, _>>::new();
            h.inner.absorb_domain(domain.as_ref());
            h
        }
        pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
            let mut h = <Self as super::PoseidonHasher<_, _>>::new_with_config(config);
            h.inner.absorb_domain(domain.as_ref());
            h
        }

        /// Create a Poseidon2 hasher selecting parameters by variant (t).
        pub fn new_variant(variant: PallasPoseidon2Variant) -> Self {
            let params = match variant {
                PallasPoseidon2Variant::T3 => &*PALLAS_POSEIDON2_PARAMS,
                PallasPoseidon2Variant::T4 => &*PALLAS_POSEIDON2_PARAMS_T4,
            };
            Self {
                inner: MultiFieldHasherV2::new_from_ref(params),
            }
        }

        /// Create Poseidon2 hasher with custom packing config and variant.
        pub fn new_with_config_variant(
            config: PackingConfig,
            variant: PallasPoseidon2Variant,
        ) -> Self {
            let params = match variant {
                PallasPoseidon2Variant::T3 => &*PALLAS_POSEIDON2_PARAMS,
                PallasPoseidon2Variant::T4 => &*PALLAS_POSEIDON2_PARAMS_T4,
            };
            Self {
                inner: MultiFieldHasherV2::new_with_config_from_ref(params, config),
            }
        }
    }

    /// Runtime-selectable Poseidon2 Pallas parameter variants.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PallasPoseidon2Variant {
        T3,
        T4,
    }

    /// Lightweight Poseidon2 (t=4) compression helper for Pallas.
    ///
    /// Exposes a simple 3→1 compression using one permutation with the
    /// capacity lane set to zero. Accepts inputs convertible into Pallas Fq.
    pub struct PallasPoseidon2Compress {
        sponge: ArkPoseidon2Sponge<ark_pallas::Fq>,
    }

    impl PallasPoseidon2Compress {
        /// Create a new compressor using t=4 Poseidon2 params for Pallas.
        pub fn new() -> Self {
            Self {
                sponge: ArkPoseidon2Sponge::new(&*PALLAS_POSEIDON2_PARAMS_T4),
            }
        }

        /// Compress exactly three inputs into one field element.
        pub fn compress3<A, B, C>(&self, a: A, b: B, c: C) -> ark_pallas::Fq
        where
            A: Into<ark_pallas::Fq>,
            B: Into<ark_pallas::Fq>,
            C: Into<ark_pallas::Fq>,
        {
            let a: ark_pallas::Fq = a.into();
            let b: ark_pallas::Fq = b.into();
            let c: ark_pallas::Fq = c.into();
            self.sponge.compress_3(a, b, c)
        }
    }
}

// BN254 Poseidon2 hasher (explicit algorithm/version)
pub mod poseidon2_bn254 {
    use super::{FieldInput, PoseidonHasher};
    use crate::hasher::MultiFieldHasherV2;
    use crate::parameters::poseidon2_bn254::{
        BN254_POSEIDON2_PARAMS, BN254_POSEIDON2_PARAMS_T4,
    };
    use crate::primitive::PackingConfig;

    pub struct BN254Poseidon2Hasher {
        inner: MultiFieldHasherV2<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>,
    }

    impl PoseidonHasher<ark_bn254::Fq, FieldInput<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>>
        for BN254Poseidon2Hasher
    {
        fn new() -> Self {
            Self { inner: MultiFieldHasherV2::new_from_ref(&*BN254_POSEIDON2_PARAMS) }
        }

        fn new_with_config(config: PackingConfig) -> Self {
            Self {
                inner: MultiFieldHasherV2::new_with_config_from_ref(
                    &*BN254_POSEIDON2_PARAMS,
                    config,
                ),
            }
        }

        fn update_field_input(
            &mut self,
            input: FieldInput<ark_bn254::Fq, ark_bn254::Fr, ark_bn254::G1Affine>,
        ) {
            self.inner.update(input)
        }
        fn digest_result(&mut self) -> ark_bn254::Fq { self.inner.digest() }
        fn reset_hasher(&mut self) { self.inner.reset() }
        fn get_element_count(&self) -> usize { self.inner.element_count() }
    }

    impl Default for BN254Poseidon2Hasher {
        fn default() -> Self { <Self as super::PoseidonHasher<_, _>>::new() }
    }

    impl BN254Poseidon2Hasher {
        pub fn new() -> Self { <Self as super::PoseidonHasher<_, _>>::new() }
        pub fn new_with_config(config: PackingConfig) -> Self {
            <Self as super::PoseidonHasher<_, _>>::new_with_config(config)
        }
        pub fn new_with_domain(domain: impl AsRef<[u8]>) -> Self {
            let mut h = <Self as super::PoseidonHasher<_, _>>::new();
            h.inner.absorb_domain(domain.as_ref());
            h
        }
        pub fn new_with_config_and_domain(config: PackingConfig, domain: impl AsRef<[u8]>) -> Self {
            let mut h = <Self as super::PoseidonHasher<_, _>>::new_with_config(config);
            h.inner.absorb_domain(domain.as_ref());
            h
        }

        pub fn new_variant_t4() -> Self {
            Self { inner: MultiFieldHasherV2::new_from_ref(&*BN254_POSEIDON2_PARAMS_T4) }
        }
        pub fn new_with_config_variant_t4(config: PackingConfig) -> Self {
            Self {
                inner: MultiFieldHasherV2::new_with_config_from_ref(
                    &*BN254_POSEIDON2_PARAMS_T4,
                    config,
                ),
            }
        }
    }
}
