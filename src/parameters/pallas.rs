//! Poseidon parameters for pallas curve.
//!
//! Defaults use arkworks' deterministic parameter derivation (Grain LFSR)
//! with t=3, α=5, M=128 security level.
//! Pallas curve (used in Mina Protocol)

use crate::ark_poseidon::ArkPoseidonConfig;
use lazy_static::lazy_static;

/// Number of full rounds for t=3
pub const FULL_ROUNDS: usize = 8;
/// Number of partial rounds for t=3
pub const PARTIAL_ROUNDS: usize = 56;

lazy_static! {
    /// Pallas Poseidon parameters for t=3 (dynamic derivation)
    pub static ref PALLAS_PARAMS: ArkPoseidonConfig<ark_pallas::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_pallas::Fq>(
            3, FULL_ROUNDS, PARTIAL_ROUNDS, 1,
        )
    };
}

/// Runtime-selectable Pallas Poseidon parameter variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PallasVariant {
    T3,
    /// Pallas Poseidon t=4, alpha=5 — rate=3 (ideal for 3 elements)
    T4,
    T5,
    T9,
    T12,
}

lazy_static! {
    /// Pallas Poseidon t=4, alpha=5, ~128-bit security (conservative rounds)
    pub static ref PALLAS_PARAMS_T4: ArkPoseidonConfig<ark_pallas::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_pallas::Fq>(4, 8, 60, 1)
    };
    /// Pallas Poseidon t=5, alpha=5, ~128-bit security (conservative rounds)
    pub static ref PALLAS_PARAMS_T5: ArkPoseidonConfig<ark_pallas::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_pallas::Fq>(5, 8, 60, 1)
    };
    /// Pallas Poseidon t=9, alpha=5, ~128-bit security (conservative rounds)
    pub static ref PALLAS_PARAMS_T9: ArkPoseidonConfig<ark_pallas::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_pallas::Fq>(9, 8, 64, 1)
    };
    /// Pallas Poseidon t=12, alpha=5, ~128-bit security (conservative rounds)
    pub static ref PALLAS_PARAMS_T12: ArkPoseidonConfig<ark_pallas::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_pallas::Fq>(12, 8, 64, 1)
    };
}

/// Get a reference to Pallas Poseidon parameters for the requested variant.
pub fn pallas_params_for(variant: PallasVariant) -> &'static ArkPoseidonConfig<ark_pallas::Fq> {
    match variant {
        PallasVariant::T3 => &*PALLAS_PARAMS,
        PallasVariant::T4 => &*PALLAS_PARAMS_T4,
        PallasVariant::T5 => &*PALLAS_PARAMS_T5,
        PallasVariant::T9 => &*PALLAS_PARAMS_T9,
        PallasVariant::T12 => &*PALLAS_PARAMS_T12,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pallas_params_load() {
        let params = &*PALLAS_PARAMS;
        assert_eq!(params.full_rounds, FULL_ROUNDS);
        assert_eq!(params.partial_rounds, PARTIAL_ROUNDS);
        assert_eq!(params.rate + params.capacity, 3);
        assert_eq!(params.alpha, 5);
    }
}

