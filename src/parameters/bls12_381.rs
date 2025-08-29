//! Poseidon parameters for bls12_381 curve.
//! Defaults use dynamic derivation (Grain LFSR) with t=3, α=5, M=128.

use crate::ark_poseidon::ArkPoseidonConfig;
use lazy_static::lazy_static;

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;

lazy_static! {
    /// BLS12-381 Poseidon parameters for t=3 (dynamic derivation)
    pub static ref BLS12_381_PARAMS: ArkPoseidonConfig<ark_bls12_381::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_bls12_381::Fq>(
            3, FULL_ROUNDS, PARTIAL_ROUNDS, 1,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bls12_381_params_load() {
        let params = &*BLS12_381_PARAMS;
        assert_eq!(params.full_rounds, FULL_ROUNDS);
        assert_eq!(params.partial_rounds, PARTIAL_ROUNDS);
        assert_eq!(params.rate + params.capacity, 3);
        assert_eq!(params.alpha, 5);
    }
}

