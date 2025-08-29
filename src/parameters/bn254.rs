//! Poseidon parameters for bn254 curve.
//! Defaults use dynamic derivation (Grain LFSR) with t=3, α=5, M=128.

use crate::ark_poseidon::ArkPoseidonConfig;
use lazy_static::lazy_static;

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;

lazy_static! {
    /// BN254 Poseidon parameters for t=3 (dynamic derivation)
    pub static ref BN254_PARAMS: ArkPoseidonConfig<ark_bn254::Fq> = {
        crate::parameters::create_dynamic_parameters::<ark_bn254::Fq>(
            3, FULL_ROUNDS, PARTIAL_ROUNDS, 1,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bn254_params_load() {
        let params = &*BN254_PARAMS;
        assert_eq!(params.full_rounds, FULL_ROUNDS);
        assert_eq!(params.partial_rounds, PARTIAL_ROUNDS);
        assert_eq!(params.rate + params.capacity, 3);
        assert_eq!(params.alpha, 5);
    }
}

