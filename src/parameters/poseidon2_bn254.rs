//! Poseidon2 parameters for the BN254 curve (Fq base field).
//!
//! Parameters are derived deterministically using the Grain LFSR via
//! `find_poseidon2_ark_and_mu`, and exposed via `lazy_static`.

use crate::ark_poseidon::ArkPoseidon2Config;
use crate::parameters::poseidon2::{create_parameters, identity_mds};
use crate::poseidon2::find_poseidon2_ark_and_mu;
use ark_ff::PrimeField;
use lazy_static::lazy_static;

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;
pub const D: u64 = 5; // S-box exponent

lazy_static! {
    /// BN254 Poseidon2 parameters for t=3 (rate=2, capacity=1)
    pub static ref BN254_POSEIDON2_PARAMS: ArkPoseidon2Config<ark_bn254::Fq> = {
        type F = ark_bn254::Fq;
        let t = 3usize; // rate + capacity
        let rate = 2usize;
        let prime_bits = F::MODULUS_BIT_SIZE as u64;
        let (ark, mu) = find_poseidon2_ark_and_mu::<F>(
            prime_bits,
            t,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
        );
        let mds = identity_mds::<F>(t);
        create_parameters::<F>(
            ark,
            mu,
            mds,
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            D,
            rate,
        )
    };

    /// BN254 Poseidon2 parameters for t=4 (rate=3, capacity=1)
    pub static ref BN254_POSEIDON2_PARAMS_T4: ArkPoseidon2Config<ark_bn254::Fq> = {
        type F = ark_bn254::Fq;
        let t = 4usize; // rate + capacity
        let rate = 3usize;
        let prime_bits = F::MODULUS_BIT_SIZE as u64;
        let (ark, mu) = find_poseidon2_ark_and_mu::<F>(
            prime_bits,
            t,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
        );
        let mds = identity_mds::<F>(t);
        create_parameters::<F>(
            ark,
            mu,
            mds,
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            D,
            rate,
        )
    };
}
