//! Poseidon2 parameter helpers.
//!
//! This module provides builders to create Poseidon2 sponge parameters from
//! provided round constants (ARK) and internal diagonal `mu` for the cheap
//! internal matrix J + Diag(mu).

use crate::ark_poseidon::ArkPoseidon2Config;
use ark_ff::PrimeField;

const CAPACITY: usize = 1; // fixed for our case 

/// Create Poseidon2 parameters from provided per-round ARK and diagonal `mu`.
///
/// - `ark`: per-round additive constants; length must be `full_rounds + partial_rounds`,
///    each row length must be `t` where `t = rate + capacity`.
/// - `mu`: diagonal for internal matrix J + Diag(mu); length must be `t`.
/// - `mds`: placeholder MDS matrix (not used by Poseidon2 permutation here, but
///   retained for API symmetry). Must be `t x t`.
#[allow(clippy::too_many_arguments)]
pub fn create_parameters<F: PrimeField>(
    ark: Vec<Vec<F>>, // len = rf + rp, each with width t
    mu: Vec<F>,       // len = t
    mds: Vec<Vec<F>>, // len = t, width = t (kept for API compatibility)
    full_rounds: usize,
    partial_rounds: usize,
    d: u64,
    rate: usize,
) -> ArkPoseidon2Config<F> {
    // t consistency checks are enforced in Poseidon2::PoseidonConfig::new
    ArkPoseidon2Config::new(full_rounds, partial_rounds, d, mds, ark, mu, rate, CAPACITY)
}

/// Convenience: build a `t x t` identity matrix.
pub fn identity_mds<F: PrimeField>(t: usize) -> Vec<Vec<F>> {
    let mut m = vec![vec![F::zero(); t]; t];
    for (i, row) in m.iter_mut().enumerate() {
        row[i] = F::one();
    }
    m
}
