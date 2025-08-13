//! Embedded Poseidon parameters for various elliptic curves.
//!
//! This module contains cryptographically secure parameters generated using
//! the official Poseidon reference implementation with 128-bit security level.

use light_poseidon::PoseidonParameters;
use ark_ff::PrimeField;

/// Security level in bits for all parameter sets
pub const SECURITY_LEVEL: u32 = 128;

/// State size (t) for all parameter sets
pub const STATE_SIZE: usize = 3;

/// Alpha value for S-box x^α
pub const ALPHA: u64 = 5;

// Submodules for each curve's parameters
pub mod pallas;
pub mod vesta;
pub mod bn254;
pub mod bls12_381;
pub mod bls12_377;

/// Helper function to create PoseidonParameters from embedded constants
pub fn create_parameters<F: PrimeField>(
    ark: Vec<F>,
    mds: Vec<Vec<F>>,
    full_rounds: usize,
    partial_rounds: usize,
) -> PoseidonParameters<F> {
    PoseidonParameters {
        ark,
        mds,
        full_rounds,
        partial_rounds,
        width: STATE_SIZE,
        alpha: ALPHA,
    }
}

/// Clone PoseidonParameters (since it doesn't implement Clone)
pub fn clone_parameters<F: PrimeField + Clone>(params: &PoseidonParameters<F>) -> PoseidonParameters<F> {
    PoseidonParameters {
        ark: params.ark.clone(),
        mds: params.mds.clone(),
        full_rounds: params.full_rounds,
        partial_rounds: params.partial_rounds,
        width: params.width,
        alpha: params.alpha,
    }
}