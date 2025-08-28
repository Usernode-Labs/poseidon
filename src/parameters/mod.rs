//! Embedded Poseidon parameters for various elliptic curves.
//!
//! This module contains cryptographically secure parameters generated using
//! the official Poseidon reference implementation with 128-bit security level.

use ark_ff::PrimeField;
use crate::ark_poseidon::ArkPoseidonConfig;
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;

/// Security level in bits for all parameter sets
pub const SECURITY_LEVEL: u32 = 128;

/// Default state size (t) for embedded static sets (t=3)
/// Dynamic variants can use other t via helper constructors.
pub const STATE_SIZE: usize = 3;

/// Alpha value for S-box x^α
pub const ALPHA: u64 = 5;

// Submodules for each curve's parameters
pub mod pallas;
pub mod vesta;
pub mod bn254;
pub mod bls12_381;
pub mod bls12_377;

/// Helper to create Poseidon sponge config from embedded constants
pub fn create_parameters<F: PrimeField>(
    ark_flat: Vec<F>,
    mds: Vec<Vec<F>>,
    full_rounds: usize,
    partial_rounds: usize,
) -> ArkPoseidonConfig<F> {
    let t = STATE_SIZE;
    let r = STATE_SIZE - 1; // absorb 2 per permutation for t=3
    let c = t - r; // 1

    // Convert flat ark constants into per-round rows of width t
    let mut ark: Vec<Vec<F>> = Vec::with_capacity(full_rounds + partial_rounds);
    for chunk in ark_flat.chunks(t) {
        ark.push(chunk.to_vec());
    }
    assert_eq!(ark.len(), full_rounds + partial_rounds, "ARK length mismatch");

    ArkPoseidonConfig::new(full_rounds, partial_rounds, ALPHA, mds, ark, r, c)
}

/// Clone Poseidon sponge config (PoseidonConfig doesn't implement Clone generically)
pub fn clone_parameters<F: PrimeField + Clone>(params: &ArkPoseidonConfig<F>) -> ArkPoseidonConfig<F> {
    ArkPoseidonConfig::new(
        params.full_rounds,
        params.partial_rounds,
        params.alpha,
        params.mds.clone(),
        params.ark.clone(),
        params.rate,
        params.capacity,
    )
}

/// Create parameters from embedded constants if available; otherwise, use arkworks defaults.
pub fn create_parameters_or_default<F>(
    ark_flat: Vec<F>,
    mds: Vec<Vec<F>>,
    full_rounds: Option<usize>,
    partial_rounds: Option<usize>,
) -> ArkPoseidonConfig<F>
where
    F: PrimeField,
{
    if !ark_flat.is_empty() && !mds.is_empty() {
        // Fall back to embedded constants path
        return create_parameters(
            ark_flat,
            mds,
            full_rounds.expect("full_rounds missing"),
            partial_rounds.expect("partial_rounds missing"),
        );
    }
    // Derive parameters via Poseidon Grain LFSR (deterministic) with common t=3 M=128 settings
    let prime_bits = F::MODULUS_BIT_SIZE as u64;
    let rate = STATE_SIZE - 1; // 2
    let fr = 8u64; // typical for t=3, alpha=5, 128-bit
    let pr = 56u64; // typical for t=3, alpha=5, 128-bit
    let skip = 0u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(prime_bits, rate, fr, pr, skip);
    ArkPoseidonConfig::new(fr as usize, pr as usize, ALPHA, mds, ark, rate, STATE_SIZE - rate)
}

/// Create Poseidon parameters dynamically for arbitrary state size t and round counts.
///
/// This uses arkworks' deterministic parameter derivation (Grain LFSR) and the
/// provided round numbers. Choose conservative round numbers for your security level.
pub fn create_dynamic_parameters<F>(
    t: usize,
    full_rounds: usize,
    partial_rounds: usize,
    capacity: usize,
) -> ArkPoseidonConfig<F>
where
    F: PrimeField,
{
    use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
    let prime_bits = F::MODULUS_BIT_SIZE as u64;
    let rate = t
        .checked_sub(capacity)
        .expect("capacity must be <= t when building Poseidon parameters");
    let skip = 0u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        prime_bits,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        skip,
    );
    ArkPoseidonConfig::new(full_rounds, partial_rounds, ALPHA, mds, ark, rate, capacity)
}
