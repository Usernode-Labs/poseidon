//! Arkworks Poseidon sponge integration scaffold.
//!
//! This module will replace the current light-poseidon based core with
//! arkworks' Poseidon sponge from `ark-crypto-primitives`.
//! We introduce thin wrappers and type aliases to minimize ripple effects.

use ark_ff::PrimeField;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

/// Re-export config and sponge types for convenience.
pub type ArkPoseidonConfig<F> = PoseidonConfig<F>;
pub type ArkPoseidonSponge<F> = PoseidonSponge<F>;

// Intentionally minimal: consumers should use ArkPoseidonSponge::new directly.
