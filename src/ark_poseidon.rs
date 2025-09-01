use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

/// Re-export config and sponge types for Poseidon (v1).
pub type ArkPoseidonConfig<F> = PoseidonConfig<F>;
pub type ArkPoseidonSponge<F> = PoseidonSponge<F>;

/// Poseidon2 aliases (our inline implementation)
pub type ArkPoseidon2Config<F> = crate::poseidon2::PoseidonConfig<F>;
pub type ArkPoseidon2Sponge<F> = crate::poseidon2::Poseidon2Sponge<F>;

// Intentionally minimal: consumers should use ArkPoseidonSponge::new directly.
