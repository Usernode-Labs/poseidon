use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

/// Re-export config and sponge types for convenience.
pub type ArkPoseidonConfig<F> = PoseidonConfig<F>;
pub type ArkPoseidonSponge<F> = PoseidonSponge<F>;

// Intentionally minimal: consumers should use ArkPoseidonSponge::new directly.
