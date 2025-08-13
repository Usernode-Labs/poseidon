//! Example demonstrating generic programming with the PoseidonHasher trait.

use poseidon_hash::prelude::*;

fn main() -> Result<(), HasherError> {
    let data = vec![RustInput::U64(42), RustInput::from_string_slice("test")];
    
    // Generic function works with any curve
    let pallas_hash = hash_generic::<PallasHasher, ark_pallas::Fq, PallasInput>(&data)?;
    let bn254_hash = hash_generic::<BN254Hasher, ark_bn254::Fq, BN254Input>(&data)?;
    
    println!("Pallas: {}", pallas_hash);
    println!("BN254:  {}", bn254_hash);
    
    // Different packing modes
    let byte_efficient = hash_with_config::<PallasHasher, ark_pallas::Fq, PallasInput>(
        &data, PackingConfig::default())?;
    let circuit_friendly = hash_with_config::<PallasHasher, ark_pallas::Fq, PallasInput>(
        &data, PackingConfig { mode: PackingMode::CircuitFriendly, ..Default::default() })?;
    
    println!("Byte-efficient:   {}", byte_efficient);
    println!("Circuit-friendly: {}", circuit_friendly);
    println!("Different modes: {}", byte_efficient != circuit_friendly);
    
    Ok(())
}

fn hash_generic<H, F, I>(data: &[RustInput]) -> Result<String, HasherError>
where
    H: PoseidonHasher<F, I>,
    F: ark_ff::PrimeField + std::fmt::Display,
{
    let mut hasher = H::new();
    for item in data {
        hasher.update_primitive(item.clone())?;
    }
    Ok(hasher.squeeze()?.to_string())
}

fn hash_with_config<H, F, I>(data: &[RustInput], config: PackingConfig) -> Result<String, HasherError>
where
    H: PoseidonHasher<F, I>,
    F: ark_ff::PrimeField + std::fmt::Display,
{
    let mut hasher = H::new_with_config(config);
    for item in data {
        hasher.update_primitive(item.clone())?;
    }
    Ok(hasher.squeeze()?.to_string())
}