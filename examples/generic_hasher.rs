//! Example demonstrating generic programming with the PoseidonHasher trait.

use poseidon_hash::prelude::*;

fn main() -> Result<(), HasherError> {
    // Different curves with same data
    let pallas_hash = hash_pallas()?;
    let bn254_hash = hash_bn254()?;
    
    println!("Pallas: {}", pallas_hash);
    println!("BN254:  {}", bn254_hash);
    
    // Different packing modes
    let byte_efficient = hash_pallas_with_config(PackingConfig::default())?;
    let circuit_friendly = hash_pallas_with_config(
        PackingConfig { mode: PackingMode::CircuitFriendly, ..Default::default() })?;
    
    println!("Byte-efficient:   {}", byte_efficient);
    println!("Circuit-friendly: {}", circuit_friendly);
    println!("Different modes: {}", byte_efficient != circuit_friendly);
    
    Ok(())
}

fn hash_pallas() -> Result<String, HasherError> {
    let mut hasher = PallasHasher::new();
    hasher.update(42u64)?;
    hasher.update("test")?;
    Ok(hasher.digest()?.to_string())
}

fn hash_bn254() -> Result<String, HasherError> {
    let mut hasher = BN254Hasher::new();
    hasher.update(42u64)?;
    hasher.update("test")?;
    Ok(hasher.digest()?.to_string())
}

fn hash_pallas_with_config(config: PackingConfig) -> Result<String, HasherError> {
    let mut hasher = PallasHasher::new_with_config(config);
    hasher.update(42u64)?;
    hasher.update("test")?;
    Ok(hasher.digest()?.to_string())
}