//! Multi-curve example demonstrating usage with different elliptic curves.

use poseidon_hash::prelude::*;

fn main() -> Result<(), HasherError> {
    // Same data, different curves
    let data = RustInput::U64(42);
    
    let mut pallas = PallasHasher::new();
    pallas.update_primitive(data.clone())?;
    let pallas_hash = pallas.digest()?;
    
    let mut bn254 = BN254Hasher::new();
    bn254.update_primitive(data)?;
    let bn254_hash = bn254.digest()?;
    
    println!("Pallas hash: {}", pallas_hash);
    println!("BN254 hash:  {}", bn254_hash);
    println!("Different curves produce different hashes: {}", 
             pallas_hash.to_string() != bn254_hash.to_string());
    
    Ok(())
}