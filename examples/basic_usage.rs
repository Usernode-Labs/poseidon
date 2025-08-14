//! Basic usage example for the Poseidon hash library.

use poseidon_hash::prelude::*;

fn main() -> Result<(), HasherError> {
    // Create a hasher
    let mut hasher = PallasHasher::new();
    
    // Hash field elements - clean direct API!
    hasher.update(ark_pallas::Fr::from(42u64))?;
    hasher.update(ark_pallas::Fq::from(100u64))?;
    
    let hash = hasher.digest()?;
    println!("Hash: {}", hash);
    
    // Hash primitive types  
    hasher.update(123u64)?;
    hasher.update("hello")?;
    
    let hash2 = hasher.digest()?;
    println!("Primitive hash: {}", hash2);
    
    Ok(())
}