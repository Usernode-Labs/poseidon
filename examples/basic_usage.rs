//! Basic usage example for the Poseidon hash library.

use poseidon_hash::prelude::*;

fn main() -> Result<(), HasherError> {
    // Create a hasher
    let mut hasher = PallasHasher::new();
    
    // Hash field elements
    hasher.update(PallasInput::ScalarField(ark_pallas::Fr::from(42u64)))?;
    hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(100u64)))?;
    
    let hash = hasher.squeeze()?;
    println!("Hash: {}", hash);
    
    // Hash primitive types
    hasher.update_primitive(RustInput::U64(123))?;
    hasher.update_primitive(RustInput::from_string_slice("hello"))?;
    
    let hash2 = hasher.squeeze()?;
    println!("Primitive hash: {}", hash2);
    
    Ok(())
}