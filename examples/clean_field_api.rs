//! Example demonstrating the clean field element API across all curves.

use poseidon_hash::prelude::*;
use ark_ec::AffineRepr;

fn main() -> Result<(), HasherError> {
    println!("🚀 Clean Field Element API Demo\n");
    
    // Pallas - clean and direct!
    println!("📝 Pallas Curve:");
    let mut pallas = PallasHasher::new();
    pallas.update(ark_pallas::Fr::from(42u64));           // Scalar field
    pallas.update(ark_pallas::Fq::from(100u64));         // Base field  
    pallas.update(ark_pallas::Affine::generator());      // Curve point
    pallas.update(123u64);                               // Primitive
    pallas.update("hello");                              // String
    let pallas_hash = pallas.digest()?;
    println!("  Hash: {}", pallas_hash);
    
    // BN254 - same clean API!
    println!("\n📝 BN254 Curve:");
    let mut bn254 = BN254Hasher::new();
    bn254.update(ark_bn254::Fr::from(42u64));            // Scalar field
    bn254.update(ark_bn254::Fq::from(100u64));          // Base field
    bn254.update(ark_bn254::G1Affine::generator());     // Curve point
    bn254.update(123u64);                                // Primitive
    bn254.update("hello");                               // String
    let bn254_hash = bn254.digest()?;
    println!("  Hash: {}", bn254_hash);
    
    // BLS12-381 - consistently clean!
    println!("\n📝 BLS12-381 Curve:");
    let mut bls381 = BLS12_381Hasher::new();
    bls381.update(ark_bls12_381::Fr::from(42u64));       // Scalar field
    bls381.update(ark_bls12_381::Fq::from(100u64));     // Base field
    bls381.update(ark_bls12_381::G1Affine::generator()); // Curve point
    bls381.update(123u64);                               // Primitive
    bls381.update("hello");                              // String
    let bls381_hash = bls381.digest()?;
    println!("  Hash: {}", bls381_hash);
    
    println!("\n✨ Notice how clean and consistent the API is across all curves!");
    println!("   No more verbose PallasInput::ScalarField(...) constructions needed!");
    
    Ok(())
}