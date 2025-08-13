//! Basic usage example for the Poseidon hash library.

use poseidon_hash::prelude::*;
use ark_ec::AffineRepr;

fn main() {
    println!("🎯 Poseidon Hash Library - Basic Usage\n");
    
    // Create a hasher for the Pallas curve
    let mut hasher = PallasHasher::new();
    
    // Create some test data
    let scalar1 = ark_pallas::Fr::from(12345u64);
    let scalar2 = ark_pallas::Fr::from(67890u64);
    let base_element = ark_pallas::Fq::from(11111u64);
    
    // Generate a curve point
    let generator = ark_pallas::Affine::generator();
    let point = generator;
    
    println!("📝 Absorbing different field types:");
    
    // Update with scalar field elements
    hasher.update(PallasInput::ScalarField(scalar1));
    println!("  • Updated with scalar field element: {}", scalar1);
    
    hasher.update(PallasInput::ScalarField(scalar2));
    println!("  • Updated with scalar field element: {}", scalar2);
    
    // Update with base field element
    hasher.update(PallasInput::BaseField(base_element));
    println!("  • Updated with base field element: {}", base_element);
    
    // Update with curve point
    hasher.update(PallasInput::CurvePoint(point));
    println!("  • Absorbed curve point (generator)");
    
    // Compute the hash
    let hash = hasher.squeeze();
    println!("\n🔥 Final hash: {}", hash);
    
    // Demonstrate reusing the hasher
    println!("\n♻️  Reusing the hasher:");
    hasher.update(PallasInput::ScalarField(scalar1));
    hasher.update(PallasInput::ScalarField(scalar2));
    let hash2 = hasher.squeeze();
    println!("  • Hash of just two scalars: {}", hash2);
    
    // Verify hashes are different
    if hash != hash2 {
        println!("\n✅ Success: Different inputs produce different hashes!");
    }
}