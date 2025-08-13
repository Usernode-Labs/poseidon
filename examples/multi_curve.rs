//! Multi-curve example demonstrating usage with different elliptic curves.

use poseidon_hash::prelude::*;
use ark_ff::PrimeField;
use ark_ec::AffineRepr;

fn main() {
    println!("🎯 Poseidon Hash Library - Multi-Curve Demo\n");
    
    // Demo 1: Pallas curve (255-bit, same size Fr and Fq)
    demo_pallas();
    
    // Demo 2: BN254 curve (254-bit, same size Fr and Fq)
    demo_bn254();
    
    // Demo 3: BLS12-381 curve (Fr=255 bits, Fq=381 bits - different sizes)
    demo_bls12_381();
    
    // Show field size comparison
    field_size_analysis();
}

fn demo_pallas() {
    println!("🔬 Demo 1: Pallas Curve");
    println!("  • Used in: Mina Protocol");
    println!("  • Field sizes: Fr=255 bits, Fq=255 bits (same size)");
    
    let mut hasher = PallasHasher::new();
    
    let scalar = ark_pallas::Fr::from(42u64);
    let base = ark_pallas::Fq::from(100u64);
    
    hasher.update(PallasInput::ScalarField(scalar)).expect("Failed to update hasher");
    hasher.update(PallasInput::BaseField(base)).expect("Failed to update hasher");
    
    let hash = hasher.squeeze().expect("Failed to compute hash");
    println!("  • Hash result: {}\n", hash.to_string().chars().take(40).collect::<String>() + "...");
}

fn demo_bn254() {
    println!("🔬 Demo 2: BN254 Curve");
    println!("  • Used in: Ethereum, zkSNARKs");
    println!("  • Field sizes: Fr=254 bits, Fq=254 bits (same size)");
    
    let mut hasher = BN254Hasher::new();
    
    let scalar = ark_bn254::Fr::from(42u64);
    let base = ark_bn254::Fq::from(100u64);
    let generator = ark_bn254::G1Affine::generator();
    
    hasher.update(BN254Input::ScalarField(scalar)).expect("Failed to update hasher");
    hasher.update(BN254Input::BaseField(base)).expect("Failed to update hasher");
    hasher.update(BN254Input::CurvePoint(generator)).expect("Failed to update hasher");
    
    let hash = hasher.squeeze().expect("Failed to compute hash");
    println!("  • Hash result: {}\n", hash.to_string().chars().take(40).collect::<String>() + "...");
}

fn demo_bls12_381() {
    println!("🔬 Demo 3: BLS12-381 Curve");
    println!("  • Used in: Ethereum 2.0, Zcash");
    println!("  • Field sizes: Fr=255 bits, Fq=381 bits (DIFFERENT sizes)");
    println!("  • Note: Fr→Fq conversion is automatic and lossless");
    
    let mut hasher = BLS12_381Hasher::new();
    
    let scalar = ark_bls12_381::Fr::from(42u64);
    let base = ark_bls12_381::Fq::from(100u64);
    
    hasher.update(BLS12_381Input::ScalarField(scalar)).expect("Failed to update hasher");
    hasher.update(BLS12_381Input::BaseField(base)).expect("Failed to update hasher");
    
    let hash = hasher.squeeze().expect("Failed to compute hash");
    println!("  • Hash result: {}\n", hash.to_string().chars().take(40).collect::<String>() + "...");
}

fn field_size_analysis() {
    println!("📊 Field Size Analysis:");
    println!("┌─────────────┬──────────┬──────────┬────────────┐");
    println!("│ Curve       │ Fr bits  │ Fq bits  │ Conversion │");
    println!("├─────────────┼──────────┼──────────┼────────────┤");
    println!("│ Pallas      │ {:8} │ {:8} │ Simple     │", 
        ark_pallas::Fr::MODULUS_BIT_SIZE, 
        ark_pallas::Fq::MODULUS_BIT_SIZE);
    println!("│ Vesta       │ {:8} │ {:8} │ Simple     │", 
        ark_vesta::Fr::MODULUS_BIT_SIZE, 
        ark_vesta::Fq::MODULUS_BIT_SIZE);
    println!("│ BN254       │ {:8} │ {:8} │ Simple     │", 
        ark_bn254::Fr::MODULUS_BIT_SIZE, 
        ark_bn254::Fq::MODULUS_BIT_SIZE);
    println!("│ BLS12-381   │ {:8} │ {:8} │ Direct     │", 
        ark_bls12_381::Fr::MODULUS_BIT_SIZE, 
        ark_bls12_381::Fq::MODULUS_BIT_SIZE);
    println!("│ BLS12-377   │ {:8} │ {:8} │ Direct     │", 
        ark_bls12_377::Fr::MODULUS_BIT_SIZE, 
        ark_bls12_377::Fq::MODULUS_BIT_SIZE);
    println!("└─────────────┴──────────┴──────────┴────────────┘");
    
    println!("\n💡 Conversion Types:");
    println!("  • Simple: Same bit size, just byte representation change");
    println!("  • Direct: Fr < Fq, direct conversion without data loss");
    println!("  • Chunking: Fr > Fq, automatic decomposition (rare)");
}