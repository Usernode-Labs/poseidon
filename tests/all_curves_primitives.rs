//! Test that all curve implementations support primitive types correctly.

use poseidon_hash::prelude::*;
use ark_ff::Zero;

#[test]
fn test_pallas_primitives() {
    let mut hasher = PallasHasher::new();
    hasher.update_primitive(RustInput::Bool(true)).expect("Failed to update");
    hasher.update_primitive(RustInput::U64(12345)).expect("Failed to update");
    let hash = hasher.squeeze().expect("Failed to squeeze");
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_vesta_primitives() {
    let mut hasher = VestaHasher::new();
    hasher.update_primitive(RustInput::Bool(false)).expect("Failed to update");
    hasher.update_primitive(RustInput::U64(67890)).expect("Failed to update");
    let hash = hasher.squeeze().expect("Failed to squeeze");
    assert_ne!(hash, ark_vesta::Fq::zero());
}

#[test]
fn test_bn254_primitives() {
    let mut hasher = BN254Hasher::new();
    hasher.update_primitive(RustInput::I32(-123)).expect("Failed to update");
    hasher.update_primitive(RustInput::from_string_slice("bn254")).expect("Failed to update");
    let hash = hasher.squeeze().expect("Failed to squeeze");
    assert_ne!(hash, ark_bn254::Fq::zero());
}

#[test]
fn test_bls12_381_primitives() {
    let mut hasher = BLS12_381Hasher::new();
    hasher.update_primitive(RustInput::U128(999999999999u128)).expect("Failed to update");
    hasher.update_primitive(RustInput::from_bytes(&[1, 2, 3, 4])).expect("Failed to update");
    let hash = hasher.squeeze().expect("Failed to squeeze");
    assert_ne!(hash, ark_bls12_381::Fq::zero());
}

#[test]
fn test_bls12_377_primitives() {
    let mut hasher = BLS12_377Hasher::new();
    hasher.update_primitive(RustInput::I64(-987654321)).expect("Failed to update");
    hasher.update_primitive(RustInput::String("bls12_377".to_string())).expect("Failed to update");
    let hash = hasher.squeeze().expect("Failed to squeeze");
    assert_ne!(hash, ark_bls12_377::Fq::zero());
}

#[test]
fn test_all_curves_with_config() {
    let circuit_config = PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    };
    
    // Test all curves with circuit-friendly config
    let mut pallas = PallasHasher::new_with_config(circuit_config);
    let mut vesta = VestaHasher::new_with_config(circuit_config);
    let mut bn254 = BN254Hasher::new_with_config(circuit_config);
    let mut bls12_381 = BLS12_381Hasher::new_with_config(circuit_config);
    let mut bls12_377 = BLS12_377Hasher::new_with_config(circuit_config);
    
    let test_bytes = &[42, 100, 255];
    
    pallas.update_primitive(RustInput::from_bytes(test_bytes)).expect("Pallas failed");
    vesta.update_primitive(RustInput::from_bytes(test_bytes)).expect("Vesta failed");
    bn254.update_primitive(RustInput::from_bytes(test_bytes)).expect("BN254 failed");
    bls12_381.update_primitive(RustInput::from_bytes(test_bytes)).expect("BLS12-381 failed");
    bls12_377.update_primitive(RustInput::from_bytes(test_bytes)).expect("BLS12-377 failed");
    
    // All should produce non-zero hashes
    assert_ne!(pallas.squeeze().expect("Pallas squeeze failed"), ark_pallas::Fq::zero());
    assert_ne!(vesta.squeeze().expect("Vesta squeeze failed"), ark_vesta::Fq::zero());
    assert_ne!(bn254.squeeze().expect("BN254 squeeze failed"), ark_bn254::Fq::zero());
    assert_ne!(bls12_381.squeeze().expect("BLS12-381 squeeze failed"), ark_bls12_381::Fq::zero());
    assert_ne!(bls12_377.squeeze().expect("BLS12-377 squeeze failed"), ark_bls12_377::Fq::zero());
}

#[test]
fn test_cross_curve_different_hashes() {
    // Same input should produce different hashes across different curves
    let input = RustInput::U64(123456789);
    
    let mut pallas = PallasHasher::new();
    let mut vesta = VestaHasher::new();
    let mut bn254 = BN254Hasher::new();
    
    pallas.update_primitive(input.clone()).expect("Pallas failed");
    vesta.update_primitive(input.clone()).expect("Vesta failed");
    bn254.update_primitive(input).expect("BN254 failed");
    
    let pallas_hash = pallas.squeeze().expect("Pallas squeeze failed");
    let vesta_hash = vesta.squeeze().expect("Vesta squeeze failed");
    let bn254_hash = bn254.squeeze().expect("BN254 squeeze failed");
    
    // Convert to string for comparison (different field types)
    let pallas_str = pallas_hash.to_string();
    let vesta_str = vesta_hash.to_string();
    let bn254_str = bn254_hash.to_string();
    
    // All hashes should be different
    assert_ne!(pallas_str, vesta_str, "Pallas and Vesta should produce different hashes");
    assert_ne!(pallas_str, bn254_str, "Pallas and BN254 should produce different hashes");
    assert_ne!(vesta_str, bn254_str, "Vesta and BN254 should produce different hashes");
}