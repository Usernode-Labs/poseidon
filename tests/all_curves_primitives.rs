//! Test that all curve implementations support primitive types correctly.

use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;
use ark_ff::Zero;

#[test]
fn test_pallas_primitives() {
    let mut hasher = PallasHasher::new();
    hasher.update(true);
    hasher.update(12345u64);
    let hash = hasher.digest();
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_vesta_primitives() {
    let mut hasher = VestaHasher::new();
    hasher.update(false);
    hasher.update(67890u64);
    let hash = hasher.digest();
    assert_ne!(hash, ark_vesta::Fq::zero());
}

#[test]
fn test_bn254_primitives() {
    let mut hasher = BN254Hasher::new();
    hasher.update(-123i32);
    hasher.update("bn254");
    let hash = hasher.digest();
    assert_ne!(hash, ark_bn254::Fq::zero());
}

#[test]
fn test_bls12_381_primitives() {
    let mut hasher = BLS12_381Hasher::new();
    hasher.update(999999999999u128);
    hasher.update(vec![1, 2, 3, 4]);
    let hash = hasher.digest();
    assert_ne!(hash, ark_bls12_381::Fq::zero());
}

#[test]
fn test_bls12_377_primitives() {
    let mut hasher = BLS12_377Hasher::new();
    hasher.update(-987654321i64);
    hasher.update("bls12_377".to_string());
    let hash = hasher.digest();
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
    
    pallas.update(test_bytes.to_vec());
    vesta.update(test_bytes.to_vec());
    bn254.update(test_bytes.to_vec());
    bls12_381.update(test_bytes.to_vec());
    bls12_377.update(test_bytes.to_vec());
    
    // All should produce non-zero hashes
    assert_ne!(pallas.digest(), ark_pallas::Fq::zero());
    assert_ne!(vesta.digest(), ark_vesta::Fq::zero());
    assert_ne!(bn254.digest(), ark_bn254::Fq::zero());
    assert_ne!(bls12_381.digest(), ark_bls12_381::Fq::zero());
    assert_ne!(bls12_377.digest(), ark_bls12_377::Fq::zero());
}

#[test]
fn test_cross_curve_different_hashes() {
    // Same input should produce different hashes across different curves
    let input = 123456789u64;
    
    let mut pallas = PallasHasher::new();
    let mut vesta = VestaHasher::new();
    let mut bn254 = BN254Hasher::new();
    
    pallas.update(input);
    vesta.update(input);
    bn254.update(input);
    
    let pallas_hash = pallas.digest();
    let vesta_hash = vesta.digest();
    let bn254_hash = bn254.digest();
    
    // Convert to string for comparison (different field types)
    let pallas_str = pallas_hash.to_string();
    let vesta_str = vesta_hash.to_string();
    let bn254_str = bn254_hash.to_string();
    
    // All hashes should be different
    assert_ne!(pallas_str, vesta_str, "Pallas and Vesta should produce different hashes");
    assert_ne!(pallas_str, bn254_str, "Pallas and BN254 should produce different hashes");
    assert_ne!(vesta_str, bn254_str, "Vesta and BN254 should produce different hashes");
}
