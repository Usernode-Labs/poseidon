//! Comprehensive tests for the primitive types hashing functionality.

use poseidon_hash::prelude::*;
use ark_ff::Zero;

#[test]
fn test_primitive_bool_hashing() {
    let mut hasher = PallasHasher::new();
    
    // Test single boolean
    hasher.update_primitive(RustInput::Bool(true)).expect("Failed to update with bool");
    let hash1 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, ark_pallas::Fq::zero());
    
    // Test different boolean value should produce different hash
    hasher.update_primitive(RustInput::Bool(false)).expect("Failed to update with bool");
    let hash2 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_primitive_integer_hashing() {
    let mut hasher = PallasHasher::new();
    
    // Test various integer types
    hasher.update_primitive(RustInput::U8(42)).expect("Failed to update with u8");
    hasher.update_primitive(RustInput::U16(1000)).expect("Failed to update with u16");
    hasher.update_primitive(RustInput::U32(100000)).expect("Failed to update with u32");
    hasher.update_primitive(RustInput::U64(10000000000u64)).expect("Failed to update with u64");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_primitive_signed_integer_hashing() {
    let mut hasher = PallasHasher::new();
    
    // Test signed integers including negative values
    hasher.update_primitive(RustInput::I8(-42)).expect("Failed to update with i8");
    hasher.update_primitive(RustInput::I16(-1000)).expect("Failed to update with i16");
    hasher.update_primitive(RustInput::I32(-100000)).expect("Failed to update with i32");
    hasher.update_primitive(RustInput::I64(-10000000000i64)).expect("Failed to update with i64");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash, ark_pallas::Fq::zero());
    
    // Test that positive and negative of same value produce different hashes
    let mut hasher1 = PallasHasher::new();
    let mut hasher2 = PallasHasher::new();
    
    hasher1.update_primitive(RustInput::I32(42)).expect("Failed to update with positive i32");
    hasher2.update_primitive(RustInput::I32(-42)).expect("Failed to update with negative i32");
    
    let hash1 = hasher1.squeeze().expect("Failed to squeeze hash");
    let hash2 = hasher2.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_primitive_string_hashing() {
    let mut hasher = PallasHasher::new();
    
    // Test string slice
    hasher.update_primitive(RustInput::from_string_slice("hello world")).expect("Failed to update with string slice");
    let hash1 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, ark_pallas::Fq::zero());
    
    // Test owned string
    hasher.update_primitive(RustInput::String("goodbye world".to_string())).expect("Failed to update with owned string");
    let hash2 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, hash2);
    
    // Test empty string
    hasher.update_primitive(RustInput::from_string_slice("")).expect("Failed to update with empty string");
    let hash3 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash3, ark_pallas::Fq::zero());
}

#[test]
fn test_primitive_bytes_hashing() {
    let mut hasher = PallasHasher::new();
    
    // Test byte slice
    let bytes = [1, 2, 3, 4, 5, 255, 0, 128];
    hasher.update_primitive(RustInput::from_bytes(&bytes)).expect("Failed to update with bytes");
    let hash1 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, ark_pallas::Fq::zero());
    
    // Test different byte slice should produce different hash
    let bytes2 = [1, 2, 3, 4, 5, 254, 0, 128]; // Changed one byte
    hasher.update_primitive(RustInput::from_bytes(&bytes2)).expect("Failed to update with bytes");
    let hash2 = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_primitive_enum_api() {
    let mut hasher = PallasHasher::new();
    
    // Test using the RustInput enum API
    hasher.update_primitive(RustInput::Bool(true)).expect("Failed to update with primitive bool");
    hasher.update_primitive(RustInput::U64(12345)).expect("Failed to update with primitive u64");
    hasher.update_primitive(RustInput::String("test".to_string())).expect("Failed to update with primitive string");
    hasher.update_primitive(RustInput::from_bytes(&[1, 2, 3])).expect("Failed to update with primitive bytes");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_mixed_field_and_primitive_types() {
    let mut hasher = PallasHasher::new();
    
    // Mix field elements and primitive types
    let scalar = ark_pallas::Fr::from(100u64);
    let base = ark_pallas::Fq::from(200u64);
    
    hasher.update(PallasInput::ScalarField(scalar)).expect("Failed to update with scalar field");
    hasher.update_primitive(RustInput::U64(300)).expect("Failed to update with u64");
    hasher.update(PallasInput::BaseField(base)).expect("Failed to update with base field");
    hasher.update_primitive(RustInput::from_string_slice("mixed")).expect("Failed to update with string");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash");
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_byte_efficient_vs_circuit_friendly_modes() {
    // Test both packing modes produce different results for the same input
    let mut hasher_byte_efficient = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::ByteEfficient,
        ..Default::default()
    });
    
    let mut hasher_circuit_friendly = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    });
    
    // Same input to both hashers
    hasher_byte_efficient.update_primitive(RustInput::from_bytes(&[1, 2, 3, 4, 5])).expect("Failed to update byte efficient hasher");
    hasher_circuit_friendly.update_primitive(RustInput::from_bytes(&[1, 2, 3, 4, 5])).expect("Failed to update circuit friendly hasher");
    
    let hash_byte_efficient = hasher_byte_efficient.squeeze().expect("Failed to squeeze byte efficient hash");
    let hash_circuit_friendly = hasher_circuit_friendly.squeeze().expect("Failed to squeeze circuit friendly hash");
    
    // Different packing modes should produce different hashes for the same input
    assert_ne!(hash_byte_efficient, hash_circuit_friendly);
}

#[test]
fn test_deterministic_hashing() {
    // Same inputs should always produce the same hash
    let test_inputs = [
        (RustInput::Bool(true), "bool"),
        (RustInput::U64(12345), "u64"),
        (RustInput::I64(-6789), "i64"),
        (RustInput::String("deterministic test".to_string()), "string"),
        (RustInput::from_bytes(&[1, 2, 3, 4, 5]), "bytes"),
    ];
    
    for (input, description) in &test_inputs {
        let mut hasher1 = PallasHasher::new();
        let mut hasher2 = PallasHasher::new();
        
        hasher1.update_primitive(input.clone()).unwrap_or_else(|_| panic!("Failed to update hasher1 with {}", description));
        hasher2.update_primitive(input.clone()).unwrap_or_else(|_| panic!("Failed to update hasher2 with {}", description));
        
        let hash1 = hasher1.squeeze().unwrap_or_else(|_| panic!("Failed to squeeze hash1 for {}", description));
        let hash2 = hasher2.squeeze().unwrap_or_else(|_| panic!("Failed to squeeze hash2 for {}", description));
        
        assert_eq!(hash1, hash2, "Hashes should be deterministic for {}", description);
    }
}

#[test]
fn test_hasher_reuse_after_squeeze() {
    let mut hasher = PallasHasher::new();
    
    // First hash
    hasher.update_primitive(RustInput::U64(100)).expect("Failed to update with first u64");
    let hash1 = hasher.squeeze().expect("Failed to squeeze first hash");
    
    // Second hash (hasher should be reset automatically)
    hasher.update_primitive(RustInput::U64(200)).expect("Failed to update with second u64");
    let hash2 = hasher.squeeze().expect("Failed to squeeze second hash");
    
    // Should produce different hashes
    assert_ne!(hash1, hash2);
    
    // Third hash with same input as first should match first hash
    hasher.update_primitive(RustInput::U64(100)).expect("Failed to update with third u64");
    let hash3 = hasher.squeeze().expect("Failed to squeeze third hash");
    
    assert_eq!(hash1, hash3);
}

#[test]
fn test_large_data_handling() {
    let mut hasher = PallasHasher::new();
    
    // Test with large string
    let large_string = "a".repeat(1000);
    hasher.update_primitive(RustInput::from_string_slice(&large_string)).expect("Failed to update with large string");
    
    // Test with large byte array
    let large_bytes: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    hasher.update_primitive(RustInput::from_bytes(&large_bytes)).expect("Failed to update with large bytes");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash for large data");
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_edge_cases() {
    let mut hasher = PallasHasher::new();
    
    // Test with zeros
    hasher.update_primitive(RustInput::U64(0)).expect("Failed to update with zero u64");
    hasher.update_primitive(RustInput::I64(0)).expect("Failed to update with zero i64");
    
    // Test with maximum values
    hasher.update_primitive(RustInput::U8(u8::MAX)).expect("Failed to update with max u8");
    hasher.update_primitive(RustInput::U64(u64::MAX)).expect("Failed to update with max u64");
    hasher.update_primitive(RustInput::I64(i64::MAX)).expect("Failed to update with max i64");
    hasher.update_primitive(RustInput::I64(i64::MIN)).expect("Failed to update with min i64");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash for edge cases");
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_empty_inputs() {
    let mut hasher = PallasHasher::new();
    
    // Test empty string and empty bytes
    hasher.update_primitive(RustInput::from_string_slice("")).expect("Failed to update with empty string");
    hasher.update_primitive(RustInput::from_bytes(&[])).expect("Failed to update with empty bytes");
    
    let hash = hasher.squeeze().expect("Failed to squeeze hash for empty inputs");
    // Even empty inputs should produce a non-zero hash due to length prefixes
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test] 
fn test_order_dependency() {
    // Different order of same inputs should produce different hashes
    let mut hasher1 = PallasHasher::new();
    let mut hasher2 = PallasHasher::new();
    
    // Same data in different order
    hasher1.update_primitive(RustInput::U64(1)).expect("Failed to update hasher1");
    hasher1.update_primitive(RustInput::U64(2)).expect("Failed to update hasher1");
    hasher1.update_primitive(RustInput::from_string_slice("test")).expect("Failed to update hasher1");
    
    hasher2.update_primitive(RustInput::from_string_slice("test")).expect("Failed to update hasher2");
    hasher2.update_primitive(RustInput::U64(2)).expect("Failed to update hasher2");
    hasher2.update_primitive(RustInput::U64(1)).expect("Failed to update hasher2");
    
    let hash1 = hasher1.squeeze().expect("Failed to squeeze hash1");
    let hash2 = hasher2.squeeze().expect("Failed to squeeze hash2");
    
    assert_ne!(hash1, hash2, "Different input order should produce different hashes");
}