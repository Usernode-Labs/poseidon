//! Comprehensive tests for the primitive types hashing functionality.

use ark_ff::Zero;
use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;

#[test]
fn test_primitive_bool_hashing() {
    let mut hasher = PallasHasher::new();

    // Test single boolean
    hasher.update(true);
    let hash1 = hasher.digest();
    assert_ne!(hash1, ark_pallas::Fq::zero());

    // Test different boolean value should produce different hash
    hasher.update(false);
    let hash2 = hasher.digest();
    assert_ne!(hash1, hash2);
}

#[test]
fn test_primitive_integer_hashing() {
    let mut hasher = PallasHasher::new();

    // Test various integer types
    hasher.update(42u8);
    hasher.update(1000u16);
    hasher.update(100000u32);
    hasher.update(10000000000u64);

    let hash = hasher.digest();
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_primitive_signed_integer_hashing() {
    let mut hasher = PallasHasher::new();

    // Test signed integers including negative values
    hasher.update(-42i8);
    hasher.update(-1000i16);
    hasher.update(-100000i32);
    hasher.update(-10000000000i64);

    let hash = hasher.digest();
    assert_ne!(hash, ark_pallas::Fq::zero());

    // Test that positive and negative of same value produce different hashes
    let mut hasher1 = PallasHasher::new();
    let mut hasher2 = PallasHasher::new();

    hasher1.update(42i32);
    hasher2.update(-42i32);

    let hash1 = hasher1.digest();
    let hash2 = hasher2.digest();
    assert_ne!(hash1, hash2);
}

#[test]
fn test_primitive_string_hashing() {
    let mut hasher = PallasHasher::new();

    // Test string slice
    hasher.update("hello world");
    let hash1 = hasher.digest();
    assert_ne!(hash1, ark_pallas::Fq::zero());

    // Test owned string
    hasher.update("goodbye world".to_string());
    let hash2 = hasher.digest();
    assert_ne!(hash1, hash2);

    // Test empty string
    hasher.update("");
    let hash3 = hasher.digest();
    assert_ne!(hash3, ark_pallas::Fq::zero());
}

#[test]
fn test_primitive_bytes_hashing() {
    let mut hasher = PallasHasher::new();

    // Test byte slice
    let bytes = [1, 2, 3, 4, 5, 255, 0, 128];
    hasher.update(bytes.to_vec());
    let hash1 = hasher.digest();
    assert_ne!(hash1, ark_pallas::Fq::zero());

    // Test different byte slice should produce different hash
    let bytes2 = [1, 2, 3, 4, 5, 254, 0, 128]; // Changed one byte
    hasher.update(bytes2.to_vec());
    let hash2 = hasher.digest();
    assert_ne!(hash1, hash2);
}

#[test]
fn test_primitive_enum_api() {
    let mut hasher = PallasHasher::new();

    // Test using the RustInput enum API
    hasher.update(true);
    hasher.update(12345u64);
    hasher.update("test".to_string());
    hasher.update(vec![1, 2, 3]);

    let hash = hasher.digest();
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_mixed_field_and_primitive_types() {
    let mut hasher = PallasHasher::new();

    // Mix field elements and primitive types
    let scalar = ark_pallas::Fr::from(100u64);
    let base = ark_pallas::Fq::from(200u64);

    hasher.update(scalar);
    hasher.update(300u64);
    hasher.update(base);
    hasher.update("mixed");

    let hash = hasher.digest();
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
    hasher_byte_efficient.update(vec![1, 2, 3, 4, 5]);
    hasher_circuit_friendly.update(vec![1, 2, 3, 4, 5]);

    let hash_byte_efficient = hasher_byte_efficient.digest();
    let hash_circuit_friendly = hasher_circuit_friendly.digest();

    // Different packing modes should produce different hashes for the same input
    assert_ne!(hash_byte_efficient, hash_circuit_friendly);
}

// Determinism covered in dedicated determinism_tests.rs

#[test]
fn test_hasher_reuse_after_digest() {
    let mut hasher = PallasHasher::new();

    // First hash
    hasher.update(100u64);
    let hash1 = hasher.finalize();

    // Create new hasher for second hash
    let mut hasher2 = PallasHasher::new();
    hasher2.update(200u64);
    let hash2 = hasher2.finalize();

    // Should produce different hashes
    assert_ne!(hash1, hash2);

    // Third hash with same input as first should match first hash
    let mut hasher3 = PallasHasher::new();
    hasher3.update(100u64);
    let hash3 = hasher3.finalize();

    assert_eq!(hash1, hash3);
}

#[test]
fn test_large_data_handling() {
    let mut hasher = PallasHasher::new();

    // Test with large string
    let large_string = "a".repeat(1000);
    hasher.update(large_string);

    // Test with large byte array
    let large_bytes: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    hasher.update(large_bytes);

    let hash = hasher.digest();
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_edge_cases() {
    let mut hasher = PallasHasher::new();

    // Test with zeros
    hasher.update(0u64);
    hasher.update(0i64);

    // Test with maximum values
    hasher.update(u8::MAX);
    hasher.update(u64::MAX);
    hasher.update(i64::MAX);
    hasher.update(i64::MIN);

    let hash = hasher.digest();
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_empty_inputs() {
    let mut hasher = PallasHasher::new();

    // Test empty string and empty bytes
    hasher.update("");
    hasher.update(Vec::<u8>::new());

    let hash = hasher.digest();
    // Even empty inputs should produce a non-zero hash due to length prefixes
    assert_ne!(hash, ark_pallas::Fq::zero());
}

#[test]
fn test_order_dependency() {
    // Different order of same inputs should produce different hashes
    let mut hasher1 = PallasHasher::new();
    let mut hasher2 = PallasHasher::new();

    // Same data in different order
    hasher1.update(1u64);
    hasher1.update(2u64);
    hasher1.update("test");

    hasher2.update("test");
    hasher2.update(2u64);
    hasher2.update(1u64);

    let hash1 = hasher1.digest();
    let hash2 = hasher2.digest();

    assert_ne!(
        hash1, hash2,
        "Different input order should produce different hashes"
    );
}
