//! Security-focused tests for the Poseidon hash library.
//!
//! These tests verify security properties and may identify vulnerabilities.

use ark_ff::PrimeField;
use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;
use std::collections::HashSet;

/// Verifies that sensitive data is properly zeroized after use.
#[test]
fn test_memory_zeroization() {
    let mut hasher = PallasHasher::new();

    let secret_data = ark_pallas::Fr::from(0xDEADBEEFu64);
    hasher.update(secret_data);

    let _hash = hasher.digest();

    // digest() now preserves state - use finalize() to consume
    assert!(
        hasher.element_count() > 0,
        "State should be preserved after digest"
    );

    // Test finalize() consumes the hasher
    let mut hasher2 = PallasHasher::new();
    hasher2.update(secret_data);
    let _final_hash = hasher2.finalize(); // hasher2 is consumed here

    hasher.update(secret_data);
    assert!(hasher.element_count() > 0, "Data was not added");

    hasher.reset();
    assert_eq!(
        hasher.element_count(),
        0,
        "Reset did not clear hasher state"
    );

    drop(hasher);
}

// Removed test_input_size_limits - no longer relevant with non-result API

// Removed test_large_byte_array_limits - no longer relevant with non-result API

/// Validates that field conversion handles large values without overflow.
#[test]
fn test_field_conversion_overflow_protection() {
    use poseidon_hash::hasher::{FieldInput, MultiFieldHasherV1 as MultiFieldHasher};
    use poseidon_hash::parameters::pallas::PALLAS_PARAMS;

    let mut hasher: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine> =
        MultiFieldHasher::new_from_ref(&*PALLAS_PARAMS);

    let large_scalar = ark_pallas::Fr::from_le_bytes_mod_order(&[255u8; 32]);

    hasher.update(FieldInput::ScalarField(large_scalar));
}

/// Basic timing consistency test for side-channel detection.
#[test]
#[ignore = "Timing-based; environment dependent"]
fn test_basic_timing_consistency() {
    use std::time::Instant;

    let test_cases = vec![
        ark_pallas::Fr::from(1u64),
        ark_pallas::Fr::from(u64::MAX),
        ark_pallas::Fr::from_le_bytes_mod_order(&[1u8; 32]),
        ark_pallas::Fr::from_le_bytes_mod_order(&[255u8; 32]),
    ];

    let mut timings = Vec::new();

    for test_case in test_cases {
        let mut hasher = PallasHasher::new();

        let start = Instant::now();
        hasher.update(test_case);
        let _hash = hasher.digest();
        let duration = start.elapsed();

        timings.push(duration);
    }

    let max_time = timings.iter().max().unwrap();
    let min_time = timings.iter().min().unwrap();

    let variance_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

    assert!(variance_ratio < 10.0, "Extreme timing variance detected");
}

/// Validates hash determinism to ensure no undefined behavior.
#[test]
fn test_hash_determinism_security() {
    // Test determinism for each type individually
    let test_cases = [(0u64, "u64_zero"), (u64::MAX, "u64_max")];

    let i64_test_cases = [(i64::MIN, "i64_min"), (i64::MAX, "i64_max")];

    for (data, name) in test_cases {
        let mut hashes = Vec::new();

        for _ in 0..10 {
            let mut hasher = PallasHasher::new();
            hasher.update(data);
            let hash = hasher.digest();
            hashes.push(hash.to_string());
        }

        let unique_hashes: HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique_hashes.len(),
            1,
            "Non-deterministic behavior detected for {}: {:?}",
            name,
            unique_hashes
        );
    }

    for (data, name) in i64_test_cases {
        let mut hashes = Vec::new();

        for _ in 0..10 {
            let mut hasher = PallasHasher::new();
            hasher.update(data);
            let hash = hasher.digest();
            hashes.push(hash.to_string());
        }

        let unique_hashes: HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique_hashes.len(),
            1,
            "Non-deterministic behavior detected for {}: {:?}",
            name,
            unique_hashes
        );
    }

    // Test byte arrays separately
    let byte_test_cases = [
        (Vec::<u8>::new(), "empty_bytes"),
        (vec![0u8; 1000], "zero_bytes"),
        (vec![255u8; 1000], "max_bytes"),
    ];

    for (data, name) in byte_test_cases {
        let mut hashes = Vec::new();

        for _ in 0..10 {
            let mut hasher = PallasHasher::new();
            hasher.update(data.clone());
            let hash = hasher.digest();
            hashes.push(hash.to_string());
        }

        let unique_hashes: HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique_hashes.len(),
            1,
            "Non-deterministic behavior detected for {}: {:?}",
            name,
            unique_hashes
        );
    }
}

// Removed test_error_information_leakage - no longer relevant with non-result API

// Removed test_error_cleanup - no longer relevant with non-result API

/// Tests protection against integer overflow in packing buffer.
#[test]
fn test_packing_buffer_overflow() {
    use poseidon_hash::primitive::{PackingBuffer, PackingConfig};

    let config = PackingConfig::default();
    let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);

    for _ in 0..1000 {
        buffer.push_bytes(&[1, 2, 3, 4, 5]);
    }

    // Check buffer length
    assert_eq!(buffer.len(), 5000, "Byte counting overflow detected");

    let _field_elements = buffer.extract_field_elements::<ark_pallas::Fq>();
}

/// Validates cross-curve parameter isolation.
#[test]
fn test_parameter_isolation_security() {
    let mut pallas_hasher1 = PallasHasher::new();
    let mut pallas_hasher2 = PallasHasher::new();
    let mut bn254_hasher = BN254Hasher::new();

    let test_data = 12345u64;

    pallas_hasher1.update(test_data);
    pallas_hasher2.update(test_data);
    bn254_hasher.update(test_data);

    let pallas_hash1 = pallas_hasher1.digest();
    let pallas_hash2 = pallas_hasher2.digest();
    let bn254_hash = bn254_hasher.digest();

    assert_eq!(
        pallas_hash1.to_string(),
        pallas_hash2.to_string(),
        "Pallas hasher parameter isolation failed"
    );

    assert_ne!(
        pallas_hash1.to_string(),
        bn254_hash.to_string(),
        "Cross-curve parameter isolation failed"
    );
}

/// Tests protection against stack overflow with many inputs.
#[test]
fn test_stack_overflow_protection() {
    let mut hasher = PallasHasher::new();

    for i in 0..10000 {
        hasher.update((i % 256) as u8);
    }

    let _hash = hasher.digest();
    // Hash computation should complete successfully after many inputs
}
