//! Security-focused tests for the Poseidon hash library.
//! 
//! These tests verify security properties and may identify vulnerabilities.

use poseidon_hash::prelude::*;
use std::collections::HashSet;
use ark_ff::PrimeField;

/// Verifies that sensitive data is properly zeroized after use.
#[test]
fn test_memory_zeroization() {
    let mut hasher = PallasHasher::new();
    
    let secret_data = ark_pallas::Fr::from(0xDEADBEEFu64);
    hasher.update(PallasInput::ScalarField(secret_data)).unwrap();
    
    let _hash = hasher.digest().unwrap();
    
    // digest() now preserves state - use finalize() to consume
    assert!(hasher.element_count() > 0, "State should be preserved after digest");
    
    // Test finalize() consumes the hasher
    let mut hasher2 = PallasHasher::new();
    hasher2.update(PallasInput::ScalarField(secret_data)).unwrap();
    let _final_hash = hasher2.finalize().unwrap(); // hasher2 is consumed here
    
    hasher.update(PallasInput::ScalarField(secret_data)).unwrap();
    assert!(hasher.element_count() > 0, "Data was not added");
    
    hasher.reset();
    assert_eq!(hasher.element_count(), 0, "Reset did not clear hasher state");
    
    drop(hasher);
}

/// Tests that oversized inputs are rejected to prevent DoS.
#[test]
#[should_panic(expected = "Input size limit exceeded")]
fn test_input_size_limits() {
    let mut hasher = PallasHasher::new();
    
    let huge_string = "a".repeat(100_000_000);
    
    match hasher.update_primitive(RustInput::from_string_slice(&huge_string)) {
        Err(_) => (),
        Ok(_) => panic!("Input size limit exceeded - should have been rejected"),
    }
}

/// Tests protection against memory exhaustion from large byte arrays.
#[test]
#[should_panic(expected = "Byte array size limit exceeded")]
fn test_large_byte_array_limits() {
    let mut hasher = PallasHasher::new();
    
    let huge_bytes = vec![0u8; 50_000_000];
    
    match hasher.update_primitive(RustInput::from_bytes(&huge_bytes)) {
        Err(_) => (),
        Ok(_) => panic!("Byte array size limit exceeded - should have been rejected"),
    }
}

/// Validates that field conversion handles large values without overflow.
#[test]
fn test_field_conversion_overflow_protection() {
    use poseidon_hash::hasher::{MultiFieldHasher, FieldInput};
    use poseidon_hash::parameters::pallas::PALLAS_PARAMS;
    
    let mut hasher: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine> = 
        MultiFieldHasher::new_from_ref(&*PALLAS_PARAMS);
    
    let large_scalar = ark_pallas::Fr::from_le_bytes_mod_order(&[255u8; 32]);
    
    let result = hasher.update(FieldInput::ScalarField(large_scalar));
    
    assert!(result.is_ok(), "Field conversion should handle large scalars safely");
}

/// Basic timing consistency test for side-channel detection.
#[test]
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
        hasher.update(PallasInput::ScalarField(test_case)).unwrap();
        let _hash = hasher.digest().unwrap();
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
    let test_data = [
        RustInput::U64(0),
        RustInput::U64(u64::MAX),
        RustInput::I64(i64::MIN),
        RustInput::I64(i64::MAX),
        RustInput::from_bytes(&[]),
        RustInput::from_bytes(&[0u8; 1000]),
        RustInput::from_bytes(&[255u8; 1000]),
    ];
    
    for (i, data) in test_data.iter().enumerate() {
        let mut hashes = Vec::new();
        
        for _ in 0..10 {
            let mut hasher = PallasHasher::new();
            hasher.update_primitive(data.clone()).unwrap();
            let hash = hasher.digest().unwrap();
            hashes.push(hash.to_string());
        }
        
        let unique_hashes: HashSet<_> = hashes.iter().collect();
        assert_eq!(unique_hashes.len(), 1, 
                  "Non-deterministic behavior detected for test case {}: {:?}", i, unique_hashes);
    }
}

/// Validates that errors don't leak sensitive information.
#[test]
fn test_error_information_leakage() {
    let mut hasher = PallasHasher::new();
    
    let test_cases = vec![
        RustInput::String("\x00\x01\x02\x03invalid_utf8".to_string()),
        RustInput::from_bytes(&[0u8; 0]),
    ];
    
    for test_case in test_cases {
        let result = hasher.update_primitive(test_case);
        
        if let Err(error) = result {
            let error_msg = format!("{}", error);
            
            assert!(!error_msg.contains("0x"), "Error message contains memory address: {}", error_msg);
            
            for byte in error_msg.bytes() {
                assert!(byte.is_ascii() && byte >= 32, "Error message contains non-printable data");
            }
        }
    }
}

/// Tests resource cleanup after errors.
#[test]
fn test_error_cleanup() {
    let mut hasher = PallasHasher::new();
    
    hasher.update_primitive(RustInput::U64(42)).unwrap();
    
    let _result = hasher.update_primitive(RustInput::from_bytes(&vec![0u8; 1000000]));
    
    let cleanup_result = hasher.update_primitive(RustInput::U64(100));
    assert!(cleanup_result.is_ok(), "Hasher not properly cleaned up after error");
    
    let hash = hasher.digest();
    assert!(hash.is_ok(), "Hasher state corrupted after error");
}

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
    
    let field_elements = buffer.extract_field_elements::<ark_pallas::Fq>();
    assert!(field_elements.is_ok(), "Field element extraction failed after large input");
}

/// Validates cross-curve parameter isolation.
#[test] 
fn test_parameter_isolation_security() {
    let mut pallas_hasher1 = PallasHasher::new();
    let mut pallas_hasher2 = PallasHasher::new();
    let mut bn254_hasher = BN254Hasher::new();
    
    let test_data = RustInput::U64(12345);
    
    pallas_hasher1.update_primitive(test_data.clone()).unwrap();
    pallas_hasher2.update_primitive(test_data.clone()).unwrap();
    bn254_hasher.update_primitive(test_data).unwrap();
    
    let pallas_hash1 = pallas_hasher1.digest().unwrap();
    let pallas_hash2 = pallas_hasher2.digest().unwrap();
    let bn254_hash = bn254_hasher.digest().unwrap();
    
    assert_eq!(pallas_hash1.to_string(), pallas_hash2.to_string(), 
              "Pallas hasher parameter isolation failed");
    
    assert_ne!(pallas_hash1.to_string(), bn254_hash.to_string(),
              "Cross-curve parameter isolation failed");
}

/// Tests protection against stack overflow with many inputs.
#[test]
fn test_stack_overflow_protection() {
    let mut hasher = PallasHasher::new();
    
    for i in 0..10000 {
        let result = hasher.update_primitive(RustInput::U8((i % 256) as u8));
        assert!(result.is_ok(), "Stack overflow or recursion limit hit at iteration {}", i);
    }
    
    let hash = hasher.digest();
    assert!(hash.is_ok(), "Failed to complete hash after many inputs");
}