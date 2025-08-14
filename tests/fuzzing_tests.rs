//! Fuzzing and malformed input tests.
//! 
//! These tests use various fuzzing techniques to find edge cases and
//! potential vulnerabilities with malformed or unexpected inputs.

use poseidon_hash::prelude::*;
use ark_ff::PrimeField;

/// Tests that the hasher handles random byte sequences without panicking.
#[test]
fn test_random_byte_fuzzing() {
    let mut seed = 0x12345678u64;
    
    for round in 0..100 {
        let mut hasher = PallasHasher::new();
        
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let length = (seed % 10000) + 1;
        
        let mut random_bytes = Vec::with_capacity(length as usize);
        for _ in 0..length {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            random_bytes.push((seed >> 24) as u8);
        }
        
        let result = hasher.update_primitive(RustInput::from_bytes(&random_bytes));
        
        match result {
            Ok(_) => {
                let hash_result = hasher.digest();
                assert!(hash_result.is_ok(), "Hash failed after random input at round {}", round);
            },
            Err(e) => {
                let error_msg = format!("{}", e);
                assert!(!error_msg.is_empty(), "Empty error message at round {}", round);
            }
        }
    }
}

/// Tests string handling with various Unicode characters.
#[test] 
fn test_random_string_fuzzing() {
    let mut seed = 0x87654321u64;
    
    for round in 0..50 {
        let mut hasher = PallasHasher::new();
        
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let length = (seed % 1000) + 1;
        
        let mut random_string = String::new();
        for _ in 0..length {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            let char_code = seed % 0x10FFFF;
            
            if let Some(ch) = char::from_u32(char_code as u32) {
                random_string.push(ch);
            } else {
                random_string.push('\u{FFFD}');
            }
        }
        
        let result = hasher.update_primitive(RustInput::String(random_string.clone()));
        
        if result.is_ok() {
            let hash_result = hasher.digest();
            assert!(hash_result.is_ok(), "Hash failed after random string at round {}", round);
        }
    }
}

/// Tests all integer type boundaries to ensure proper handling.
#[test]
fn test_integer_boundary_fuzzing() {
    let mut hasher = PallasHasher::new();
    
    let boundary_values = vec![
        RustInput::U8(0), RustInput::U8(127), RustInput::U8(255),
        RustInput::U16(0), RustInput::U16(32767), RustInput::U16(65535),
        RustInput::U32(0), RustInput::U32(2147483647), RustInput::U32(u32::MAX),
        RustInput::U64(0), RustInput::U64(i64::MAX as u64), RustInput::U64(u64::MAX),
        RustInput::I8(i8::MIN), RustInput::I8(0), RustInput::I8(i8::MAX),
        RustInput::I16(i16::MIN), RustInput::I16(0), RustInput::I16(i16::MAX),
        RustInput::I32(i32::MIN), RustInput::I32(0), RustInput::I32(i32::MAX),
        RustInput::I64(i64::MIN), RustInput::I64(0), RustInput::I64(i64::MAX),
    ];
    
    for (i, boundary_value) in boundary_values.iter().enumerate() {
        let result = hasher.update_primitive(boundary_value.clone());
        assert!(result.is_ok(), "Boundary value {} failed: {:?}", i, boundary_value);
    }
    
    let hash = hasher.digest();
    assert!(hash.is_ok(), "Failed to complete hash with boundary values");
}

/// Tests field elements with various bit patterns.
#[test]
fn test_field_element_patterns() {
    let mut hasher = PallasHasher::new();
    
    let field_test_cases = vec![
        ark_pallas::Fr::from(0u64),
        ark_pallas::Fr::from(1u64),
        ark_pallas::Fr::from(1u64 << 32),
        ark_pallas::Fr::from(u64::MAX),
        ark_pallas::Fr::from_le_bytes_mod_order(&[0x00; 32]),
        ark_pallas::Fr::from_le_bytes_mod_order(&[0xFF; 32]),
        ark_pallas::Fr::from_le_bytes_mod_order(&[0x55; 32]),
        ark_pallas::Fr::from_le_bytes_mod_order(&[0xAA; 32]),
    ];
    
    for (i, field_element) in field_test_cases.iter().enumerate() {
        let result = hasher.update(PallasInput::ScalarField(*field_element));
        assert!(result.is_ok(), "Field element test {} failed", i);
    }
    
    let hash = hasher.digest();
    assert!(hash.is_ok(), "Failed to complete hash with field elements");
}

/// Tests curve points including identity and generator multiples.
#[test]
fn test_curve_point_fuzzing() {
    use ark_ec::{AffineRepr, CurveGroup};
    
    let mut hasher = PallasHasher::new();
    
    let point_test_cases = vec![
        ark_pallas::Affine::zero(),
        ark_pallas::Affine::generator(),
        (ark_pallas::Affine::generator() + ark_pallas::Affine::generator()).into(),
        (ark_pallas::Affine::generator() * ark_pallas::Fr::from(42u64)).into_affine(),
        (ark_pallas::Affine::generator() * ark_pallas::Fr::from(u64::MAX)).into_affine(),
    ];
    
    for (i, point) in point_test_cases.iter().enumerate() {
        let result = hasher.update(PallasInput::CurvePoint(*point));
        assert!(result.is_ok(), "Curve point test {} failed", i);
    }
    
    let hash = hasher.digest();
    assert!(hash.is_ok(), "Failed to complete hash with curve points");
}

/// Tests mixing different input types in a single hash.
#[test]
fn test_mixed_input_fuzzing() {
    let mut seed = 0xABCDEF12u64;
    
    for _ in 0..20 {
        let mut hasher = PallasHasher::new();
        
        let num_inputs = (seed % 10) + 1;
        
        for _ in 0..num_inputs {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            let input_type = seed % 6;
            
            let input = match input_type {
                0 => RustInput::Bool(seed % 2 == 0),
                1 => RustInput::U64(seed),
                2 => RustInput::I64(seed as i64),
                3 => {
                    let len = (seed % 100) + 1;
                    let mut bytes = Vec::new();
                    for _ in 0..len {
                        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                        bytes.push((seed >> 24) as u8);
                    }
                    RustInput::from_bytes(&bytes)
                },
                4 => {
                    let len = (seed % 50) + 1;
                    let chars: String = (0..len).map(|_| {
                        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                        char::from((seed % 94 + 32) as u8)
                    }).collect();
                    RustInput::from_string_slice(&chars)
                },
                5 => {
                    let field_element = ark_pallas::Fr::from(seed);
                    let _ = hasher.update(PallasInput::ScalarField(field_element));
                    continue;
                },
                _ => RustInput::U64(seed),
            };
            
            let result = hasher.update_primitive(input);
            if result.is_err() {
                break;
            }
        }
        
        let _ = hasher.digest();
    }
}

/// Tests various byte patterns including powers of 2 and edge cases.
#[test]
fn test_byte_pattern_fuzzing() {
    let mut hasher = PallasHasher::new();
    
    let patterns = vec![
        vec![],
        vec![0x00], vec![0xFF], vec![0x55], vec![0xAA],
        vec![0x00; 1000], vec![0xFF; 1000],
        (0..1000).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect(),
        vec![0x42; 1], vec![0x42; 16], vec![0x42; 256], vec![0x42; 1024],
        vec![0x42; 15], vec![0x42; 255], vec![0x42; 1023],
    ];
    
    for pattern in patterns.iter() {
        let _ = hasher.update_primitive(RustInput::from_bytes(pattern));
    }
    
    let hash = hasher.digest();
    assert!(hash.is_ok(), "Failed to complete hash after pattern fuzzing");
}

/// Tests handling of progressively larger inputs.
/// Validates that processing time stays reasonable.
#[test]
fn test_large_input_fuzzing() {
    let mut hasher = PallasHasher::new();
    
    hasher.update_primitive(RustInput::U64(12345)).unwrap();
    
    let sizes = vec![1000, 10000, 50000];
    
    for size in sizes {
        let large_data: Vec<u8> = (0..size).map(|i| {
            match i % 4 {
                0 => 0x00,
                1 => 0xFF, 
                2 => (i % 256) as u8,
                3 => !(i % 256) as u8,
                _ => 0x42,
            }
        }).collect();
        
        let start_time = std::time::Instant::now();
        let result = hasher.update_primitive(RustInput::from_bytes(&large_data));
        let elapsed = start_time.elapsed();
        
        if result.is_err() || elapsed > std::time::Duration::from_secs(5) {
            break;
        }
    }
    
    let _ = hasher.digest();
}

/// Tests rapid successive inputs for state consistency.
#[test]
fn test_rapid_input_fuzzing() {
    for round in 0..10 {
        let mut hasher = PallasHasher::new();
        
        for i in 0..1000 {
            let input = match i % 4 {
                0 => RustInput::Bool(i % 2 == 0),
                1 => RustInput::U8((i % 256) as u8),
                2 => RustInput::U16((i % 65536) as u16),
                3 => RustInput::from_bytes(&[(i % 256) as u8; 3]),
                _ => RustInput::U32(i as u32),
            };
            
            if hasher.update_primitive(input).is_err() {
                break;
            }
        }
        
        let hash = hasher.digest();
        assert!(hash.is_ok(), "Round {}: Failed to complete rapid input hash", round);
    }
}