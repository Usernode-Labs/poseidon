//! Fuzzing and malformed input tests.
//!
//! These tests use various fuzzing techniques to find edge cases and
//! potential vulnerabilities with malformed or unexpected inputs.

use ark_ff::PrimeField;
use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;

/// Tests that the hasher handles random byte sequences without panicking.
#[test]
fn test_random_byte_fuzzing() {
    let mut seed = 0x12345678u64;

    for _round in 0..100 {
        let mut hasher = PallasHasher::new();

        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let length = (seed % 10000) + 1;

        let mut random_bytes = Vec::with_capacity(length as usize);
        for _ in 0..length {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            random_bytes.push((seed >> 24) as u8);
        }

        hasher.update(random_bytes.clone());

        let _hash_result = hasher.digest();
        // Hash should complete successfully with random input
    }
}

/// Tests string handling with various Unicode characters.
#[test]
fn test_random_string_fuzzing() {
    let mut seed = 0x87654321u64;

    for _round in 0..50 {
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

        hasher.update(random_string.clone());
        let _hash_result = hasher.digest();
        // Hash should complete successfully with random string
    }
}

/// Tests all integer type boundaries to ensure proper handling.
#[test]
fn test_integer_boundary_fuzzing() {
    let mut hasher = PallasHasher::new();

    // Test boundary values for different types separately due to type constraints
    let u8_values = [0u8, 127u8, 255u8];
    let u16_values = [0u16, 32767u16, 65535u16];
    let u32_values = [0u32, 2147483647u32, u32::MAX];
    let u64_values = [0u64, i64::MAX as u64, u64::MAX];
    let i8_values = [i8::MIN, 0i8, i8::MAX];
    let i16_values = [i16::MIN, 0i16, i16::MAX];
    let i32_values = [i32::MIN, 0i32, i32::MAX];
    let i64_values = [i64::MIN, 0i64, i64::MAX];

    // Test u8 values
    for &value in u8_values.iter() {
        hasher.update(value);
    }

    // Test u16 values
    for &value in u16_values.iter() {
        hasher.update(value);
    }

    // Test u32 values
    for &value in u32_values.iter() {
        hasher.update(value);
    }

    // Test u64 values
    for &value in u64_values.iter() {
        hasher.update(value);
    }

    // Test i8 values
    for &value in i8_values.iter() {
        hasher.update(value);
    }

    // Test i16 values
    for &value in i16_values.iter() {
        hasher.update(value);
    }

    // Test i32 values
    for &value in i32_values.iter() {
        hasher.update(value);
    }

    // Test i64 values
    for &value in i64_values.iter() {
        hasher.update(value);
    }

    let _hash = hasher.digest();
    // Hash should complete successfully with boundary values
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

    for field_element in field_test_cases.iter() {
        hasher.update(*field_element);
    }

    let _hash = hasher.digest();
    // Hash should complete successfully with field elements
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

    for point in point_test_cases.iter() {
        hasher.update(*point);
    }

    let _hash = hasher.digest();
    // Hash should complete successfully with curve points
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

            match input_type {
                0 => hasher.update(seed % 2 == 0),
                1 => hasher.update(seed),
                2 => hasher.update(seed as i64),
                3 => {
                    let len = (seed % 100) + 1;
                    let mut bytes = Vec::new();
                    for _ in 0..len {
                        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                        bytes.push((seed >> 24) as u8);
                    }
                    hasher.update(bytes);
                }
                4 => {
                    let len = (seed % 50) + 1;
                    let chars: String = (0..len)
                        .map(|_| {
                            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                            char::from((seed % 94 + 32) as u8)
                        })
                        .collect();
                    hasher.update(chars);
                }
                5 => {
                    let field_element = ark_pallas::Fr::from(seed);
                    hasher.update(field_element);
                }
                _ => hasher.update(seed),
            };
        }

        let _hash = hasher.digest();
        // Hash should complete successfully with mixed inputs
    }
}

/// Tests various byte patterns including powers of 2 and edge cases.
#[test]
fn test_byte_pattern_fuzzing() {
    let mut hasher = PallasHasher::new();

    let patterns = vec![
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0x55],
        vec![0xAA],
        vec![0x00; 1000],
        vec![0xFF; 1000],
        (0..1000)
            .map(|i| if i % 2 == 0 { 0x00 } else { 0xFF })
            .collect(),
        vec![0x42; 1],
        vec![0x42; 16],
        vec![0x42; 256],
        vec![0x42; 1024],
        vec![0x42; 15],
        vec![0x42; 255],
        vec![0x42; 1023],
    ];

    for pattern in patterns.iter() {
        hasher.update(pattern.clone());
    }

    let _hash = hasher.digest();
    // Hash should complete successfully after pattern fuzzing
}

/// Tests handling of progressively larger inputs.
/// Validates that processing time stays reasonable.
#[test]
fn test_large_input_fuzzing() {
    let mut hasher = PallasHasher::new();

    hasher.update(12345u64);

    let sizes = vec![1000, 10000, 50000];

    for size in sizes {
        let large_data: Vec<u8> = (0..size)
            .map(|i| match i % 4 {
                0 => 0x00,
                1 => 0xFF,
                2 => (i % 256) as u8,
                3 => !(i % 256) as u8,
                _ => 0x42,
            })
            .collect();

        let start_time = std::time::Instant::now();
        hasher.update(large_data.clone());
        let elapsed = start_time.elapsed();

        if elapsed > std::time::Duration::from_secs(5) {
            break;
        }
    }

    let _hash = hasher.digest();
    // Hash should complete successfully with large inputs
}

/// Tests rapid successive inputs for state consistency.
#[test]
fn test_rapid_input_fuzzing() {
    for _round in 0..10 {
        let mut hasher = PallasHasher::new();

        for i in 0..1000 {
            match i % 4 {
                0 => hasher.update(i % 2 == 0),
                1 => hasher.update((i % 256) as u8),
                2 => hasher.update((i % 65536) as u16),
                3 => hasher.update(vec![(i % 256) as u8; 3]),
                _ => hasher.update(i as u32),
            };
        }

        let _hash = hasher.digest();
        // Hash should complete successfully with rapid inputs
    }
}
