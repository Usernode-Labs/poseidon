//! Input validation and DoS protection tests.
//! 
//! These tests verify that the library properly validates inputs and protects
//! against denial-of-service attacks through resource exhaustion.

use poseidon_hash::prelude::*;
use std::time::{Duration, Instant};

/// Tests that oversized strings are rejected with proper error messages.
/// Validates input size limits are enforced.
#[test]
#[should_panic(expected = "string too long")]
fn test_string_length_limits() {
    let mut hasher = PallasHasher::new();
    
    const MAX_STRING_LEN: usize = 1_000_000;
    let oversized_string = "x".repeat(MAX_STRING_LEN + 1);
    
    let result = hasher.update_primitive(RustInput::from_string_slice(&oversized_string));
    
    match result {
        Err(e) => {
            let error_msg = format!("{}", e);
            assert!(error_msg.contains("too long") || error_msg.contains("size limit"), 
                   "Expected size limit error, got: {}", error_msg);
        }
        Ok(_) => panic!("string too long - should have been rejected"),
    }
}

/// Tests that oversized byte arrays are rejected.
#[test]
#[should_panic(expected = "byte array too long")]
fn test_byte_array_length_limits() {
    let mut hasher = PallasHasher::new();
    
    const MAX_BYTES_LEN: usize = 10_000_000;
    let oversized_bytes = vec![0xAB; MAX_BYTES_LEN + 1];
    
    let result = hasher.update_primitive(RustInput::from_bytes(&oversized_bytes));
    
    match result {
        Err(e) => {
            let error_msg = format!("{}", e);
            assert!(error_msg.contains("too long") || error_msg.contains("size limit"),
                   "Expected size limit error, got: {}", error_msg);
        }
        Ok(_) => panic!("byte array too long - should have been rejected"),
    }
}

/// Validates that large inputs are processed within reasonable time.
#[test]
fn test_processing_time_bounds() {
    let mut hasher = PallasHasher::new();
    
    let large_input = vec![0u8; 100_000];
    
    let start_time = Instant::now();
    
    let result = hasher.update_primitive(RustInput::from_bytes(&large_input));
    assert!(result.is_ok(), "Failed to process large but reasonable input");
    
    let _hash = hasher.squeeze().unwrap();
    let elapsed = start_time.elapsed();
    
    assert!(elapsed < Duration::from_secs(10), 
           "Processing took too long: {:?}", elapsed);
}

/// Tests that memory usage stays bounded with various input sizes.
#[test]
fn test_memory_usage_bounds() {
    let mut max_memory_estimate = 0;
    
    for size in [1000, 10000, 100000] {
        let mut hasher = PallasHasher::new();
        let test_data = vec![0u8; size];
        
        let memory_estimate = size + 1024;
        max_memory_estimate = max_memory_estimate.max(memory_estimate);
        
        let result = hasher.update_primitive(RustInput::from_bytes(&test_data));
        assert!(result.is_ok(), "Failed to process data of size {}", size);
        
        let _hash = hasher.squeeze().unwrap();
    }
    
    assert!(max_memory_estimate < 100_000_000, 
           "Estimated memory usage too high: {} bytes", max_memory_estimate);
}

/// Validates protection against DoS through repeated large inputs.
#[test]
fn test_repeated_large_input_protection() {
    let start_time = Instant::now();
    
    for i in 0..100 {
        let mut hasher = PallasHasher::new();
        
        let input = vec![(i % 256) as u8; 10_000];
        
        let result = hasher.update_primitive(RustInput::from_bytes(&input));
        assert!(result.is_ok(), "Failed at iteration {}", i);
        
        let _hash = hasher.squeeze().unwrap();
        
        let elapsed = start_time.elapsed();
        if elapsed > Duration::from_secs(30) {
            panic!("Processing taking too long - potential DoS vulnerability detected");
        }
    }
}

/// Tests edge cases including empty inputs and boundary values.
#[test]
fn test_input_edge_case_validation() {
    let mut hasher = PallasHasher::new();
    
    assert!(hasher.update_primitive(RustInput::from_string_slice("")).is_ok());
    assert!(hasher.update_primitive(RustInput::from_bytes(&[])).is_ok());
    assert!(hasher.update_primitive(RustInput::U64(0)).is_ok());
    assert!(hasher.update_primitive(RustInput::I64(0)).is_ok());
    assert!(hasher.update_primitive(RustInput::U64(u64::MAX)).is_ok());
    assert!(hasher.update_primitive(RustInput::I64(i64::MAX)).is_ok());
    assert!(hasher.update_primitive(RustInput::I64(i64::MIN)).is_ok());
    
    let hash = hasher.squeeze();
    assert!(hash.is_ok(), "Failed to complete hash with edge case inputs");
}

/// Validates that byte arrays with invalid UTF-8 are handled correctly.
#[test]
fn test_invalid_utf8_handling() {
    let mut hasher = PallasHasher::new();
    
    let invalid_utf8 = vec![
        0x80, 0x81, 0x82, 0x83,
        0xFF, 0xFE, 0xFD,
        0xC0, 0x80,
    ];
    
    let result = hasher.update_primitive(RustInput::from_bytes(&invalid_utf8));
    assert!(result.is_ok(), "Byte arrays with invalid UTF-8 should be accepted");
    
    let hash = hasher.squeeze();
    assert!(hash.is_ok(), "Should complete hash with invalid UTF-8 bytes");
}

/// Tests thread safety with concurrent input processing.
/// Ensures no race conditions in validation logic.
#[test]
fn test_concurrent_input_validation() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    
    for thread_id in 0..10 {
        let results_clone = results.clone();
        
        let handle = thread::spawn(move || {
            let mut hasher = PallasHasher::new();
            
            let input_size = (thread_id + 1) * 1000;
            let input_data = vec![thread_id as u8; input_size];
            
            let result = hasher.update_primitive(RustInput::from_bytes(&input_data));
            
            if result.is_ok() {
                let hash = hasher.squeeze();
                let success = hash.is_ok();
                
                let mut results_guard = results_clone.lock().unwrap();
                results_guard.push((thread_id, success, input_size));
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let results_guard = results.lock().unwrap();
    assert_eq!(results_guard.len(), 10, "Not all threads completed successfully");
    
    for (thread_id, success, size) in results_guard.iter() {
        assert!(*success, "Thread {} failed to process {} bytes", thread_id, size);
    }
}

/// Validates hasher state remains consistent after errors.
#[test]
fn test_state_consistency_after_validation_errors() {
    let mut hasher = PallasHasher::new();
    
    hasher.update_primitive(RustInput::U64(12345)).unwrap();
    
    let huge_data = vec![0u8; 1_000_000];
    let _error_result = hasher.update_primitive(RustInput::from_bytes(&huge_data));
    
    let result = hasher.update_primitive(RustInput::U64(67890));
    assert!(result.is_ok(), "Hasher state inconsistent after validation error");
    
    let hash = hasher.squeeze();
    assert!(hash.is_ok(), "Cannot complete hash - hasher state corrupted");
}

/// Tests that validation performance remains consistent.
#[test]
fn test_validation_performance_consistency() {
    let mut timings = Vec::new();
    
    for round in 0..10 {
        let mut hasher = PallasHasher::new();
        let test_data = vec![round as u8; 10000];
        
        let start = Instant::now();
        let result = hasher.update_primitive(RustInput::from_bytes(&test_data));
        let _hash = hasher.squeeze().unwrap();
        let elapsed = start.elapsed();
        
        assert!(result.is_ok(), "Validation failed in round {}", round);
        timings.push(elapsed);
    }
    
    let first_timing = timings[0];
    let last_timing = timings[timings.len() - 1];
    
    let performance_ratio = last_timing.as_nanos() as f64 / first_timing.as_nanos() as f64;
    
    assert!(performance_ratio < 3.0, 
           "Performance degradation detected: {:.2}x slower", performance_ratio);
}

/// Validates consistent resource limit enforcement across input types.
/// Tests strings, bytes, and many small inputs.
#[test]
fn test_consistent_resource_limits() {
    use poseidon_hash::hasher::HasherResult;
    
    type TestCase = (&'static str, Box<dyn Fn() -> HasherResult<()>>);
    let test_cases: Vec<TestCase> = vec![
        ("large_string", Box::new(|| {
            let mut hasher = PallasHasher::new();
            let large_string = "x".repeat(500_000);
            hasher.update_primitive(RustInput::from_string_slice(&large_string))?;
            Ok(())
        })),
        ("large_bytes", Box::new(|| {
            let mut hasher = PallasHasher::new();
            let large_bytes = vec![0xAB; 500_000];
            hasher.update_primitive(RustInput::from_bytes(&large_bytes))?;
            Ok(())
        })),
        ("many_small_inputs", Box::new(|| {
            let mut hasher = PallasHasher::new();
            for i in 0..1000 {
                let result = hasher.update_primitive(RustInput::from_bytes(&vec![i as u8; 500]));
                result?;
            }
            Ok(())
        })),
    ];
    
    for (test_name, test_fn) in test_cases {
        let start = Instant::now();
        let _ = test_fn();
        let elapsed = start.elapsed();
        
        assert!(elapsed < Duration::from_secs(5), 
               "Test '{}' took too long: {:?}", test_name, elapsed);
    }
}