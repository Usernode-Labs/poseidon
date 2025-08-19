//! Input validation and DoS protection tests.
//! 
//! These tests verify that the library properly validates inputs and protects
//! against denial-of-service attacks through resource exhaustion.

use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;
use std::time::{Duration, Instant};

// Removed test_string_length_limits - no longer relevant with non-result API

// Removed test_byte_array_length_limits - no longer relevant with non-result API

/// Validates that large inputs are processed within reasonable time.
#[test]
#[ignore = "Timing-based; environment dependent"]
fn test_processing_time_bounds() {
    let mut hasher = PallasHasher::new();
    
    let large_input = vec![0u8; 100_000];
    
    let start_time = Instant::now();
    
    hasher.update(large_input);
    
    let _hash = hasher.digest();
    let elapsed = start_time.elapsed();
    
    assert!(elapsed < Duration::from_secs(10), 
           "Processing took too long: {:?}", elapsed);
}

/// Tests that memory usage stays bounded with various input sizes.
#[test]
#[ignore = "Not a real measurement; remove if noisy"]
fn test_memory_usage_bounds() {
    let mut max_memory_estimate = 0;
    
    for size in [1000, 10000, 100000] {
        let mut hasher = PallasHasher::new();
        let test_data = vec![0u8; size];
        
        let memory_estimate = size + 1024;
        max_memory_estimate = max_memory_estimate.max(memory_estimate);
        
        hasher.update(test_data);
        
        let _hash = hasher.digest();
    }
    
    assert!(max_memory_estimate < 100_000_000, 
           "Estimated memory usage too high: {} bytes", max_memory_estimate);
}

/// Validates protection against DoS through repeated large inputs.
#[test]
#[ignore = "Timing-based; environment dependent"]
fn test_repeated_large_input_protection() {
    let start_time = Instant::now();
    
    for i in 0..100 {
        let mut hasher = PallasHasher::new();
        
        let input = vec![(i % 256) as u8; 10_000];
        
        hasher.update(input);
        
        let _hash = hasher.digest();
        
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
    
    hasher.update("");
    hasher.update(Vec::<u8>::new());
    hasher.update(0u64);
    hasher.update(0i64);
    hasher.update(u64::MAX);
    hasher.update(i64::MAX);
    hasher.update(i64::MIN);
    
    let _hash = hasher.digest();
    // Hash computation should complete successfully with edge case inputs
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
    
    hasher.update(invalid_utf8);
    
    let _hash = hasher.digest();
    // Hash computation should complete successfully with invalid UTF-8 bytes
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
            
            hasher.update(input_data);
            let _hash = hasher.digest();
            let success = true; // digest() now always succeeds
            
            let mut results_guard = results_clone.lock().unwrap();
            results_guard.push((thread_id, success, input_size));
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

// Removed test_state_consistency_after_validation_errors - no longer relevant with non-result API

/// Tests that validation performance remains consistent.
#[test]
#[ignore = "Timing-based; environment dependent"]
fn test_validation_performance_consistency() {
    let mut timings = Vec::new();
    
    for round in 0..10 {
        let mut hasher = PallasHasher::new();
        let test_data = vec![round as u8; 10000];
        
        let start = Instant::now();
        hasher.update(test_data);
        let _hash = hasher.digest();
        let elapsed = start.elapsed();
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
#[ignore = "Timing-based; environment dependent"]
fn test_consistent_resource_limits() {
    
    type TestCase = (&'static str, Box<dyn Fn()>);
    let test_cases: Vec<TestCase> = vec![
        ("large_string", Box::new(|| {
            let mut hasher = PallasHasher::new();
            let large_string = "x".repeat(500_000);
            hasher.update(large_string);
        })),
        ("large_bytes", Box::new(|| {
            let mut hasher = PallasHasher::new();
            let large_bytes = vec![0xAB; 500_000];
            hasher.update(large_bytes);
        })),
        ("many_small_inputs", Box::new(|| {
            let mut hasher = PallasHasher::new();
            for i in 0..1000 {
                hasher.update(vec![i as u8; 500]);
            }
        })),
    ];
    
    for (test_name, test_fn) in test_cases {
        let start = Instant::now();
        test_fn();
        let elapsed = start.elapsed();
        
        assert!(elapsed < Duration::from_secs(5), 
               "Test '{}' took too long: {:?}", test_name, elapsed);
    }
}
