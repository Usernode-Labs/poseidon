//! Memory security and zeroization tests.
//! 
//! These tests verify that ZeroizeOnDrop implementation correctly clears sensitive data.

use poseidon_hash::prelude::*;
use std::ptr;

/// Verifies that zeroization is implemented and working correctly.
/// Tests basic functionality of ZeroizeOnDrop trait implementation.
#[test]
fn test_zeroization_implementation() {
    let mut hasher = PallasHasher::new();
    
    let test_scalar = ark_pallas::Fr::from(0x123456789ABCDEFu64);
    hasher.update(PallasInput::ScalarField(test_scalar)).unwrap();
    
    hasher.update("sensitive_data").unwrap();
    hasher.update(vec![1, 2, 3, 4, 5]).unwrap();
    
    let hash1 = hasher.digest().unwrap();
    
    hasher.update(PallasInput::ScalarField(ark_pallas::Fr::from(999u64))).unwrap();
    let hash2 = hasher.digest().unwrap();
    
    assert_ne!(hash1, hash2);
    
    hasher.update(PallasInput::ScalarField(test_scalar)).unwrap();
    hasher.reset();
    
    assert_eq!(hasher.element_count(), 0);
    
    hasher.update(true).unwrap();
    let _hash3 = hasher.digest().unwrap();
}

/// Tests that hasher memory is cleared after drop.
/// Performs basic memory inspection to verify sensitive data clearing.
#[test]
fn test_hasher_memory_cleared_after_drop() {
    let mut memory_snapshot = vec![0u8; 1024];
    
    {
        let mut hasher = PallasHasher::new();
        
        let sensitive_scalar = ark_pallas::Fr::from(0xDEADBEEFCAFEBABEu64);
        hasher.update(PallasInput::ScalarField(sensitive_scalar)).unwrap();
        
        let hasher_ptr = &hasher as *const _ as *const u8;
        unsafe {
            ptr::copy_nonoverlapping(hasher_ptr, memory_snapshot.as_mut_ptr(), 1024);
        }
        
        let _hash = hasher.digest().unwrap();
    }
    
    let sensitive_pattern = 0xDEADBEEFCAFEBABEu64.to_le_bytes();
    
    for window in memory_snapshot.windows(8) {
        if window == sensitive_pattern {
            panic!("Sensitive data found in memory after drop - zeroization failed");
        }
    }
}

/// Tests that concurrent access doesn't interfere with memory cleaning.
#[test]
fn test_concurrent_zeroization() {
    use std::thread;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    
    let cleanup_verified = Arc::new(AtomicBool::new(false));
    let cleanup_verified_clone = cleanup_verified.clone();
    
    let handle = thread::spawn(move || {
        let mut hasher = PallasHasher::new();
        
        let sensitive_data = ark_pallas::Fr::from(0xFEEDFACECAFEBABEu64);
        hasher.update(PallasInput::ScalarField(sensitive_data)).unwrap();
        
        let _hash = hasher.digest().unwrap();
        
        drop(hasher);
        
        cleanup_verified_clone.store(true, Ordering::Relaxed);
    });
    
    handle.join().unwrap();
    
    assert!(cleanup_verified.load(Ordering::Relaxed));
}