//! Side-channel resistance tests.
//! 
//! These tests attempt to detect potential side-channel vulnerabilities
//! through timing analysis and other observable behaviors.

use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;
use std::time::{Duration, Instant};
use ark_ff::PrimeField;

/// Tests timing consistency across different field element values.
/// Checks for timing leaks that could reveal information about processed data.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_timing_consistency_field_elements() {
    let test_cases = vec![
        ark_pallas::Fr::from(0u64),
        ark_pallas::Fr::from(1u64),
        ark_pallas::Fr::from(u64::MAX),
        ark_pallas::Fr::from_le_bytes_mod_order(&[255u8; 32]),
        ark_pallas::Fr::from_le_bytes_mod_order(&[0xAA; 32]),
    ];
    
    let mut timings = Vec::new();
    const NUM_ROUNDS: usize = 100;
    
    for test_case in &test_cases {
        let mut round_timings = Vec::new();
        
        for _ in 0..NUM_ROUNDS {
            let mut hasher = PallasHasher::new();
            
            let start = Instant::now();
            hasher.update(PallasInput::ScalarField(*test_case));
            let _hash = hasher.digest();
            let elapsed = start.elapsed();
            
            round_timings.push(elapsed);
        }
        
        timings.push(round_timings);
    }
    
    analyze_timing_consistency(&timings, "field_elements");
}

/// Tests timing behavior with different input sizes.
/// Ensures processing time scales appropriately.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_timing_consistency_input_sizes() {
    let input_sizes = vec![1, 10, 100, 1000, 10000];
    let mut timings = Vec::new();
    const NUM_ROUNDS: usize = 50;
    
    for &size in &input_sizes {
        let mut round_timings = Vec::new();
        let test_data = vec![0x42u8; size];
        
        for _ in 0..NUM_ROUNDS {
            let mut hasher = PallasHasher::new();
            
            let start = Instant::now();
            hasher.update(test_data.clone());
            let _hash = hasher.digest();
            let elapsed = start.elapsed();
            
            round_timings.push(elapsed);
        }
        
        timings.push(round_timings);
    }
    
    analyze_timing_consistency(&timings, "input_sizes");
}

/// Tests for timing differences based on data patterns.
/// Different bit patterns shouldn't cause timing variations.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_timing_consistency_data_patterns() {
    let patterns = vec![
        vec![0u8; 1000],
        vec![0xFFu8; 1000],
        vec![0x55u8; 1000],
        vec![0xAAu8; 1000],
        (0..1000).map(|i| (i % 256) as u8).collect(),
    ];
    
    let mut timings = Vec::new();
    const NUM_ROUNDS: usize = 50;
    
    for pattern_data in &patterns {
        let mut round_timings = Vec::new();
        
        for _ in 0..NUM_ROUNDS {
            let mut hasher = PallasHasher::new();
            
            let start = Instant::now();
            hasher.update(pattern_data.clone());
            let _hash = hasher.digest();
            let elapsed = start.elapsed();
            
            round_timings.push(elapsed);
        }
        
        timings.push(round_timings);
    }
    
    analyze_timing_consistency(&timings, "data_patterns");
}

/// Tests field conversion timing for side-channel leaks.
/// Large and small field values should take similar time to process.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_field_conversion_timing() {
    use poseidon_hash::hasher::{MultiFieldHasher, FieldInput};
    use poseidon_hash::parameters::pallas::PALLAS_PARAMS;
    
    let test_scalars = vec![
        ark_pallas::Fr::from(1u64),
        ark_pallas::Fr::from(u64::MAX),
        ark_pallas::Fr::from_le_bytes_mod_order(&[255u8; 32]),
    ];
    
    let mut timings = Vec::new();
    const NUM_ROUNDS: usize = 100;
    
    for test_scalar in &test_scalars {
        let mut round_timings = Vec::new();
        
        for _ in 0..NUM_ROUNDS {
            let mut hasher: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine> = 
                MultiFieldHasher::new_from_ref(&*PALLAS_PARAMS);
            
            let start = Instant::now();
            hasher.update(FieldInput::ScalarField(*test_scalar));
            let _hash = hasher.digest();
            let elapsed = start.elapsed();
            
            round_timings.push(elapsed);
        }
        
        timings.push(round_timings);
    }
    
    analyze_timing_consistency(&timings, "field_conversion");
}

/// Tests timing consistency across different curve types.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_cross_curve_timing_consistency() {
    let test_data = vec![0x42u8; 1000];
    let mut all_timings = Vec::new();
    const NUM_ROUNDS: usize = 50;
    
    let mut pallas_timings = Vec::new();
    for _ in 0..NUM_ROUNDS {
        let mut hasher = PallasHasher::new();
        let start = Instant::now();
        hasher.update(test_data.clone());
        let _hash = hasher.digest();
        pallas_timings.push(start.elapsed());
    }
    all_timings.push(pallas_timings);
    
    let mut bn254_timings = Vec::new();
    for _ in 0..NUM_ROUNDS {
        let mut hasher = BN254Hasher::new();
        let start = Instant::now();
        hasher.update(test_data.clone());
        let _hash = hasher.digest();
        bn254_timings.push(start.elapsed());
    }
    all_timings.push(bn254_timings);
    
    let mut bls381_timings = Vec::new();
    for _ in 0..NUM_ROUNDS {
        let mut hasher = BLS12_381Hasher::new();
        let start = Instant::now();
        hasher.update(test_data.clone());
        let _hash = hasher.digest();
        bls381_timings.push(start.elapsed());
    }
    all_timings.push(bls381_timings);
    
    analyze_timing_consistency(&all_timings, "cross_curve");
}

/// Tests for cache timing effects.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_cache_timing_effects() {
    const NUM_ROUNDS: usize = 100;
    let test_data = vec![0x42u8; 4096];
    
    let mut cold_cache_timings = Vec::new();
    let mut warm_cache_timings = Vec::new();
    
    for round in 0..NUM_ROUNDS {
        let mut hasher = PallasHasher::new();
        
        let start = Instant::now();
        hasher.update(test_data.clone());
        let _hash = hasher.digest();
        let elapsed = start.elapsed();
        
        if round == 0 {
            cold_cache_timings.push(elapsed);
        } else {
            warm_cache_timings.push(elapsed);
        }
    }
    
    let cold_avg = average_duration(&cold_cache_timings);
    let warm_avg = average_duration(&warm_cache_timings);
    
    let cache_ratio = cold_avg.as_nanos() as f64 / warm_avg.as_nanos() as f64;
    assert!(cache_ratio < 10.0, "Significant cache timing effect detected: {:.2}x", cache_ratio);
}

/// Tests branch prediction effects with predictable vs unpredictable data.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_branch_prediction_effects() {
    const NUM_ROUNDS: usize = 100;
    const DATA_SIZE: usize = 1000;
    
    let predictable_data = vec![0u8; DATA_SIZE];
    
    let mut unpredictable_data = Vec::with_capacity(DATA_SIZE);
    let mut seed = 0x12345678u32;
    for _ in 0..DATA_SIZE {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        unpredictable_data.push((seed >> 24) as u8);
    }
    
    let mut predictable_timings = Vec::new();
    let mut unpredictable_timings = Vec::new();
    
    for _ in 0..NUM_ROUNDS {
        let mut hasher = PallasHasher::new();
        let start = Instant::now();
        hasher.update(predictable_data.clone());
        let _hash = hasher.digest();
        predictable_timings.push(start.elapsed());
    }
    
    for _ in 0..NUM_ROUNDS {
        let mut hasher = PallasHasher::new();
        let start = Instant::now();
        hasher.update(unpredictable_data.clone());
        let _hash = hasher.digest();
        unpredictable_timings.push(start.elapsed());
    }
    
    let predictable_avg = average_duration(&predictable_timings);
    let unpredictable_avg = average_duration(&unpredictable_timings);
    
    let timing_ratio = unpredictable_avg.as_nanos() as f64 / predictable_avg.as_nanos() as f64;
    assert!((0.5..=2.0).contains(&timing_ratio), 
            "Branch prediction effects detected: {:.2}x", timing_ratio);
}

/// Tests memory access patterns for timing leaks.
#[test]
#[ignore = "Strict timing test - run with --ignored flag"]
fn test_memory_access_patterns() {
    let test_cases = vec![
        vec![0x11u8; 16],
        vec![0x22u8; 32],
        vec![0x33u8; 64],
        vec![0x44u8; 17],
        vec![0x55u8; 33],
        create_sparse_pattern(1000),
    ];
    
    let mut timings = Vec::new();
    const NUM_ROUNDS: usize = 50;
    
    for test_data in &test_cases {
        let mut round_timings = Vec::new();
        
        for _ in 0..NUM_ROUNDS {
            let mut hasher = PallasHasher::new();
            
            let start = Instant::now();
            hasher.update(test_data.clone());
            let _hash = hasher.digest();
            let elapsed = start.elapsed();
            
            round_timings.push(elapsed);
        }
        
        timings.push(round_timings);
    }
    
    analyze_timing_consistency(&timings, "memory_access_patterns");
}

// Helper functions

fn average_duration(durations: &[Duration]) -> Duration {
    if durations.is_empty() {
        return Duration::from_nanos(0);
    }
    
    let total_nanos: u128 = durations.iter().map(|d| d.as_nanos()).sum();
    Duration::from_nanos((total_nanos / durations.len() as u128) as u64)
}

fn standard_deviation_duration(durations: &[Duration]) -> f64 {
    if durations.len() < 2 {
        return 0.0;
    }
    
    let avg = average_duration(durations);
    let avg_nanos = avg.as_nanos() as f64;
    
    let variance: f64 = durations
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - avg_nanos;
            diff * diff
        })
        .sum::<f64>() / (durations.len() - 1) as f64;
    
    variance.sqrt()
}

fn analyze_timing_consistency(all_timings: &[Vec<Duration>], test_name: &str) {
    let mut max_coefficient_of_variation = 0.0f64;
    
    for timings in all_timings.iter() {
        let avg = average_duration(timings);
        let std_dev = standard_deviation_duration(timings);
        
        let cv = if avg.as_nanos() > 0 {
            std_dev / avg.as_nanos() as f64
        } else {
            0.0
        };
        
        max_coefficient_of_variation = max_coefficient_of_variation.max(cv);
    }
    
    if all_timings.len() > 1 {
        let avg_times: Vec<Duration> = all_timings.iter().map(|t| average_duration(t)).collect();
        let min_avg = avg_times.iter().min();
        let max_avg = avg_times.iter().max();
        
        let ratio = max_avg.unwrap().as_nanos() as f64 / min_avg.unwrap().as_nanos() as f64;
        
        assert!(ratio < 5.0, 
                "High timing variance in {}: {:.2}x difference", test_name, ratio);
    }
    
    assert!(max_coefficient_of_variation < 0.5, 
            "High timing variability in {}: CV={:.3}", test_name, max_coefficient_of_variation);
}

fn create_sparse_pattern(size: usize) -> Vec<u8> {
    let mut pattern = vec![0u8; size];
    
    for i in (0..size).step_by(64) {
        pattern[i] = 0xFF;
    }
    
    pattern
}
