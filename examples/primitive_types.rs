//! Example demonstrating the new primitive types hashing functionality.

use poseidon_hash::prelude::*;

fn main() {
    println!("🚀 Poseidon Hash Library - Primitive Types Hashing\n");
    
    // Create a hasher with default (byte-efficient) configuration
    let mut hasher = PallasHasher::new();
    
    println!("📝 Hashing various primitive types:");
    
    // Hash different primitive types
    hasher.update_primitive(RustInput::Bool(true)).expect("Failed to update with bool");
    println!("  • Added boolean: true");
    
    hasher.update_primitive(RustInput::U64(12345)).expect("Failed to update with u64");
    println!("  • Added u64: 12345");
    
    hasher.update_primitive(RustInput::I32(-6789)).expect("Failed to update with i32");
    println!("  • Added i32: -6789");
    
    hasher.update_primitive(RustInput::from_string_slice("Hello, Poseidon!")).expect("Failed to update with string");
    println!("  • Added string: \"Hello, Poseidon!\"");
    
    hasher.update_primitive(RustInput::from_bytes(&[1, 2, 3, 4, 5, 255])).expect("Failed to update with bytes");
    println!("  • Added bytes: [1, 2, 3, 4, 5, 255]");
    
    let hash1 = hasher.digest().expect("Failed to compute hash");
    println!("\n🔥 Hash (byte-efficient mode): {}", hash1);
    
    // Demonstrate the enum-based API
    println!("\n🔧 Using the enum-based API:");
    hasher.update_primitive(RustInput::Bool(false)).expect("Failed to update with primitive");
    hasher.update_primitive(RustInput::U128(999999999999999u128)).expect("Failed to update with primitive");
    hasher.update_primitive(RustInput::String("Enum API test".to_string())).expect("Failed to update with primitive");
    
    let hash2 = hasher.digest().expect("Failed to compute hash");
    println!("Hash with enum API: {}", hash2);
    
    // Demonstrate circuit-friendly mode
    println!("\n⚡ Circuit-friendly mode (for zk-circuits):");
    let mut circuit_hasher = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    });
    
    circuit_hasher.update_primitive(RustInput::from_bytes(&[1, 2, 3, 4, 5])).expect("Failed to update circuit hasher");
    let hash3 = circuit_hasher.digest().expect("Failed to compute circuit hash");
    println!("Circuit-friendly hash: {}", hash3);
    
    // Mix field elements and primitive types
    println!("\n🌊 Mixing field elements and primitive types:");
    let scalar = ark_pallas::Fr::from(42u64);
    hasher.update(PallasInput::ScalarField(scalar)).expect("Failed to update with scalar");
    hasher.update_primitive(RustInput::U64(100)).expect("Failed to update with u64");
    hasher.update_primitive(RustInput::from_string_slice("mixed types")).expect("Failed to update with string");
    
    let hash4 = hasher.digest().expect("Failed to compute mixed hash");
    println!("Mixed hash: {}", hash4);
    
    // Demonstrate deterministic hashing
    println!("\n🔒 Deterministic hashing:");
    let mut hasher1 = PallasHasher::new();
    let mut hasher2 = PallasHasher::new();
    
    let test_data = vec![
        RustInput::Bool(true),
        RustInput::U64(123456),
        RustInput::String("deterministic".to_string()),
        RustInput::from_bytes(&[10, 20, 30]),
    ];
    
    for input in &test_data {
        hasher1.update_primitive(input.clone()).expect("Failed to update hasher1");
        hasher2.update_primitive(input.clone()).expect("Failed to update hasher2");
    }
    
    let hash_a = hasher1.digest().expect("Failed to compute deterministic hash A");
    let hash_b = hasher2.digest().expect("Failed to compute deterministic hash B");
    
    if hash_a == hash_b {
        println!("✅ Deterministic hashing works! Both hashes match: {}", hash_a);
    } else {
        println!("❌ Hash mismatch: {} vs {}", hash_a, hash_b);
    }
    
    // Performance comparison example
    println!("\n📊 Performance comparison:");
    let test_bytes = (0..1000).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    
    let start = std::time::Instant::now();
    let mut byte_efficient_hasher = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::ByteEfficient,
        ..Default::default()
    });
    byte_efficient_hasher.update_primitive(RustInput::from_bytes(&test_bytes)).expect("Failed to update byte efficient");
    let _hash_efficient = byte_efficient_hasher.digest().expect("Failed to compute efficient hash");
    let byte_efficient_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let mut circuit_friendly_hasher = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    });
    circuit_friendly_hasher.update_primitive(RustInput::from_bytes(&test_bytes)).expect("Failed to update circuit friendly");
    let _hash_circuit = circuit_friendly_hasher.digest().expect("Failed to compute circuit hash");
    let circuit_friendly_time = start.elapsed();
    
    println!("  • Byte-efficient mode: {:?}", byte_efficient_time);
    println!("  • Circuit-friendly mode: {:?}", circuit_friendly_time);
    
    println!("\n✨ Try different packing configurations to see how they affect the results!");
    
    // Demonstrate large input handling
    println!("\n📦 Large input handling:");
    let large_string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);
    hasher.update_primitive(RustInput::from_string_slice(&large_string)).expect("Failed to update with large string");
    let hash_large = hasher.digest().expect("Failed to compute large hash");
    println!("Hash of large string ({} chars): {}", large_string.len(), hash_large);
}