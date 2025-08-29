//! Example demonstrating the new primitive types hashing functionality.

use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;

fn main() {
    println!("🚀 Poseidon Hash Library - Primitive Types Hashing\n");

    // Create a hasher with default (byte-efficient) configuration
    let mut hasher = PallasHasher::new();

    println!("📝 Hashing various primitive types:");

    // Hash different primitive types
    hasher.update(true);
    println!("  • Added boolean: true");

    hasher.update(12345u64);
    println!("  • Added u64: 12345");

    hasher.update(-6789i32);
    println!("  • Added i32: -6789");

    hasher.update("Hello, Poseidon!");
    println!("  • Added string: \"Hello, Poseidon!\"");

    hasher.update(vec![1u8, 2, 3, 4, 5, 255]);
    println!("  • Added bytes: [1, 2, 3, 4, 5, 255]");

    let hash1 = hasher.digest();
    println!("\n🔥 Hash (byte-efficient mode): {}", hash1);

    // Demonstrate the unified API with more types
    println!("\n🔧 Adding more types:");
    hasher.update(false);
    hasher.update(999999999999999u128);
    hasher.update("Unified API test".to_string());

    let hash2 = hasher.digest();
    println!("Hash with enum API: {}", hash2);

    // Demonstrate circuit-friendly mode
    println!("\n⚡ Circuit-friendly mode (for zk-circuits):");
    let mut circuit_hasher = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    });

    circuit_hasher.update(vec![1u8, 2, 3, 4, 5]);
    let hash3 = circuit_hasher.digest();
    println!("Circuit-friendly hash: {}", hash3);

    // Mix field elements and primitive types
    println!("\n🌊 Mixing field elements and primitive types:");
    let scalar = ark_pallas::Fr::from(42u64);
    hasher.update(scalar);
    hasher.update(100u64);
    hasher.update("mixed types");

    let hash4 = hasher.digest();
    println!("Mixed hash: {}", hash4);

    // Demonstrate deterministic hashing
    println!("\n🔒 Deterministic hashing:");
    let mut hasher1 = PallasHasher::new();
    let mut hasher2 = PallasHasher::new();

    // Add the same data to both hashers
    hasher1.update(true);
    hasher1.update(123456u64);
    hasher1.update("deterministic");
    hasher1.update(vec![10u8, 20, 30]);

    hasher2.update(true);
    hasher2.update(123456u64);
    hasher2.update("deterministic");
    hasher2.update(vec![10u8, 20, 30]);

    let hash_a = hasher1.digest();
    let hash_b = hasher2.digest();

    if hash_a == hash_b {
        println!(
            "✅ Deterministic hashing works! Both hashes match: {}",
            hash_a
        );
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
    byte_efficient_hasher.update(test_bytes.clone());
    let _hash_efficient = byte_efficient_hasher.digest();
    let byte_efficient_time = start.elapsed();

    let start = std::time::Instant::now();
    let mut circuit_friendly_hasher = PallasHasher::new_with_config(PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    });
    circuit_friendly_hasher.update(test_bytes);
    let _hash_circuit = circuit_friendly_hasher.digest();
    let circuit_friendly_time = start.elapsed();

    println!("  • Byte-efficient mode: {:?}", byte_efficient_time);
    println!("  • Circuit-friendly mode: {:?}", circuit_friendly_time);

    println!("\n✨ Try different packing configurations to see how they affect the results!");

    // Demonstrate large input handling
    println!("\n📦 Large input handling:");
    let large_string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);
    hasher.update(large_string.as_str());
    let hash_large = hasher.digest();
    println!(
        "Hash of large string ({} chars): {}",
        large_string.len(),
        hash_large
    );
}
