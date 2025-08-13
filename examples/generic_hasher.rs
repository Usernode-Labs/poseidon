//! Example demonstrating generic programming with the PoseidonHasher trait.

use poseidon_hash::prelude::*;

fn main() {
    println!("🔧 Generic Poseidon Hashing with Traits\n");
    
    // Test data that will be hashed by different curve hashers
    let test_data = vec![
        RustInput::Bool(true),
        RustInput::U64(42),
        RustInput::from_string_slice("generic trait demo"),
        RustInput::from_bytes(&[0xFF, 0x00, 0xAA, 0x55]),
    ];
    
    println!("📝 Test data:");
    println!("  • Bool: true");
    println!("  • U64: 42");
    println!("  • String: \"generic trait demo\"");
    println!("  • Bytes: [0xFF, 0x00, 0xAA, 0x55]");
    println!();
    
    // Demonstrate generic hashing function
    println!("🎯 Using generic hash function:");
    let pallas_hash = hash_primitives_generic::<PallasHasher, ark_pallas::Fq, PallasInput>(&test_data);
    let bn254_hash = hash_primitives_generic::<BN254Hasher, ark_bn254::Fq, BN254Input>(&test_data);
    let vesta_hash = hash_primitives_generic::<VestaHasher, ark_vesta::Fq, VestaInput>(&test_data);
    
    println!("  • Pallas:  {}...", pallas_hash.chars().take(30).collect::<String>());
    println!("  • BN254:   {}...", bn254_hash.chars().take(30).collect::<String>());
    println!("  • Vesta:   {}...", vesta_hash.chars().take(30).collect::<String>());
    
    // Demonstrate generic hashing with different configurations
    println!("\n⚙️  Using different configurations:");
    let byte_efficient = hash_with_config::<PallasHasher, ark_pallas::Fq, PallasInput>(&test_data, PackingConfig::default());
    let circuit_friendly = hash_with_config::<PallasHasher, ark_pallas::Fq, PallasInput>(&test_data, PackingConfig {
        mode: PackingMode::CircuitFriendly,
        ..Default::default()
    });
    
    println!("  • Byte-efficient:   {}...", byte_efficient.chars().take(30).collect::<String>());
    println!("  • Circuit-friendly: {}...", circuit_friendly.chars().take(30).collect::<String>());
    
    if byte_efficient != circuit_friendly {
        println!("\n✅ Different configurations produce different results!");
    }
    
    println!("\n🚀 The trait enables clean generic programming over all curve hashers!");
}

/// Generic function that can work with any curve hasher implementing PoseidonHasher
fn hash_primitives_generic<H, F, I>(data: &[RustInput]) -> String 
where
    H: PoseidonHasher<F, I>,
    F: ark_ff::PrimeField + std::fmt::Display,
{
    let mut hasher = H::new();
    
    for item in data {
        hasher.update_primitive(item.clone()).expect("Failed to update hasher");
    }
    
    hasher.squeeze().expect("Failed to squeeze hash").to_string()
}

/// Generic function that creates a hasher with custom configuration
fn hash_with_config<H, F, I>(data: &[RustInput], config: PackingConfig) -> String
where
    H: PoseidonHasher<F, I>,
    F: ark_ff::PrimeField + std::fmt::Display,
{
    let mut hasher = H::new_with_config(config);
    
    for item in data {
        hasher.update_primitive(item.clone()).expect("Failed to update hasher");
    }
    
    hasher.squeeze().expect("Failed to squeeze hash").to_string()
}