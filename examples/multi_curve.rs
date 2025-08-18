//! Multi-curve example demonstrating usage with different elliptic curves.

use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

fn main() {
    // Same data, different curves
    let data = 42u64;
    
    let mut pallas = PallasHasher::new();
    pallas.update(data);
    let pallas_hash = pallas.digest();
    
    let mut bn254 = BN254Hasher::new();
    bn254.update(data);
    let bn254_hash = bn254.digest();
    
    println!("Pallas hash: {}", pallas_hash);
    println!("BN254 hash:  {}", bn254_hash);
    println!("Different curves produce different hashes: {}", 
             pallas_hash.to_string() != bn254_hash.to_string());
}
