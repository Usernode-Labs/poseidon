//! Error cascading demonstration

use poseidon_hash::prelude::*;

fn main() {
    println!("🔍 Error Cascading Demo\n");
    
    let mut hasher = PallasHasher::new();
    
    // Normal operation
    println!("✅ Normal operation:");
    hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64))).unwrap();
    let hash = hasher.squeeze().unwrap();
    println!("  Hash: {}\n", hash.to_string().chars().take(40).collect::<String>() + "...");
    
    // Demonstrate error types
    println!("🔍 Error handling:");
    println!("  Our HasherError properly wraps and cascades PoseidonError");
    println!("  This provides users with detailed, actionable error information");
    println!("  instead of generic 'hashing failed' messages.\n");
    
    // Show error structure
    match hasher.squeeze() {
        Ok(result) => println!("  Empty state hash: {result}"),
        Err(HasherError::PoseidonError(poseidon_err)) => {
            println!("  Cascaded Poseidon error: {poseidon_err}");
        },
        Err(HasherError::PointConversionFailed) => {
            println!("  Point conversion failed");
        },
        Err(HasherError::NumericConversionFailed { reason }) => {
            println!("  Numeric conversion failed: {reason}");
        }
    }
    
    println!("\n💡 Benefits of error cascading:");
    println!("  • Preserves original error context");
    println!("  • Provides actionable debugging information");
    println!("  • Follows Rust best practices");
    println!("  • Allows users to handle specific error conditions");
}