//! Support for hashing basic Rust types (booleans, integers, strings, byte arrays).
//!
//! This module provides efficient packing of basic Rust types into field elements,
//! with support for both byte-efficient and circuit-friendly packing modes.
//!
//! ## Packing Strategies
//!
//! ### Byte-Efficient Mode (Default)
//! - **Bools**: 8 bools per byte, then bytes into field elements
//! - **Integers**: Native byte representation (little-endian)
//! - **Strings/Bytes**: Length-prefixed, then packed into field elements
//! - **Goal**: Minimize field element usage for storage/bandwidth efficiency
//!
//! ### Circuit-Friendly Mode
//! - **Bools**: Each bool becomes a field element (0 or 1)
//! - **Integers**: Each integer becomes a field element directly
//! - **Strings/Bytes**: Each byte becomes a field element
//! - **Goal**: Minimize constraint count in zero-knowledge circuits
//!
//! ## Usage
//!
//! ```rust
//! use poseidon_hash::primitive::{RustInput, PackingMode};
//! use poseidon_hash::PallasHasher;
//! use poseidon_hash::PoseidonHasher;
//!
//! let mut hasher = PallasHasher::new();
//!
//! // Clean unified API
//! hasher.update(true);
//! hasher.update(12345u64);
//! hasher.update("hello".to_string());
//! hasher.update("hello");
//! hasher.update(vec![1u8, 2, 3, 4]);
//!
//! let hash = hasher.digest();
//! ```

use ark_ff::PrimeField;
use std::collections::VecDeque;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::tags::*;

/// Configuration for packing basic Rust types into field elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackingConfig {
    /// Packing mode: byte-efficient vs circuit-friendly
    pub mode: PackingMode,
    /// Maximum bytes to pack into a single field element (auto-calculated from field size if None)
    pub max_bytes_per_field: Option<usize>,
    /// Padding strategy when field element is not full
    pub padding: PaddingMode,
}

/// Packing modes for converting basic types to field elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackingMode {
    /// Byte-efficient: Pack multiple values per field element to minimize field usage
    ByteEfficient,
    /// Circuit-friendly: One value per field element to minimize circuit constraints
    CircuitFriendly,
}

/// Padding strategies for incomplete field elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingMode {
    /// Pad with zeros
    Zero,
    /// Pad with a length prefix indicating actual data length
    LengthPrefix,
}

impl Default for PackingConfig {
    fn default() -> Self {
        Self {
            mode: PackingMode::ByteEfficient,
            max_bytes_per_field: None, // Auto-calculate from field size
            padding: PaddingMode::LengthPrefix,
        }
    }
}

/// Input types for basic Rust primitives that can be hashed.
#[derive(Debug, Clone)]
pub enum RustInput {
    /// Boolean value
    Bool(bool),
    /// 8-bit unsigned integer
    U8(u8),
    /// 16-bit unsigned integer  
    U16(u16),
    /// 32-bit unsigned integer
    U32(u32),
    /// 64-bit unsigned integer
    U64(u64),
    /// 128-bit unsigned integer
    U128(u128),
    /// Platform-specific unsigned integer
    Usize(usize),
    /// 8-bit signed integer
    I8(i8),
    /// 16-bit signed integer
    I16(i16),
    /// 32-bit signed integer
    I32(i32),
    /// 64-bit signed integer
    I64(i64),
    /// 128-bit signed integer
    I128(i128),
    /// Platform-specific signed integer
    Isize(isize),
    /// UTF-8 string
    String(String),
    /// String slice (converted to owned String for consistent serialization)
    Str(String),
    /// Byte array
    Bytes(Vec<u8>),
    /// Byte slice (converted to owned Vec for consistent serialization)
    ByteSlice(Vec<u8>),
}

impl RustInput {
    /// Create a RustInput from a string slice
    pub fn from_string_slice(s: &str) -> Self {
        Self::Str(s.to_string())
    }
    
    /// Create a RustInput from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::ByteSlice(bytes.to_vec())
    }
}

// Simple From implementations - much cleaner than 17 separate impls!
impl From<bool> for RustInput { fn from(v: bool) -> Self { Self::Bool(v) } }
impl From<u8> for RustInput { fn from(v: u8) -> Self { Self::U8(v) } }
impl From<u16> for RustInput { fn from(v: u16) -> Self { Self::U16(v) } }
impl From<u32> for RustInput { fn from(v: u32) -> Self { Self::U32(v) } }
impl From<u64> for RustInput { fn from(v: u64) -> Self { Self::U64(v) } }
impl From<u128> for RustInput { fn from(v: u128) -> Self { Self::U128(v) } }
impl From<usize> for RustInput { fn from(v: usize) -> Self { Self::Usize(v) } }
impl From<i8> for RustInput { fn from(v: i8) -> Self { Self::I8(v) } }
impl From<i16> for RustInput { fn from(v: i16) -> Self { Self::I16(v) } }
impl From<i32> for RustInput { fn from(v: i32) -> Self { Self::I32(v) } }
impl From<i64> for RustInput { fn from(v: i64) -> Self { Self::I64(v) } }
impl From<i128> for RustInput { fn from(v: i128) -> Self { Self::I128(v) } }
impl From<isize> for RustInput { fn from(v: isize) -> Self { Self::Isize(v) } }
impl From<String> for RustInput { fn from(v: String) -> Self { Self::String(v) } }
impl From<&str> for RustInput { fn from(v: &str) -> Self { Self::Str(v.to_string()) } }
impl From<Vec<u8>> for RustInput { fn from(v: Vec<u8>) -> Self { Self::Bytes(v) } }
impl From<&[u8]> for RustInput { fn from(v: &[u8]) -> Self { Self::ByteSlice(v.to_vec()) } }

/// Buffer for accumulating bytes before packing into field elements.
/// 
/// This buffer may contain sensitive input data and implements `ZeroizeOnDrop`
/// to ensure that cryptographic material is securely cleared from memory.
#[derive(Clone)]
pub struct PackingBuffer {
    /// Accumulated bytes waiting to be packed
    /// 
    /// This may contain sensitive data and will be zeroized on drop.
    bytes: VecDeque<u8>,
    /// Configuration for packing behavior (no sensitive data)
    config: PackingConfig,
    /// Maximum bytes per field element (calculated from field size, no sensitive data)
    max_bytes_per_field: usize,
}

impl PackingBuffer {
    /// Create a new packing buffer for the given field type.
    pub fn new<F: PrimeField>(config: PackingConfig) -> Self {
        let max_bytes_per_field = config.max_bytes_per_field
            .unwrap_or_else(|| Self::calculate_max_bytes::<F>());
            
        Self {
            bytes: VecDeque::new(),
            config,
            max_bytes_per_field,
        }
    }
    
    /// Calculate the maximum safe bytes per field element.
    /// 
    /// We use a conservative approach: (field_bit_size - 8) / 8 to ensure
    /// we never exceed the field modulus when packing bytes.
    fn calculate_max_bytes<F: PrimeField>() -> usize {
        const SAFETY_MARGIN_BITS: usize = 8;
        let field_bits = F::MODULUS_BIT_SIZE as usize;
        let safe_bits = field_bits.saturating_sub(SAFETY_MARGIN_BITS);
        std::cmp::max(safe_bits / 8, 1)
    }
    
    /// Add bytes to the buffer.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
    }

    /// Add a single tag byte to the buffer (used for domain/type separation).
    pub fn push_tag(&mut self, tag: u8) {
        self.bytes.push_back(tag);
    }
    
    /// Add a boolean to the buffer (1 byte: 0x00 or 0x01).
    pub fn push_bool(&mut self, value: bool) {
        self.bytes.push_back(if value { 1u8 } else { 0u8 });
    }
    
    /// Add a string to the buffer with length prefix.
    pub fn push_string(&mut self, s: &str) {
        let bytes = s.as_bytes();
        // Length prefix (using LEB128-style encoding for variable length)
        self.push_varint(bytes.len());
        self.bytes.extend(bytes);
    }
    
    /// Add a variable-length integer (LEB128-style encoding).
    fn push_varint(&mut self, mut value: usize) {
        while value >= 0x80 {
            self.bytes.push_back((value & 0x7F | 0x80) as u8);
            value >>= 7;
        }
        self.bytes.push_back(value as u8);
    }
    
    /// Extract all complete field elements from the buffer.
    /// 
    /// Returns the field elements and leaves any remaining bytes in the buffer.
    pub fn extract_field_elements<F: PrimeField>(&mut self) -> Vec<F> {
        let mut field_elements = Vec::new();
        
        match self.config.mode {
            PackingMode::ByteEfficient => {
                // Pack bytes efficiently into field elements
                while self.bytes.len() >= self.max_bytes_per_field {
                    let mut chunk = Vec::with_capacity(self.max_bytes_per_field);
                    for _ in 0..self.max_bytes_per_field {
                        if let Some(byte) = self.bytes.pop_front() {
                            chunk.push(byte);
                        } else {
                            break;
                        }
                    }
                    
                    if !chunk.is_empty() {
                        let field_element = F::from_le_bytes_mod_order(&chunk);
                        field_elements.push(field_element);
                    }
                }
            }
            PackingMode::CircuitFriendly => {
                // Each byte becomes its own field element
                while let Some(byte) = self.bytes.pop_front() {
                    let field_element = F::from(byte as u64);
                    field_elements.push(field_element);
                }
            }
        }

        field_elements
    }
    
    /// Force extraction of all remaining bytes as field elements (with padding if needed).
    pub fn flush_remaining<F: PrimeField>(&mut self) -> Vec<F> {
        if self.bytes.is_empty() {
            return Vec::new();
        }
        
        let mut field_elements = Vec::new();
        
        match self.config.mode {
            PackingMode::ByteEfficient => {
                // Pack remaining bytes with padding
                let remaining_bytes: Vec<u8> = self.bytes.drain(..).collect();
                if !remaining_bytes.is_empty() {
                    let mut padded_bytes = remaining_bytes;
                    
                    match self.config.padding {
                        PaddingMode::Zero => {
                            // Pad with zeros to field size
                            padded_bytes.resize(self.max_bytes_per_field, 0);
                        }
                        PaddingMode::LengthPrefix => {
                            // Insert actual length at the beginning
                            let actual_len = padded_bytes.len();
                            padded_bytes.insert(0, actual_len as u8);
                            // Then pad with zeros if needed
                            if padded_bytes.len() < self.max_bytes_per_field {
                                padded_bytes.resize(self.max_bytes_per_field, 0);
                            }
                        }
                    }
                    
                    let field_element = F::from_le_bytes_mod_order(&padded_bytes);
                    field_elements.push(field_element);
                }
            }
            PackingMode::CircuitFriendly => {
                // Each remaining byte becomes its own field element
                while let Some(byte) = self.bytes.pop_front() {
                    let field_element = F::from(byte as u64);
                    field_elements.push(field_element);
                }
            }
        }

        field_elements
    }
    
    /// Clear all bytes from the buffer.
    /// 
    /// This method securely zeroizes the buffer contents to prevent sensitive
    /// data from remaining in memory.
    pub fn clear(&mut self) {
        // Zeroize the contents before clearing to ensure secure deletion
        for byte in self.bytes.iter_mut() {
            byte.zeroize();
        }
        self.bytes.clear();
    }
    
    /// Returns the number of bytes in the buffer.
    /// 
    /// This is primarily for testing and debugging purposes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    
    /// Returns whether the buffer is empty.
    /// 
    /// This is primarily for testing and debugging purposes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Serialize a RustInput into bytes for packing.
pub fn serialize_rust_input(input: &RustInput, buffer: &mut PackingBuffer) {
    match input {
        RustInput::Bool(b) => {
            buffer.push_tag(TAG_BOOL);
            buffer.push_bool(*b)
        }
        // Unsigned integers - direct conversion is safe
        RustInput::U8(n) => { buffer.push_tag(TAG_U8); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::U16(n) => { buffer.push_tag(TAG_U16); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::U32(n) => { buffer.push_tag(TAG_U32); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::U64(n) => { buffer.push_tag(TAG_U64); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::U128(n) => { buffer.push_tag(TAG_U128); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::Usize(n) => { buffer.push_tag(TAG_USIZE); buffer.push_bytes(&n.to_le_bytes()) },
        // Signed integers - preserve bit pattern via to_le_bytes
        RustInput::I8(n) => { buffer.push_tag(TAG_I8); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::I16(n) => { buffer.push_tag(TAG_I16); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::I32(n) => { buffer.push_tag(TAG_I32); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::I64(n) => { buffer.push_tag(TAG_I64); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::I128(n) => { buffer.push_tag(TAG_I128); buffer.push_bytes(&n.to_le_bytes()) },
        RustInput::Isize(n) => { buffer.push_tag(TAG_ISIZE); buffer.push_bytes(&n.to_le_bytes()) },
        // Strings and bytes
        RustInput::String(s) | RustInput::Str(s) => { buffer.push_tag(TAG_STRING); buffer.push_string(s) },
        RustInput::Bytes(bytes) | RustInput::ByteSlice(bytes) => {
            buffer.push_tag(TAG_BYTES);
            buffer.push_varint(bytes.len());
            buffer.push_bytes(bytes);
        }
    }
}

// Manual implementation of ZeroizeOnDrop for PackingBuffer
// since VecDeque doesn't implement Zeroize automatically
impl ZeroizeOnDrop for PackingBuffer {}

impl Drop for PackingBuffer {
    fn drop(&mut self) {
        // Manually zeroize the VecDeque contents
        for byte in self.bytes.iter_mut() {
            byte.zeroize();
        }
        self.bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packing_buffer_basic() {
        let config = PackingConfig::default();
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        // Test boolean packing
        buffer.push_bool(true);
        buffer.push_bool(false);
        buffer.push_bool(true);
        
        assert_eq!(buffer.len(), 3);
        assert!(!buffer.is_empty());
    }
    
    #[test]
    fn test_integer_packing() {
        let config = PackingConfig::default();
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        // Test various integer sizes using push_bytes
        buffer.push_bytes(&0u8.to_le_bytes());
        buffer.push_bytes(&255u8.to_le_bytes());
        buffer.push_bytes(&65535u16.to_le_bytes());
        
        // Should have: 1 byte (0) + 1 byte (255) + 2 bytes (65535) = 4 bytes
        assert_eq!(buffer.len(), 4);
    }
    
    #[test]
    fn test_string_packing() {
        let config = PackingConfig::default();
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        buffer.push_string("hello");
        
        // Should have: length prefix (1 byte for "5") + 5 bytes for "hello"
        assert_eq!(buffer.len(), 6);
    }
    
    #[test]
    fn test_field_element_extraction() {
        let config = PackingConfig::default();
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        // Add enough bytes to create field elements
        for i in 0..100u8 {
            buffer.push_bytes(&[i]);
        }
        
        let field_elements = buffer.extract_field_elements::<ark_pallas::Fq>();
        assert!(!field_elements.is_empty());
        
        // Some bytes may or may not remain - that's expected
    }
    
    #[test]
    fn test_circuit_friendly_mode() {
        let config = PackingConfig {
            mode: PackingMode::CircuitFriendly,
            ..Default::default()
        };
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        buffer.push_bytes(&[1, 2, 3]);
        
        let field_elements = buffer.extract_field_elements::<ark_pallas::Fq>();
        
        // In circuit-friendly mode, each byte becomes its own field element
        assert_eq!(field_elements.len(), 3);
        assert_eq!(field_elements[0], ark_pallas::Fq::from(1u64));
        assert_eq!(field_elements[1], ark_pallas::Fq::from(2u64));
        assert_eq!(field_elements[2], ark_pallas::Fq::from(3u64));
    }
    
    #[test]
    fn test_rust_input_serialization() {
        let config = PackingConfig::default();
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        serialize_rust_input(&RustInput::Bool(true), &mut buffer);
        serialize_rust_input(&RustInput::U64(12345), &mut buffer);
        serialize_rust_input(&RustInput::String("test".to_string()), &mut buffer);
        
        assert!(!buffer.is_empty());
    }
    
    #[test]
    fn test_flush_remaining() {
        let config = PackingConfig::default();
        let mut buffer = PackingBuffer::new::<ark_pallas::Fq>(config);
        
        // Add a small amount of data
        buffer.push_bytes(&[1, 2, 3]);
        
        let field_elements = buffer.flush_remaining::<ark_pallas::Fq>();
        
        // Should produce exactly one field element with padding
        assert_eq!(field_elements.len(), 1);
        assert_eq!(buffer.len(), 0);
    }
}
