//! Primitive tagging scheme
//!
//! Tags are small u8 discriminants used to disambiguate primitive input kinds.
//! They are injected into the primitive byte stream before packing into field
//! elements. Field/point inputs are disambiguated via Domain-in-Rate class
//! tweaks and do not use tags anymore.

// Primitive types (byte-level tags)
pub const TAG_BOOL: u8 = 0x10;
pub const TAG_U8: u8 = 0x11;
pub const TAG_U16: u8 = 0x12;
pub const TAG_U32: u8 = 0x13;
pub const TAG_U64: u8 = 0x14;
pub const TAG_U128: u8 = 0x15;
pub const TAG_USIZE: u8 = 0x16;
pub const TAG_I8: u8 = 0x17;
pub const TAG_I16: u8 = 0x18;
pub const TAG_I32: u8 = 0x19;
pub const TAG_I64: u8 = 0x1A;
pub const TAG_I128: u8 = 0x1B;
pub const TAG_ISIZE: u8 = 0x1C;
pub const TAG_STRING: u8 = 0x20;
pub const TAG_BYTES: u8 = 0x21;
