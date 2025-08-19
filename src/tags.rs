//! Internal tagging scheme for domain/type separation.
//! Tags are small u8 discriminants used to disambiguate input kinds.
//!
//! Note: For primitives we inject tags into the byte stream.
//! For field/point inputs we currently precede with a tag field element F::from(tag).
//! A future refinement could unify all inputs through the byte-packing path.

// Field-level domains
pub const TAG_BASE_FIELD: u8 = 0x01;
pub const TAG_SCALAR_FIELD: u8 = 0x02;
pub const TAG_CURVE_POINT_FINITE: u8 = 0x03;
pub const TAG_CURVE_POINT_INFINITY: u8 = 0x04;

// Domain context (field-level tag precedes a tagged byte sequence)
pub const TAG_DOMAIN_CTX: u8 = 0x05;


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
