//! Generic multi-field Poseidon hasher implementation.
//!
//! This module provides the core [`MultiFieldHasher`] that can work with any elliptic curve
//! and automatically handles field conversions between different field types (Fr, Fq, curve points).
//!
//! ## Features
//!
//! - **Safe numeric conversions** - Uses `try_from()` instead of unsafe casts
//! - **Comprehensive error handling** - Cascades underlying [`PoseidonError`] with full context
//! - **Proper hash chaining** - Ensures all inputs affect the final hash result
//! - **Multiple field support** - Handles Fr ↔ Fq conversion with different bit sizes
//!
//! ## Usage
//!
//! Most users should use the curve-specific hashers from [`crate::types`] instead of this
//! generic implementation directly. However, this module is useful for:
//! - Library authors who need to be generic over curves
//! - Advanced users who want maximum flexibility
//! - Understanding the underlying implementation
//!
//! ```rust
//! use poseidon_hash::hasher::{MultiFieldHasher, FieldInput, HasherResult};
//! use poseidon_hash::parameters::pallas::PALLAS_PARAMS;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut hasher: MultiFieldHasher<ark_pallas::Fq, ark_pallas::Fr, ark_pallas::Affine> =
//!     MultiFieldHasher::new_from_ref(&*PALLAS_PARAMS);
//!     
//! hasher.update(FieldInput::ScalarField(ark_pallas::Fr::from(42u64)));
//! let hash = hasher.digest();
//! # Ok(())
//! # }
//! ```

use crate::ark_poseidon::ArkPoseidonSponge;
use crate::primitive::{PackingBuffer, PackingConfig, RustInput, serialize_rust_input};
// field-level tags removed in DiR-only mode; primitive tags are used in primitive.rs
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, Zero};
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Errors that can occur during hashing operations.
#[derive(Error, Debug)]
pub enum HasherError {
    /// Failed to extract coordinates from curve point
    #[error("Failed to extract curve point coordinates")]
    PointConversionFailed,
    /// Numeric conversion failed (overflow or underflow)
    #[error("Numeric conversion failed: {reason}")]
    NumericConversionFailed {
        /// Description of the specific conversion failure
        reason: String,
    },
}

/// Result type for hasher operations.
pub type HasherResult<T> = Result<T, HasherError>;

/// Multi-field input types for the generic Poseidon hasher.
///
/// This enum provides type-safe input handling for different field element types
/// within the same elliptic curve ecosystem.
#[derive(Debug, Clone)]
pub enum FieldInput<F: PrimeField, S: PrimeField, G: AffineRepr<BaseField = F>> {
    /// Base field element (Fq) - added directly without conversion
    BaseField(F),
    /// Scalar field element (Fr) - converted to base field representation
    ScalarField(S),
    /// Curve point in affine representation - coordinates extracted as base field elements
    CurvePoint(G),
    /// Primitive Rust type that needs packing
    Primitive(RustInput),
}

// Single blanket implementation for all primitive types!
impl<F: PrimeField, S: PrimeField, G: AffineRepr<BaseField = F>, T: Into<RustInput>> From<T>
    for FieldInput<F, S, G>
{
    fn from(value: T) -> Self {
        Self::Primitive(value.into())
    }
}

/// Advanced multi-field Poseidon hasher with sophisticated field conversion capabilities.
///
/// This generic hasher can work with any elliptic curve and automatically handles
/// conversion between different field types within the same curve's ecosystem.
///
/// # Security
///
/// This struct implements `ZeroizeOnDrop` to ensure that sensitive cryptographic data
/// (field elements, internal state) is securely cleared from memory when the hasher
/// is dropped, protecting against memory analysis attacks.
///
/// # Type Parameters
///
/// * `F: PrimeField + Zero` - Base field (Fq) used for curve coordinates and final hash output
/// * `S: PrimeField` - Scalar field (Fr) used for private keys and discrete logarithms  
/// * `G: AffineRepr<BaseField = F>` - Curve points in affine representation
#[derive(ZeroizeOnDrop)]
pub struct MultiFieldHasher<F: PrimeField, S: PrimeField, G: AffineRepr<BaseField = F>> {
    /// Poseidon hasher instance parameterized over the base field F
    ///
    /// Note: This contains cryptographic parameters that are public and don't need zeroization.
    /// The internal state of the Poseidon hasher may contain sensitive data, but we can't
    /// control its zeroization directly as it's from an external crate.
    #[zeroize(skip)]
    sponge: ArkPoseidonSponge<F>,
    #[zeroize(skip)]
    base_sponge: ArkPoseidonSponge<F>,
    /// Buffer for accumulating primitive types before packing into field elements
    ///
    /// This may contain sensitive input data and will be zeroized on drop.
    primitive_buffer: PackingBuffer,
    #[zeroize(skip)]
    count: usize,
    /// Phantom data to track scalar field type S without storing instances
    #[zeroize(skip)]
    _phantom_s: PhantomData<S>,
    /// Phantom data to track curve point type G without storing instances  
    #[zeroize(skip)]
    _phantom_g: PhantomData<G>,
    // Poseidon rate (from params)
    #[zeroize(skip)]
    rate: usize,
    // Current lane cursor within the rate for DiR mode
    #[zeroize(skip)]
    lane_cursor: usize,
    // Domain-in-Rate constants per class
    #[zeroize(skip)]
    dir_consts: DirConstants<F>,
    // Pending per-domain tweak to apply at next block boundary (DiR)
    #[zeroize(skip)]
    pending_domain: Option<[F; MAX_RATE]>,
    /// If true, delay applying domain tweak until lane_cursor == 0
    #[zeroize(skip)]
    pending_domain_at_block_start: bool,
    /// Number of lanes left to apply from pending_domain (when active)
    #[zeroize(skip)]
    domain_lanes_remaining: usize,
}

const SAFETY_MARGIN_BITS: usize = 8;
const MAX_RATE: usize = 12;

// Tagging strategy enum removed: library operates in Domain-in-Rate mode only

#[derive(Debug, Clone)]
struct DirConstants<F: PrimeField + Zero> {
    base: [F; MAX_RATE],
    scalar: [F; MAX_RATE],
    curve_finite: [F; MAX_RATE],
    curve_infinity: [F; MAX_RATE],
    primitive: [F; MAX_RATE],
}

fn derive_lane_constants<F: PrimeField + Zero>(label: &str, rate: usize) -> [F; MAX_RATE] {
    use core::array::from_fn;
    assert!(
        rate <= MAX_RATE,
        "rate {} exceeds MAX_RATE {}",
        rate,
        MAX_RATE
    );
    from_fn(|i| {
        if i < rate {
            let s = format!("{}|{}", label, i);
            F::from_le_bytes_mod_order(s.as_bytes())
        } else {
            F::zero()
        }
    })
}

fn derive_domain_tweak<F: PrimeField + Zero>(domain: &[u8], rate: usize) -> [F; MAX_RATE] {
    use core::array::from_fn;
    assert!(
        rate <= MAX_RATE,
        "rate {} exceeds MAX_RATE {}",
        rate,
        MAX_RATE
    );
    from_fn(|i| {
        if i < rate {
            let mut buf = Vec::with_capacity(12 + domain.len() + 8);
            buf.extend_from_slice(b"DIR|DOMAIN|");
            buf.extend_from_slice(domain);
            buf.extend_from_slice(b"|");
            buf.extend_from_slice(&(i as u64).to_le_bytes());
            F::from_le_bytes_mod_order(&buf)
        } else {
            F::zero()
        }
    })
}

fn build_dir_constants<F: PrimeField + Zero>(rate: usize) -> DirConstants<F> {
    DirConstants {
        base: derive_lane_constants("DIR|BASE", rate),
        scalar: derive_lane_constants("DIR|SCALAR", rate),
        curve_finite: derive_lane_constants("DIR|CURVE_FIN", rate),
        curve_infinity: derive_lane_constants("DIR|CURVE_INF", rate),
        primitive: derive_lane_constants("DIR|PRIM", rate),
    }
}

impl<F, S, G> MultiFieldHasher<F, S, G>
where
    F: PrimeField + Zero + ark_crypto_primitives::sponge::Absorb,
    S: PrimeField,
    G: AffineRepr<BaseField = F>,
{
    #[inline]
    /// Compute Domain-in-Rate adjusted elements without mutating hasher state.
    ///
    /// Applies per-class lane tweaks and any pending one-block domain tweak
    /// relative to the current internal cursor, but does not change internal
    /// counters or pending flags. Used by `digest()` to absorb remaining
    /// buffered elements into a cloned sponge while preserving the live state.
    fn compute_domain_in_rate_adjusted_elements_without_mutating_state(
        &self,
        elems: &[F],
        class: DirClass,
    ) -> Vec<F> {
        let consts = &self.dir_consts;
        let class_vec = match class {
            DirClass::Base => &consts.base,
            DirClass::Scalar => &consts.scalar,
            DirClass::CurveFinite => &consts.curve_finite,
            DirClass::CurveInfinity => &consts.curve_infinity,
            DirClass::Primitive => &consts.primitive,
        };

        let mut adjusted: Vec<F> = Vec::with_capacity(elems.len());
        let mut lane_cursor = self.lane_cursor;
        let mut pending_domain_at_block_start = self.pending_domain_at_block_start;
        let mut domain_lanes_remaining = self.domain_lanes_remaining;
        let mut dom_active = self.pending_domain.is_some();
        let dom_ref = self.pending_domain.as_ref();
        for &e in elems.iter() {
            let lane = lane_cursor % self.rate;
            let mut v = e + class_vec[lane];
            if dom_active && let Some(dom) = dom_ref {
                let should_apply_now = if pending_domain_at_block_start {
                    lane == 0
                } else {
                    true
                };
                if should_apply_now && domain_lanes_remaining > 0 {
                    v += dom[lane];
                    domain_lanes_remaining -= 1;
                    pending_domain_at_block_start = false;
                    if domain_lanes_remaining == 0 {
                        dom_active = false;
                    }
                }
            }
            adjusted.push(v);
            lane_cursor = (lane_cursor + 1) % self.rate;
        }
        adjusted
    }
    #[inline]
    fn assert_scalar_fits_base_field() {
        // We intentionally keep the API infallible. Enforce at construction time
        // that the scalar field does not exceed the base field by bit size.
        // This avoids ambiguous Fr→Fq mappings for unsupported curves.
        if S::MODULUS_BIT_SIZE > F::MODULUS_BIT_SIZE {
            panic!(
                "Unsupported curve configuration: Fr bit size ({}) exceeds Fq bit size ({}). This library does not support Fr→Fq limb decomposition.",
                S::MODULUS_BIT_SIZE,
                F::MODULUS_BIT_SIZE
            );
        }
    }

    fn max_bytes_per_field() -> usize {
        let field_bits = F::MODULUS_BIT_SIZE as usize;
        let safe_bits = field_bits.saturating_sub(SAFETY_MARGIN_BITS);
        std::cmp::max(safe_bits / 8, 1)
    }
    /// Creates a new multi-field hasher from Poseidon parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - Poseidon parameters for the base field F
    pub fn new(params: crate::ark_poseidon::ArkPoseidonConfig<F>) -> Self {
        Self::assert_scalar_fits_base_field();
        let sponge = ArkPoseidonSponge::new(&params);
        let rate = params.rate;
        Self {
            base_sponge: sponge.clone(),
            sponge,
            primitive_buffer: PackingBuffer::new::<F>(PackingConfig::default()),
            count: 0,
            _phantom_s: PhantomData,
            _phantom_g: PhantomData,
            rate,
            lane_cursor: 0,
            dir_consts: build_dir_constants::<F>(rate),
            pending_domain: None,
            pending_domain_at_block_start: false,
            domain_lanes_remaining: 0,
        }
    }

    /// Creates a new multi-field hasher from a reference to Poseidon parameters.
    ///
    /// This method clones the parameters internally.
    ///
    /// # Arguments
    ///
    /// * `params` - Reference to Poseidon parameters for the base field F
    pub fn new_from_ref(params: &crate::ark_poseidon::ArkPoseidonConfig<F>) -> Self
    where
        F: Clone,
    {
        Self::assert_scalar_fits_base_field();
        Self::new(crate::parameters::clone_parameters(params))
    }

    /// Creates a new multi-field hasher with custom packing configuration.
    ///
    /// # Arguments
    ///
    /// * `params` - Poseidon parameters for the base field F
    /// * `packing_config` - Configuration for packing primitive types
    pub fn new_with_config(
        params: crate::ark_poseidon::ArkPoseidonConfig<F>,
        packing_config: PackingConfig,
    ) -> Self {
        Self::assert_scalar_fits_base_field();
        let sponge = ArkPoseidonSponge::new(&params);
        let rate = params.rate;
        Self {
            base_sponge: sponge.clone(),
            sponge,
            primitive_buffer: PackingBuffer::new::<F>(packing_config),
            count: 0,
            _phantom_s: PhantomData,
            _phantom_g: PhantomData,
            rate,
            lane_cursor: 0,
            dir_consts: build_dir_constants::<F>(rate),
            pending_domain: None,
            pending_domain_at_block_start: false,
            domain_lanes_remaining: 0,
        }
    }

    // No longer used: compression chaining replaced by Poseidon sponge

    /// Creates a new multi-field hasher with custom packing configuration from parameter reference.
    ///
    /// # Arguments
    ///
    /// * `params` - Reference to Poseidon parameters for the base field F
    /// * `packing_config` - Configuration for packing primitive types
    pub fn new_with_config_from_ref(
        params: &crate::ark_poseidon::ArkPoseidonConfig<F>,
        packing_config: PackingConfig,
    ) -> Self
    where
        F: Clone,
    {
        Self::assert_scalar_fits_base_field();
        Self::new_with_config(crate::parameters::clone_parameters(params), packing_config)
    }

    // DiR-only mode: specialized constructors removed; use new()/new_with_config()

    /// Absorb a domain context using Domain-in-Rate lane tweaks.
    /// This namespaces the hasher so identical inputs produce different hashes across domains.
    pub fn absorb_domain(&mut self, domain: &[u8]) {
        // Derive per-lane tweak from the actual domain bytes.
        // Apply starting at the next block boundary (lane 0).
        let tweak = derive_domain_tweak::<F>(domain, self.rate);
        self.pending_domain = Some(tweak);
        self.pending_domain_at_block_start = true;
        self.domain_lanes_remaining = self.rate;
    }

    /// Absorbs a base field element (Fq) directly into the hasher state.
    pub fn update_base_field(&mut self, element: F) {
        self.absorb_dir(&[element], DirClass::Base);
    }

    /// Absorbs a scalar field element (Fr) with automatic conversion to base field (Fq).
    ///
    /// Handles different field bit size relationships:
    /// * Same bit size: Simple byte representation conversion
    /// * Fr < Fq: Direct conversion without data loss
    /// * Fr > Fq: Not supported (guarded at construction time)
    pub fn update_scalar_field(&mut self, element: S) {
        let fr_bits = S::MODULUS_BIT_SIZE;
        let fq_bits = F::MODULUS_BIT_SIZE;
        if fr_bits > fq_bits {
            panic!(
                "Unsupported curve configuration encountered at runtime: Fr bit size ({}) exceeds Fq bit size ({}).",
                fr_bits, fq_bits
            );
        }
        let bytes = element.into_bigint().to_bytes_le();
        let converted = F::from_le_bytes_mod_order(&bytes);
        self.absorb_dir(&[converted], DirClass::Scalar);
    }

    /// Absorbs a curve point by extracting and hashing its affine coordinates.
    pub fn update_curve_point(&mut self, point: G) {
        if let Some((x, y)) = point.xy() {
            self.absorb_dir(&[x, y], DirClass::CurveFinite);
        } else {
            // Represent infinity as a single tweaked zero element
            self.absorb_dir(&[F::zero()], DirClass::CurveInfinity);
        }
    }

    /// Absorbs any field input type using the appropriate specialized method.
    pub fn update(&mut self, input: FieldInput<F, S, G>) {
        match input {
            FieldInput::BaseField(fq) => {
                self.update_base_field(fq);
            }
            FieldInput::ScalarField(fr) => self.update_scalar_field(fr),
            FieldInput::CurvePoint(point) => self.update_curve_point(point),
            FieldInput::Primitive(rust_input) => self.update_primitive(rust_input),
        }
    }

    /// Absorbs a primitive Rust type by serializing and packing it into field elements.
    ///
    /// This method handles the conversion of basic Rust types (bool, integers, strings, etc.)
    /// into field elements using the configured packing strategy.
    ///
    /// # Arguments
    ///
    /// * `input` - The primitive value to add
    fn update_primitive(&mut self, input: RustInput) {
        // Serialize the input into the primitive buffer
        serialize_rust_input(&input, &mut self.primitive_buffer);
        // Extract any complete field elements
        let field_elements = self.primitive_buffer.extract_field_elements::<F>();
        if !field_elements.is_empty() {
            self.absorb_dir(&field_elements, DirClass::Primitive);
        }
    }

    /// Finalizes via sponge: clones internal sponge, absorbs remaining primitives, squeezes one element.
    pub fn digest(&mut self) -> F {
        let mut sponge = self.sponge.clone();
        let mut buf = self.primitive_buffer.clone();
        let remaining = buf.flush_remaining::<F>();
        if !remaining.is_empty() {
            // Apply DiR tweaks relative to current state without mutating it
            let adjusted = self.compute_domain_in_rate_adjusted_elements_without_mutating_state(
                &remaining,
                DirClass::Primitive,
            );
            sponge.absorb(&adjusted);
        }
        sponge.squeeze_native_field_elements(1)[0]
    }

    /// Consume the hasher and return the final hash result.
    ///
    /// This is equivalent to `digest()` but takes ownership of the hasher,
    /// ensuring it cannot be used again and triggering automatic cleanup via `ZeroizeOnDrop`.
    /// Useful when you want to guarantee the hasher is consumed after getting the final result.
    ///
    /// # Returns
    ///
    /// The final hash of all added elements.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use poseidon_hash::PallasHasher;
    /// # use poseidon_hash::PoseidonHasher;
    /// # fn main() {
    /// let mut hasher = PallasHasher::new();
    ///
    /// hasher.update(42u64);
    /// hasher.update(100u64);
    ///
    /// let final_hash = hasher.finalize();  // hasher is consumed here
    /// // hasher can no longer be used
    /// # }
    /// ```
    pub fn finalize(mut self) -> F {
        let remaining = self.primitive_buffer.flush_remaining::<F>();
        if !remaining.is_empty() {
            self.absorb_dir(&remaining, DirClass::Primitive);
        }
        self.sponge.squeeze_native_field_elements(1)[0]
    }

    /// Resets the hasher state without changing parameters (DiR baseline).
    ///
    /// This method securely clears all sensitive data from memory using zeroization.
    pub fn reset(&mut self) {
        self.sponge = self.base_sponge.clone();
        self.primitive_buffer.clear();
        self.count = 0;
        self.lane_cursor = 0;
        self.pending_domain = None;
        self.pending_domain_at_block_start = false;
        self.domain_lanes_remaining = 0;
    }

    /// Returns the current number of elements added.
    pub fn element_count(&self) -> usize {
        self.count
    }
}

#[derive(Clone, Copy, Debug)]
enum DirClass {
    Base,
    Scalar,
    CurveFinite,
    CurveInfinity,
    Primitive,
}

impl<F, S, G> MultiFieldHasher<F, S, G>
where
    F: PrimeField + Zero + ark_crypto_primitives::sponge::Absorb,
    S: PrimeField,
    G: AffineRepr<BaseField = F>,
{
    fn absorb_dir(&mut self, elems: &[F], class: DirClass) {
        // Per-class lane constants
        let consts = &self.dir_consts;
        let class_vec = match class {
            DirClass::Base => &consts.base,
            DirClass::Scalar => &consts.scalar,
            DirClass::CurveFinite => &consts.curve_finite,
            DirClass::CurveInfinity => &consts.curve_infinity,
            DirClass::Primitive => &consts.primitive,
        };

        let mut adjusted: Vec<F> = Vec::with_capacity(elems.len());
        for &e in elems.iter() {
            let lane = self.lane_cursor % self.rate;

            // Start with per-class tweak for this lane
            let mut v = e + class_vec[lane];

            // Apply a one-shot domain tweak to the next full block, aligned to lane 0
            if let Some(dom) = self.pending_domain.as_ref() {
                let should_apply_now = if self.pending_domain_at_block_start {
                    lane == 0
                } else {
                    true
                };

                if should_apply_now && self.domain_lanes_remaining > 0 {
                    v += dom[lane];
                    self.domain_lanes_remaining -= 1;
                    self.pending_domain_at_block_start = false; // we've started applying this block
                    if self.domain_lanes_remaining == 0 {
                        self.pending_domain = None;
                        self.pending_domain_at_block_start = false;
                    }
                }
            }

            adjusted.push(v);
            self.lane_cursor = (self.lane_cursor + 1) % self.rate;
        }
        self.sponge.absorb(&adjusted);
        self.count += adjusted.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BN254Hasher, BN254Input, PallasHasher, PallasInput, PoseidonHasher};
    use ark_ec::AffineRepr;

    #[test]
    fn test_embedded_parameters_basic() {
        let mut hasher = PallasHasher::new();

        let a = ark_pallas::Fq::from(1u64);
        let b = ark_pallas::Fq::from(2u64);

        // Old way still works
        hasher.update(PallasInput::BaseField(a));
        hasher.update(PallasInput::BaseField(b));

        let hash = hasher.digest();
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_from_implementations() {
        let mut hasher = PallasHasher::new();

        // New way - much cleaner!
        hasher.update(ark_pallas::Fq::from(1u64));
        hasher.update(ark_pallas::Fr::from(2u64));
        hasher.update(ark_pallas::Affine::generator());

        let hash = hasher.digest();
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_unified_update_api() {
        let mut hasher = PallasHasher::new();

        // Everything through a single update method - this is the dream API!
        hasher.update(ark_pallas::Fq::from(1u64));
        hasher.update(ark_pallas::Fr::from(2u64));
        hasher.update(ark_pallas::Affine::generator());
        hasher.update(true);
        hasher.update(42u64);
        hasher.update("hello");
        hasher.update(vec![1u8, 2, 3]);

        let hash = hasher.digest();
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_api_comparison() {
        // Manual enum construction (still works)
        let mut explicit_style = PallasHasher::new();
        explicit_style.update(PallasInput::ScalarField(ark_pallas::Fr::from(42u64)));
        explicit_style.update(PallasInput::Primitive(RustInput::Bool(true)));
        explicit_style.update(PallasInput::Primitive(RustInput::from_string_slice("test")));

        // Clean unified API (recommended)
        let mut unified_style = PallasHasher::new();
        unified_style.update(ark_pallas::Fr::from(42u64)); // Direct!
        unified_style.update(true); // Natural!  
        unified_style.update("test"); // Intuitive!

        // Both produce the same result
        assert_eq!(explicit_style.digest(), unified_style.digest());
    }

    #[test]
    fn test_generic_from_implementations() {
        // Test that generic From implementations work for all curves!
        let mut pallas = crate::types::PallasHasher::new();
        let mut bn254 = crate::types::BN254Hasher::new();

        // Same API works for all curves thanks to generic implementations
        pallas.update(42u64);
        pallas.update(true);
        pallas.update("hello");

        bn254.update(42u64);
        bn254.update(true);
        bn254.update("hello");

        // Different curves produce different hashes for same input
        let pallas_hash = pallas.digest();
        let bn254_hash = bn254.digest();
        assert_ne!(pallas_hash.to_string(), bn254_hash.to_string());
    }

    #[test]
    fn test_proper_chaining_with_embedded_params() {
        // Test that chaining works correctly with embedded parameters
        let mut hasher = PallasHasher::new();

        let a = ark_pallas::Fr::from(1u64);
        let b = ark_pallas::Fr::from(2u64);
        let c = ark_pallas::Fr::from(3u64);
        let d = ark_pallas::Fr::from(4u64);

        hasher.update(PallasInput::ScalarField(a));
        hasher.update(PallasInput::ScalarField(b));
        hasher.update(PallasInput::ScalarField(c));
        hasher.update(PallasInput::ScalarField(d));

        let hash_abcd = hasher.digest();

        // Hash just the last two elements
        let mut hasher2 = PallasHasher::new();
        hasher2.update(PallasInput::ScalarField(c));
        hasher2.update(PallasInput::ScalarField(d));

        let hash_cd = hasher2.digest();

        // These should be different due to proper chaining
        assert_ne!(hash_abcd, hash_cd);
    }

    #[test]
    fn test_multi_field_types() {
        let mut hasher = PallasHasher::new();

        let scalar = ark_pallas::Fr::from(42u64);
        let base = ark_pallas::Fq::from(100u64);
        let generator = ark_pallas::Affine::generator();

        hasher.update(PallasInput::ScalarField(scalar));
        hasher.update(PallasInput::BaseField(base));
        hasher.update(PallasInput::CurvePoint(generator));

        let hash = hasher.digest();
        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_cross_curve_type_safety() {
        // Each curve hasher has its own embedded parameters
        let mut pallas_hasher = PallasHasher::new();
        let mut bn254_hasher = BN254Hasher::new();

        let pallas_scalar = ark_pallas::Fr::from(123u64);
        let bn254_scalar = ark_bn254::Fr::from(123u64);

        pallas_hasher.update(PallasInput::ScalarField(pallas_scalar));
        bn254_hasher.update(BN254Input::ScalarField(bn254_scalar));

        let pallas_hash = pallas_hasher.digest();
        let bn254_hash = bn254_hasher.digest();

        // These should be different because they use different parameters
        assert_ne!(pallas_hash.to_string(), bn254_hash.to_string());
    }

    #[test]
    fn test_default_constructor() {
        // Test that Default trait works for convenient initialization
        let mut hasher: PallasHasher = Default::default();

        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64)));
        let hash = hasher.digest();

        assert_ne!(hash, ark_pallas::Fq::zero());
    }

    #[test]
    fn test_hasher_reuse() {
        let mut hasher = PallasHasher::new();

        // First hash
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(1u64)));
        let hash1 = hasher.digest();

        // Second hash (now includes both elements since digest preserves state)
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(2u64)));
        let hash2 = hasher.digest();

        // Should be different because hash2 contains both elements
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_digest_preserves_state_and_finalize() {
        let mut hasher = PallasHasher::new();

        // Add some data
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64)));

        // Get hash - state should be preserved
        let first_hash = hasher.digest();
        assert_ne!(first_hash, ark_pallas::Fq::zero());

        // State should be preserved - element count should be > 0
        assert!(
            hasher.element_count() > 0,
            "State was not preserved after digest"
        );

        // Add more data
        hasher.update(PallasInput::BaseField(ark_pallas::Fq::from(100u64)));

        // Second digest should be different (contains both elements)
        let second_hash = hasher.digest();
        assert_ne!(first_hash, second_hash);

        // State should still be preserved
        assert!(hasher.element_count() > 0, "State was cleared after digest");

        // Test finalize (consumes hasher)
        let mut hasher2 = PallasHasher::new();
        hasher2.update(PallasInput::BaseField(ark_pallas::Fq::from(42u64)));
        let finalized = hasher2.finalize();

        // Should match the first hash (same single input)
        assert_eq!(first_hash, finalized);
    }
}
