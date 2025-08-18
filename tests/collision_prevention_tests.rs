//! Tests to ensure domain/type tags prevent cross-type collisions.

use ark_ff::{PrimeField, BigInteger};
use poseidon_hash::types::PallasHasher;
use poseidon_hash::PoseidonHasher;

#[test]
fn test_basefield_vs_identical_bytes() {
    // Base field element built from bytes vs feeding the same bytes as a primitive
    let fq = ark_pallas::Fq::from(0x01020304u64);
    let bytes = fq.into_bigint().to_bytes_le();

    let mut h1 = PallasHasher::new();
    h1.update(ark_pallas::Fq::from_le_bytes_mod_order(&bytes));
    let hash1 = h1.digest();

    let mut h2 = PallasHasher::new();
    h2.update(bytes);
    let hash2 = h2.digest();

    assert_ne!(hash1, hash2, "Domain tags should separate Fq and Bytes domains");
}

#[test]
fn test_u16_vs_two_u8() {
    let mut h1 = PallasHasher::new();
    h1.update(0x0102u16);
    let hash1 = h1.digest();

    let mut h2 = PallasHasher::new();
    h2.update(0x02u8);
    h2.update(0x01u8);
    let hash2 = h2.digest();

    assert_ne!(hash1, hash2, "Type tags should disambiguate U16 vs two U8");
}

#[test]
fn test_i8_minus1_vs_u8_255() {
    let mut h1 = PallasHasher::new();
    h1.update(-1i8);
    let hash1 = h1.digest();

    let mut h2 = PallasHasher::new();
    h2.update(255u8);
    let hash2 = h2.digest();

    assert_ne!(hash1, hash2, "Type tags should disambiguate I8(-1) vs U8(255)");
}

#[test]
fn test_scalar_vs_basefield_same_bytes() {
    let fr = ark_pallas::Fr::from(0x42424242u64);
    let bytes = fr.into_bigint().to_bytes_le();
    let fq = ark_pallas::Fq::from_le_bytes_mod_order(&bytes);

    let mut h1 = PallasHasher::new();
    h1.update(fr);
    let hash1 = h1.digest();

    let mut h2 = PallasHasher::new();
    h2.update(fq);
    let hash2 = h2.digest();

    assert_ne!(hash1, hash2, "Domain tags should separate Fr and Fq inputs");
}

#[test]
fn test_curve_infinity_vs_two_zero_basefield() {
    use ark_ec::AffineRepr;

    let mut h1 = PallasHasher::new();
    h1.update(ark_pallas::Affine::zero());
    let hash1 = h1.digest();

    let mut h2 = PallasHasher::new();
    h2.update(ark_pallas::Fq::from(0u64));
    h2.update(ark_pallas::Fq::from(0u64));
    let hash2 = h2.digest();

    assert_ne!(hash1, hash2, "Tags should disambiguate infinity from two zero Fq elements");
}
