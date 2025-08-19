use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

#[test]
fn test_determinism_across_types() {
    // Bool
    let mut h1 = PallasHasher::new();
    let mut h2 = PallasHasher::new();
    h1.update(true);
    h2.update(true);
    assert_eq!(h1.digest(), h2.digest());

    // u64
    let mut h1 = PallasHasher::new();
    let mut h2 = PallasHasher::new();
    h1.update(12345u64);
    h2.update(12345u64);
    assert_eq!(h1.digest(), h2.digest());

    // i64
    let mut h1 = PallasHasher::new();
    let mut h2 = PallasHasher::new();
    h1.update(-6789i64);
    h2.update(-6789i64);
    assert_eq!(h1.digest(), h2.digest());

    // String
    let mut h1 = PallasHasher::new();
    let mut h2 = PallasHasher::new();
    h1.update("deterministic test".to_string());
    h2.update("deterministic test".to_string());
    assert_eq!(h1.digest(), h2.digest());

    // Bytes
    let mut h1 = PallasHasher::new();
    let mut h2 = PallasHasher::new();
    h1.update(vec![1u8, 2, 3, 4, 5]);
    h2.update(vec![1u8, 2, 3, 4, 5]);
    assert_eq!(h1.digest(), h2.digest());
}

#[test]
fn test_determinism_mixed_sequence() {
    let mut h1 = PallasHasher::new();
    let mut h2 = PallasHasher::new();

    let seq: Vec<PallasInput> = vec![
        42u64.into(),
        true.into(),
        "abc".to_string().into(),
        vec![9u8, 8, 7].into(),
    ];

    for item in &seq { h1.update(item.clone()); }
    for item in &seq { h2.update(item.clone()); }

    assert_eq!(h1.digest(), h2.digest());
}
