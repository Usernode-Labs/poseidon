use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

#[test]
fn test_string_vs_bytes_same_content_differ() {
    let s = "hello".to_string();
    let b = b"hello".to_vec();

    let mut hs = PallasHasher::new();
    hs.update(s);
    let hs_hash = hs.digest();

    let mut hb = PallasHasher::new();
    hb.update(b);
    let hb_hash = hb.digest();

    assert_ne!(hs_hash, hb_hash, "String and Bytes must hash differently due to tags");
}

#[test]
fn test_domain_only_same_across_packing_configs() {
    // With no payload, only the domain affects the state. Since domain encoding is fixed,
    // different packing configs should produce the same digest.
    let domain = "DOMAIN_ONLY";

    let mut h_default = PallasHasher::new_with_domain(domain);
    let default_hash = h_default.digest();

    let cfg = PackingConfig { mode: PackingMode::CircuitFriendly, ..Default::default() };
    let mut h_circuit = PallasHasher::new_with_config_and_domain(cfg, domain);
    let circuit_hash = h_circuit.digest();

    assert_eq!(default_hash, circuit_hash, "Domain-only hash should be invariant to packing config");
}
