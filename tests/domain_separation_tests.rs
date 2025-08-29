use poseidon_hash::PoseidonHasher;
use poseidon_hash::types::PallasHasher;

#[test]
fn test_different_domains_produce_different_hashes() {
    let mut h_vrf = PallasHasher::new_with_domain("VRF_DOMAIN");
    let mut h_block = PallasHasher::new_with_domain("BLOCK_HASH_DOMAIN");

    h_vrf.update(12345u64);
    h_block.update(12345u64);

    let hv = h_vrf.digest();
    let hb = h_block.digest();

    assert_ne!(hv, hb, "Different domains must produce different hashes");
}

#[test]
fn test_same_domain_same_inputs_equal() {
    let mut h1 = PallasHasher::new_with_domain("VRF_DOMAIN");
    let mut h2 = PallasHasher::new_with_domain("VRF_DOMAIN");

    h1.update(42u64);
    h2.update(42u64);

    assert_eq!(h1.digest(), h2.digest());
}
