use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use poseidon_hash::BN254Poseidon2Hasher;
use poseidon_hash::PoseidonHasher;

// Deterministic pseudo-random generator over the field via from(u64)
fn gen_inputs_bn254(n: usize) -> Vec<ark_bn254::Fq> {
    (0..n)
        .map(|i| ark_bn254::Fq::from((i as u64).wrapping_mul(0x9E3779B97F4A7C15)))
        .collect()
}

fn bench_simple_hash_stream_poseidon2_bn254(c: &mut Criterion) {
    let mut group = c.benchmark_group("simple_hash_stream_poseidon2_bn254");
    for &n in &[128usize, 1024, 4096, 16384] {
        let inputs = gen_inputs_bn254(n);
        group.throughput(Throughput::Bytes((n * 32) as u64));
        group.bench_with_input(
            BenchmarkId::new("bn2542_update_digest", n),
            &inputs,
            |b, inputs| {
                b.iter_batched(
                    || BN254Poseidon2Hasher::new_with_domain("STREAM2_BN"),
                    |mut hasher| {
                        for &x in inputs.iter() { hasher.update(x); }
                        let _ = hasher.digest();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_simple_hash_reuse_reset_poseidon2_bn254(c: &mut Criterion) {
    let mut group = c.benchmark_group("simple_hash_reuse_reset_poseidon2_bn254");
    let n = 4096usize;
    let inputs = gen_inputs_bn254(n);
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function("bn2542_reuse_reset_per_elem", |b| {
        b.iter_batched(
            || BN254Poseidon2Hasher::new_with_domain("REUSE2_BN"),
            |mut hasher| {
                for &x in inputs.iter() {
                    hasher.update(x);
                    let _ = hasher.digest();
                    hasher.reset();
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_simple_hash_minimal_poseidon2_bn254(c: &mut Criterion) {
    // Measures a single digest after absorbing exactly 3 elements (t=4 → rate=3)
    let mut group = c.benchmark_group("simple_hash_minimal_poseidon2_bn254");
    group.bench_function("bn2542_absorb3_digest", |b| {
        b.iter_batched(
            || BN254Poseidon2Hasher::new_with_domain("MIN2_BN"),
            |mut hasher| {
                hasher.update(ark_bn254::Fq::from(1u64));
                hasher.update(ark_bn254::Fq::from(2u64));
                hasher.update(ark_bn254::Fq::from(3u64));
                let _ = hasher.digest();
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_simple_hash_stream_poseidon2_bn254,
    bench_simple_hash_reuse_reset_poseidon2_bn254,
    bench_simple_hash_minimal_poseidon2_bn254
);
criterion_main!(benches);
