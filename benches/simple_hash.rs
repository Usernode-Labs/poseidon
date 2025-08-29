use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;

// Deterministic pseudo-random generator over the field via from(u64)
fn gen_inputs_pallas(n: usize) -> Vec<ark_pallas::Fq> {
    (0..n)
        .map(|i| ark_pallas::Fq::from((i as u64).wrapping_mul(0x9E3779B97F4A7C15)))
        .collect()
}

fn bench_simple_hash_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("simple_hash_stream");
    for &n in &[128usize, 1024, 4096, 16384] {
        let inputs = gen_inputs_pallas(n);
        group.throughput(Throughput::Bytes((n * 32) as u64));
        group.bench_with_input(
            BenchmarkId::new("pallas_update_digest", n),
            &inputs,
            |b, inputs| {
                b.iter_batched(
                    || PallasHasher::new_with_domain("STREAM"),
                    |mut hasher| {
                        for &x in inputs.iter() {
                            hasher.update(x);
                        }
                        let _ = hasher.digest();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_simple_hash_reuse_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("simple_hash_reuse_reset");
    let n = 4096usize;
    let inputs = gen_inputs_pallas(n);
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function("pallas_reuse_reset_per_elem", |b| {
        b.iter_batched(
            || PallasHasher::new_with_domain("REUSE"),
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

criterion_group!(
    benches,
    bench_simple_hash_stream,
    bench_simple_hash_reuse_reset
);
criterion_main!(benches);
