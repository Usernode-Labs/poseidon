use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

fn gen_inputs_pallas(n: usize) -> Vec<ark_pallas::Fq> {
    (0..n).map(|i| ark_pallas::Fq::from((i as u64).wrapping_mul(0x9E3779B97F4A7C15))).collect()
}

// Baseline: per-node create hasher, absorb two children with tags, finalize
fn compress2_new(a: ark_pallas::Fq, b: ark_pallas::Fq) -> ark_pallas::Fq {
    let mut h = PallasHasher::new_with_domain("MERKLE2");
    h.update(a);
    h.update(b);
    h.finalize()
}

// Variant: reuse one hasher; digest() + reset() per node
fn compress2_reuse(h: &mut PallasHasher, a: ark_pallas::Fq, b: ark_pallas::Fq) -> ark_pallas::Fq {
    h.update(a);
    h.update(b);
    let out = h.digest();
    h.reset();
    out
}

// Domain-in-Rate variants using the integrated constructors
fn compress2_dir_new(a: ark_pallas::Fq, b: ark_pallas::Fq) -> ark_pallas::Fq {
    let mut h = PallasHasher::new_with_domain_dir("MERKLE2");
    h.update(a);
    h.update(b);
    h.finalize()
}

fn compress2_dir_reuse(h: &mut PallasHasher, a: ark_pallas::Fq, b: ark_pallas::Fq) -> ark_pallas::Fq {
    h.update(a);
    h.update(b);
    let out = h.digest();
    h.reset();
    out
}

fn build_merkle_binary_new(leaves: &[ark_pallas::Fq]) -> ark_pallas::Fq {
    assert!(leaves.len() >= 2 && leaves.len().is_power_of_two());
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|c| compress2_new(c[0], c[1]))
            .collect();
    }
    level[0]
}

fn build_merkle_binary_reuse(leaves: &[ark_pallas::Fq]) -> ark_pallas::Fq {
    assert!(leaves.len() >= 2 && leaves.len().is_power_of_two());
    let mut level = leaves.to_vec();
    let mut h = PallasHasher::new_with_domain("MERKLE2");
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for c in level.chunks_exact(2) {
            next.push(compress2_reuse(&mut h, c[0], c[1]));
        }
        level = next;
    }
    level[0]
}

fn bench_compress2(c: &mut Criterion) {
    let mut group = c.benchmark_group("compress2_binary");
    let pairs = gen_inputs_pallas(1 << 12); // 4096 elems -> 2048 pairs
    let num_pairs = pairs.len() / 2;
    group.throughput(Throughput::Elements(num_pairs as u64));

    group.bench_function("new_per_node", |b| {
        b.iter_batched(
            || pairs.clone(),
            |inputs| {
                let mut acc = ark_pallas::Fq::from(0u64);
                for chunk in inputs.chunks_exact(2) {
                    acc += compress2_new(chunk[0], chunk[1]);
                }
                acc
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("reuse_reset", |b| {
        b.iter_batched(
            || (pairs.clone(), PallasHasher::new_with_domain("MERKLE2")),
            |(inputs, mut h)| {
                let mut acc = ark_pallas::Fq::from(0u64);
                for chunk in inputs.chunks_exact(2) {
                    acc += compress2_reuse(&mut h, chunk[0], chunk[1]);
                }
                acc
            },
            BatchSize::SmallInput,
        )
    });

    // Domain-in-Rate counterparts in the same group for side-by-side comparison
    group.bench_function("dir_new_per_node", |b| {
        b.iter_batched(
            || pairs.clone(),
            |inputs| {
                let mut acc = ark_pallas::Fq::from(0u64);
                for chunk in inputs.chunks_exact(2) {
                    acc += compress2_dir_new(chunk[0], chunk[1]);
                }
                acc
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("dir_reuse_reset", |b| {
        b.iter_batched(
            || (pairs.clone(), PallasHasher::new_with_domain_dir("MERKLE2")),
            |(inputs, mut h)| {
                let mut acc = ark_pallas::Fq::from(0u64);
                for chunk in inputs.chunks_exact(2) {
                    acc += compress2_dir_reuse(&mut h, chunk[0], chunk[1]);
                }
                acc
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_merkle_tree_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_binary_build");
    for &n_leaves in &[1usize << 8, 1 << 12, 1 << 14] { // 256, 4096, 16384
        let leaves = gen_inputs_pallas(n_leaves);
        group.throughput(Throughput::Elements(n_leaves as u64));

        group.bench_with_input(BenchmarkId::new("new_per_node", n_leaves), &leaves, |b, leaves| {
            b.iter_batched(|| leaves.clone(), |l| build_merkle_binary_new(&l), BatchSize::SmallInput)
        });

        group.bench_with_input(BenchmarkId::new("reuse_reset", n_leaves), &leaves, |b, leaves| {
            b.iter_batched(|| leaves.clone(), |l| build_merkle_binary_reuse(&l), BatchSize::SmallInput)
        });

        // DiR versions
        group.bench_with_input(BenchmarkId::new("dir_new_per_node", n_leaves), &leaves, |b, leaves| {
            b.iter_batched(|| leaves.clone(), |l| {
                assert!(l.len().is_power_of_two());
                let mut level = l.clone();
                while level.len() > 1 {
                    level = level
                        .chunks_exact(2)
                        .map(|c| compress2_dir_new(c[0], c[1]))
                        .collect();
                }
                level[0]
            }, BatchSize::SmallInput)
        });

        group.bench_with_input(BenchmarkId::new("dir_reuse_reset", n_leaves), &leaves, |b, leaves| {
            b.iter_batched(|| leaves.clone(), |l| {
                assert!(l.len().is_power_of_two());
                let mut level = l.clone();
                let mut h = PallasHasher::new_with_domain_dir("MERKLE2");
                while level.len() > 1 {
                    let mut next = Vec::with_capacity(level.len() / 2);
                    for c in level.chunks_exact(2) {
                        next.push(compress2_dir_reuse(&mut h, c[0], c[1]));
                    }
                    level = next;
                }
                level[0]
            }, BatchSize::SmallInput)
        });
    }
    group.finish();
}

criterion_group!(benches, bench_compress2, bench_merkle_tree_build);
criterion_main!(benches);
