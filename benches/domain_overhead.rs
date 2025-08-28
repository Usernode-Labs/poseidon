use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use poseidon_hash::*;
use poseidon_hash::PoseidonHasher;

fn compress2_with_domain(domain: &str, a: ark_pallas::Fq, b: ark_pallas::Fq) -> ark_pallas::Fq {
    let mut h = PallasHasher::new_with_domain(domain);
    h.update(a);
    h.update(b);
    h.finalize()
}

fn bench_domain_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_overhead_per_node");
    let a = ark_pallas::Fq::from(1u64);
    let b = ark_pallas::Fq::from(2u64);

    let domains: Vec<(&str, String)> = vec![
        ("short", "D".to_string()),
        ("medium", "MERKLE2".to_string()),
        ("long32", "X".repeat(32)),
        ("long64", "Y".repeat(64)),
    ];

    // Baseline: no domain
    group.bench_function(BenchmarkId::new("baseline_no_domain", 2), |bch| {
        bch.iter_batched(
            || PallasHasher::new(),
            |mut h| { h.update(a); h.update(b); let _ = h.finalize(); },
            BatchSize::SmallInput,
        );
    });

    // DiR baseline: no domain in-rate (constructor only)
    group.bench_function(BenchmarkId::new("dir_baseline_no_domain", 2), |bch| {
        bch.iter_batched(
            || PallasHasher::new_dir(),
            |mut h| { h.update(a); h.update(b); let _ = h.finalize(); },
            BatchSize::SmallInput,
        );
    });

    for (label, dom) in domains.iter() {
        group.bench_function(BenchmarkId::new(*label, 2), |bch| {
            bch.iter(|| compress2_with_domain(dom.as_str(), a, b));
        });
        // DiR with domain
        group.bench_function(BenchmarkId::new(&format!("dir_{}", label), 2), |bch| {
            bch.iter_batched(
                || PallasHasher::new_with_domain_dir(dom.as_str()),
                |mut h| { let mut hh = h; hh.update(a); hh.update(b); let _ = hh.finalize(); },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_domain_overhead);
criterion_main!(benches);
