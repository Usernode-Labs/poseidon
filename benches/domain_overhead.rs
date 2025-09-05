use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;

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

    // Baseline (DiR): no domain
    group.bench_function(BenchmarkId::new("baseline_no_domain", 2), |bch| {
        bch.iter_batched(
            PallasHasher::new,
            |mut h| {
                h.update(a);
                h.update(b);
                let _ = h.finalize();
            },
            BatchSize::SmallInput,
        );
    });

    for (label, dom) in domains.iter() {
        group.bench_function(BenchmarkId::new(*label, 2), |bch| {
            bch.iter(|| compress2_with_domain(dom.as_str(), a, b));
        });
        // DiR with domain (default)
        group.bench_function(BenchmarkId::new(label.to_string(), 2), |bch| {
            bch.iter_batched(
                || PallasHasher::new_with_domain(dom.as_str()),
                |mut h| {
                    h.update(a);
                    h.update(b);
                    let _ = h.finalize();
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_domain_overhead);
criterion_main!(benches);
