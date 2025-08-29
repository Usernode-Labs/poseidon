use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use poseidon_hash::PoseidonHasher;
use poseidon_hash::*;

fn bench_rate_thresholds(c: &mut Criterion) {
    // Current params: t=3, rate=2. We sweep m=1..12 inputs to provide a
    // baseline for future larger-t comparisons while still using the crate API.
    let mut group = c.benchmark_group("rate_thresholds_pallas");
    let inputs: Vec<ark_pallas::Fq> = (1u64..=12).map(|i| ark_pallas::Fq::from(i)).collect();

    for m in 1..=12usize {
        group.throughput(Throughput::Elements(m as u64));
        // Tagged path
        group.bench_with_input(
            BenchmarkId::new("tagged_absorb_m_digest", m),
            &m,
            |bch, &mm| {
                bch.iter_batched(
                    || PallasHasher::new_with_domain("RATE"),
                    |mut h| {
                        for i in 0..mm {
                            h.update(inputs[i]);
                        }
                        let _ = h.digest();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        // DiR path
        group.bench_with_input(
            BenchmarkId::new("dir_absorb_m_digest", m),
            &m,
            |bch, &mm| {
                bch.iter_batched(
                    || PallasHasher::new_with_domain_dir("RATE"),
                    |mut h| {
                        for i in 0..mm {
                            h.update(inputs[i]);
                        }
                        let _ = h.digest();
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_rate_thresholds);
criterion_main!(benches);
