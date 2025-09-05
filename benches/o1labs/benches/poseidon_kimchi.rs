use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput, black_box};
use mina_curves::pasta::Fp;
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    pasta::fp_kimchi as SpongeParametersKimchi,
    poseidon::{ArithmeticSponge as Poseidon, Sponge},
};

fn bench_minimal(c: &mut Criterion) {
    // Measures one block: absorb 2 (t=3, rate=2) then squeeze once
    let mut group = c.benchmark_group("o1labs_poseidon_minimal");
    group.bench_function("absorb2_digest", |b| {
        b.iter_batched(
            || Poseidon::<Fp, PlonkSpongeConstantsKimchi>::new(SpongeParametersKimchi::static_params()),
            |mut sp| {
                sp.absorb(&[Fp::from(1u64), Fp::from(2u64)]);
                let _ = black_box(sp.squeeze());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_stream(c: &mut Criterion) {
    // Absorb N elements then squeeze once, mirroring our simple_hash_stream
    let mut group = c.benchmark_group("o1labs_poseidon_stream");
    for &n in &[128usize, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes((n * 32) as u64));
        group.bench_with_input(BenchmarkId::new("update_digest", n), &n, |b, &nn| {
            b.iter_batched(
                || {
                    let inputs: Vec<Fp> = (0..nn as u64).map(Fp::from).collect();
                    (
                        Poseidon::<Fp, PlonkSpongeConstantsKimchi>::new(SpongeParametersKimchi::static_params()),
                        inputs,
                    )
                },
                |(mut sp, inputs)| {
                    sp.absorb(&inputs);
                    let _ = black_box(sp.squeeze());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_minimal, bench_stream);
criterion_main!(benches);

