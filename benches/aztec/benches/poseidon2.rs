use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use acir_field::FieldElement as FE;
use acir_field::AcirField;

fn permute4_bn254(inputs: &[FE; 4]) -> [FE; 4] {
    // Convert inputs to big-endian 32B chunks
    let mut in_bytes = Vec::with_capacity(4 * 32);
    for x in inputs.iter() {
        let be = x.to_be_bytes();
        in_bytes.extend_from_slice(&be[be.len() - 32..]);
    }

    let mut out_ptr: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let rc = unsafe {
        aztec_barretenberg_sys_rs::bb_poseidon2_permutation_bn254(
            in_bytes.as_ptr(),
            4,
            &mut out_ptr,
            &mut out_len,
        )
    };
    assert_eq!(rc, 0, "bb_poseidon2_permutation_bn254 returned error: {}", rc);
    assert_eq!(out_len, 128, "unexpected output length: {}", out_len);

    let out_slice = unsafe { core::slice::from_raw_parts(out_ptr, out_len) };
    let mut out = [FE::zero(); 4];
    for i in 0..4 {
        let mut be = [0u8; 32];
        be.copy_from_slice(&out_slice[i * 32..(i + 1) * 32]);
        out[i] = FE::from_be_bytes_reduce(&be);
    }
    unsafe { aztec_barretenberg_sys_rs::bb_free(out_ptr) };
    out
}

// Lightweight, permutation-backed sponge with t=4, rate=3 (not for production use).
#[derive(Clone)]
struct Poseidon2Sponge {
    state: [FE; 4],
    idx: usize, // next rate slot to absorb into (0..3)
}

impl Poseidon2Sponge {
    fn new() -> Self {
        Self { state: [FE::zero(); 4], idx: 0 }
    }

    fn absorb(&mut self, x: FE) {
        // Add-absorb into current rate limb, permute when rate is full.
        self.state[self.idx] = self.state[self.idx] + x;
        self.idx += 1;
        if self.idx == 3 { // rate = 3
            self.state = permute4_bn254(&self.state);
            self.idx = 0;
        }
    }

    fn absorb_slice(&mut self, xs: &[FE]) {
        for &x in xs { self.absorb(x); }
    }

    fn digest(mut self) -> FE {
        // Simple padding to ensure completion: absorb domain "1" and finalize.
        self.state[self.idx] = self.state[self.idx] + FE::from(1u128);
        // Capacity tweak to avoid trivial collisions in this toy sponge.
        self.state[3] = self.state[3] + FE::from(1u128);
        self.state = permute4_bn254(&self.state);
        self.state[0]
    }
}

fn gen_inputs(n: usize) -> Vec<FE> {
    // Deterministic pseudo-random-ish sequence using multiplicative step
    (0..n)
        .map(|i| FE::from((i as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15)))
        .collect()
}

fn bench_minimal(c: &mut Criterion) {
    // One permutation over 4 elements; report the first limb as digest
    let mut group = c.benchmark_group("aztec_poseidon2_minimal");
    group.bench_function("permute4_digest", |b| {
        b.iter_batched(
            || [FE::from(1u128), FE::from(2u128), FE::from(3u128), FE::from(4u128)],
            |inputs| {
                let out = permute4_bn254(&inputs);
                let _ = black_box(out[0]);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_stream(c: &mut Criterion) {
    // Absorb N elements, finalize once. Mirrors our simple stream benches.
    let mut group = c.benchmark_group("aztec_poseidon2_stream");
    for &n in &[128usize, 1024, 4096, 16384] {
        let inputs = gen_inputs(n);
        group.throughput(Throughput::Bytes((n * 32) as u64));
        group.bench_with_input(BenchmarkId::new("update_digest", n), &inputs, |b, xs| {
            b.iter_batched(
                || Poseidon2Sponge::new(),
                |mut sp| {
                    sp.absorb_slice(xs);
                    let _ = black_box(sp.digest());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_minimal, bench_stream);
criterion_main!(benches);
