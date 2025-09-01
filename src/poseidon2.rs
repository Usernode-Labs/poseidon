use ark_crypto_primitives::sponge::{
    Absorb, CryptographicSponge, DuplexSpongeMode, FieldBasedCryptographicSponge, SpongeExt,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::grain_lfsr::PoseidonGrainLFSR;
// use ark_std::any::TypeId;

pub fn find_poseidon2_ark_and_mu<F: PrimeField>(
    prime_bits: u64,
    t: usize, // = rate + capacity (usually capacity=1)
    rf: u64,
    rp: u64,
) -> (Vec<Vec<F>>, Vec<F>) {
    // 1) ARK via Grain (unchanged)
    let mut lfsr = PoseidonGrainLFSR::new(false, prime_bits, t as u64, rf, rp);
    let mut ark = Vec::<Vec<F>>::with_capacity((rf + rp) as usize);
    for _ in 0..(rf + rp) {
        ark.push(lfsr.get_field_elements_rejection_sampling(t));
    }

    // 2) μ for the internal matrix (from Grain, with safety checks)
    let mu = gen_mu_internal_from_grain::<F>(&mut lfsr, t);

    (ark, mu)
}

// ---------------- μ generation ----------------

fn gen_mu_internal_from_grain<F: PrimeField>(lsfr: &mut PoseidonGrainLFSR, t: usize) -> Vec<F> {
    loop {
        // draw t candidates (canonical field elements), discard zeros
        let mu: Vec<F> = lsfr
            .get_field_elements_mod_p::<F>(t)
            .into_iter()
            .filter(|x| !x.is_zero())
            .collect();
        if mu.len() != t {
            continue;
        }

        if has_duplicates(&mu) {
            continue;
        } // optional but recommended
        if !invertible_j_plus_diag(&mu) {
            continue;
        } // det(J+Diag(μ)) ≠ 0

        // Small-t extras (paper makes M_int MDS for t∈{2,3})
        // TODO: remove, we will hardcode small t∈{2,3} MDS matrices
        let ok = match t {
            2 => {
                let one = F::one();
                (mu[0] * mu[1] - one) != F::zero() // μ0μ1 ≠ 1
            }
            3 => {
                let one = F::one();
                if mu[0] * mu[1] == one || mu[0] * mu[2] == one || mu[1] * mu[2] == one {
                    false
                } else {
                    let two = one + one;
                    (mu[0] * mu[1] * mu[2] - mu[0] - mu[1] - mu[2] + two) != F::zero()
                }
            }
            _ => true,
        };
        if !ok {
            continue;
        }

        return mu;
    }
}

fn has_duplicates<F: PrimeField>(v: &[F]) -> bool {
    for i in 0..v.len() {
        for j in i + 1..v.len() {
            if v[i] == v[j] {
                return true;
            }
        }
    }
    false
}

// det(J + Diag(μ)) = (∏ μ_i) * (1 + Σ μ_i^{-1})  (matrix determinant lemma)
fn invertible_j_plus_diag<F: PrimeField>(mu: &[F]) -> bool {
    let mut prod = F::one();
    let mut sum_inv = F::zero();
    for &m in mu {
        let inv = match m.inverse() {
            Some(v) => v,
            None => return false,
        };
        prod *= m;
        sum_inv += inv;
    }
    (prod * (F::one() + sum_inv)) != F::zero()
}

// The sponge is from arkworks, it holds for poseidon2 as well, the permutation is from the reference impl of poseidon2

/// Config and RNG used
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonConfig<F: PrimeField> {
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Exponent used in S-boxes.
    pub d: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: Vec<Vec<F>>,
    /// Poseidon2 internal diagonal mu for the cheap internal matrix J + Diag(mu).
    pub mu: Vec<F>,
    /// Maximally Distance Separating (MDS) Matrix.
    pub mds: Vec<Vec<F>>,
    /// The rate (in terms of number of field elements).
    /// See [On the Indifferentiability of the Sponge Construction](https://iacr.org/archive/eurocrypt2008/49650180/49650180.pdf)
    /// for more details on the rate and capacity of a sponge.
    pub rate: usize,
    /// The capacity (in terms of number of field elements).
    pub capacity: usize,
}

#[derive(Clone)]
/// A duplex sponge based using the Poseidon permutation.
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct Poseidon2Sponge<F: PrimeField> {
    /// Sponge Config
    pub parameters: PoseidonConfig<F>,

    // Sponge State
    /// Current sponge's state (current elements in the permutation block)
    pub state: Vec<F>,
    /// Current mode (whether its absorbing or squeezing)
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> Poseidon2Sponge<F> {
    // Poseidon2: efficient 4x4 mixing applied per 4-lane block
    // This implements y = M4 * x with the cheap add/double schedule, where
    // M4 = [ [5,7,1,3],
    //        [4,6,1,1],
    //        [1,3,5,7],
    //        [1,1,4,6] ].
    fn matmul_m4(state: &mut [F]) {
        let t = state.len();
        let t4 = t / 4;
        for i in 0..t4 {
            let s = i * 4;
            let mut t0 = state[s];
            t0.add_assign(&state[s + 1]);
            let mut t1 = state[s + 2];
            t1.add_assign(&state[s + 3]);
            let mut t2 = state[s + 1];
            t2.double_in_place();
            t2.add_assign(&t1);
            let mut t3 = state[s + 3];
            t3.double_in_place();
            t3.add_assign(&t0);
            let mut t4 = t1;
            t4.double_in_place();
            t4.double_in_place();
            t4.add_assign(&t3);
            let mut t5 = t0;
            t5.double_in_place();
            t5.double_in_place();
            t5.add_assign(&t2);
            let mut t6 = t3;
            t6.add_assign(&t5);
            let mut t7 = t2;
            t7.add_assign(&t4);
            state[s] = t6;
            state[s + 1] = t5;
            state[s + 2] = t7;
            state[s + 3] = t4;
        }
    }

    // Poseidon2: external matrix (cheap MDS) + leading application
    // For t=2: y = [ [2,1], [1,2] ] * x (circ(2,1)).
    // For t=3: y = matrix with 2 on diagonal, 1 elsewhere (circ(2,1,1)).
    // For t=4: y = M4 * x, where M4 is as in matmul_m4.
    // For t in {8,12,16,20,24}: apply M4 to each 4-lane block, then add lane-wise
    // sums across blocks; this matches the block-circulant external matrix where
    // diagonal blocks are 2*M4 and off-diagonal blocks are M4.
    fn matmul_external(state: &mut [F]) {
        let t = state.len();
        match t {
            2 => {
                let mut sum = state[0];
                sum.add_assign(&state[1]);
                state[0].add_assign(&sum);
                state[1].add_assign(&sum);
            }
            3 => {
                let mut sum = state[0];
                sum.add_assign(&state[1]);
                sum.add_assign(&state[2]);
                state[0].add_assign(&sum);
                state[1].add_assign(&sum);
                state[2].add_assign(&sum);
            }
            4 => {
                Self::matmul_m4(state);
            }
            8 | 12 | 16 | 20 | 24 => {
                // First, block-wise 4x4
                Self::matmul_m4(state);
                // Then, add lane-wise sums across 4-lane blocks
                let t4 = t / 4;
                let mut stored: [F; 4] = [F::zero(), F::zero(), F::zero(), F::zero()];
                for l in 0..4 {
                    stored[l] = state[l];
                    for j in 1..t4 {
                        stored[l].add_assign(&state[4 * j + l]);
                    }
                }
                for i in 0..t {
                    state[i].add_assign(&stored[i % 4]);
                }
            }
            _ => panic!("unsupported Poseidon2 t for external matrix"),
        }
    }

    // Poseidon2: internal matrix y_i = (sum x_j) + mu_i * x_i
    fn matmul_internal_with_mu(state: &mut [F], mu: &[F]) {
        let t = state.len();
        match t {
            2 => {
                // Concrete internal matrix for t=2:
                // [2, 1]
                // [1, 3]
                let mut sum = state[0];
                sum.add_assign(&state[1]);
                state[0].add_assign(&sum);
                state[1].double_in_place();
                state[1].add_assign(&sum);
            }
            3 => {
                // Concrete internal matrix for t=3:
                // [2, 1, 1]
                // [1, 2, 1]
                // [1, 1, 3]
                let mut sum = state[0];
                sum.add_assign(&state[1]);
                sum.add_assign(&state[2]);
                state[0].add_assign(&sum);
                state[1].add_assign(&sum);
                state[2].double_in_place();
                state[2].add_assign(&sum);
            }
            4 | 8 | 12 | 16 | 20 | 24 => {
                let mut sum = state[0];
                for j in 1..t {
                    sum.add_assign(&state[j]);
                }
                for i in 0..t {
                    state[i].mul_assign(&mu[i]);
                    state[i].add_assign(&sum);
                }
            }
            _ => panic!("unsupported Poseidon2 t for internal matrix"),
        }
    }

    fn apply_s_box(state: &mut [F], is_full_round: bool, d: u64) {
        // Performance optimization
        let sbox_p = |input: &mut F| -> F {
            let mut input2 = *input;
            input2.square_in_place();

            match d {
                3 => {
                    let mut out = input2;
                    out.mul_assign(input);
                    out
                }
                5 => {
                    let mut out = input2;
                    out.square_in_place();
                    out.mul_assign(input);
                    out
                }
                7 => {
                    let mut out = input2;
                    out.square_in_place();
                    out.mul_assign(&input2);
                    out.mul_assign(input);
                    out
                }
                _ => {
                    panic!()
                }
            }
        };

        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = sbox_p(elem);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = sbox_p(&mut state[0]);
        }
    }

    fn permute(&mut self) {
        // Poseidon2 round structure (inline):
        // 1) external linear layer at beginning
        // 2) rf/2 full rounds: +ARK (all lanes), S-box (all), external mix
        // 3) rp partial rounds: +ARK (lane 0), S-box (lane 0), internal mix (J+Diag(mu))
        // 4) rf/2 full rounds: +ARK (all), S-box (all), external mix

        let rf = self.parameters.full_rounds;
        let rp = self.parameters.partial_rounds;
        let d = self.parameters.d;
        let mu = &self.parameters.mu;

        // 1) pre-round external mix
        Self::matmul_external(&mut self.state);

        // 2) first half full rounds
        let fr_half = rf / 2;
        for r in 0..fr_half {
            // add round constants to all lanes
            for (i, lane) in self.state.iter_mut().enumerate() {
                lane.add_assign(&self.parameters.ark[r][i]);
            }
            // S-box on all lanes
            Self::apply_s_box(&mut self.state, true, d);
            // external mix
            Self::matmul_external(&mut self.state);
        }

        // 3) partial rounds
        for r in fr_half..(fr_half + rp) {
            // add round constant only to first lane
            self.state[0].add_assign(&self.parameters.ark[r][0]);
            // S-box only first lane
            Self::apply_s_box(&mut self.state, false, d);
            // internal cheap mix using mu
            Self::matmul_internal_with_mu(&mut self.state, mu);
        }

        // 4) second half full rounds
        for r in (fr_half + rp)..(rf + rp) {
            for (i, lane) in self.state.iter_mut().enumerate() {
                lane.add_assign(&self.parameters.ark[r][i]);
            }
            Self::apply_s_box(&mut self.state, true, d);
            Self::matmul_external(&mut self.state);
        }
    }

    /// Compress 3 field elements into 1 using a single Poseidon2 permutation.
    ///
    /// Requires t=4 (rate=3, capacity=1) parameters. Builds a state
    /// [0, x0, x1, x2] with capacity lane set to 0, runs one permutation,
    /// and returns the first lane.
    pub fn compress_3(&self, x0: F, x1: F, x2: F) -> F {
        assert_eq!(
            self.parameters.rate + self.parameters.capacity,
            4,
            "compress_3 requires t=4 parameters"
        );
        assert_eq!(self.parameters.capacity, 1, "compress_3 expects capacity=1");
        assert_eq!(self.parameters.rate, 3, "compress_3 expects rate=3");

        let mut tmp = self.clone();
        // Place capacity as the last lane: [x0, x1, x2, 0]
        tmp.state = vec![x0, x1, x2, F::zero()];
        tmp.permute();
        tmp.state[0]
    }

    #[cfg(test)]
    pub fn permute_state_for_test(&self, state: &mut [F]) {
        let mut tmp = self.clone();
        tmp.state = state.to_vec();
        tmp.permute();
        state.clone_from_slice(&tmp.state);
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.parameters.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.parameters.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.parameters.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.parameters.capacity + i + rate_start_index] += element;
            }
            self.permute();
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, mut rate_start_index: usize, output: &mut [F]) {
        let mut output_remaining = output;
        loop {
            // if we can finish in this call
            if rate_start_index + output_remaining.len() <= self.parameters.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Repeat with updated output slices
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            // Unless we are done with squeezing in this call, permute.
            if !output_remaining.is_empty() {
                self.permute();
            }

            rate_start_index = 0;
        }
    }
}

impl<F: PrimeField> PoseidonConfig<F> {
    /// Initialize the parameter for Poseidon Sponge.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        full_rounds: usize,
        partial_rounds: usize,
        d: u64,
        mds: Vec<Vec<F>>,
        ark: Vec<Vec<F>>,
        mu: Vec<F>,
        rate: usize,
        capacity: usize,
    ) -> Self {
        assert_eq!(ark.len(), full_rounds + partial_rounds);
        for item in &ark {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(mds.len(), rate + capacity);
        for item in &mds {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(
            mu.len(),
            rate + capacity,
            "mu length must equal t (rate+capacity)"
        );
        Self {
            full_rounds,
            partial_rounds,
            d,
            mds,
            ark,
            mu,
            rate,
            capacity,
        }
    }
}

impl<F: PrimeField> CryptographicSponge for Poseidon2Sponge<F> {
    type Config = PoseidonConfig<F>;

    fn new(parameters: &Self::Config) -> Self {
        let state = vec![F::zero(); parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            parameters: parameters.clone(),
            state,
            mode,
        }
    }

    fn absorb(&mut self, input: &impl Absorb) {
        let elems = input.to_sponge_field_elements_as_vec::<F>();
        if elems.is_empty() {
            return;
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.parameters.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems.as_slice());
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.absorb_internal(0, elems.as_slice());
            }
        };
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let usable_bytes = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_native_field_elements(num_elements);

        let mut bytes: Vec<u8> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            let elem_bytes = elem.into_bigint().to_bytes_le();
            bytes.extend_from_slice(&elem_bytes[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        bytes
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let usable_bits = (F::MODULUS_BIT_SIZE - 1) as usize;

        let num_elements = (num_bits + usable_bits - 1) / usable_bits;
        let src_elements = self.squeeze_native_field_elements(num_elements);

        let mut bits: Vec<bool> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            let elem_bits = elem.into_bigint().to_bits_le();
            bits.extend_from_slice(&elem_bits[..usable_bits]);
        }

        bits.truncate(num_bits);
        bits
    }

    // fn squeeze_field_elements_with_sizes<F2: PrimeField>(
    //     &mut self,
    //     sizes: &[FieldElementSize],
    // ) -> Vec<F2> {
    //     if F::characteristic() == F2::characteristic() {
    //         // native case
    //         let mut buf = Vec::with_capacity(sizes.len());
    //         field_cast(
    //             &self.squeeze_native_field_elements_with_sizes(sizes),
    //             &mut buf,
    //         )
    //         .unwrap();
    //         buf
    //     } else {
    //         squeeze_field_elements_with_sizes_default_impl(self, sizes)
    //     }
    // }

    // fn squeeze_field_elements<F2: PrimeField>(&mut self, num_elements: usize) -> Vec<F2> {
    //     if TypeId::of::<F>() == TypeId::of::<F2>() {
    //         let result = self.squeeze_native_field_elements(num_elements);
    //         let mut cast = Vec::with_capacity(result.len());
    //         field_cast(&result, &mut cast).unwrap();
    //         cast
    //     } else {
    //         self.squeeze_field_elements_with_sizes::<F2>(
    //             vec![FieldElementSize::Full; num_elements].as_slice(),
    //         )
    //     }
    // }
}

impl<F: PrimeField> FieldBasedCryptographicSponge<F> for Poseidon2Sponge<F> {
    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.parameters.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}

#[derive(Clone)]
/// Stores the state of a Poseidon Sponge. Does not store any parameter.
pub struct PoseidonSpongeState<F: PrimeField> {
    state: Vec<F>,
    mode: DuplexSpongeMode,
}

impl<CF: PrimeField> SpongeExt for Poseidon2Sponge<CF> {
    type State = PoseidonSpongeState<CF>;

    fn from_state(state: Self::State, params: &Self::Config) -> Self {
        let mut sponge = Self::new(params);
        sponge.mode = state.mode;
        sponge.state = state.state;
        sponge
    }

    fn into_state(self) -> Self::State {
        Self::State {
            state: self.state,
            mode: self.mode,
        }
    }
}

#[cfg(test)]
mod poseidon2_pallas_kats {
    use super::*;
    use ark_ff::{PrimeField, Zero};

    fn hex_be_to_fq(hex: &str) -> ark_pallas::Fq {
        let h = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(h).expect("valid hex");
        ark_pallas::Fq::from_be_bytes_mod_order(&bytes)
    }

    #[test]
    /// Test vector from HL reference implementation for Poseidon2 over Pallas, t=3
    fn permutation_kat_pallas_t3() {
        type F = ark_pallas::Fq;
        // Parse vendored HL RC3 from resource file to avoid giant code constants
        let rc_txt = include_str!("../tests/resources/hl_pallas.rc3.txt");
        fn parse_hex_fq(h: &str) -> F {
            let s = h.trim();
            let hh = s.strip_prefix("0x").unwrap_or(s);
            F::from_be_bytes_mod_order(&hex::decode(hh).unwrap())
        }
        let t = 3usize;
        let rf = 8usize;
        let rp = 56usize;
        let d = 5u64;
        // Extract all 0x... hex triples per row
        let mut ark: Vec<Vec<F>> = Vec::new();
        let mut collecting = false;
        let mut row: Vec<F> = Vec::new();
        for line in rc_txt.lines() {
            if line.contains("vec![") {
                collecting = true;
                row.clear();
            }
            if collecting {
                for cap in line.split('"').filter(|s| s.starts_with("0x")) {
                    row.push(parse_hex_fq(cap));
                }
                if line.contains("],") {
                    collecting = false;
                    if row.len() == 3 {
                        ark.push(row.clone());
                    }
                    row.clear();
                }
            }
        }
        assert_eq!(ark.len(), rf + rp, "HL RC3 rows must equal rf+rp");
        // HL MAT_DIAG3_M_1 is [1,1,2]
        let mu = vec![F::from(1u64), F::from(1u64), F::from(2u64)];
        let mds = crate::parameters::poseidon2::identity_mds::<F>(t);
        let cfg = PoseidonConfig::new(rf, rp, d, mds, ark, mu, t - 1, 1);
        let sponge = Poseidon2Sponge::<F>::new(&cfg);
        let mut state = [F::from(0u64), F::from(1u64), F::from(2u64)];
        sponge.permute_state_for_test(&mut state);

        let exp0 =
            hex_be_to_fq("0x1a9b54c7512a914dd778282c44b3513fea7251420b9d95750baae059b2268d7a");
        let exp1 =
            hex_be_to_fq("0x1c48ea0994a7d7984ea338a54dbf0c8681f5af883fe988d59ba3380c9f7901fc");
        let exp2 =
            hex_be_to_fq("0x079ddd0a80a3e9414489b526a2770448964766685f4c4842c838f8a23120b401");

        assert_eq!(state[0], exp0);
        assert_eq!(state[1], exp1);
        assert_eq!(state[2], exp2);
    }

    #[test]
    fn compress_3_matches_one_perm_t4_pallas() {
        type F = ark_pallas::Fq;
        use crate::parameters::poseidon2_pallas::PALLAS_POSEIDON2_PARAMS_T4;

        let sponge = Poseidon2Sponge::<F>::new(&*PALLAS_POSEIDON2_PARAMS_T4);
        let a = F::from(1u64);
        let b = F::from(2u64);
        let c = F::from(3u64);

        // Manual one-permutation on [a, b, c, 0]
        let mut manual = sponge.clone();
        manual.state = vec![a, b, c, F::zero()];
        manual.permute();
        let expected = manual.state[0];

        // compress_3 should match
        let out = sponge.compress_3(a, b, c);
        assert_eq!(out, expected);
    }
}
