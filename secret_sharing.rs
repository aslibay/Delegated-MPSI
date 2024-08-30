use blake3::Hasher;
use rand::{rngs::OsRng, RngCore};
use std::{
    ops::BitXorAssign,
    simd::{mask8x64, u8x64, Simd},
};

use crate::SHARE_BYTE_COUNT;

pub struct SimdBytes {
    pub bytes: Vec<Simd<u8, 64>>,
}

impl SimdBytes {
    // TODO: Try #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        SimdBytes {
            bytes: bytes
                .chunks_exact(64)
                .into_iter()
                .map(u8x64::from_slice)
                .collect(),
        }
    }

    pub fn select(
        masks: &[mask8x64],
        true_values: SimdBytes,
        false_values: SimdBytes,
    ) -> SimdBytes {
        SimdBytes {
            bytes: masks
                .iter()
                .zip(true_values.bytes)
                .zip(false_values.bytes)
                .map(|((mask, t), f)| mask.select(t, f))
                .collect(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes
            .iter()
            .flat_map(|b| b.as_array())
            .copied()
            .collect()
    }
}

impl BitXorAssign for SimdBytes {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (x, y) in self.bytes.iter_mut().zip(rhs.bytes.into_iter()) {
            *x ^= y;
        }
    }
}

// TODO: Try #[inline]
pub fn xof(seed: &[u8], byte_count: usize) -> SimdBytes {
    let mut output_reader = Hasher::new().update(seed).finalize_xof();
    let mut expanded_bytes: Vec<u8> = vec![0; byte_count];
    output_reader.fill(&mut expanded_bytes);

    SimdBytes::from_bytes(&expanded_bytes)
}

pub fn create_zero_share(seeds: &[[u8; 16]], byte_count: usize) -> SimdBytes {
    let mut seeds_iterator = seeds.iter();

    let mut share = xof(seeds_iterator.next().unwrap(), byte_count);
    for seed in seeds_iterator {
        share ^= xof(seed, byte_count);
    }

    share
}

pub fn conditionally_corrupt_share(share: SimdBytes, conditions: &[bool]) -> SimdBytes {
    let conditions_expanded: Vec<bool> = conditions
        .iter()
        .flat_map(|b| [*b; SHARE_BYTE_COUNT])
        .collect();
    let masks: Vec<mask8x64> = conditions_expanded
        .array_chunks()
        .map(|chunk| mask8x64::from_array(*chunk))
        .collect();

    let mut randomness = vec![0; SHARE_BYTE_COUNT * conditions.len()];
    OsRng.fill_bytes(&mut randomness);
    let randomness_simd = SimdBytes::from_bytes(&randomness);

    SimdBytes::select(&masks, randomness_simd, share)
}

#[cfg(test)]
mod test {
    use crate::secret_sharing::{conditionally_corrupt_share, create_zero_share, SimdBytes};

    #[test]
    fn test_secret_shares() {
        let share_1 = create_zero_share(&vec![[1; 16], [2; 16]], 128);
        let share_2 = create_zero_share(&vec![[1; 16], [3; 16]], 128);
        let share_3 = create_zero_share(&vec![[2; 16], [3; 16]], 128);

        assert_ne!(share_1.to_bytes(), [0; 128]);
        assert_eq!(share_1.to_bytes().len(), 128);
        assert_ne!(share_2.to_bytes(), [0; 128]);
        assert_eq!(share_2.to_bytes().len(), 128);
        assert_ne!(share_3.to_bytes(), [0; 128]);
        assert_eq!(share_3.to_bytes().len(), 128);

        let mut aggregated = share_1;
        aggregated ^= share_2;
        aggregated ^= share_3;

        assert_eq!(aggregated.to_bytes(), [0; 128]);
    }

    #[test]
    fn test_corrupt_shares() {
        let share = SimdBytes::from_bytes(&[0u8; 320]);
        let mut conditions = [false; 64];
        conditions[1] = true;
        conditions[4] = true;
        conditions[30] = true;
        conditions[31] = true;
        let corrupted = conditionally_corrupt_share(
            SimdBytes {
                bytes: share.bytes.clone(),
            },
            &conditions,
        );

        assert_eq!(share.to_bytes()[0..5], corrupted.to_bytes()[0..5]);
        assert_ne!(share.to_bytes()[5..10], corrupted.to_bytes()[5..10]);
        assert_eq!(share.to_bytes()[10..15], corrupted.to_bytes()[10..15]);
        assert_eq!(share.to_bytes()[15..20], corrupted.to_bytes()[15..20]);
        assert_ne!(share.to_bytes()[20..25], corrupted.to_bytes()[20..25]);
        assert_eq!(share.to_bytes()[25..30], corrupted.to_bytes()[25..30]);
        assert_eq!(share.to_bytes()[30..35], corrupted.to_bytes()[30..35]);
        assert_eq!(share.to_bytes()[35..40], corrupted.to_bytes()[35..40]);
    }
}
