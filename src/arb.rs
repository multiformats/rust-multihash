use quickcheck::{Arbitrary, Gen};
use rand::{
    distributions::{weighted::WeightedIndex, Distribution},
    Rng,
};

use crate::MultihashGeneric;

/// Generates a random valid multihash.
impl<const S: usize> Arbitrary for MultihashGeneric<S> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        // In real world lower multihash codes are more likely to happen, hence distribute them
        // with bias towards smaller values.
        let weights = [128, 64, 32, 16, 8, 4, 2, 1];
        let dist = WeightedIndex::new(weights.iter()).unwrap();
        let code = match dist.sample(g) {
            0 => g.gen_range(0, u64::pow(2, 7)),
            1 => g.gen_range(u64::pow(2, 7), u64::pow(2, 14)),
            2 => g.gen_range(u64::pow(2, 14), u64::pow(2, 21)),
            3 => g.gen_range(u64::pow(2, 21), u64::pow(2, 28)),
            4 => g.gen_range(u64::pow(2, 28), u64::pow(2, 35)),
            5 => g.gen_range(u64::pow(2, 35), u64::pow(2, 42)),
            6 => g.gen_range(u64::pow(2, 42), u64::pow(2, 49)),
            7 => g.gen_range(u64::pow(2, 56), u64::pow(2, 63)),
            _ => unreachable!(),
        };

        // Maximum size is S byte due to the generic.
        let size = g.gen_range(0, S);
        let mut data = [0; S];
        g.fill_bytes(&mut data);
        MultihashGeneric::wrap(code, &data[..size]).unwrap()
    }
}
