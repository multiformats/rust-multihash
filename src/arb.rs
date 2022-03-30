use quickcheck::Gen;
use rand::{
    distributions::{weighted::WeightedIndex, Distribution},
    Rng,
};

use arbitrary::{size_hint, Unstructured};

use crate::MultihashGeneric;

/// Generates a random valid multihash.
impl<const S: usize> quickcheck::Arbitrary for MultihashGeneric<S> {
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

impl<'a, const S: usize> arbitrary::Arbitrary<'a> for MultihashGeneric<S> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut code = 0u64;
        for x in u.arbitrary_iter::<u8>()? {
            // arbitrary_iter gives next item with probability 1/2
            let next = code
                .checked_shl(7)
                .zip(x.ok())
                .map(|(next, x)| next.saturating_add((x & 0x7F) as u64));

            match next {
                None => break,
                Some(next) => code = next,
            }
        }

        let size = u.int_in_range(0..=S)?;
        let data = u.bytes(size)?;

        Ok(MultihashGeneric::wrap(code, data).unwrap())
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        size_hint::and(<[usize; 2]>::size_hint(depth), (0, None))
    }
}

#[cfg(test)]
mod tests {
    use crate::MultihashGeneric;
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn arbitrary() {
        let mut u = Unstructured::new(&[
            1, 2, 4, 13, 5, 6, 7, 8, 9, 6, 10, 243, 43, 231, 123, 43, 153,
        ]);
        let mh = <MultihashGeneric<16> as Arbitrary>::arbitrary(&mut u).unwrap();
        let mh2 =
            MultihashGeneric::<16>::wrap(2, &[5, 6, 7, 8, 9, 6, 10, 243, 43, 231, 123, 43, 153])
                .unwrap();
        assert_eq!(mh, mh2);
    }
}
