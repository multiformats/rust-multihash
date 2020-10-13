use quickcheck::{Arbitrary, Gen};

use crate::{Multihash, U64};

#[cfg(feature = "multihash-impl")]
use crate::{Code, MultihashCode};
#[cfg(feature = "multihash-impl")]
use rand::seq::SliceRandom;

#[cfg(feature = "multihash-impl")]
const HASHES: [Code; 15] = [
    Code::Sha2_256,
    Code::Sha2_512,
    Code::Sha3_224,
    Code::Sha3_256,
    Code::Sha3_384,
    Code::Sha3_512,
    Code::Keccak224,
    Code::Keccak256,
    Code::Keccak384,
    Code::Keccak512,
    Code::Blake2b256,
    Code::Blake2b512,
    Code::Blake2s128,
    Code::Blake2s256,
    Code::Blake3_256,
];

/// Generates a random valid multihash.
///
/// This is done by encoding a random piece of data.
#[cfg(feature = "multihash-impl")]
impl Arbitrary for Multihash<U64> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let code = *HASHES.choose(g).unwrap();
        let mut data = [0; 1024];
        g.fill_bytes(&mut data);
        // encoding an actual random piece of data might be better than just choosing
        // random numbers of the appropriate size, since some hash algos might produce
        // a limited set of values
        code.digest(&data)
    }
}

#[cfg(not(feature = "multihash-impl"))]
use rand::Rng;

/// Generates a random valid multihash.
#[cfg(not(feature = "multihash-impl"))]
impl Arbitrary for Multihash<U64> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let code = g.gen::<u64>();
        // Maximum size is 64 byte due to the `U64` generic
        let size = g.gen_range(0, 64);
        let mut data = [0; 64];
        g.fill_bytes(&mut data);
        Multihash::wrap(code, &data[..size]).unwrap()
    }
}
