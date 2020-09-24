use quickcheck::{Arbitrary, Gen};
use rand::seq::SliceRandom;

use crate::{Code, Multihash, U64};

const HASHES: [Code; 15] = [
    Code::Sha1,
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
];

/// Generates a random valid multihash.
///
/// This is done by encoding a random piece of data.
impl Arbitrary for Multihash<U64> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let code = *HASHES.choose(g).unwrap();
        let data: Vec<u8> = Arbitrary::arbitrary(g);
        // encoding an actual random piece of data might be better than just choosing
        // random numbers of the appropriate size, since some hash algos might produce
        // a limited set of values
        code.digest(&data)
    }
}
