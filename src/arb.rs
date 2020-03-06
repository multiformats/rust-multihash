use quickcheck::{Arbitrary, Gen};
use rand::seq::SliceRandom;

use crate::{Code, Code::*, Multihash};

const HASHES: [Code; 16] = [
    Identity, Sha1, Sha2_256, Sha2_512, Sha3_512, Sha3_384, Sha3_256, Sha3_224, Keccak224,
    Keccak256, Keccak384, Keccak512, Blake2b256, Blake2b512, Blake2s128, Blake2s256,
];

/// Generates a random hash algorithm.
///
/// The more exotic ones will be generated just as frequently as the common ones.
impl Arbitrary for Code {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        *HASHES.choose(g).unwrap()
    }
}

/// Generates a random valid multihash.
///
/// This is done by encoding a random piece of data.
impl Arbitrary for Multihash {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let code: Code = Arbitrary::arbitrary(g);
        let data: Vec<u8> = Arbitrary::arbitrary(g);
        // encoding an actual random piece of data might be better than just choosing
        // random numbers of the appropriate size, since some hash algos might produce
        // a limited set of values
        code.hasher().digest(&data)
    }
}
