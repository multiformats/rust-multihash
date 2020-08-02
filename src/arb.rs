use quickcheck::{Arbitrary, Gen};
use rand::seq::SliceRandom;

use crate::multihash::MultihashCreate;
use crate::multihash_impl::{
    Multihash, BLAKE2B_256, BLAKE2B_512, BLAKE2S_128, BLAKE2S_256, IDENTITY, KECCAK_224,
    KECCAK_256, KECCAK_384, KECCAK_512, SHA1, SHA2_256, SHA2_512, SHA3_224, SHA3_256, SHA3_384,
    SHA3_512,
};

const HASHES: [u64; 16] = [
    IDENTITY,
    SHA1,
    SHA2_256,
    SHA2_512,
    SHA3_512,
    SHA3_384,
    SHA3_256,
    SHA3_224,
    KECCAK_224,
    KECCAK_256,
    KECCAK_384,
    KECCAK_512,
    BLAKE2B_256,
    BLAKE2B_512,
    BLAKE2S_128,
    BLAKE2S_256,
];

/// Generates a random valid multihash.
///
/// This is done by encoding a random piece of data.
impl Arbitrary for Multihash {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let code = *HASHES.choose(g).unwrap();
        let data: Vec<u8> = Arbitrary::arbitrary(g);
        // encoding an actual random piece of data might be better than just choosing
        // random numbers of the appropriate size, since some hash algos might produce
        // a limited set of values
        Multihash::new(code, &data).unwrap()
    }
}
