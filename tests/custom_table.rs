use tiny_multihash::derive::Multihash;
use tiny_multihash::{Digest, Error, Hasher, MultihashDigest};

const FOO: u64 = 0x01;
const BAR: u64 = 0x02;

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    #[mh(code = FOO, hasher = tiny_multihash::Sha2_256)]
    Foo(tiny_multihash::Sha2Digest<tiny_multihash::U32>),
    #[mh(code = BAR, hasher = tiny_multihash::Sha2_512)]
    Bar(tiny_multihash::Sha2Digest<tiny_multihash::U64>),
}
