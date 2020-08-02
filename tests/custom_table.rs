use multihash::derive::Multihash;
use multihash::{read_code, read_digest, Error, Hasher, MultihashCreate, MultihashDigest};

const FOO: u64 = 0x01;
const BAR: u64 = 0x02;

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    #[mh(code = FOO, hasher = multihash::Sha2_256)]
    Foo(multihash::Sha2Digest<multihash::U32>),
    #[mh(code = BAR, hasher = multihash::Sha2_512)]
    Bar(multihash::Sha2Digest<multihash::U64>),
}
