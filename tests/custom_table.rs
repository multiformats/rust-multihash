#[macro_use]
extern crate multihash;

use multihash::{read_code, read_digest, Error, Hasher, MultihashCode, MultihashDigest};

#[derive(Clone, Copy, Debug, Eq, Hash, Multihash, PartialEq)]
enum MyCodeTable {
    #[mh(code = 0x1, hasher = multihash::Sha2_256, digest = multihash::Sha2Digest<multihash::U32>)]
    Foo,
    #[mh(code = 0x2, hasher = multihash::Sha2_512, digest = multihash::Sha2Digest<multihash::U64>)]
    Bar,
}
