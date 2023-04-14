use multihash_derive::MultihashDigest;

#[derive(Clone, Debug, Eq, PartialEq, Copy, MultihashDigest)]
#[mh(alloc_size = 32)]
pub enum Code {
    #[mh(code = 0x0, hasher = multihash_codetable::Identity256)]
    Identity256,
    /// Multihash array for hash function.
    #[mh(code = 0x38b64f, hasher = multihash_codetable::Strobe256)]
    Strobe256,
}

fn main() {
    assert_multihash_size_32(Code::Identity256.digest(&[]));
    assert_multihash_size_32(Code::Strobe256.digest(&[]));
}

fn assert_multihash_size_32(_mh: multihash_derive::Multihash<32>) {

}
