use std::convert::TryFrom;

use multihash::{Code, MultihashDigest, Sha3_512};

#[test]
fn to_u64() {
    assert_eq!(<u64>::from(Code::Keccak256), 0x1b);
}

#[test]
fn from_u64() {
    assert_eq!(Code::try_from(0xb220), Ok(Code::Blake2b256));
}

#[test]
fn hasher() {
    let expected = Sha3_512::digest(b"abcdefg");
    let hasher = Box::<dyn MultihashDigest>::from(Code::Sha3_512);
    assert_eq!(hasher.digest(b"abcdefg"), expected);
}
