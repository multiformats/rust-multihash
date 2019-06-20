#![cfg(not(feature = "std"))]
#![no_std]

extern crate multihash;
use multihash::{MultihashDigest, Sha2_256};

#[test]
fn test_basic_no_std() {
    assert_eq!(Sha2_256::digest(b"hello world").as_ref().len(), 34,);
}
