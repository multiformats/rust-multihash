use multihash::{wrap, Code, Multihash, MultihashDigest, Sha3_512};

#[test]
fn to_u64() {
    assert_eq!(Code::Keccak256.to_u64(), 0x1b);
    assert_eq!(Code::Custom(0x1234).to_u64(), 0x1234);
}

#[test]
fn from_u64() {
    assert_eq!(Code::from_u64(0xb220), Code::Blake2b256);
    assert_eq!(Code::from_u64(0x0011_2233), Code::Custom(0x0011_2233));
}

#[test]
fn hasher() {
    let expected = Sha3_512::digest(b"abcdefg");
    let hasher = Code::Sha3_512.hasher().unwrap();
    assert_eq!(hasher.digest(b"abcdefg"), expected);
    assert!(Code::Custom(0x2222).hasher().is_none());
}

#[test]
fn custom_multihash_digest() {
    #[derive(Clone, Debug)]
    struct SameHash;
    impl MultihashDigest for SameHash {
        fn code(&self) -> Code {
            Code::Custom(0x9999)
        }

        fn digest(&self, _data: &[u8]) -> Multihash {
            let data = b"alwaysthesame";
            wrap(Self.code(), data)
        }

        fn input(&mut self, _data: &[u8]) {}
        fn result(self) -> Multihash {
            Self::digest(&self, &[])
        }
    }

    let my_hash = SameHash.digest(b"abc");
    assert_eq!(my_hash.digest(), b"alwaysthesame");
}
