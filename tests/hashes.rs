use std::convert::TryFrom;

use multihash::{wrap, BoxedMultihashDigest, Code, MultihashDigest, MultihashGeneric, Sha3_512};

enum MyCodeTable {
    Foo = 1,
    Bar = 2,
}

impl From<MyCodeTable> for u64 {
    /// Return the code as integer value.
    fn from(code: MyCodeTable) -> Self {
        code as _
    }
}

impl TryFrom<u64> for MyCodeTable {
    type Error = String;

    /// Return the `Code` based on the integer value. Error if no matching code exists.
    fn try_from(raw: u64) -> Result<Self, Self::Error> {
        match raw {
            1 => Ok(MyCodeTable::Foo),
            2 => Ok(MyCodeTable::Bar),
            _ => Err("Cannot convert".to_string()),
        }
    }
}

#[derive(Default)]
struct SameHash;
impl SameHash {
    pub const CODE: MyCodeTable = MyCodeTable::Foo;
    /// Hash some input and return the sha1 digest.
    pub fn digest(_data: &[u8]) -> MultihashGeneric<MyCodeTable> {
        let digest = b"alwaysthesame";
        wrap(Self::CODE, digest)
    }
}

impl MultihashDigest<MyCodeTable> for SameHash {
    #[inline]
    fn code(&self) -> MyCodeTable {
        Self::CODE
    }
    #[inline]
    fn digest(&self, data: &[u8]) -> MultihashGeneric<MyCodeTable> {
        Self::digest(data)
    }
    #[inline]
    fn input(&mut self, _data: &[u8]) {}
    #[inline]
    fn result(self) -> MultihashGeneric<MyCodeTable> {
        wrap(Self::CODE, b"alwaysthesame")
    }
    #[inline]
    fn result_reset(&mut self) -> MultihashGeneric<MyCodeTable> {
        wrap(Self::CODE, b"")
    }
    #[inline]
    fn reset(&mut self) {}
}

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
    let hasher: BoxedMultihashDigest = Code::Sha3_512.into();
    assert_eq!(hasher.digest(b"abcdefg"), expected);
}

#[test]
fn hasher_custom_codes() {
    impl From<MyCodeTable> for BoxedMultihashDigest<MyCodeTable> {
        fn from(code: MyCodeTable) -> Self {
            match code {
                MyCodeTable::Foo => Box::new(SameHash::default()),
                MyCodeTable::Bar => Box::new(SameHash::default()),
            }
        }
    }

    let expected = SameHash::digest(b"abcdefg");
    let hasher: BoxedMultihashDigest<_> = MyCodeTable::Foo.into();
    assert_eq!(hasher.digest(b"abcdefg"), expected);
}
