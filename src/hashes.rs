use digest::{BlockInput, FixedOutput, Input, Reset};
use generic_array::typenum::Unsigned;

use multihash_digest::MultihashDigest;

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "20"]
#[Code = "0x11"]
pub struct Sha1(#[digest] sha1::Sha1);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "32"]
#[Code = "0x12"]
pub struct Sha2256(#[digest] sha2::Sha256);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "64"]
#[Code = "0x13"]
pub struct Sha2512(#[digest] sha2::Sha512);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "28"]
#[Code = "0x17"]
pub struct Sha3224(#[digest] sha3::Sha3_224);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "32"]
#[Code = "0x16"]
pub struct Sha3256(#[digest] sha3::Sha3_256);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "48"]
#[Code = "0x15"]
pub struct Sha3384(#[digest] sha3::Sha3_384);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "64"]
#[Code = "0x14"]
pub struct Sha3512(#[digest] sha3::Sha3_512);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "28"]
#[Code = "0x1A"]
pub struct Keccak224(#[digest] sha3::Keccak224);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "32"]
#[Code = "0x1B"]
pub struct Keccak256(#[digest] sha3::Keccak256);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "48"]
#[Code = "0x1C"]
pub struct Keccak384(#[digest] sha3::Keccak384);

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "64"]
#[Code = "0x1D"]
pub struct Keccak512(#[digest] sha3::Keccak512);

// #[derive(Default, Clone, Debug, MultihashDigest)]
// #[Size = "64"]
// #[Code = "0xb240"]
// pub struct Blake2b(#[digest] blake2::Blake2b);

#[cfg(test)]
mod tests {
    use super::super::{Digest, MultihashDigest};
    use super::Sha2256;

    use sha2::Sha256;

    use hex;

    #[test]
    fn test_multihash_sha2265() {
        assert_eq!(Sha2256::size(), 32);
        assert_eq!(Sha2256::name(), "Sha2256");

        let expected =
            hex::decode("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
                .expect("invalid hex fixture");

        let mut hasher = Sha2256::new();
        hasher.input(b"hello");
        hasher.input(b"world");
        assert_eq!(hasher.result().to_vec(), expected);

        assert_eq!(Sha2256::digest(b"helloworld").to_vec(), expected);
    }

    #[test]
    fn test_wrap() {
        let expected =
            hex::decode("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
                .expect("invalid hex fixture");

        let raw_digest = Sha256::digest(b"helloworld");

        assert_eq!(Sha2256::wrap(&raw_digest).to_vec(), expected);
    }
}
