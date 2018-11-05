use digest::{BlockInput, FixedOutput, Input, Reset};
use sha2::Sha256;

use multihash_digest::MultihashDigest;

#[derive(Default, Clone, Debug, MultihashDigest)]
#[Size = "32"]
#[Code = "0x12"]
#[Name = "SHA2-256"]
pub struct Sha2256(Sha256);

#[cfg(test)]
mod tests {
    use super::super::{Digest, MultihashDigest};
    use super::Sha2256;

    use hex;

    #[test]
    fn test_multi_hash_sha265() {
        assert_eq!(Sha2256::size(), 32);
        assert_eq!(Sha2256::name(), "SHA2-256");

        let expected =
            hex::decode("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
                .expect("invalid hex fixture");

        let mut hasher = Sha2256::new();
        hasher.input(b"hello");
        hasher.input(b"world");
        assert_eq!(hasher.result().to_vec(), expected);

        assert_eq!(Sha2256::digest(b"helloworld").to_vec(), expected);
    }
}
