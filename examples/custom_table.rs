use std::convert::TryFrom;

use tiny_multihash::derive::Multihash;
use tiny_multihash::typenum::{U20, U25};
use tiny_multihash::{
    Digest, Error, Hasher, Multihash as DefaultMultihash, MultihashDigest, RawMultihash,
    Sha2Digest, Sha2_256, StatefulHasher,
};

// The Multihash code is independent of whether the hash is truncated or not
const SHA2_256: u64 = 0x12;
const BLAKE2B_200: u64 = 0xb219;

// You can implement a custom hasher. This is a SHA2 256-bit hasher that returns a hash that is
// truncated to 160 bits.
#[derive(Default, Debug)]
pub struct Sha2_256Truncated20(Sha2_256);
impl StatefulHasher for Sha2_256Truncated20 {
    type Size = U20;
    type Digest = Sha2Digest<Self::Size>;
    fn update(&mut self, input: &[u8]) {
        self.0.update(input)
    }
    fn finalize(&self) -> Self::Digest {
        let digest = self.0.finalize();
        let truncated = &digest.as_ref()[..20];
        Self::Digest::try_from(truncated).expect("digest sizes always match")
    }
    fn reset(&mut self) {
        self.0.reset();
    }
}

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    /// Example for using a custom hasher which returns truncated hashes
    #[mh(code = SHA2_256, hasher = Sha2_256Truncated20)]
    Sha2_256Truncated20(tiny_multihash::Sha2Digest<U20>),
    /// Example for using a hasher with a bit size that is not exported by default
    #[mh(code = BLAKE2B_200, hasher = tiny_multihash::Blake2bHasher::<U25>)]
    Blake2b200(tiny_multihash::Blake2bDigest<U25>),
}

fn main() {
    // Create new hashes from some input data
    let blake_hash = Multihash::new(BLAKE2B_200, b"hello world!").unwrap();
    println!("{:02x?}", blake_hash);
    // A truncated hash, still has the same Multihash code as a non-truncated one
    let truncated_sha2_hash = Multihash::new(SHA2_256, b"hello world!").unwrap();
    println!("{:02x?}", truncated_sha2_hash);

    // Sometimes you might not need to hash new data, you just want to get the information about
    // a Multihash. This is what `RawMultihash` is for.
    let truncated_sha2_bytes = truncated_sha2_hash.to_bytes();
    let unknown_hash = RawMultihash::from_bytes(&truncated_sha2_bytes).unwrap();
    //println!("{:02x?}", unknown_hash);
    println!("SHA2 256-bit hash truncated to 160 bits:");
    println!("  code: {:x?}", unknown_hash.code());
    println!("  size: {}", unknown_hash.size());
    println!("  digest: {:02x?}", unknown_hash.digest());

    // Though you can transform a `RawMultihash` into your custom one if you have something for
    // the related code specified
    let truncated_sha2_hash_again: Multihash = unknown_hash.to_mh().unwrap();
    assert_eq!(truncated_sha2_hash_again, truncated_sha2_hash);

    // Not only the code is checked, but also the Digest size. This way you don't accidentally
    // work with truncated hashes without knowing.
    // To try this out we create a usual SHA2 256-bit hash that wasn't truncated
    let sha2_raw_hash = DefaultMultihash::new(SHA2_256, b"hello world!")
        .unwrap()
        .to_raw()
        .unwrap();
    println!("SHA2 256-bit hash:");
    println!("  code: {:x?}", sha2_raw_hash.code());
    println!("  size: {}", sha2_raw_hash.size());
    println!("  digest: {:02x?}", sha2_raw_hash.digest());
    // Now we try to convert it to a Multihash as part of our custom Multihash table
    let sha2_hash_error: Result<Multihash, _> = sha2_raw_hash.to_mh();
    // It errors as we only have defined a truncated SHA2 hash
    println!("Hash has the wrong size: {:?}", sha2_hash_error);
    // But it of course works with the default Multihash table
    let sha2_hash: Result<DefaultMultihash, _> = sha2_raw_hash.to_mh();
    println!(
        "The size matches the one of the default Multihash table: {:02x?}",
        sha2_hash
    );
}
