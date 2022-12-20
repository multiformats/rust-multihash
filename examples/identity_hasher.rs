use multihash::derive::Multihash;
use multihash::{Error, Hasher, MultihashDigest, MultihashGeneric, Sha2_256};

/// update appends to end of buffer but truncates/ignores bytes after len > S
#[derive(Debug)]
pub struct IdentityTrunk<const S: usize> {
    cursor: usize,
    arr: [u8; S],
}

impl<const S: usize> Default for IdentityTrunk<S> {
    fn default() -> Self {
        Self {
            cursor: 0,
            arr: [0u8; S],
        }
    }
}
impl<const S: usize> Hasher for IdentityTrunk<S> {
    fn update(&mut self, input: &[u8]) {
        let src_end = (self.cursor + input.len()).min(self.arr.len());
        let input_end = input.len().min(self.arr.len() - self.cursor);

        self.arr[self.cursor..src_end].copy_from_slice(&input[..input_end]);
        self.cursor = src_end;
    }
    fn finalize(&mut self) -> &[u8] {
        &self.arr[..self.cursor]
    }
    fn reset(&mut self) {
        *self = Self {
            cursor: 0,
            arr: [0u8; S],
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, Multihash, PartialEq)]
#[mh(alloc_size = 64)]
pub enum Code {
    #[mh(code = 0x00, hasher = IdentityTrunk::<64>)]
    IdentityTrunk,
    #[mh(code = 0x12, hasher = Sha2_256)]
    Sha2_256,
}

fn main() {
    // overwrite and trunk with code

    let src = b"hello world!";
    let ident_trunk = Code::IdentityTrunk.digest(src);

    assert_eq!(ident_trunk.digest(), src);

    // input bigger than default table, but still const sized
    let big_src = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus vehicula tempor magna quis egestas. Etiam quis rhoncus neque.";

    let truncated = Code::IdentityTrunk.digest(big_src);
    assert_eq!(truncated.digest(), &big_src[..64]);
    //
    // Helper functions cannot be used with normal table if S != alloc_size, fancier const trait bounds in the future may allow for interop where S <= alloc_size
    //

    pub const IDENTITY_CODE: u64 = 0x0;
    // blind copy of the input array
    pub fn identity_hash_arr<const S: usize>(input: &[u8; S]) -> MultihashGeneric<S> {
        MultihashGeneric::wrap(IDENTITY_CODE, input).unwrap()
    }

    // input is truncated to S size
    pub fn identity_hash<const S: usize>(input: &[u8]) -> MultihashGeneric<S> {
        let mut hasher = IdentityTrunk::<S>::default();
        hasher.update(input);
        MultihashGeneric::wrap(IDENTITY_CODE, hasher.finalize()).unwrap()
    }

    // makes use of the const sized input to infer the output size
    let big_arr_mh = identity_hash_arr(big_src);
    assert_eq!(big_arr_mh.digest(), big_src);
    // size must be specified
    let big_mh = identity_hash::<128>(big_src);
    assert_eq!(big_mh.digest(), big_src);
}
