use bytes::{Buf, Bytes};

use multihash::derive::Multihash;
use multihash::{Error, Hasher, MultihashDigest, MultihashGeneric, Sha2_256};

/// update appends and truncates/ignores updates > S
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

/// Borrows and concats slices using Bytes crate
#[derive(Debug, Default)]
pub struct IdentityBorrow(Bytes);

impl Hasher for IdentityBorrow {
    fn update(&mut self, input: &[u8]) {
        let new = (*self.0).chain(input);
        self.0 = Bytes::copy_from_slice(new.chunk());
    }
    fn finalize(&mut self) -> &[u8] {
        &self.0
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// update allocates & appends, Alloc only
#[derive(Default, Debug)]
pub struct IdentityAlloc(Vec<u8>);

impl Hasher for IdentityAlloc {
    fn update(&mut self, input: &[u8]) {
        self.0.extend(input);
    }
    fn finalize(&mut self) -> &[u8] {
        &self.0
    }
    fn reset(&mut self) {
        self.0.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, Multihash, PartialEq)]
#[mh(alloc_size = 64)]
pub enum Code {
    #[mh(code = 0x00, hasher = IdentityTrunk::<64>)]
    IdentityTrunk,
    // These will panic and if input > alloc_size, use alternate methods if you want to use bigger than alocated size
    // #[mh(code = 0x02, hasher = IdentityBorrow)]
    // IdentityBorrow,
    // #[mh(code = 0x03, hasher = IdentityAlloc)]
    // IdentityAlloc,
    #[mh(code = 0x12, hasher = Sha2_256)]
    Sha2_256,
}

fn main() {
    // overwrite and trunk with code

    let src = b"hello world!";
    let ident_trunk = Code::IdentityTrunk.digest(src);

    // for bigger than default table, but still known smaller than a const

    let big_src = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus vehicula tempor magna quis egestas. Etiam quis rhoncus neque.";

    // Helper functions cannot be used with normal table if S != alloc_size, fancier const trait bounds in the future may allow for interop where S <= alloc_size

    pub const IDENTITY_CODE: u64 = 0x0;
    // input must be const sized for this
    pub fn identity_hash_arr<const S: usize>(input: &[u8; S]) -> MultihashGeneric<S> {
        MultihashGeneric::wrap(IDENTITY_CODE, input).unwrap()
    }

    // input is truncated to S size
    pub fn identity_hash<const S: usize>(input: &[u8]) -> MultihashGeneric<S> {
        let mut hasher = IdentityTrunk::<S>::default();
        hasher.update(input);
        MultihashGeneric::wrap(IDENTITY_CODE, hasher.finalize()).unwrap()
    }

    let big_arr_mh = identity_hash_arr(big_src);
    let big_mh = identity_hash::<128>(big_src);
}
