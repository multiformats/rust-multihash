use alloc::{sync::Arc, vec::Vec};

/// MAX_INLINE is the maximum size of a multihash that can be stored inline
///
/// We want the currently most common multihashes using 256bit hashes to be stored inline. These
/// hashes are 34 bytes long. An overall size of 38 seems like a good compromise. It allows storing
/// any 256bit hash with some room to spare and gives an overall size for Storage of 40 bytes, which
/// is a multiple of 8. We need 2 extra bytes, one for the size and one for the enum discriminator.
const MAX_INLINE: usize = 38;

#[derive(Clone)]
pub(crate) enum Storage {
    /// hash is stored inline if it is smaller than MAX_INLINE
    Inline(u8, [u8; MAX_INLINE]),
    /// hash is stored on the heap. this must be only used if the hash is actually larger than
    /// MAX_INLINE bytes to ensure an unique representation.
    Heap(Arc<[u8]>),
}

impl Storage {
    /// The raw bytes.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Storage::Inline(len, bytes) => &bytes[..(*len as usize)],
            Storage::Heap(data) => &data,
        }
    }

    /// creates storage from a vec. For a size up to MAX_INLINE, this will not allocate.
    pub fn from_slice(slice: &[u8]) -> Self {
        let len = slice.len();
        if len <= MAX_INLINE {
            let mut data: [u8; MAX_INLINE] = [0; MAX_INLINE];
            data[..len].copy_from_slice(slice);
            Storage::Inline(len as u8, data)
        } else {
            Storage::Heap(slice.into())
        }
    }

    /// creates storage from multiple slices. For a size up to MAX_INLINE, this will not allocate.
    pub fn from_slices(slices: &[&[u8]]) -> Self {
        let n = slices.iter().fold(0usize, |a, s| a.saturating_add(s.len()));
        if n <= MAX_INLINE {
            let s = slices
                .iter()
                .fold(([0; MAX_INLINE], 0), |(mut array, i), s| {
                    array[i..i + s.len()].copy_from_slice(s);
                    (array, i + s.len())
                });
            Storage::Inline(n as u8, s.0)
        } else {
            let mut v = Vec::with_capacity(n);
            for s in slices {
                v.extend_from_slice(s)
            }
            Storage::Heap(v.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Storage, MAX_INLINE};
    use quickcheck::quickcheck;

    #[test]
    fn struct_size() {
        // this should be true for both 32 and 64 bit archs
        assert_eq!(std::mem::size_of::<Storage>(), 40);
    }

    #[test]
    fn roundtrip() {
        // check that .bytes() returns whatever the storage was created with
        for i in 0..((MAX_INLINE + 10) as u8) {
            let data = (0..i).collect::<Vec<u8>>();
            let storage = Storage::from_slice(&data);
            assert_eq!(data, storage.bytes());
        }
    }

    fn check_invariants(storage: Storage) -> bool {
        match storage {
            Storage::Inline(len, _) => len as usize <= MAX_INLINE,
            Storage::Heap(arc) => arc.len() > MAX_INLINE,
        }
    }

    quickcheck! {
        fn roundtrip_check(data: Vec<u8>) -> bool {
            let storage = Storage::from_slice(&data);
            storage.bytes() == data.as_slice() && check_invariants(storage)
        }

        fn from_slices_roundtrip_check(data: Vec<Vec<u8>>) -> bool {
            let mut slices = Vec::new();
            let mut expected = Vec::new();
            for v in data.iter() {
                slices.push(v.as_slice());
                expected.extend_from_slice(&v);
            }
            let storage = Storage::from_slices(&slices);
            storage.bytes() == expected.as_slice() && check_invariants(storage)
        }
    }
}
