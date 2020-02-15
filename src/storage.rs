use std::sync::Arc;

const MAX_INLINE: usize = 39;

#[derive(Clone)]
pub enum Storage {
    /// hash is stored inline. if it is smaller than 39 bytes it should be padded with 0u8
    Inline([u8; MAX_INLINE]),
    /// hash is stored on the heap. this must be only used if the hash is actually larger than
    /// 39 bytes to ensure an unique representation.
    Heap(Arc<[u8]>),
}

impl Storage {
    /// The raw bytes. Note that this can be longer than the data this storage has been created from.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Storage::Inline(bytes) => bytes,
            Storage::Heap(data) => &data,
        }
    }

    /// creates storage from a vec. Note that this will not preserve the size.
    pub fn from_slice(slice: &[u8]) -> Self {
        if slice.len() <= MAX_INLINE {
            let mut data: [u8; MAX_INLINE] = [0; MAX_INLINE];
            data[..slice.len()].copy_from_slice(slice);
            Storage::Inline(data)
        } else {
            Storage::Heap(slice.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Storage;

    #[test]
    fn test_size() {
        assert_eq!(std::mem::size_of::<Storage>(), 40);
    }
}
