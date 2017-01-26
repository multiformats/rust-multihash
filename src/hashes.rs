/// List of types currently supported in the multihash spec.
///
/// Not all hash types are supported by this library.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Hash {
    /// Encoding unsupported
    SHA1,
    /// SHA-256 (32-byte hash size)
    SHA2256,
    /// SHA-512 (64-byte hash size)
    SHA2512,
    /// Encoding unsupported
    SHA3512,
    /// Encoding unsupported
    SHA3384,
    /// Encoding unsupported
    SHA3256,
    /// Encoding unsupported
    SHA3224,
    /// Encoding unsupported
    Blake2b,
    /// Encoding unsupported
    Blake2s,
}

impl Hash {
    /// Get the corresponding hash code
    pub fn code(&self) -> u8 {
        match *self {
            Hash::SHA1 => 0x11,
            Hash::SHA2256 => 0x12,
            Hash::SHA2512 => 0x13,
            Hash::SHA3512 => 0x14,
            Hash::SHA3384 => 0x15,
            Hash::SHA3256 => 0x16,
            Hash::SHA3224 => 0x17,
            Hash::Blake2b => 0x40,
            Hash::Blake2s => 0x41,
        }
    }

    /// Get the hash length in bytes
    pub fn size(&self) -> u8 {
        match *self {
            Hash::SHA1 => 20,
            Hash::SHA2256 => 32,
            Hash::SHA2512 => 64,
            Hash::SHA3512 => 64,
            Hash::SHA3384 => 64,
            Hash::SHA3256 => 64,
            Hash::SHA3224 => 64,
            Hash::Blake2b => 64,
            Hash::Blake2s => 32,
        }
    }

    /// Get the human readable name
    pub fn name(&self) -> &str {
        match *self {
            Hash::SHA1 => "SHA1",
            Hash::SHA2256 => "SHA2-256",
            Hash::SHA2512 => "SHA2-512",
            Hash::SHA3512 => "SHA3-512",
            Hash::SHA3384 => "SHA3-384",
            Hash::SHA3256 => "SHA3-256",
            Hash::SHA3224 => "SHA3-224",
            Hash::Blake2b => "Blake-2b",
            Hash::Blake2s => "Blake-2s",
        }
    }

    pub fn from_code(code: u8) -> Option<Hash> {
        match code {
            0x11 => Some(Hash::SHA1),
            0x12 => Some(Hash::SHA2256),
            0x13 => Some(Hash::SHA2512),
            0x14 => Some(Hash::SHA3512),
            0x15 => Some(Hash::SHA3384),
            0x16 => Some(Hash::SHA3256),
            0x17 => Some(Hash::SHA3224),
            0x40 => Some(Hash::Blake2b),
            0x41 => Some(Hash::Blake2s),
            _ => None,
        }
    }
}
