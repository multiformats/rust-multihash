use errors::Error;

/// List of types currently supported in the multihash spec.
///
/// Not all hash types are supported by this library.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
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
        use Hash::*;

        match *self {
            SHA1 => 0x11,
            SHA2256 => 0x12,
            SHA2512 => 0x13,
            SHA3512 => 0x14,
            SHA3384 => 0x15,
            SHA3256 => 0x16,
            SHA3224 => 0x17,
            Blake2b => 0x40,
            Blake2s => 0x41,
        }
    }

    /// Get the hash length in bytes
    pub fn size(&self) -> u8 {
        use Hash::*;

        match *self {
            SHA1 => 20,
            SHA2256 | Blake2s => 32,
            SHA2512 | SHA3512 | SHA3384 | SHA3256 | SHA3224 | Blake2b => 64,

        }
    }

    /// Get the human readable name
    pub fn name(&self) -> &str {
        use Hash::*;

        match *self {
            SHA1 => "SHA1",
            SHA2256 => "SHA2-256",
            SHA2512 => "SHA2-512",
            SHA3512 => "SHA3-512",
            SHA3384 => "SHA3-384",
            SHA3256 => "SHA3-256",
            SHA3224 => "SHA3-224",
            Blake2b => "Blake-2b",
            Blake2s => "Blake-2s",
        }
    }

    pub fn from_code(code: u8) -> Result<Hash, Error> {
        use Hash::*;

        Ok(match code {
            0x11 => SHA1,
            0x12 => SHA2256,
            0x13 => SHA2512,
            0x14 => SHA3512,
            0x15 => SHA3384,
            0x16 => SHA3256,
            0x17 => SHA3224,
            0x40 => Blake2b,
            0x41 => Blake2s,
            _ => return Err(Error::UnkownCode),
        })
    }
}
