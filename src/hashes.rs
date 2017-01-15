/// List of types currently supported in the multihash spec.
///
/// Not all hash types are supported by this library.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum HashTypes {
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

impl HashTypes {
    /// Get the corresponding hash code
    pub fn code(&self) -> u8 {
        match *self {
            HashTypes::SHA1 => 0x11,
            HashTypes::SHA2256 => 0x12,
            HashTypes::SHA2512 => 0x13,
            HashTypes::SHA3512 => 0x14,
            HashTypes::SHA3384 => 0x15,
            HashTypes::SHA3256 => 0x16,
            HashTypes::SHA3224 => 0x17,
            HashTypes::Blake2b => 0x40,
            HashTypes::Blake2s => 0x41,
        }
    }

    /// Get the hash length in bytes
    pub fn size(&self) -> u8 {
        match *self {
            HashTypes::SHA1 => 20,
            HashTypes::SHA2256 => 32,
            HashTypes::SHA2512 => 64,
            HashTypes::SHA3512 => 64,
            HashTypes::SHA3384 => 64,
            HashTypes::SHA3256 => 64,
            HashTypes::SHA3224 => 64,
            HashTypes::Blake2b => 64,
            HashTypes::Blake2s => 32,
        }
    }

    /// Get the human readable name
    pub fn name(&self) -> &str {
        match *self {
            HashTypes::SHA1 => "SHA1",
            HashTypes::SHA2256 => "SHA2-256",
            HashTypes::SHA2512 => "SHA2-512",
            HashTypes::SHA3512 => "SHA3-512",
            HashTypes::SHA3384 => "SHA3-384",
            HashTypes::SHA3256 => "SHA3-256",
            HashTypes::SHA3224 => "SHA3-224",
            HashTypes::Blake2b => "Blake-2b",
            HashTypes::Blake2s => "Blake-2s",
        }
    }

    pub fn from_code(code: u8) -> Option<HashTypes> {
        match code {
            0x11 => Some(HashTypes::SHA1),
            0x12 => Some(HashTypes::SHA2256),
            0x13 => Some(HashTypes::SHA2512),
            0x14 => Some(HashTypes::SHA3512),
            0x15 => Some(HashTypes::SHA3384),
            0x16 => Some(HashTypes::SHA3256),
            0x17 => Some(HashTypes::SHA3224),
            0x40 => Some(HashTypes::Blake2b),
            0x41 => Some(HashTypes::Blake2s),
            _ => None,
        }
    }
}
