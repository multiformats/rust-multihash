/// List of types currently supported in the multihash spec.
///
/// Not all hash types are supported by this library.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum HashTypes {
    /// SHA1 (64-bytee hash size)
    SHA1,
    /// SHA2-256 (32-byte hash size)
    SHA2256,
    /// SHA2-512 (64-byte hash size)
    SHA2512,
    /// SHA3-512 (64-byte hash size)
    SHA3512,
    /// SHA3-384 (48-byte hash size)
    SHA3384,
    /// SHA3-256 (32-byte hash size)
    SHA3256,
    /// SHA3-224 (28-byte hash size)
    SHA3224,
    /// SHAKE-128
    SHAKE128,
    /// SHAKE-256
    SHAKE256,
    /// Blake2s
    Blake2b,
    /// Blake2b
    Blake2s
}

impl HashTypes {
    /// Get the corresponding hash code
    pub fn code(&self) -> u8 {
        match *self {
            HashTypes::SHA1     => 0x11,
            HashTypes::SHA2256  => 0x12,
            HashTypes::SHA2512  => 0x13,
            HashTypes::SHA3512  => 0x14,
            HashTypes::SHA3384  => 0x15,
            HashTypes::SHA3256  => 0x16,
            HashTypes::SHA3224  => 0x17,
            HashTypes::SHAKE128 => 0x18,
            HashTypes::SHAKE256 => 0x19,
            HashTypes::Blake2b  => 0x40,
            HashTypes::Blake2s  => 0x41,
        }
    }

    /// Get the hash length in bytes
    pub fn size(&self) -> u8 {
        match *self {
	    HashTypes::SHA1     => 20,
	    HashTypes::SHA2256  => 32,
	    HashTypes::SHA2512  => 64,
	    HashTypes::SHA3512  => 64,
        HashTypes::SHA3384  => 48,
        HashTypes::SHA3256  => 32,
        HashTypes::SHA3224  => 28,
        HashTypes::SHAKE128 => 16,
        HashTypes::SHAKE256 => 32,
	    HashTypes::Blake2b  => 64,
	    HashTypes::Blake2s  => 32,
        }
    }

    /// Get the human readable name
    pub fn name(&self) -> &str {
        match *self {
	    HashTypes::SHA1     => "SHA1",
	    HashTypes::SHA2256  => "SHA2-256",
	    HashTypes::SHA2512  => "SHA2-512",
	    HashTypes::SHA3512  => "SHA3-512",
        HashTypes::SHA3384  => "SHA3-384",
        HashTypes::SHA3256  => "SHA3-256",
        HashTypes::SHA3224  => "SHA3-224",
        HashTypes::SHAKE128 => "SHAKE-128",
        HashTypes::SHAKE256 => "SHAKE-256",
	    HashTypes::Blake2b  => "Blake-2b",
	    HashTypes::Blake2s  => "Blake-2s",
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
            0x18 => Some(HashTypes::SHAKE128),
            0x19 => Some(HashTypes::SHAKE256),
            0x40 => Some(HashTypes::Blake2b),
            0x41 => Some(HashTypes::Blake2s),
            _    => None
        }
    }
}
