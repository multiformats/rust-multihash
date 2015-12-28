// List of types currently supported in Multihash.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum HashTypes {
    SHA1, // unsupported
    SHA2256,
    SHA2512, // unsupported
    SHA3, // unsupported
    Blake2b, // unsupported
    Blake2s // unsupported
}

impl HashTypes {
    /// Get the corresponding hash code
    pub fn code(&self) -> u8 {
        match *self {
            HashTypes::SHA1    => 0x11,
            HashTypes::SHA2256 => 0x12,
            HashTypes::SHA2512 => 0x13,
            HashTypes::SHA3    => 0x14,
            HashTypes::Blake2b => 0x40,
            HashTypes::Blake2s => 0x41,
        }
    }

    /// Get the hash length in bytes
    pub fn len(&self) -> u8 {
        match *self {
	    HashTypes::SHA1     => 20,
	    HashTypes::SHA2256  => 32,
	    HashTypes::SHA2512  => 64,
	    HashTypes::SHA3     => 64,
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
	    HashTypes::SHA3     => "SHA3",
	    HashTypes::Blake2b  => "Blake-2b",
	    HashTypes::Blake2s  => "Blake-2s",
        }
    }

    pub fn from_code(code: u8) -> Option<HashTypes> {
        match code {
            0x11 => Some(HashTypes::SHA1),
            0x12 => Some(HashTypes::SHA2256),
            0x13 => Some(HashTypes::SHA2512),
            0x14 => Some(HashTypes::SHA3),
            0x40 => Some(HashTypes::Blake2b),
            0x41 => Some(HashTypes::Blake2s),
            _    => None
        }
    }
}
