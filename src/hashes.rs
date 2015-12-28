// List of types currently supported in Multihash.
pub enum HashTypes {
    SHA1, // unsupported
    SHA2256,
    SHA2512, // unsupported
    SHA3, // unsupported
    Blake2b, // unsupported
    Blake2s // unsupported
}

impl HashTypes {
    pub fn to_u8(&self) -> u8 {
        match *self {
            HashTypes::SHA1 => 0x11,
            HashTypes::SHA2256 => 0x12,
            HashTypes::SHA2512 => 0x13,
            HashTypes::SHA3 => 0x14,
            HashTypes::Blake2b => 0x40,
            HashTypes::Blake2s => 0x41,
        }
    }
}
