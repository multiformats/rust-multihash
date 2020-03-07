use blake2b_simd::{Params as Blake2bParams, State as Blake2b};
use blake2s_simd::{Params as Blake2sParams, State as Blake2s};
use digest::Digest;

use crate::digests::{wrap, Multihash, MultihashDigest};

#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! impl_code {
    ($(
        #[$doc:meta]
        $name:ident => $code:expr,
    )*) => {
        /// The code of Multihash.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Code {
            $(
                #[$doc]
                $name,
            )*
            /// Make it possible to use a custom code that is not part of the enum yet
            Custom(u64),
        }

        impl Code {
            /// Return the code as integer value.
            pub fn to_u64(&self) -> u64 {
                match *self {
                    $(Self::$name => $code,)*
                    Self::Custom(code) => code,
                }
            }

            /// Return the `Code` based on the integer value. If the code is
            /// unknown/not implemented yet then it returns a `Code::Custom`.
            /// implements with that value.
            pub fn from_u64(code: u64) -> Self {
                match code {
                    $($code => Self::$name,)*
                    _ => Self::Custom(code),
                }
            }

            /// Return the hasher that is used to create a hash with this code.
            ///
            /// If a custom code is used, `None` is returned.
            pub fn hasher(&self) -> Option<Box<dyn MultihashDigest>> {
                match *self {
                    $(Self::$name => Some(Box::new($name::default())),)*
                    Self::Custom(_) => None,
                }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! derive_digest {
    ($(
        #[$doc:meta]
        @sha $type:ty as $name:ident => $code:expr,
    )*) => {
        $(
            #[$doc]
            #[derive(Clone, Debug, Default)]
            pub struct $name($type);
            impl $name {
                const CODE: Code = Code::$name;

                /// Computes the digest of
                fn digest(&self, data: &[u8]) -> Multihash {
                    let digest = <$type>::digest(&data);
                    wrap(Self::CODE, &digest)
                }
            }
            impl MultihashDigest for $name {
                fn code(&self) -> Code {
                    Self::CODE
                }
                fn digest(&self, data: &[u8]) -> Multihash {
                    Self::digest(self, data)
                }
                fn input(&mut self, data: &[u8]) {
                    Digest::input(&mut self.0, data)
                }
                fn result(self) -> Multihash {
                    wrap(Self::CODE, Digest::result(self.0).as_slice())
                }
            }

            derive_digest!(@write $name);
        )*
    };
    ($(
        #[$docs:meta]
        @blake $type:ty | $params:ty as $name:ident => $code:expr,
    )*) => {
        $(
            #[$docs]
            #[derive(Clone, Debug)]
            pub struct $name($type);
            impl $name {
                const CODE: Code = Code::$name;

                fn digest(&self, data: &[u8]) -> Multihash {
                    let digest = Self::default().0.update(&data).finalize();
                    wrap(Self::CODE, &digest.as_bytes())
                }
            }
            impl Default for $name {
                fn default() -> Self {
                    $name(<$params>::new().hash_length(32).to_state())
                }
            }
            impl MultihashDigest for $name {
                fn code(&self) -> Code {
                    Self::CODE
                }
                fn digest(&self, data: &[u8]) -> Multihash {
                    Self::digest(self, data)
                }
                fn input(&mut self, data: &[u8]) {
                    self.0.update(data);
                }
                fn result(self) -> Multihash {
                    let digest = self.0.finalize();
                    wrap(Self::CODE, &digest.as_bytes())
                }
            }

            derive_digest!(@write $name);
        )*
    };
    (@write $name:ident) => {
        impl ::std::io::Write for $name {
            fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
                <$name as MultihashDigest>::input(self, buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> ::std::io::Result<()> {
                Ok(())
            }
        }
    };
}

impl_code! {
    /// Identity (Raw binary )
    Identity => 0x00,
    /// SHA-1 (20-byte hash size)
    Sha1 => 0x11,
    /// SHA-256 (32-byte hash size)
    Sha2_256 => 0x12,
    /// SHA-512 (64-byte hash size)
    Sha2_512 => 0x13,
    /// SHA3-224 (28-byte hash size)
    Sha3_224 => 0x17,
    /// SHA3-256 (32-byte hash size)
    Sha3_256 => 0x16,
    /// SHA3-384 (48-byte hash size)
    Sha3_384 => 0x15,
    /// SHA3-512 (64-byte hash size)
    Sha3_512 => 0x14,
    /// Keccak-224 (28-byte hash size)
    Keccak224 => 0x1a,
    /// Keccak-256 (32-byte hash size)
    Keccak256 => 0x1b,
    /// Keccak-384 (48-byte hash size)
    Keccak384 => 0x1c,
    /// Keccak-512 (64-byte hash size)
    Keccak512 => 0x1d,
    /// BLAKE2b-256 (32-byte hash size)
    Blake2b256 => 0xb220,
    /// BLAKE2b-512 (64-byte hash size)
    Blake2b512 => 0xb240,
    /// BLAKE2s-128 (16-byte hash size)
    Blake2s128 => 0xb250,
    /// BLAKE2s-256 (32-byte hash size)
    Blake2s256 => 0xb260,
}

/// The Identity hasher.
#[derive(Clone, Debug, Default)]
pub struct Identity(Vec<u8>);
impl MultihashDigest for Identity {
    fn code(&self) -> Code {
        Self::CODE
    }
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
    fn input(&mut self, data: &[u8]) {
        if ((self.0.len() as u64) + (data.len() as u64)) >= u64::from(std::u32::MAX) {
            panic!("Input data for identity hash is too large, it needs to be less than 2^32.")
        }
        self.0.extend_from_slice(data)
    }
    fn result(self) -> Multihash {
        wrap(Self::CODE, &self.0)
    }
}
impl Identity {
    /// The code of Identity hasher, 0x00.
    pub const CODE: Code = Code::Identity;
    /// Hash some input and return the raw binary digest.
    pub fn digest(data: &[u8]) -> Multihash {
        if (data.len() as u64) >= u64::from(std::u32::MAX) {
            panic!("Input data for identity hash is too large, it needs to be less than 2^32.")
        }
        wrap(Self::CODE, &data)
    }
}

derive_digest! {
    /// The SHA-1 hasher.
    @sha ::sha1::Sha1 as Sha1 => 0x11,
    /// The SHA2-256 hasher.
    @sha ::sha2::Sha256 as Sha2_256 => 0x12,
    /// The SHA2-512 hasher.
    @sha ::sha2::Sha512 as Sha2_512 => 0x13,
    /// The SHA3-224 hasher.
    @sha ::sha3::Sha3_224 as Sha3_224 => 0x17,
    /// The SHA3-256 hasher.
    @sha ::sha3::Sha3_256 as Sha3_256 => 0x16,
    /// The SHA3-384 hasher.
    @sha ::sha3::Sha3_384 as Sha3_384 => 0x15,
    /// The SHA3-512 hasher.
    @sha ::sha3::Sha3_512 as Sha3_512 => 0x14,
    /// The Keccak-224 hasher.
    @sha ::sha3::Keccak224 as Keccak224 => 0x1a,
    /// The Keccak-256 hasher.
    @sha ::sha3::Keccak256 as Keccak256 => 0x1b,
    /// The Keccak-384 hasher.
    @sha ::sha3::Keccak384 as Keccak384 => 0x1c,
    /// The Keccak-512 hasher.
    @sha ::sha3::Keccak512 as Keccak512 => 0x1d,
}
derive_digest! {
    /// The Blake2b-256 hasher.
    @blake Blake2b | Blake2bParams as Blake2b256 => 0xb220,
    /// The Blake2b-512 hasher.
    @blake Blake2b | Blake2bParams as Blake2b512 => 0xb240,
    /// The Blake2s-128 hasher.
    @blake Blake2s | Blake2sParams as Blake2s128 => 0xb250,
    /// The Blake2s-256 hasher.
    @blake Blake2s | Blake2sParams as Blake2s256 => 0xb260,
}
