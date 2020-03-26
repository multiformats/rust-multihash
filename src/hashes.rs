use std::convert::TryFrom;

use blake2b_simd::{Params as Blake2bParams, State as Blake2b};
use blake2s_simd::{Params as Blake2sParams, State as Blake2s};
use digest::Digest;

use crate::digests::{wrap, Multihash, MultihashDigest};
use crate::errors::DecodeError;

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
        }

        impl TryFrom<Code> for Box<dyn MultihashDigest<Code>> {
            // TODO vmx 2020-03-25: Use a better error than `DeocdeError`
            type Error = DecodeError;

            fn try_from(code: Code) -> Result<Self, Self::Error> {
                match code {
                    $(Code::$name => Ok(Box::new($name::default())),)*
                }
            }
        }

        impl From<Code> for u64 {
            /// Return the code as integer value.
            fn from(code: Code) -> Self {
                match code {
                    $(Code::$name => $code,)*
                }
            }
        }

        impl TryFrom<u64> for Code {
            type Error = DecodeError;

            /// Return the `Code` based on the integer value. Error if no matching code exists.
            fn try_from(raw: u64) -> Result<Self, Self::Error> {
                match raw {
                    $($code => Ok(Self::$name),)*
                    _ => Err(DecodeError::UnknownCode),
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
        @sha $type:ty as $name:ident;
            @code_doc $code_doc:literal,
    )*) => {
        $(
            #[$doc]
            #[derive(Clone, Debug, Default)]
            pub struct $name($type);
            impl $name {
                #[doc = $code_doc]
                pub const CODE: Code = Code::$name;
                /// Hash some input and return the Multihash digest.
                pub fn digest(data: &[u8]) -> Multihash {
                    let digest = <$type>::digest(&data);
                    wrap(Self::CODE, &digest)
                }
            }
            impl MultihashDigest<Code> for $name {
                #[inline]
                fn code(&self) -> Code {
                    Self::CODE
                }
                #[inline]
                fn digest(&self, data: &[u8]) -> Multihash {
                    Self::digest(data)
                }
                #[inline]
                fn input(&mut self, data: &[u8]) {
                    self.0.input(data)
                }
                #[inline]
                fn result(self) -> Multihash {
                    wrap(Self::CODE, self.0.result().as_slice())
                }
                #[inline]
                fn result_reset(&mut self) -> Multihash {
                    wrap(Self::CODE, self.0.result_reset().as_slice())
                }
                #[inline]
                fn reset(&mut self) {
                    self.0.reset()
                }
            }
            impl ::std::io::Write for $name {
                #[inline]
                fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
                    <$name as MultihashDigest<Code>>::input(self, buf);
                    Ok(buf.len())
                }
                #[inline]
                fn flush(&mut self) -> ::std::io::Result<()> {
                    Ok(())
                }
            }
        )*
    };
    ($(
        #[$doc:meta]
        @blake $type:ty | $params:ty as $name:ident $len:expr;
            @code_doc $code_doc:literal,
    )*) => {
        $(
            #[$doc]
            #[derive(Clone, Debug)]
            pub struct $name($type);
            impl $name {
                #[doc = $code_doc]
                pub const CODE: Code = Code::$name;
                /// Hash some input and return the Multihash digest.
                pub fn digest(data: &[u8]) -> Multihash {
                    let digest = <$params>::new().hash_length($len).hash(data);
                    wrap(Self::CODE, &digest.as_bytes())
                }
            }
            impl Default for $name {
                fn default() -> Self {
                    $name(<$params>::new().hash_length($len).to_state())
                }
            }
            impl MultihashDigest<Code> for $name {
                #[inline]
                fn code(&self) -> Code {
                    Self::CODE
                }
                #[inline]
                fn digest(&self, data: &[u8]) -> Multihash {
                    Self::digest(data)
                }
                #[inline]
                fn input(&mut self, data: &[u8]) {
                    self.0.update(data);
                }
                #[inline]
                fn result(self) -> Multihash {
                    let digest = self.0.finalize();
                    wrap(Self::CODE, digest.as_bytes())
                }
                #[inline]
                fn result_reset(&mut self) -> Multihash {
                    let digest = self.0.finalize();
                    let hash = wrap(Self::CODE, digest.as_bytes());
                    self.reset();
                    hash
                }
                #[inline]
                fn reset(&mut self) {
                    self.0 = Self::default().0;
                }
            }
            impl ::std::io::Write for $name {
                #[inline]
                fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
                    <$name as MultihashDigest<Code>>::input(self, buf);
                    Ok(buf.len())
                }
                #[inline]
                fn flush(&mut self) -> ::std::io::Result<()> {
                    self.0.finalize();
                    Ok(())
                }
            }
        )*
    };
}

impl_code! {
    /// Identity (Raw binary)
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
impl MultihashDigest<Code> for Identity {
    #[inline]
    fn code(&self) -> Code {
        Self::CODE
    }
    #[inline]
    fn digest(&self, data: &[u8]) -> Multihash {
        Self::digest(data)
    }
    #[inline]
    fn input(&mut self, data: &[u8]) {
        if ((self.0.len() as u64) + (data.len() as u64)) >= u64::from(std::u32::MAX) {
            panic!("Input data for identity hash is too large, it needs to be less than 2^32.")
        }
        self.0.extend_from_slice(data)
    }
    #[inline]
    fn result(self) -> Multihash {
        wrap(Self::CODE, &self.0)
    }
    #[inline]
    fn result_reset(&mut self) -> Multihash {
        let hash = wrap(Self::CODE, &self.0);
        self.reset();
        hash
    }
    #[inline]
    fn reset(&mut self) {
        self.0.clear()
    }
}
impl Identity {
    /// The code of the Identity hasher, 0x00.
    pub const CODE: Code = Code::Identity;
    /// Hash some input and return the raw binary digest.
    pub fn digest(data: &[u8]) -> Multihash {
        if (data.len() as u64) >= u64::from(std::u32::MAX) {
            panic!("Input data for identity hash is too large, it needs to be less than 2^32.")
        }
        wrap(Self::CODE, data)
    }
}

derive_digest! {
    /// The SHA-1 hasher.
    @sha ::sha1::Sha1 as Sha1;
        @code_doc "The code of the SHA-1 hasher, 0x11.",
    /// The SHA2-256 hasher.
    @sha ::sha2::Sha256 as Sha2_256;
        @code_doc "The code of the SHA2-256 hasher, 0x12.",
    /// The SHA2-512 hasher.
    @sha ::sha2::Sha512 as Sha2_512;
        @code_doc "The code of the SHA2-512 hasher, 0x13.",
    /// The SHA3-224 hasher.
    @sha ::sha3::Sha3_224 as Sha3_224;
        @code_doc "The code of the SHA3-224 hasher, 0x17.",
    /// The SHA3-256 hasher.
    @sha ::sha3::Sha3_256 as Sha3_256;
        @code_doc "The code of the SHA3-256 hasher, 0x16.",
    /// The SHA3-384 hasher.
    @sha ::sha3::Sha3_384 as Sha3_384;
        @code_doc "The code of the SHA3-384 hasher, 0x15.",
    /// The SHA3-512 hasher.
    @sha ::sha3::Sha3_512 as Sha3_512;
        @code_doc "The code of the SHA3-512 hasher, 0x14.",
    /// The Keccak-224 hasher.
    @sha ::sha3::Keccak224 as Keccak224;
        @code_doc "The code of the Keccak-224 hasher, 0x1a.",
    /// The Keccak-256 hasher.
    @sha ::sha3::Keccak256 as Keccak256;
        @code_doc "The code of the Keccak-256 hasher, 0x1b.",
    /// The Keccak-384 hasher.
    @sha ::sha3::Keccak384 as Keccak384;
        @code_doc "The code of the Keccak-384 hasher, 0x1c.",
    /// The Keccak-512 hasher.
    @sha ::sha3::Keccak512 as Keccak512;
        @code_doc "The code of the Keccak-512 hasher, 0x1d.",
}
derive_digest! {
    /// The Blake2b-256 hasher.
    @blake Blake2b | Blake2bParams as Blake2b256 32;
        @code_doc "The code of the Blake2-256 hasher, 0xb220.",
    /// The Blake2b-512 hasher.
    @blake Blake2b | Blake2bParams as Blake2b512 64;
        @code_doc "The code of the Blake2-512 hasher, 0xb240.",
    /// The Blake2s-128 hasher.
    @blake Blake2s | Blake2sParams as Blake2s128 16;
        @code_doc "The code of the Blake2-128 hasher, 0xb250.",
    /// The Blake2s-256 hasher.
    @blake Blake2s | Blake2sParams as Blake2s256 32;
        @code_doc "The code of the Blake2-256 hasher, 0xb260.",
}
