#[cfg(not(feature = "std"))]
use core2::{error::Error as StdError, io};
#[cfg(feature = "std")]
use std::{error::Error as StdError, io};

use unsigned_varint::decode::Error as DecodeError;

/// Opaque error struct for operations involving a [`Multihash`](crate::Multihash).
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

impl Error {
    /// The specified code is not supported by code table.
    /// FIXME: This should not be in our public API because it is only needed by the custom derive which we have no knowledge of in this crate.
    pub fn unsupported_code(code: u64) -> Self {
        Self {
            kind: Kind::UnsupportedCode(code),
        }
    }

    pub(crate) const fn invalid_size(size: u64) -> Self {
        Self {
            kind: Kind::InvalidSize(size),
        }
    }

    #[cfg(not(feature = "std"))]
    pub(crate) const fn insufficient_varint_bytes() -> Self {
        Self {
            kind: Kind::Varint(unsigned_varint::decode::Error::Insufficient),
        }
    }

    #[cfg(not(feature = "std"))]
    pub(crate) const fn varint_overflow() -> Self {
        Self {
            kind: Kind::Varint(unsigned_varint::decode::Error::Overflow),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.kind.fmt(f)
    }
}

#[derive(Debug)]
enum Kind {
    /// Io error.
    Io(io::Error),
    /// Unsupported multihash code.
    UnsupportedCode(u64),
    /// Invalid multihash size.
    InvalidSize(u64),
    /// Invalid varint.
    Varint(DecodeError),
}

#[cfg(feature = "std")]
pub(crate) fn unsigned_variant_to_multihash_error(err: unsigned_varint::io::ReadError) -> Error {
    match err {
        unsigned_varint::io::ReadError::Io(err) => io_to_multihash_error(err),
        unsigned_varint::io::ReadError::Decode(err) => Error {
            kind: Kind::Varint(err),
        },
        _ => unreachable!(),
    }
}

pub(crate) fn io_to_multihash_error(err: io::Error) -> Error {
    Error {
        kind: Kind::Io(err),
    }
}

impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::UnsupportedCode(code) => write!(f, "Unsupported multihash code {code}."),
            Self::InvalidSize(size) => write!(f, "Invalid multihash size {size}."),
            Self::Varint(err) => write!(f, "{err}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.kind {
            Kind::Io(inner) => Some(inner),
            Kind::UnsupportedCode(_) => None,
            Kind::InvalidSize(_) => None,
            Kind::Varint(_) => None, // FIXME: Does not implement `core2::Error`.
        }
    }
}
