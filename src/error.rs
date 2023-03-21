#[cfg(not(feature = "std"))]
use core2::{error::Error as StdError, io::Error as IoError};
#[cfg(feature = "std")]
use std::{error::Error as StdError, io::Error as IoError};

use unsigned_varint::decode::Error as DecodeError;

/// Multihash error.
#[derive(Debug)]
pub enum Error {
    /// Io error.
    Io(IoError),
    /// Unsupported multihash code.
    UnsupportedCode(u64),
    /// Invalid multihash size.
    InvalidSize(u64),
    /// Invalid varint.
    Varint(DecodeError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::UnsupportedCode(code) => write!(f, "Unsupported multihash code {code}."),
            Self::InvalidSize(size) => write!(f, "Invalid multihash size {size}."),
            Self::Varint(err) => write!(f, "{err}"),
        }
    }
}

impl StdError for Error {}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

#[cfg(feature = "std")]
impl From<unsigned_varint::io::ReadError> for Error {
    fn from(err: unsigned_varint::io::ReadError) -> Self {
        match err {
            unsigned_varint::io::ReadError::Io(err) => Self::Io(err),
            unsigned_varint::io::ReadError::Decode(err) => Self::Varint(err),
            _ => unreachable!(),
        }
    }
}
