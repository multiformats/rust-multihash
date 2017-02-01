use std::{fmt, error};

#[derive(Debug)]
pub enum Error {
    UnsupportedType,
    BadInputLength,
    UnkownCode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::UnsupportedType => "This type is not supported yet",
            Error::BadInputLength => "Not matching input length",
            Error::UnkownCode => "Found unkown code",
        }
    }
}
