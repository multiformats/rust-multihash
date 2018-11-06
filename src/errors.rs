#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "This type is not supported yet")]
    UnsupportedTpye,
    #[fail(display = "Not matching input length")]
    BadInputLength,
    #[fail(display = "Found unknown code: {}", _0)]
    UnknownCode(u32),
    #[fail(display = "Invalid multihash")]
    Invalid,
}
