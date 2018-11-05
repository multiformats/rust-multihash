use digest::Digest;

pub trait MultihashDigest: ::std::fmt::Debug + Digest {
    fn size() -> usize;
    fn name() -> &'static str;
    fn code() -> u8;
}
