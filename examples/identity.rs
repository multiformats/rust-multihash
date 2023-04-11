use multihash::Multihash;

//! An example for how to use the "identity" hash of [`Multihash`].
//!
//! Identity hashing means we don't actually perform any hashing.
//! Instead, we just store data directly in place of the "digest".
//!
//! [`Multihash::wrap`] returns an error in case the provided digest is too big for the available space.
//! Make sure you construct a [`Multihash`] with a large enough buffer for your data.
//!
//! Typically, the way you want to use the "identity" hash is:
//! 1. Check if your data is smaller than whatever buffer size you chose.
//! 2. If yes, store the data inline.
//! 3. If no, hash it make it fit into the provided buffer.

fn main() {
    let valid_identity_hash = Multihash::<64>::wrap(0, b"foobar").unwrap();
    let invalid_identity_hash = Multihash::<2>::wrap(0, b"foobar");

    assert_eq!(valid_identity_hash.digest(), b"foobar");
    assert_eq!(invalid_identity_hash.unwrap_err().to_string(), "Invalid multihash size 6.");
}
