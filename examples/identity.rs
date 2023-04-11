use multihash::Multihash;

fn main() {
    let valid_identity_hash = Multihash::<64>::wrap(0, b"foobar").unwrap();
    let invalid_identity_hash = Multihash::<2>::wrap(0, b"foobar");

    assert_eq!(valid_identity_hash.digest(), b"foobar");
    assert_eq!(invalid_identity_hash.unwrap_err().to_string(), "Invalid multihash size 6.");
}
