extern crate multihash;

use multihash::*;

/// Helper function to convert a hex-encoded byte array back into a bytearray
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut c = 0;
    let mut v = Vec::new();
    while c < s.len() {
        v.push(u8::from_str_radix(&s[c..c+2], 16).unwrap());
        c += 2;
    }
    v

}

#[test]
fn multihash_encode () {
    assert_eq!(
        encode(HashTypes::SHA2256, "helloworld".as_bytes()).unwrap(),
        hex_to_bytes("1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
    );
    assert_eq!(
        encode(HashTypes::SHA2256, "beep boop".as_bytes()).unwrap(),
        hex_to_bytes("122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c")
    );
    assert_eq!(
        encode(HashTypes::SHA2512, "hello world".as_bytes()).unwrap(),
        hex_to_bytes("1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f")
    );

}

#[test]
fn multihash_decode () {
    let hash: Vec<u8> = encode(HashTypes::SHA2256, "helloworld".as_bytes()).unwrap();
    assert_eq!(
        decode(&hash).unwrap().alg,
        HashTypes::SHA2256
    )
}

#[test]
fn hash_types () {
    assert_eq!(HashTypes::SHA2256.size(), 32);
    assert_eq!(HashTypes::SHA2256.name(), "SHA2-256");
}
