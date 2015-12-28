extern crate multihash;

use multihash::*;

#[test]
fn multihash_encode () {
    assert_eq!(
        encode(HashTypes::SHA2256, "helloworld").unwrap(),
        "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
    );
    assert_eq!(
        encode(HashTypes::SHA2256, "beep boop").unwrap(),
        "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c"
    );
    assert_eq!(
        encode(HashTypes::SHA2512, "hello world").unwrap(),
        "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    );

}

#[test]
fn multihash_decode () {
    let hash = encode(HashTypes::SHA2256, "helloworld").unwrap();
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
