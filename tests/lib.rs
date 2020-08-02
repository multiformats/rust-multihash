use multihash::{
    Blake2b256, Blake2b512, Blake2s128, Blake2s256, Hasher, Identity256, Keccak224, Keccak256,
    Keccak384, Keccak512, Multihash, MultihashDigest, RawMultihash, Sha1, Sha2_256, Sha2_512,
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, BLAKE2B_256, BLAKE2B_512, BLAKE2S_128, BLAKE2S_256,
    KECCAK_224, KECCAK_256, KECCAK_384, KECCAK_512, SHA1, SHA2_256, SHA2_512, SHA3_224, SHA3_256,
    SHA3_384, SHA3_512,
};

/// Helper function to convert a hex-encoded byte array back into a bytearray
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut c = 0;
    let mut v = Vec::new();
    while c < s.len() {
        v.push(u8::from_str_radix(&s[c..c + 2], 16).unwrap());
        c += 2;
    }
    v
}

macro_rules! assert_encode {
    {$( $alg:ty, $data:expr, $expect:expr; )*} => {
        $(
            let hex = hex_to_bytes($expect);
            assert_eq!(
                Multihash::from(<$alg>::digest($data)).to_bytes(),
                hex,
                "{:?} encodes correctly", stringify!($alg)
            );

            let mut hasher = <$alg>::default();
            hasher.update($data);
            assert_eq!(
                Multihash::from(hasher.finalize()).to_bytes(),
                hex,
                "{:?} encodes correctly", stringify!($alg)
            );
        )*
    }
}

#[allow(clippy::cognitive_complexity)]
#[test]
fn multihash_encode() {
    assert_encode! {
        // A hash with a length bigger than 0x80, hence needing 2 bytes to encode the length
        //Identity256, b"abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz", "00a1016162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a";
        //Identity256, b"beep boop", "00096265657020626f6f70";
        Sha1, b"beep boop", "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        Sha2_256, b"helloworld", "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        Sha2_256, b"beep boop", "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        Sha2_512, b"hello world", "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        Sha3_224, b"hello world", "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        Sha3_256, b"hello world", "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        Sha3_384, b"hello world", "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        Sha3_512, b"hello world", "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Keccak224, b"hello world", "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Keccak256, b"hello world", "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Keccak384, b"hello world", "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Keccak512, b"hello world", "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Blake2b512, b"hello world", "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        Blake2s256, b"hello world", "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
        Blake2b256, b"hello world", "a0e40220256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        Blake2s128, b"hello world", "d0e4021037deae0226c30da2ab424a7b8ee14e83";
    }
}

macro_rules! assert_decode {
    {$( $alg:ident, $hash:expr; )*} => {
        $(
            let hash = hex_to_bytes($hash);
            assert_eq!(
                Multihash::from_bytes(&hash).unwrap().code(),
                $alg,
                "{:?} decodes correctly", stringify!($alg)
            );
        )*
    }
}

#[test]
fn assert_decode() {
    assert_decode! {
        //Identity256, "000a68656c6c6f776f726c64";
        SHA1, "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        SHA2_256, "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        SHA2_256, "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        SHA2_512, "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        SHA3_224, "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        SHA3_256, "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        SHA3_384, "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        SHA3_512, "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        KECCAK_224, "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        KECCAK_256, "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        KECCAK_384, "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        KECCAK_512, "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        BLAKE2B_512, "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        BLAKE2S_256, "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
        BLAKE2B_256, "a0e40220256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        BLAKE2S_128, "d0e4021037deae0226c30da2ab424a7b8ee14e83";
    }
}

macro_rules! assert_roundtrip {
    ($( $alg:ident ),*) => {
        $(
            {
                let hash = Multihash::from($alg::digest(b"helloworld"));
                assert_eq!(
                    Multihash::from_bytes(&hash.to_bytes()).unwrap().code(),
                    hash.code()
                );
            }
            {
                let mut hasher = $alg::default();
                hasher.update(b"helloworld");
                let hash = Multihash::from(hasher.finalize());
                assert_eq!(
                    Multihash::from_bytes(&hash.to_bytes()).unwrap().code(),
                    hash.code()
                );
            }
        )*
    }
}

#[allow(clippy::cognitive_complexity)]
#[test]
fn assert_roundtrip() {
    assert_roundtrip!(
        Identity256,
        Sha1,
        Sha2_256,
        Sha2_512,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Keccak224,
        Keccak256,
        Keccak384,
        Keccak512,
        Blake2b512,
        Blake2s256
    );
}
/*
/// Testing the public interface of `Multihash` and `MultihashRef`
fn test_methods(hasher: impl MultihasherCode<Code>, prefix: &str, digest: &str) {
    let expected_bytes = hex_to_bytes(&format!("{}{}", prefix, digest));
    hasher.update(b"hello world");
    let multihash = Multihash::from(hasher.finalize());
    assert_eq!(Multihash::from_bytes(&expected_bytes).unwrap(), multihash);
    assert_eq!(multihash.to_bytes(), &expected_bytes[..]);
    assert_eq!(multihash.digest(), &hex_to_bytes(digest)[..]);
}

#[test]
fn multihash_methods() {
    //test_methods(Identity256::default(), "000b", "68656c6c6f20776f726c64");
    test_methods(
        Sha1::default(),
        "1114",
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    );
    test_methods(
        Sha2_256::default(),
        "1220",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
    test_methods(
        Sha2_512::default(),
        "1340",
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
    test_methods(
        Sha3_224::default(),
        "171C",
        "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5",
    );
    test_methods(
        Sha3_256::default(),
        "1620",
        "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
    );
    test_methods(
        Sha3_384::default(),
        "1530",
        "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b");
    test_methods(
        Sha3_512::default(),
        "1440",
        "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
    test_methods(
        Keccak224::default(),
        "1A1C",
        "25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568",
    );
    test_methods(
        Keccak256::default(),
        "1B20",
        "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
    );
    test_methods(
        Keccak384::default(),
        "1C30",
        "65fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f");
    test_methods(
        Keccak512::default(),
        "1D40",
        "3ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d");
    test_methods(
        Blake2b512::default(),
        "c0e40240",
        "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0");
    test_methods(
        Blake2s256::default(),
        "e0e40220",
        "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b",
    );
    test_methods(
        Blake2b256::default(),
        "a0e40220",
        "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
    );
    test_methods(
        Blake2s128::default(),
        "d0e40210",
        "37deae0226c30da2ab424a7b8ee14e83",
    );
}*/

#[test]
#[should_panic]
fn test_long_identity_hash() {
    // A hash with a length bigger than 0x80, hence needing 2 bytes to encode the length
    let input = b"abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz";
    Identity256::digest(input);
}

#[test]
fn multihash_errors() {
    assert!(
        Multihash::from_bytes(&[]).is_err(),
        "Should error on empty data"
    );
    assert!(
        Multihash::from_bytes(&[1, 2, 3]).is_err(),
        "Should error on invalid multihash"
    );
    assert!(
        Multihash::from_bytes(&[1, 2, 3]).is_err(),
        "Should error on invalid prefix"
    );
    assert!(
        Multihash::from_bytes(&[0x12, 0x20, 0xff]).is_err(),
        "Should error on correct prefix with wrong digest"
    );
    let identity_code: u8 = 0x00;
    let identity_length = 3;
    assert!(
        Multihash::from_bytes(&[identity_code, identity_length, 1, 2, 3, 4]).is_err(),
        "Should error on wrong hash length"
    );
}

#[test]
fn test_raw_multihash() {
    let digest_hex = "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
    let digest_bytes = hex_to_bytes(digest_hex);
    let mh = RawMultihash::from_bytes(&digest_bytes).unwrap();
    assert_eq!(mh.code(), SHA3_256);
    assert_eq!(mh.size(), 32);
    assert_eq!(mh.digest(), &digest_bytes[2..]);
}
