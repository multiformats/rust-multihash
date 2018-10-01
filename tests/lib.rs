use multihash::{encode, Hash, Multihash, MultihashRef};

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
    {$( $alg:ident, $data:expr, $expect:expr; )*} => {
        $(
            assert_eq!(
                encode(Hash::$alg, $data).expect("Must be supported").into_bytes(),
                hex_to_bytes($expect),
                "{:?} encodes correctly", Hash::$alg
            );
        )*
    }
}

#[test]
fn multihash_encode() {
    assert_encode! {
        SHA1, b"beep boop", "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        SHA2256, b"helloworld", "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        SHA2256, b"beep boop", "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        SHA2512, b"hello world", "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        SHA3224, b"hello world", "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        SHA3256, b"hello world", "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        SHA3384, b"hello world", "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        SHA3512, b"hello world", "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Keccak224, b"hello world", "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Keccak256, b"hello world", "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Keccak384, b"hello world", "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Keccak512, b"hello world", "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Blake2b512, b"hello world", "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        Blake2s256, b"hello world", "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
    }
}

macro_rules! assert_decode {
    {$( $alg:ident, $hash:expr; )*} => {
        $(
            let hash = hex_to_bytes($hash);
            assert_eq!(
                MultihashRef::from_slice(&hash).unwrap().algorithm(),
                Hash::$alg,
                "{:?} decodes correctly", Hash::$alg
            );
        )*
    }
}

#[test]
fn assert_decode() {
    assert_decode! {
        SHA1, "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        SHA2256, "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        SHA2256, "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        SHA2512, "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        SHA3224, "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        SHA3256, "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        SHA3384, "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        SHA3512, "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Keccak224, "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Keccak256, "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Keccak384, "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Keccak512, "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Blake2b512, "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        Blake2s256, "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
    }
}

macro_rules! assert_roundtrip {
    ($( $alg:ident ),*) => {
        $(
            {
                let hash: Vec<u8> = encode(Hash::$alg, b"helloworld").unwrap().into_bytes();
                assert_eq!(
                    MultihashRef::from_slice(&hash).unwrap().algorithm(),
                    Hash::$alg
                );
            }
        )*
    }
}

#[test]
fn assert_roundtrip() {
    assert_roundtrip!(
        SHA1, SHA2256, SHA2512, SHA3224, SHA3256, SHA3384, SHA3512, Keccak224, Keccak256,
        Keccak384, Keccak512, Blake2b512, Blake2s256
    );
}

#[test]
fn hash_types() {
    assert_eq!(Hash::SHA1.size(), 20);
    assert_eq!(Hash::SHA2256.size(), 32);
    assert_eq!(Hash::SHA2512.size(), 64);
    assert_eq!(Hash::SHA3224.size(), 28);
    assert_eq!(Hash::SHA3256.size(), 32);
    assert_eq!(Hash::SHA3384.size(), 48);
    assert_eq!(Hash::SHA3512.size(), 64);
    assert_eq!(Hash::Keccak224.size(), 28);
    assert_eq!(Hash::Keccak256.size(), 32);
    assert_eq!(Hash::Keccak384.size(), 48);
    assert_eq!(Hash::Keccak512.size(), 64);
    assert_eq!(Hash::Blake2b512.size(), 64);
    assert_eq!(Hash::Blake2b256.size(), 32);
    assert_eq!(Hash::Blake2s256.size(), 32);
    assert_eq!(Hash::Blake2s128.size(), 16);
}

/// Testing the public interface of `Multihash` and `MultihashRef`
fn test_methods(hash: Hash, prefix: &str, digest: &str) {
    let expected_bytes = hex_to_bytes(&format!("{}{}", prefix, digest));
    let multihash = encode(hash, b"hello world").unwrap();
    assert_eq!(
        Multihash::from_bytes(expected_bytes.clone()).unwrap(),
        multihash
    );
    assert_eq!(multihash.as_bytes(), &expected_bytes[..]);
    assert_eq!(multihash.algorithm(), hash);
    assert_eq!(multihash.digest(), &hex_to_bytes(digest)[..]);

    let multihash_ref = multihash.as_ref();
    assert_eq!(multihash, multihash_ref);
    assert_eq!(multihash_ref, multihash);
    assert_eq!(
        MultihashRef::from_slice(&expected_bytes[..]).unwrap(),
        multihash_ref
    );
    assert_eq!(multihash_ref.algorithm(), multihash.algorithm());
    assert_eq!(multihash_ref.digest(), multihash.digest());
    assert_eq!(multihash_ref.as_bytes(), multihash.as_bytes());

    let multihash_clone = multihash_ref.to_owned();
    assert_eq!(multihash, multihash_clone);
    assert_eq!(multihash.into_bytes(), &expected_bytes[..]);
}

#[test]
fn multihash_methods() {
    test_methods(
        Hash::SHA1,
        "1114",
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    );
    test_methods(
        Hash::SHA2256,
        "1220",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
    test_methods(
        Hash::SHA2512,
        "1340",
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
    test_methods(
        Hash::SHA3224,
        "171C",
        "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5",
    );
    test_methods(
        Hash::SHA3256,
        "1620",
        "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
    );
    test_methods(
        Hash::SHA3384,
        "1530",
        "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b");
    test_methods(
        Hash::SHA3512,
        "1440",
        "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
    test_methods(
        Hash::Keccak224,
        "1A1C",
        "25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568",
    );
    test_methods(
        Hash::Keccak256,
        "1B20",
        "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
    );
    test_methods(
        Hash::Keccak384,
        "1C30",
        "65fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f");
    test_methods(
        Hash::Keccak512,
        "1D40",
        "3ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d");
}

#[test]
fn multihash_errors() {
    assert!(
        Multihash::from_bytes(Vec::new()).is_err(),
        "Should error on empty data"
    );
    assert!(
        Multihash::from_bytes(vec![1, 2, 3]).is_err(),
        "Should error on invalid multihash"
    );
    assert!(
        Multihash::from_bytes(vec![1, 2, 3]).is_err(),
        "Should error on invalid prefix"
    );
    assert!(
        Multihash::from_bytes(vec![0x12, 0x20, 0xff]).is_err(),
        "Should error on correct prefix with wrong digest"
    );
}

#[test]
fn multihash_ref_errors() {
    assert!(
        MultihashRef::from_slice(&[]).is_err(),
        "Should error on empty data"
    );
    assert!(
        MultihashRef::from_slice(&[1, 2, 3]).is_err(),
        "Should error on invalid multihash"
    );
    assert!(
        MultihashRef::from_slice(&[0x12, 0xff, 0x03]).is_err(),
        "Should error on invalid prefix"
    );
    assert!(
        MultihashRef::from_slice(&[0x12, 0x20, 0xff]).is_err(),
        "Should error on correct prefix with wrong digest"
    );
}
