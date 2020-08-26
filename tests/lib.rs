use multihash::*;

macro_rules! assert_encode {
    {$( $alg:ty, $data:expr, $expect:expr; )*} => {
        $(
            let bytes = hex::decode($expect).unwrap();
            assert_eq!(
                <$alg>::digest($data).into_bytes(),
                bytes,
                "{:?} encodes correctly", stringify!($alg)
            );

            let mut hasher = <$alg>::default();
            &mut hasher.input($data);
            assert_eq!(
                hasher.result().into_bytes(),
                bytes,
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
        Identity, b"abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz", "00a1016162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a206162636465666768696a6b6c6d6e6f707172737475767778797a";
        Identity, b"beep boop", "00096265657020626f6f70";
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

    #[cfg(feature = "use_blake3")]
    assert_encode! {
        Blake3, b"hello world", "1e20d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    }
}

macro_rules! assert_decode {
    {$( $alg:ty, $hash:expr; )*} => {
        $(
            let hash = hex::decode($hash).unwrap();
            assert_eq!(
                MultihashRef::from_slice(&hash).unwrap().algorithm(),
                <$alg>::CODE,
                "{:?} decodes correctly", stringify!($alg)
            );
        )*
    }
}

#[test]
fn assert_decode() {
    assert_decode! {
        Identity, "000a68656c6c6f776f726c64";
        Sha1, "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        Sha2_256, "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        Sha2_256, "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        Sha2_512, "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        Sha3_224, "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        Sha3_256, "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        Sha3_384, "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        Sha3_512, "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Keccak224, "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Keccak256, "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Keccak384, "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Keccak512, "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Blake2b512, "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        Blake2s256, "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
        Blake2b256, "a0e40220256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        Blake2s128, "d0e4021037deae0226c30da2ab424a7b8ee14e83";
    }
    #[cfg(feature = "use_blake3")]
    assert_decode! {
        Blake3, "1e20d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    }
}

macro_rules! assert_roundtrip {
    ($( $alg:ident ),*) => {
        $(
            {
                let hash: Vec<u8> = $alg::digest(b"helloworld").into_bytes();
                assert_eq!(
                    MultihashRef::from_slice(&hash).unwrap().algorithm(),
                    $alg::CODE
                );
            }
            {
                let mut hasher = $alg::default();
                &mut hasher.input(b"helloworld");
                let hash: Vec<u8> = hasher.result().into_bytes();
                assert_eq!(
                    MultihashRef::from_slice(&hash).unwrap().algorithm(),
                    $alg::CODE
                );
            }
        )*
    }
}

#[allow(clippy::cognitive_complexity)]
#[test]
fn assert_roundtrip() {
    assert_roundtrip!(
        Identity, Sha1, Sha2_256, Sha2_512, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Keccak224,
        Keccak256, Keccak384, Keccak512, Blake2b512, Blake2s256
    );
}

/// Testing the public interface of `Multihash` and `MultihashRef`
fn test_methods(hash: impl MultihashDigest<Code>, prefix: &str, digest: &str) {
    let expected_bytes = hex::decode(&format!("{}{}", prefix, digest)).unwrap();
    let multihash = hash.digest(b"hello world");
    assert_eq!(
        Multihash::from_bytes(expected_bytes.clone()).unwrap(),
        multihash
    );
    assert_eq!(multihash.as_bytes(), &expected_bytes[..]);
    assert_eq!(multihash.algorithm(), hash.code());
    assert_eq!(multihash.digest(), hex::decode(digest).unwrap().as_slice());

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
    test_methods(Identity::default(), "000b", "68656c6c6f20776f726c64");
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
    #[cfg(feature = "use_blake3")]
    test_methods(
        Blake3::default(),
        "1e20",
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24",
    );
}

#[test]
fn test_long_identity_hash() {
    // A hash with a length bigger than 0x80, hence needing 2 bytes to encode the length
    let input = b"abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz";
    let multihash = Identity::digest(input);
    assert_eq!(multihash.digest().to_vec(), input.to_vec());
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
    let identity_code = <u64>::from(Identity::CODE) as u8;
    let identity_length = 3;
    assert!(
        Multihash::from_bytes(vec![identity_code, identity_length, 1, 2, 3, 4]).is_err(),
        "Should error on wrong hash length"
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
    let identity_code = <u64>::from(Identity::CODE) as u8;
    let identity_length = 3;
    assert!(
        MultihashRef::from_slice(&[identity_code, identity_length, 1, 2, 3, 4]).is_err(),
        "Should error on wrong hash length"
    );

    let unsupported_code = 0x04;
    let hash_length = 3;
    assert_eq!(
        MultihashRef::from_slice(&[unsupported_code, hash_length, 1, 2, 3]),
        Err(DecodeError::UnknownCode),
        "Should error on codes that are not part of the code table"
    );
}

#[test]
fn wrap() {
    let mh = Sha2_256::digest(b"hello world");
    let digest = mh.digest();
    let wrapped: Multihash = multihash::wrap(Code::Sha2_256, &digest);
    assert_eq!(wrapped.algorithm(), Code::Sha2_256);
}

#[test]
fn wrap_generic() {
    let mh = Sha2_256::digest(b"hello world");
    let digest = mh.digest();
    let wrapped: MultihashGeneric<u64> = multihash::wrap(124, &digest);
    assert_eq!(wrapped.algorithm(), 124);
}
