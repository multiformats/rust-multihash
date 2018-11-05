extern crate hex;
extern crate multihash;

use multihash::*;

macro_rules! assert_encode {
    {$( $alg:ident, $data:expr, $expect:expr; )*} => {
        $(
            assert_eq!(
                $alg::digest($data).to_vec(),
                hex::decode($expect).expect("invalid hex fixture"),
                "{} encodes correctly", $alg::name(),
            );
        )*
    }
}

#[test]
fn multihash_encode() {
    assert_encode! {
        Sha1, b"beep boop", "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        Sha2256, b"helloworld", "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        Sha2256, b"beep boop", "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        Sha2512, b"hello world", "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        Sha3224, b"hello world", "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        Sha3256, b"hello world", "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        Sha3384, b"hello world", "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        Sha3512, b"hello world", "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Keccak224, b"hello world", "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Keccak256, b"hello world", "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Keccak384, b"hello world", "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Keccak512, b"hello world", "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Blake2b, b"foo", "c0e40240ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d";
    }
}

// macro_rules! assert_decode {
//     {$( $alg:ident, $hash:expr; )*} => {
//         $(
//             let hash = hex_to_bytes($hash);
//             assert_eq!(
//                 decode(&hash).unwrap().alg,
//                 Hash::$alg,
//                 "{} decodes correctly", Hash::$alg.name()
//             );
//         )*
//     }
// }

// #[test]
// fn assert_decode() {
//     assert_decode! {
//         Sha1, "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
//         Sha2256, "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
//         Sha2256, "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
//         Sha2512, "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
//         Sha3224, "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
//         Sha3256, "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
//         Sha3384, "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
//         Sha3512, "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
//         Keccak224, "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
//         Keccak256, "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
//         Keccak384, "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
//         Keccak512, "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
//     }
// }

// macro_rules! assert_roundtrip {
//     ($( $alg:ident ),*) => {
//         $(
//             {
//                 let hash: Vec<u8> = encode(Hash::$alg, b"helloworld").unwrap();
//                 assert_eq!(
//                     decode(&hash).unwrap().alg,
//                     Hash::$alg
//                 );
//             }
//         )*
//     }
// }

// #[test]
// fn assert_roundtrip() {
//     assert_roundtrip!(
//         Sha1, Sha2256, Sha2512, Sha3224, Sha3256, Sha3384, Sha3512, Keccak224, Keccak256,
//         Keccak384, Keccak512
//     );
// }
