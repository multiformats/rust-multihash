use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;

use multihash::{encode, Hash};

macro_rules! group_encode {
    ($criterion:ident, $( $id:expr => $hash:expr, $input:expr)* ) => {{
        let mut group = $criterion.benchmark_group("encode");
        $(
            group.bench_function($id, |b| {
                b.iter(|| {
                    let _ = black_box(encode($hash, $input).unwrap());
                })
            });
        )*
        group.finish();
    }};
}

fn bench_encode(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..1024).map(|_| rng.gen()).collect();
    group_encode!(c,
        "identity" => Hash::Identity, &data
        "sha1" => Hash::SHA1, &data
        "sha2_256" => Hash::SHA2256, &data
        "sha2_512" => Hash::SHA2512, &data
        "sha3_224" => Hash::SHA3224, &data
        "sha3_256" => Hash::SHA3256, &data
        "sha3_384" => Hash::SHA3384, &data
        "keccak_224" => Hash::Keccak224, &data
        "keccak_256" => Hash::Keccak256, &data
        "keccak_384" => Hash::Keccak384, &data
        "keccak_512" => Hash::Keccak512, &data
        "blake2b_256" => Hash::Blake2b256, &data
        "blake2b_512" => Hash::Blake2b512, &data
        "blake2s_128" => Hash::Blake2s128, &data
        "blake2s_256" => Hash::Blake2s256, &data
    );
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
