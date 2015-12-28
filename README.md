# rust-multihash

[![Build Status](https://img.shields.io/travis/Dignifiedquire/rust-multihash/master.svg?style=flat-square)](https://travis-ci.org/Dignifiedquire/rust-multihash)
[![](https://img.shields.io/badge/rust-docs-blue.svg?style=flat-square)](http://dignifiedquire.github.io/rust-multihash/multihash/struct.Multihash.html)

> [multihash](https://github.com/jbenet/multihash) implementation in Rust.


## Usage

First add this to your `Cargo.toml`

```toml
[dependencies]
multihash = "*"
```

```rust
crate extern multihash

use multihash::{encode, decode, HashType};

let hash = encode(HashTpype:SHA2256, "my hash").unwrap();
let multi = decode(&hash).unwrap();
```

## Supported Hash Types

* `SHA2 256`
* `SHA2 512`


## Dependencies

This uses [libsodium](https://github.com/jedisct1/libsodium) and [sodiumoxide](https://github.com/dnaq/sodiumoxide)
for the hashing so it depends on libsodium being installed.

## License

[MIT](LICENSE)
